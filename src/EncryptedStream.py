"""Encrypted low-level connections.

This file implements the lowest-level connections to other peers, and
the basis of the ChatChat protocol. At this level, all we're concerned
with is connecting to single other computers via TCP/IP, exchanging
public keys, and getting secure connections.

"""

from io import BufferedIOBase, BufferedRWPair, BufferedWriter, BufferedReader
from types import TracebackType
from typing import Any, Callable, cast, Optional, Tuple, Type, Union
import socket
import sys
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey as _PrivateKey,
    X25519PublicKey as _PublicKey,
)
from cryptography.hazmat.primitives.ciphers import (
    algorithms,
    Cipher,
    CipherContext,
    modes,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from Serial import serialize_bytes, deserialize_bytes

# Explicit re-export so mypy doesn't complain if we re-use these in
# other files.
PrivateKey = _PrivateKey
PublicKey = _PublicKey

# Maximum number of simultaneous connections to allow in the backlog,
# in the unlikely event that multiple clients connect between `accept`
# calls.
BACKLOG = 16

# Magic number we use to identify the ChatChat protocol.
MAGIC = b'ChatChat\n'

# If this is `True`, don't actually encrypt messages. Makes life a bit
# easier when debugging with Wireshark.
DRY_RUN = False


class EncryptedStream(BufferedIOBase):
    """An encrypted network connection to another computer."""

    def __init__(
            self,
            inner: BufferedRWPair,
            outgoing_key: bytes,
            incoming_key: bytes,
    ) -> None:
        """Creates a new EncryptedStream.

        The stream will send and receive encrypted data using the
        given pair of keys: one for encrypting outgoing data, and
        another for decrypting incoming data. (Due to the nature of a
        stream cipher, these should always be different from each
        other.)

        """
        self._inner = inner
        self._incoming_key = incoming_key
        self._outgoing_key = outgoing_key

        nonce = b'\0' * 16

        # Using CTR mode to get a stream cipher.
        self._decryptor: CipherContext = Cipher(
            algorithms.AES(self._incoming_key),
            modes.CTR(nonce),
        ).decryptor()  # type: ignore

        self._encryptor: CipherContext = Cipher(
            algorithms.AES(self._outgoing_key),
            modes.CTR(nonce),
        ).decryptor()  # type: ignore

    @staticmethod
    def connect(
            other_addr: str,
            other_port: int,
            private_key: PrivateKey,
            key_checker: Callable[[PublicKey], bool],
    ) -> 'EncryptedStream':
        """Establishes a new connection to `other_addr`.

        This function uses public-key cryptography to generate a
        shared pair of keys for sending traffic both ways, rather than
        using pre-existing known keys. Authenticates the connection
        using `private_key`. Passes the public key the peer sends
        through the provided `key_checker` function; if the function
        returns `true`, then we accept their public key, and if it
        returns `false`, we abort the connection and raise an
        exception.

        """
        sock = socket.socket()
        sock.connect((other_addr, other_port))

        # This is annoying: if you look at the source code,
        # `sock.makefile` returns a BufferedRWPair, but mypy isn't
        # convinced of that.
        bufferpair = cast(BufferedRWPair, sock.makefile('rwb'))

        magic_number_check(bufferpair)
        c2s, s2c = key_exchange(bufferpair, private_key, key_checker)

        return EncryptedStream(bufferpair, c2s, s2c)

    def __exit__(
            self,
            exc_type: Optional[Type[BaseException]],
            exc_val: Optional[BaseException],
            exc_tb: Optional[TracebackType]
    ) -> None:
        """Exits a `with` block."""
        BufferedIOBase.__exit__(self, exc_type, exc_val, exc_tb)
        self._inner.close()

    def write(self, data: Any) -> int:
        """Sends an array of bytes over the socket.

        Adds `data` to the buffer of bytes to be sent, and may or may
        not send some amount of actual data over the wire; use
        `flush()` to immediately send any remaining data. Throws an
        exception if the data cannot be sent. This function can be
        considered secure: under no circumstances can an eavesdropper
        on the wire be able to obtain or modify `data`.

        """
        if DRY_RUN:
            encrypted = data
        else:
            encrypted = self._encryptor.update(data)
        return self._inner.write(encrypted)

    def read(self, n: Optional[int] = None) -> bytes:
        """Receives an array of bytes from the socket.

        Throws an exception if a networking or security error occurs.
        The semantics of this function are the same as those of
        io.BufferedIOPair.read.

        """
        encrypted = self._inner.read(n)
        if DRY_RUN:
            return encrypted
        else:
            return self._decryptor.update(encrypted)

    def flush(self) -> None:
        """Sends any buffered bytes from the socket.

        Immediately sends any bytes that have been queued using
        `write`.

        """
        self._inner.flush()

    def close(self) -> None:
        """Closes the socket.

        After this function is called, the socket object becomes
        invalidated, and no further member functions may be called.

        """
        self._inner.close()


class EncryptedListener:
    """A listener for EncryptedStream connections.

    A socket that binds to a TCP address and listens for connections,
    performs key exchanges, and yields the authenticated, encrypted
    connections as EncryptedStreams.

    """

    def __init__(
            self,
            addr: Union[int, str],
            port: int,
            our_private_key: PrivateKey,
            key_checker: Callable[[PublicKey], bool],
    ) -> None:
        """Create a new listener socket.

        Uses the given address, port, and private key. When remote
        peers connect to this listener, the EncryptedListener passes
        the public key they send through the `key_checker` function;
        if and only if it returns `true`, use their public key and our
        private key to negotiate a secure, encrypted connection, which
        is yielded as an `EncryptedStream`; otherwise, reject their
        connection as a security violation.

        Throws an exception if binding to the address-port pair fails.

        """

        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)

        self._sock.bind((addr, port))
        self._sock.listen(BACKLOG)

        self._private_key = our_private_key
        self._key_checker = key_checker

    def __enter__(self) -> 'EncryptedListener':
        return self

    def __exit__(
            self,
            exc_type: Optional[Type[BaseException]],
            exc_val: Optional[BaseException],
            exc_tb: Optional[TracebackType]
    ) -> None:
        """Exits a `with` block."""
        self._sock.close()

    def accept(self) -> EncryptedStream:
        """Waits for the next EncryptedStream connection.

        Waits for the next valid, encrypted connection to the listener
        socket, and returns it as an encrypted stream.

        """
        while True:
            try:
                sock, _ret_addr = self._sock.accept()
                buf = cast(BufferedRWPair, sock.makefile('rwb'))

                # BUG: These are blocking operations, which will lock
                # up the main thread if someone connects and then
                # doesn't send any data.
                magic_number_check(buf)

                c2s, s2c = key_exchange(
                    buf,
                    self._private_key,
                    self._key_checker
                )
                return EncryptedStream(buf, s2c, c2s)

            except Exception as e:
                print('Warning: rejected incoming connection: ' + str(e))


def magic_number_check(sock: BufferedRWPair) -> None:
    """Checks that the remote machine is using the correct protocol.

    Sends the protocol's magic number over the socket, and expects the
    machine on the other end to return the same magic number.

    """
    sock.write(MAGIC)
    sock.flush()
    if sock.read(len(MAGIC)) != MAGIC:
        raise ProtocolException('received incorrect magic number')


def key_exchange(
        sock: BufferedRWPair,
        private_key: PrivateKey,
        key_checker: Callable[[PublicKey], bool],
) -> Tuple[bytes, bytes]:
    """Performs a key exchange over the socket with the given private key.

    Checks the public key the peer sends with the function
    `key_checker`; raises an exception if that function returns
    `False`.

    Returns a pair of keys: the first one for use when sending data
    from the client to the server, and the second for use when sending
    data from the server to the client. Which machine is the server
    and which is the client is beyond the scope of this function.

    """
    our_pk_bytes = private_key.public_key().public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw,
    )

    # Send and receive public keys.
    serialize_bytes(
        cast(BufferedWriter, sock),
        our_pk_bytes,
    )
    sock.flush()

    their_pk = PublicKey.from_public_bytes(bytes(deserialize_bytes(
        cast(BufferedReader, sock)
    )))

    if not key_checker(their_pk):
        raise ProtocolException("rejected peer's public key")

    shared_key = private_key.exchange(their_pk)

    return (
        HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'Client to server',
        ).derive(shared_key),
        HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'Server to client',
        ).derive(shared_key),
    )


class ProtocolException(Exception):
    """An exception that occurs at the protocol level."""


def basic_test() -> None:
    command = sys.argv[1]
    if command == 'listen':
        with EncryptedListener(
                '0.0.0.0',
                18457,
                PrivateKey.generate(),
                lambda k: True,
        ) as listener:
            while True:
                with listener.accept() as connection:
                    # Test buffering
                    connection.write(b'Hello ')
                    connection.flush()
                    time.sleep(1)
                    connection.write(b'World!')

    elif command == 'connect':
        with EncryptedStream.connect(
                sys.argv[2],
                18457,
                PrivateKey.generate(),
                lambda k: True,
        ) as connection:
            print(connection.read(1000))

    else:
        print('unknown command ' + command)


if __name__ == '__main__':
    basic_test()
