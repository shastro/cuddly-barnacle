"""This file implements the lowest-level connections to other peers,
   and the basis of the ChatChat protocol. At this level, all we're
   concerned with is connecting to single other computers via TCP/IP,
   exchanging public keys, and getting secure connections."""

from io import BufferedIOBase, BufferedRWPair, BufferedWriter, BufferedReader
from typing import Any, Callable, cast, Optional, Tuple
import socket
import sys
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey as PrivateKey,
    X25519PublicKey as PublicKey,
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

# Maximum number of simultaneous connections to allow in the backlog,
# in the unlikely event that multiple clients connect between `accept`
# calls.
BACKLOG = 16

# Magic number we use to identify the ChatChat protocol.
MAGIC = b'ChatChat\n'


class EncryptedStream(BufferedIOBase):
    """An encrypted network connection to another computer."""

    def __init__(
            self,
            inner: BufferedRWPair,
            outgoing_key: bytes,
            incoming_key: bytes,
    ) -> None:
        """Creates a new EncryptedStream that promises that the given buffered
           socket can be used to send and receive encrypted traffic
           with the given key."""
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
        """Establishes a connection to `other_addr`. Authenticates the
           connection using `private_key`. Passes the public key the
           peer sends through the provided `key_checker` function; if
           the function returns `true`, then we accept their public
           key, and if it returns `false`, we abort the connection and
           raise an exception."""
        sock = socket.socket()
        sock.connect((other_addr, other_port))

        # This is annoying: if you look at the source code,
        # `sock.makefile` returns a BufferedRWPair, but mypy isn't
        # convinced of that.
        buf = cast(BufferedRWPair, sock.makefile('rwb'))

        magic_number_check(buf)
        c2s, s2c = key_exchange(buf, private_key, key_checker)

        return EncryptedStream(buf, c2s, s2c)

    def write(self, data: Any) -> int:
        """Sends an array of bytes over the socket; throws an exception if the
           data cannot be sent. This function can be considered
           secure: under no circumstances can an eavesdropper on the
           wire be able to obtain `data`."""
        encrypted = self._encryptor.update(data)
        return self._inner.write(encrypted)

    def read(self, n: Optional[int] = None) -> bytes:
        """Receives an array of bytes from the socket; throws an exception if
           a networking or security error occurs. The semantics of
           this function are the same as those of
           io.BufferedIOPair.read."""
        encrypted = self._inner.read(n)
        return self._decryptor.update(encrypted)

    def flush(self) -> None:
        """Immediately reads and writes any unwritten bytes from the
           socket."""
        self._inner.flush()

    def close(self) -> None:
        """Closes the socket. After this function is called, `send` and `recv`
           must never be used again on the socket."""
        self._inner.close()


class EncryptedListener:
    """A socket that binds to an address and listens for encrypted
       connections, and yields them as EncryptedStreams."""

    def __init__(
            self,
            addr: str,
            port: int,
            our_private_key: PrivateKey,
            key_checker: Callable[[PublicKey], bool],
    ) -> None:
        """Create a new listener socket with the given address, port, and
           private key. When remote peers connect to this listener,
           pass the public key they send through the `key_checker`
           function; if and only if it returns `true`, use their
           public key and our private key to negotiate a secure,
           encrypted connection, which is yielded as an
           `EncryptedStream`.

           Throws an exception if binding to the address-port pair
           fails."""

        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)

        self._sock.bind((addr, port))
        self._sock.listen(BACKLOG)

        self._private_key = our_private_key
        self._key_checker = key_checker

    def accept(self) -> EncryptedStream:
        """Waits for the next valid, encrypted connection to the listener
           socket, and returns it as an encrypted stream."""
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
    """Sends the protocol's magic number over the socket, and expects the
       machine on the other end to return the same magic number."""
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
       from the client to the server, and the second for use when
       sending data from the server to the client."""
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

    their_pk = PublicKey.from_public_bytes(deserialize_bytes(
        cast(BufferedReader, sock)
    ))

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
        listener = EncryptedListener(
            '0.0.0.0',
            18457,
            PrivateKey.generate(),
            lambda k: True
        )
        while True:
            connection = listener.accept()

            # Test buffering
            connection.write(b'Hello ')
            connection.flush()
            time.sleep(1)
            connection.write(b'World!')

            connection.close()

    elif command == 'connect':
        connection = EncryptedStream.connect(
            sys.argv[2],
            18457,
            PrivateKey.generate(),
            lambda k: True
        )

        print(connection.read(1000))
        connection.close()

    else:
        print('unknown command ' + command)


if __name__ == '__main__':
    basic_test()
