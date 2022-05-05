"""Encrypted low-level connections.

This file implements the lowest-level connections to other peers, and
the basis of the ChatChat protocol. At this level, all we're concerned
with is connecting to single other computers via TCP/IP, exchanging
public keys, and getting secure connections.

"""

from io import BufferedIOBase, BufferedRWPair, BufferedWriter, BufferedReader
from types import TracebackType
from typing import Any, Callable, cast, Optional, Tuple, Type
import socket
import sys
import time
import unittest
import threading

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
    Encoding as _Encoding,
    PublicFormat as _PublicFormat,
)

from Serial import Serialize, Deserialize

# Explicit re-export so mypy doesn't complain if we re-use these in
# other files.
PrivateKey = _PrivateKey
PublicKey = _PublicKey
Encoding = _Encoding
PublicFormat = _PublicFormat


# Maximum number of simultaneous connections to allow in the backlog,
# in the unlikely event that multiple clients connect between `accept`
# calls.
BACKLOG = 16

# Magic number we use to identify the ChatChat protocol.
MAGIC = b"ChatChat\n"

# If this is `True`, don't actually encrypt messages. Makes life a bit
# easier when debugging with Wireshark.
DRY_RUN = True

# If this is `True`, don't check keys. This is extremely insecure and
# should not be used in production.
DISABLE_KEY_CHECK = True

# Address of a computer within the network we're using. In this case,
# it's an IP address-port number pair.
PeerAddress = Tuple[str, int]


class EncryptedStream(BufferedIOBase):
    """An encrypted network connection to another computer."""

    def __init__(
        self,
        inner: BufferedRWPair,
        selector: int,
        outgoing_key: bytes,
        incoming_key: bytes,
    ) -> None:
        """Creates a new EncryptedStream.

        This constructor is considered private and should not be used
        by external classes under any circumstances; it can change at
        any time.

        The stream will send and receive encrypted data using the
        given pair of keys: one for encrypting outgoing data, and
        another for decrypting incoming data. (Due to the nature of a
        stream cipher, these should always be different from each
        other.)

        The first parameter to the function (inner) is the actual
        object used for exchanging data; the second parameter
        (selector) is used as a parameter to the `select()` function.

        Postconditions: `_inner` is an open stream.

        """
        self._inner = inner
        self._selector = selector
        self._incoming_key = incoming_key
        self._outgoing_key = outgoing_key

        nonce = b"\0" * 16

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
        our_addr: PeerAddress,
        other_addr: PeerAddress,
        private_key: PrivateKey,
        key_checker: Callable[[PublicKey], bool],
    ) -> "EncryptedStream":
        """Establishes a new connection to `other_addr`.

        This function uses public-key cryptography to generate a
        shared pair of keys for sending traffic both ways, rather than
        using pre-existing known keys. Authenticates the connection
        using `private_key`. Passes the public key the peer sends
        through the provided `key_checker` function; if the function
        returns `true`, then we accept their public key, and if it
        returns `false`, we abort the connection and raise an
        exception.

        Postcondition: a connection to `other_addr` is created, and a
        key exchange is performed.

        """
        sock = socket.socket()
        sock.connect(other_addr)

        # This is annoying: if you look at the source code,
        # `sock.makefile` returns a BufferedRWPair, but mypy isn't
        # convinced of that.
        bufferpair = cast(BufferedRWPair, sock.makefile("rwb"))

        magic_number_check(bufferpair)
        their_addr, c2s, s2c = handshake(
            bufferpair,
            private_key,
            our_addr,
            key_checker,
        )

        return EncryptedStream(bufferpair, sock.fileno(), c2s, s2c)

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> None:
        """Exits a `with` block.

        Precondition: `_inner` is an open stream.

        Postcondition: `_inner` is a closed stream.

        """
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

        Precondition: `_inner` is an open stream.

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

        Precondition: `_inner` is an open stream.

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

        Postcondition: `_inner` has zero bytes in its buffer.

        """
        self._inner.flush()

    def close(self) -> None:
        """Closes the socket.

        After this function is called, the socket object becomes
        invalidated, and no further member functions may be called.

        Precondition: `_inner` is an open stream.

        Postcondition: `_inner` is a closed stream.

        """
        self._inner.close()

    def selector(self) -> int:
        """Gets the object to pass to the `select` function.

        This function is pure.

        """
        return self._selector


class EncryptedListener:
    """A listener for EncryptedStream connections.

    A socket that binds to a TCP address and listens for connections,
    performs key exchanges, and yields the authenticated, encrypted
    connections as EncryptedStreams.

    """

    def __init__(
        self,
        addr: PeerAddress,
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

        Precondition: the system is not listening on address `addr`.

        Postcondition: the system is listening on address `addr`.

        """

        self._addr = addr

        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        self._sock.bind(addr)
        self._sock.listen(BACKLOG)

        self._private_key = our_private_key
        self._key_checker = key_checker

    def __enter__(self) -> "EncryptedListener":
        """Enters a `with` block.

        Since this operation has no special meaning for an
        EncryptedListener, this function does nothing.

        This function is pure.

        """
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> None:
        """Exits a `with` block.

        Precondition: `_sock` is an open socket.

        Postcondition: `_sock` is a closed socket.

        """
        self._sock.close()

    def accept(self) -> Tuple[EncryptedStream, PeerAddress]:
        """Waits for the next EncryptedStream connection.

        Waits for the next valid, encrypted connection to the listener
        socket, and returns it as an encrypted stream. Also returns
        the address and port of the remote host.

        Precondition: `_sock` is an open socket.

        """
        while True:
            try:
                sock, source_addr = self._sock.accept()
                buf = cast(BufferedRWPair, sock.makefile("rwb"))

                # BUG: These are blocking operations, which will lock
                # up the main thread if someone connects and then
                # doesn't send any data.
                magic_number_check(buf)

                return_addr, c2s, s2c = handshake(
                    buf, self._private_key, self._addr, self._key_checker
                )

                # If we want to connect to the remote node, we'll use
                # the physical source_addr, but a different port.
                addr = (source_addr[0], return_addr[1])

                return (EncryptedStream(buf, sock.fileno(), s2c, c2s), addr)

            except Exception as e:
                if isinstance(e, OSError):
                    raise e
                print("Warning: rejected incoming connection: " + str(e))


def magic_number_check(sock: BufferedRWPair) -> None:
    """Checks that the remote machine is using the correct protocol.

    Sends the protocol's magic number over the socket, and expects the
    machine on the other end to return the same magic number.

    """
    sock.write(MAGIC)
    sock.flush()
    response = sock.read(len(MAGIC))
    if response != MAGIC:
        response_str = response.decode("utf-8", errors="replace")
        magic_str = MAGIC.decode("utf-8", errors="replace")
        raise VersionException(
            f'got magic number "{response_str}", expected "{magic_str}"'
        )


def handshake(
    sock: BufferedRWPair,
    private_key: PrivateKey,
    local_addr: PeerAddress,
    key_checker: Callable[[PublicKey], bool],
) -> Tuple[PeerAddress, bytes, bytes]:
    """Performs a key exchange over the socket with the given private key.

    Checks the public key the peer sends with the function
    `key_checker`; raises an exception if that function returns
    `False`.

    Returns the address to use for reconnecting to the peer, as well
    as a pair of keys: the first one for use when sending data from
    the client to the server, and the second for use when sending data
    from the server to the client. Which machine is the server and
    which is the client is beyond the scope of this function.

    """
    our_pk_bytes = private_key.public_key().public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw,
    )

    # Send and receive public keys.
    Serialize.bytes(
        cast(BufferedWriter, sock),
        our_pk_bytes,
    )
    sock.flush()

    their_pk = PublicKey.from_public_bytes(
        bytes(Deserialize.bytes(cast(BufferedReader, sock)))
    )

    if not (DISABLE_KEY_CHECK or key_checker(their_pk)):
        raise SecurityException("rejected peer's public key")

    shared_key = private_key.exchange(their_pk)

    # Send and receive listener socket addresses. This might be
    # redundant in most cases, but allows clients to run nodes on
    # different ports, which is especially important for debugging.
    Serialize.bytes(
        cast(BufferedWriter, sock),
        local_addr[0].encode("utf-8"),
    )
    Serialize.long(cast(BufferedWriter, sock), local_addr[1])

    sock.flush()
    their_ip = Deserialize.bytes(cast(BufferedReader, sock)).decode("utf-8")
    their_port = Deserialize.long(cast(BufferedReader, sock))
    their_addr = (their_ip, their_port)

    return (
        their_addr,
        HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"Client to server",
        ).derive(shared_key),
        HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"Server to client",
        ).derive(shared_key),
    )


class ProtocolException(Exception):
    """An exception that occurs at the protocol level."""

    def __init__(self, reason: str):
        message = f"protocol error: {reason}"
        super().__init__(message)


class VersionException(ProtocolException):
    """Raised when we're communicating with a different program version."""

    def __init__(self, reason: str):
        message = f"peer returned wrong magic number: {reason}"
        super().__init__(message)


class SecurityException(ProtocolException):
    """Raised when security cannot be guaranteed."""

    def __init__(self, reason: str):
        message = f"security error: {reason}"
        super().__init__(message)


class TestEncryptedListener(unittest.TestCase):
    def test_begins_listening(self):
        """Verify that `EncryptedListener()` begins listening.

        The precondition and postcondition on `EncryptedListener()`
        contradict each other; verify that this is the case by
        creating two `EncryptedListener`s with the same parameters and
        detecting the exception caused by the contradiction.

        """
        addr = ("0.0.0.0", 2525)
        private_key = PrivateKey.generate()
        key_checker = lambda k: True  # noqa: E731

        with EncryptedListener(addr, private_key, key_checker):
            with self.assertRaises(OSError):
                # Should error out: address already in use.
                EncryptedListener(addr, private_key, key_checker)

    def test_stops_listening(self):
        """Verify that `__exit__` stops listening."""
        addr = ("0.0.0.0", 2526)
        private_key = PrivateKey.generate()
        key_checker = lambda k: True  # noqa: E731

        listener = EncryptedListener(addr, private_key, key_checker)
        listener.__exit__(None, None, None)
        with self.assertRaises(OSError):
            listener.accept()

    def test_accept(self):
        """Verify that `accept` can receive a connection."""
        addr_1 = ("0.0.0.0", 2527)
        addr_2 = ("0.0.0.0", 2528)
        private_key_1 = PrivateKey.generate()
        private_key_2 = PrivateKey.generate()
        key_checker = lambda k: True  # noqa: E731

        with EncryptedListener(
                addr_1,
                private_key_1,
                key_checker,
        ) as listener:
            # Need to connect from another thread, so the handshake
            # can take place properly.
            threading.Thread(
                target=lambda: EncryptedStream.connect(
                    addr_2,
                    addr_1,
                    private_key_2,
                    key_checker,
                )
            ).start()

            listener.accept()


class TestEncryptedStream(unittest.TestCase):
    def test_sending_data(self):
        """Test sending data between two EncryptedStreams.

        By implication, this tests the postcondition on the function
        EncryptedStream.__init__, the postcondition on connect(), the
        postcondition on write(), and the postcondition on read().

        """
        addr_1 = ("0.0.0.0", 2529)
        addr_2 = ("0.0.0.0", 2530)
        private_key_1 = PrivateKey.generate()
        private_key_2 = PrivateKey.generate()
        key_checker = lambda k: True  # noqa: E731

        with EncryptedListener(
                addr_1,
                private_key_1,
                key_checker,
        ) as listener:
            global conn_1
            conn_1 = None

            def connect():
                global conn_1
                print("connecting")
                conn_1 = EncryptedStream.connect(
                    addr_2,
                    addr_1,
                    private_key_2,
                    key_checker
                )
                print("connected")

            threading.Thread(
                target=connect,
            ).start()
            conn_2, _addr = listener.accept()
            time.sleep(1)       # race condition

            conn_2.write(b'hello')
            conn_2.flush()
            self.assertEqual(conn_1.read(5), b'hello')


def basic_test() -> None:
    command = sys.argv[1]
    if command == "listen":
        with EncryptedListener(
            ("0.0.0.0", 18457),
            PrivateKey.generate(),
            lambda k: True,
        ) as listener:
            while True:
                # with listener.accept() as connection:
                connection, (addr, port) = listener.accept()

                # Test buffering
                connection.write(b"Hello ")
                connection.flush()
                time.sleep(1)
                connection.write(b"World!")

                connection.close()

    elif command == "connect":
        with EncryptedStream.connect(
            ("0.0.0.0", 18457),
            (sys.argv[2], 18457),
            PrivateKey.generate(),
            lambda k: True,
        ) as connection:
            print(connection.read(1000))

    else:
        print("unknown command " + command)


if __name__ == "__main__":
    # basic_test()
    unittest.main()
