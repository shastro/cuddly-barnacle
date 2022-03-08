"""This file implements the lowest-level connections to other peers,
   and the basis of the ChatChat protocol. At this level, all we're
   concerned with is connecting to single other computers via TCP/IP,
   exchanging public keys, and getting secure connections."""

from typing import Callable
import socket

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey as PrivateKey,
    X25519PublicKey as PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import (
    Cipher,
    algorithms,
    modes,
    CipherContext,
)

import sys

# Maximum number of simultaneous connections to allow in the backlog.
# This affects basically nothing.
BACKLOG = 16

# Maximum buffer size to receive data from.
BUFSIZE = 4096

# Magic number we use to identify the ChatChat protocol.
MAGIC = b'ChatChat\n'


class EncryptedStream:
    """An encrypted network connection to another computer."""

    def __init__(
            self,
            sock: socket.socket,
            key: bytes,
            buf: bytearray,
    ) -> None:
        """Creates a new EncryptedStream that promises that the given socket
           can be used to send and receive encrypted traffic with the
           given key."""
        self._sock = sock
        self._key = key
        self._buf = buf

        # BUG: We're using the same key and IV to encrypt traffic
        # going both ways at the moment, which is trivial to break.
        nonce = b'\0' * 16

        # Using CTR mode to get a stream cipher.
        cipher = Cipher(algorithms.AES(self._key), modes.CTR(nonce))
        self._encryptor: CipherContext = cipher.encryptor()  # type: ignore
        self._decryptor: CipherContext = cipher.decryptor()  # type: ignore

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
        buf = bytearray()

        magic_number_check(sock, buf)

        key = key_exchange(sock, buf, private_key, key_checker)

        return EncryptedStream(sock, key, buf)

    def send(self, data: bytes) -> None:
        """Sends an array of bytes over the socket; throws an exception if the
           data cannot be sent. This function can be considered
           secure: under no circumstances can an eavesdropper on the
           wire be able to obtain `data`."""
        encrypted = self._encryptor.update(data)
        self._sock.send(encrypted)  # send_all?

    def recv(self) -> bytes:
        """Receives an array of bytes from the socket; throws an exception if
           a networking or security error occurs. Due to the nature of
           TCP, the returned data may be a portion of a valid packet,
           or more than one valid packet; it is the responsibility of
           the caller to maintain bytes that have been received and
           assemble them into proper protocol data."""
        encrypted = self._sock.recv(BUFSIZE)
        return self._decryptor.update(encrypted)

    def close(self) -> None:
        """Closes the socket. After this function is called, `send` and `recv`
           must never be used again on the socket."""
        self._sock.close()


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
                buf = bytearray()

                # BUG: These are blocking operations, which will lock
                # up the main thread if someone connects and then
                # doesn't send any data.
                magic_number_check(sock, buf)

                key = key_exchange(
                    sock,
                    buf,
                    self._private_key,
                    self._key_checker
                )
                return EncryptedStream(sock, key, buf)

            except ProtocolException as e:
                print('Warning: rejected incoming connection: ' + str(e))


def magic_number_check(sock: socket.socket, buf: bytearray) -> None:
    """Sends the protocol's magic number over the socket, and expects the
       machine on the other end to return the same magic number. Uses
       `buf` as storage for buffering on the socket."""
    sock.send(MAGIC)
    if read_exact(sock, buf, len(MAGIC)) != MAGIC:
        raise ProtocolException('received incorrect magic number')


def key_exchange(
        sock: socket.socket,
        buf: bytearray,
        private_key: PrivateKey,
        key_checker: Callable[[PublicKey], bool],
) -> bytes:
    """Performs a key exchange with over the socket with the given private
       key. Checks the public key the peer sends with the functin
       `key_checker`; raises an exception if that function returns
       `False`."""
    our_pk_bytes = private_key.public_key().public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw,
    )

    # Send and receive public keys prefixed by their lengths as 32-bit
    # (4-byte) integers.
    sock.send(bytearray(len(our_pk_bytes).to_bytes(4, 'big')) + our_pk_bytes)
    their_pk_len = int.from_bytes(read_exact(sock, buf, 4), 'big')
    their_pk_bytes = bytes(read_exact(sock, buf, their_pk_len))
    their_pk = PublicKey.from_public_bytes(their_pk_bytes)

    if not key_checker(their_pk):
        raise ProtocolException("rejected peer's public key")

    shared_key = private_key.exchange(their_pk)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        # I'm 85% certain these should both be None; need to do
        # further research to be positive, though. ~~Alex
        salt=None,
        info=None,
    ).derive(shared_key)

    return derived_key


def read_exact(
        sock: socket.socket,
        buf: bytearray,
        length: int,
) -> bytearray:
    """Reads exactly `length` bytes from `sock`, using `buf` to store
       extra bytes read. Throws an exception if less than `length`
       bytes can be read from the socket."""
    while len(buf) < length:
        nextbuf = sock.recv(BUFSIZE)
        if len(nextbuf) == 0:
            raise ProtocolException('unexpected EOF')

        buf += nextbuf

    read = buf[0:length]
    del buf[0:length]

    return read


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
            connection.send(b'Hello World!')
            connection.close()

    elif command == 'connect':
        connection = EncryptedStream.connect(
            sys.argv[2],
            18457,
            PrivateKey.generate(),
            lambda k: True
        )

        buf = bytearray()
        while True:
            next_buf = connection.recv()
            if len(next_buf) == 0:
                break
            buf += next_buf

        print(buf)
        connection.close()

    else:
        print('unknown command ' + command)


if __name__ == '__main__':
    basic_test()
