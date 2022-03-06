"""This file implements the lowest-level connections to other peers,
   and the basis of the ChatChat protocol. At this level, all we're
   concerned with is connecting to single other computers via TCP/IP,
   exchanging public keys, and getting secure connections."""

from typing import Callable, Optional
import socket

# Maximum number of simultaneous connections to allow in the backlog.
# This affects basically nothing.
BACKLOG = 16


class EncryptedStream:
    """An encrypted network connection to another computer."""

    @staticmethod
    def connect(
            other_addr: str,
            our_private_key: str,
            their_public_key: Callable[[str], bool],
    ) -> Optional[EncryptedStream]:  # noqa: F821
        """Establishes a connection to `other_addr`. Authenticates the
           connection using `our_private_key`. Passes the public key
           the peer sends through the provided `their_public_key`
           function; if the function returns `true`, then we accept
           their public key, and if it returns `false`, we abort the
           connection and raise an exception."""
        pass

    def send(self, data: bytearray) -> None:
        """Sends an array of bytes over the socket; throws an exception if the
           data cannot be sent. This function can be considered
           secure: under no circumstances can an eavesdropper on the
           wire be able to obtain `data`."""
        pass

    def recv(self) -> bytearray:
        """Receives an array of bytes from the socket; throws an exception if
           a networking or security error occurs. Due to the nature of
           TCP, the returned data may be a portion of a valid packet,
           or more than one valid packet; it is the responsibility of
           the caller to maintain bytes that have been received and
           assemble them into proper protocol data."""
        pass

    def close(self) -> None:
        """Closes the socket. After this function is called, `send` and `recv`
           must never be used again on the socket."""
        pass


class EncryptedListener:
    """A socket that binds to an address and listens for encrypted
       connections, and yields them as EncryptedStreams."""

    def __init__(
            self,
            addr: str,
            port: int,
            our_private_key: str,
            their_public_key: Callable[[str], bool],
    ) -> None:
        """Create a new listener socket with the given address, port, and
           private key. When remote peers connect to this listener,
           pass the public key they send through the
           `their_public_key` function; if and only if it returns
           `true`, use their public key and our private key to
           negotiate a secure, encrypted connection, which is yielded
           as an `EncryptedStream`.

           Throws an exception if binding to the address-port pair
           fails."""

        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)

        self._sock.bind((addr, port))
        self._sock.listen(BACKLOG)

    def accept(self) -> EncryptedStream:
        """Waits for the next valid, encrypted connection to the listener
           socket, and returns it as an encrypted stream."""
        pass
