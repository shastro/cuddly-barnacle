"""This file implements the lowest-level connections to other peers,
   and the basis of the ChatChat protocol. At this level, all we're
   concerned with is connecting to single other computers via TCP/IP,
   exchanging public keys, and getting secure connections."""

from typing import Callable


class PeerSocket:
    """A connection to a single other peer in the ChatChat network."""

    def __init__(
            self,
            other_addr: str,
            our_private_key: str,
            their_public_key: Callable[[str], bool]
    ) -> None:
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
