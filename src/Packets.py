"""Network packet classes & definitions."""

from abc import ABC, abstractmethod
from enum import Enum, auto, unique
from io import BufferedReader, BufferedWriter
from typing import List, Optional, cast
import sys

from Event import Event, EventMessagePost, EventJoin, EventLeave
from Serial import Serialize, Deserialize
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey as PrivateKey,
)
from EncryptedStream import (
    ProtocolException,
    EncryptedListener,
    EncryptedStream,
    PeerAddress,
)


@unique
class PacketId(Enum):
    """Packet ID numbers."""

    # Message request and response: one peer requests the list of
    # every message the other peer has satisfying some predicate.
    GET_EVENTS = auto()
    GET_EVENTS_RESP = auto()

    # Post event: a peer sends a new event that every other peer on
    # the network can see.
    POST_EVENT = auto()

    # Reroute: a peer sends an event to its predecessor, indicating
    # that the predecessor should set its successor to a different
    # node.
    REROUTE = auto()


class Packet:
    """A packet that can be sent and received over the network."""

    def __init__(self, inner: 'PacketBase') -> None:
        self._inner = inner

    @staticmethod
    def deserialize(stream: BufferedReader) -> 'Packet':
        kind = Deserialize.byte(stream)
        inner: Optional[PacketBase] = None
        if kind == PacketId.GET_EVENTS.value:
            inner = PacketGetEvents.deserialize(stream)
        elif kind == PacketId.GET_EVENTS_RESP.value:
            inner = PacketGetEventsResp.deserialize(stream)
        elif kind == PacketId.POST_EVENT.value:
            inner = PacketPostEvent.deserialize(stream)
        else:
            raise ProtocolException('unknown packet type ' + str(kind))

        return Packet(inner)

    def serialize(self, stream: BufferedWriter) -> None:
        if isinstance(self._inner, PacketGetEvents):
            Serialize.byte(stream, PacketId.GET_EVENTS.value)
        elif isinstance(self._inner, PacketGetEventsResp):
            Serialize.byte(stream, PacketId.GET_EVENTS_RESP.value)
        elif isinstance(self._inner, PacketPostEvent):
            Serialize.byte(stream, PacketId.POST_EVENT.value)
        else:
            raise ProtocolException('unknown event ' + str(self._inner))

        self._inner.serialize(stream)


class PacketBase(ABC):
    """The base class from which all network packets inherit."""

    @staticmethod
    @abstractmethod
    def deserialize(stream: BufferedReader) -> 'PacketBase':
        """Read the packet's bytes from the network.

        Return the represented packet object.

        """
        pass

    @abstractmethod
    def serialize(self, stream: BufferedWriter) -> None:
        """Converts the packet to bytes, and writes them to the network."""
        pass


class PacketPeerInfo(PacketBase):
    """Provide peer information.

    This should always be the first packet sent over an
    `EncryptedConnection`, and provides information about the
    """


class PacketGetEvents(PacketBase):
    """Request for events since a particular time.

    The time is represented as a number of nanoseconds past
    1970-01-01.

    """

    def __init__(self, since: int) -> None:
        self._since = since

    @staticmethod
    def deserialize(stream: BufferedReader) -> 'PacketGetEvents':
        return PacketGetEvents(Deserialize.long(stream))

    def serialize(self, stream: BufferedWriter) -> None:
        Serialize.long(stream, self._since)


class PacketGetEventsResp(PacketBase):
    """List of events, sent as a response to PacketGetEvents."""

    def __init__(self, events: List[Event]) -> None:
        self._events = events

    @staticmethod
    def deserialize(stream: BufferedReader) -> 'PacketGetEventsResp':
        return PacketGetEventsResp(Deserialize.list(Event.deserialize, stream))

    def serialize(self, stream: BufferedWriter) -> None:
        Serialize.list(
            lambda stream, ev: ev.serialize(stream),
            stream,
            self._events
        )


class PacketPostEvent(PacketBase):
    """Post a new event."""

    # TODO: This also probably needs a digital signature.
    def __init__(self, event: Event) -> None:
        self._event = event

    @staticmethod
    def deserialize(stream: BufferedReader) -> 'PacketPostEvent':
        return PacketPostEvent(Event.deserialize(stream))

    def serialize(self, stream: BufferedWriter) -> None:
        self._event.serialize(stream)


class PacketReroute(PacketBase):
    """Reroute the network loop."""

    def __init__(self, addr: PeerAddress) -> None:
        self._addr = addr

    @staticmethod
    def deserialize(stream: BufferedReader) -> 'PacketReroute':
        ip_addr = Deserialize.str(stream)
        ip_port = Deserialize.long(stream)

        return PacketReroute((ip_addr, ip_port))

    def serialize(self, stream: BufferedWriter) -> None:
        Serialize.str(stream, self._addr[0])
        Serialize.long(stream, self._addr[1])


def packet_test() -> None:
    """Tests a pair of clients sending packets to each other."""
    command = sys.argv[1]
    if command == 'listen':
        listener = EncryptedListener(
            ('0.0.0.0', 18457),
            PrivateKey.generate(),
            lambda k: True,
        )
        while True:
            connection, (_addr, _port) = listener.accept()
            send_pkt = Packet(PacketGetEventsResp(
                [
                    Event(EventJoin('Alex')),
                    Event(EventMessagePost(
                        'Alex',
                        1646873070000,
                        'Hello World!',
                    )),
                    Event(EventLeave('Alex')),
                ]
            ))
            send_pkt.serialize(cast(BufferedWriter, connection))
            connection.close()

    elif command == 'connect':
        connection = EncryptedStream.connect(
            ('0.0.0.0', 18457),
            (sys.argv[2], 18457),
            PrivateKey.generate(),
            lambda k: True,
        )
        recv_pkt = Packet.deserialize(cast(BufferedReader, connection))
        print(recv_pkt)


if __name__ == '__main__':
    packet_test()
