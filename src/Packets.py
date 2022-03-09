"""Network packet classes & definitions."""

from abc import ABC, abstractmethod
from enum import Enum, auto, unique
from io import BufferedReader, BufferedWriter
from typing import List, Optional

from Event import Event
from Serial import (
    deserialize_long,
    deserialize_byte,
    deserialize_list,
    serialize_long,
    serialize_byte,
    serialize_list,
)
from PeerSocket import ProtocolException


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


class Packet:
    """A packet that can be sent and received over the network."""

    def __init__(self, inner: 'PacketBase') -> None:
        self._inner = inner

    @staticmethod
    def deserialize(stream: BufferedReader) -> 'Packet':
        kind = deserialize_byte(stream)
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
            serialize_byte(stream, PacketId.GET_EVENTS.value)
        elif isinstance(self._inner, PacketGetEventsResp):
            serialize_byte(stream, PacketId.GET_EVENTS_RESP.value)
        elif isinstance(self._inner, PacketPostEvent):
            serialize_byte(stream, PacketId.POST_EVENT.value)
        else:
            raise ProtocolException('unknown event ' + str(self._inner))

        self._inner.serialize(stream)


class PacketBase(ABC):
    """The base class from which all network packets inherit."""

    @staticmethod
    @abstractmethod
    def deserialize(stream: BufferedReader) -> 'PacketBase':
        """Read the packet's bytes from the network, and return the
           represented packet object."""
        pass

    @abstractmethod
    def serialize(self, stream: BufferedWriter) -> None:
        """Convert the packet's content to bytes, and write them to the
           network."""
        pass


class PacketGetEvents(PacketBase):
    """Request for events since a particular time (represented as a number
       of nanoseconds past 1970-01-01)."""

    def __init__(self, since: int) -> None:
        self._since = since

    @staticmethod
    def deserialize(stream: BufferedReader) -> 'PacketGetEvents':
        return PacketGetEvents(deserialize_long(stream))

    def serialize(self, stream: BufferedWriter) -> None:
        serialize_long(stream, self._since)


class PacketGetEventsResp(PacketBase):
    """List of events, sent as a response to PacketGetEvents."""

    def __init__(self, events: List[Event]) -> None:
        self._events = events

    @staticmethod
    def deserialize(stream: BufferedReader) -> 'PacketGetEventsResp':
        return PacketGetEventsResp(deserialize_list(Event.deserialize, stream))

    def serialize(self, stream: BufferedWriter) -> None:
        serialize_list(
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
