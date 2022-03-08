"""Network packet classes & definitions."""

from enum import Enum, auto, unique
from io import BufferedReader, BufferedWriter
from typing import List

from Event import Event


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


class PacketBase:
    """The base class from which all network packets inherit."""

    @staticmethod
    def deserialize(stream: BufferedReader) -> 'PacketBase':
        """Read the packet's bytes from the network, and return the
           represented packet object."""
        pass

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
        return PacketGetEvents(int.from_bytes(stream.read(8), 'big'))

    def serialize(self, stream: BufferedWriter) -> None:
        stream.write(self._since.to_bytes(8, 'big'))


class PacketGetEventsResp(PacketBase):
    """List of events, sent as a response to PacketGetEvents."""

    def __init__(self, events: List[Event]) -> None:
        self._events = events

    @staticmethod
    def deserialize(stream: BufferedReader) -> 'PacketGetEventsResp':
        n_events = int.from_bytes(stream.read(4), 'big')

        events = []
        for _ in range(n_events):
            events.append(Event.deserialize(stream))

        return PacketGetEventsResp(events)

    def serialize(self, stream: BufferedWriter) -> None:
        stream.write(len(self._events).to_bytes(4, 'big'))

        for ev in self._events:
            ev.serialize(stream)


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
