"""Network packet classes & definitions."""

from enum import Enum, auto


class PacketId(Enum):
    """Packet ID numbers."""

    # Message request and response: one peer requests the list of
    # every message the other peer has satisfying some predicate.
    GET_EVENTS = auto()
    GET_EVENTS_RESP = auto()

    # Post event: a peer sends a new event that every other peer on
    # the network can see.
    POST_EVENT = auto()
