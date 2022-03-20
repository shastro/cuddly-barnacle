"""Event types within a ChatChat channel."""

from abc import ABC, abstractmethod
from enum import Enum, auto, unique
from io import BufferedReader, BufferedWriter
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PublicKey as PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from Serial import (
    deserialize_bytes,
    deserialize_str,
    deserialize_long,
    deserialize_byte,
    serialize_bytes,
    serialize_str,
    serialize_long,
    serialize_byte,
)
from EncryptedStream import ProtocolException


@unique
class EventId(Enum):
    """Types of events."""

    # A user posted a chat message.
    MESSAGE_POST = auto()

    # A new user was added to the chat. The event includes the user's
    # public key; after this event is sent, a user with that public
    # key is now authorized to join the network.
    INVITE = auto()

    # A user was removed from the chat. The user should be removed
    # from user lists in the user interface, and their public key is
    # now invalidated for receiving messages.
    BAN = auto()

    # A user started their chat client, and should now be denoted as
    # "online" in the user interface.
    JOIN = auto()

    # A user turned off their chat client, and should now be denoted
    # as "offline" in the user interface.
    LEAVE = auto()


class Event:
    """An event on the ChatChat network.

    The defining feature of an 'event' is that each event should be
    recorded within a ChatChat network's chat history, propagated to
    every connected client, and remembered forever.

    """

    def __init__(self, inner: 'EventBase') -> None:
        self._inner = inner

    @staticmethod
    def deserialize(stream: BufferedReader) -> 'Event':
        kind = deserialize_byte(stream)
        inner: Optional[EventBase] = None
        if kind == EventId.MESSAGE_POST.value:
            inner = EventMessagePost.deserialize(stream)
        elif kind == EventId.INVITE.value:
            inner = EventInvite.deserialize(stream)
        elif kind == EventId.BAN.value:
            inner = EventBan.deserialize(stream)
        elif kind == EventId.JOIN.value:
            inner = EventJoin.deserialize(stream)
        elif kind == EventId.LEAVE.value:
            inner = EventLeave.deserialize(stream)
        else:
            raise ProtocolException('unknown event type ' + str(kind))

        return Event(inner)

    def serialize(self, stream: BufferedWriter) -> None:
        if isinstance(self._inner, EventMessagePost):
            serialize_byte(stream, EventId.MESSAGE_POST.value)
        elif isinstance(self._inner, EventInvite):
            serialize_byte(stream, EventId.INVITE.value)
        elif isinstance(self._inner, EventBan):
            serialize_byte(stream, EventId.BAN.value)
        elif isinstance(self._inner, EventJoin):
            serialize_byte(stream, EventId.JOIN.value)
        elif isinstance(self._inner, EventLeave):
            serialize_byte(stream, EventId.LEAVE.value)
        else:
            raise ProtocolException('unknown event ' + str(self._inner))

        self._inner.serialize(stream)


class EventBase(ABC):
    """The base class for the body of an Event."""

    @staticmethod
    @abstractmethod
    def deserialize(stream: BufferedReader) -> 'EventBase':
        pass

    @abstractmethod
    def serialize(self, stream: BufferedWriter) -> None:
        pass


class EventMessagePost(EventBase):
    """An event indicating that a message was posted to the network."""

    def __init__(self, author: str, timestamp: int, text: str) -> None:
        self._author = author
        self._timestamp = timestamp
        self._text = text

    @staticmethod
    def deserialize(stream: BufferedReader) -> 'EventMessagePost':
        return EventMessagePost(
            deserialize_str(stream),
            deserialize_long(stream),
            deserialize_str(stream),
        )

    def serialize(self, stream: BufferedWriter) -> None:
        serialize_str(stream, self._author)
        serialize_long(stream, self._timestamp)
        serialize_str(stream, self._text)


class EventInvite(EventBase):
    """An event indicating that a user has been added to the chat."""

    def __init__(self, name: str, pub_key: PublicKey) -> None:
        self._name = name
        self._pub_key = pub_key

    @staticmethod
    def deserialize(stream: BufferedReader) -> 'EventInvite':
        return EventInvite(
            deserialize_str(stream),
            PublicKey.from_public_bytes(deserialize_bytes(stream)),
        )

    def serialize(self, stream: BufferedWriter) -> None:
        serialize_str(stream, self._name)
        serialize_bytes(stream, self._pub_key.public_bytes(
            encoding=Encoding.Raw,
            format=PublicFormat.Raw
        ))


class EventBan(EventBase):
    """An event indicating that a user has left the chat."""

    def __init__(self, name: str) -> None:
        self._name = name

    @staticmethod
    def deserialize(stream: BufferedReader) -> 'EventBan':
        return EventBan(deserialize_str(stream))

    def serialize(self, stream: BufferedWriter) -> None:
        serialize_str(stream, self._name)


class EventJoin(EventBase):
    """An event signaling that a user is now online."""

    def __init__(self, name: str) -> None:
        self._name = name

    @staticmethod
    def deserialize(stream: BufferedReader) -> 'EventJoin':
        return EventJoin(deserialize_str(stream))

    def serialize(self, stream: BufferedWriter) -> None:
        serialize_str(stream, self._name)


class EventLeave(EventBase):
    """An event signaling that a user is now offline."""

    def __init__(self, name: str) -> None:
        self._name = name

    @staticmethod
    def deserialize(stream: BufferedReader) -> 'EventLeave':
        return EventLeave(deserialize_str(stream))

    def serialize(self, stream: BufferedWriter) -> None:
        serialize_str(stream, self._name)
