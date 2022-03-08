"""Event types within a ChatChat channel."""

from enum import Enum, auto


class EventId(Enum):
    """Types of events that are recorded within a ChatChat network's chat
       history and propagated to every connected client."""

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
    """An event that should be recorded within a ChatChat network's
       chat history and propagated to every connected client."""

    def __init__(self) -> None:
        pass
