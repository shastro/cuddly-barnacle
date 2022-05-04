"""The top-level status of a node."""

from threading import Thread
import hashlib
import datetime

import Database
import Environment
from EncryptedStream import (
    PeerAddress,
    PublicKey,
    PrivateKey,
)
from Topology import (
    initialize as topology_init,
    StableState,
    HubState,
    SpokeState,
    SolitaryState,
)
from typing import Optional, List, Any
from Event import (
    Event,
    EventMessagePost,
)
from Serial import MemorySerializer, MemoryDeserializer


class Node:
    """The local node on the network."""

    def __init__(self):
        env = Environment.Env()

        self._database = Database.SQLiteDB(env.get_database_path())
        self._database.createEmpty(False)

        peer_items: List[Database.PeerItem] = self._database.query(
            Database.TrustSelector(
                Database.PeerSelector(None),
                True,
            )
        )
        peer_addrs = [(item._addr, item._port) for item in peer_items]

        peer_key_items: List[Database.PubKeyItem] = self._database.query(
            Database.PubKeySelector(None)
        )
        peer_keys = [
            PublicKey.from_public_bytes(
                bytes.fromhex(item._key)
            ) for item in peer_key_items
        ]

        self._state = topology_init(
            my_addr=(
                env.get_config().networking.local_addr,
                env.get_config().networking.local_port,
            ),
            peer_addrs=peer_addrs,
            peer_keys=peer_keys,
            private_key=env.get_config().security.private_key,
        )

        Thread(
            target=self.manage_state,
            args=()
        ).start()

    def manage_state(self) -> None:
        """Manages the node's network state forever."""
        while True:
            self._state = self._state.run()
            for event in self._state.get_new_events():
                self.handle_event(event)

    def handle_event(self, event: Event) -> None:
        """Handles an incoming event.

        If the event is already included in the database, this
        function does nothing; otherwise, the function inserts the
        event into the database, and forwards it to other clients.

        """
        blob = MemorySerializer()
        event.serialize(blob)

        hash = hashlib.sha256()
        hash.update(blob.bytes())

        if len(self._database.query(
            Database.HashSelector(
                [hash.hexdigest()]
            )
        )) == 0:
            timestamp = 0
            if isinstance(event._inner, EventMessagePost):
                timestamp = event._inner._timestamp

            self._database.write([
                Database.EventItem(
                    datetime.datetime.fromtimestamp(timestamp),
                    hash.hexdigest(),
                    blob.bytes(),
                )
            ])

            self._state.send_events([event])

    def add_address(
            self,
            addr: PeerAddress,
    ) -> None:
        self._database.write([
            Database.PeerItem(
                addr[0],
                addr[1],
                datetime.datetime.now(),
                True,
            )
        ])

        self._state.add_peer(addr)

    def get_messages(
            self,
            start: Optional[int],
            end: Optional[int]
    ) -> List[str]:
        """Gets a list of every event that occurred between the timestamps."""
        events: List[Database.EventItem] = self._database.query(
            Database.TimeSelector(
                Database.HashSelector(None),
                datetime.datetime.fromtimestamp(start or 0),
                datetime.datetime.fromtimestamp(end or 1851675863),
            )
        )

        # fuck it, we're using strings here
        messages: List[str] = []
        for event in events:
            event_obj = Event.deserialize(MemoryDeserializer(event.get_blob()))

            # We only care about message events.
            inner = event_obj._inner
            if isinstance(inner, EventMessagePost):
                messages.append(f"<{inner._author}> {inner._text}")

        return messages

    def get_status(self) -> str:
        """Gets a short description of the node's status."""
        if isinstance(self._state, StableState):
            return 'Connected'
        elif isinstance(self._state, HubState):
            return 'Connected, acting as entry node'
        elif isinstance(self._state, SpokeState):
            return 'Connecting'
        elif isinstance(self._state, SolitaryState):
            return 'Disconnected'
        else:
            return 'Error'
