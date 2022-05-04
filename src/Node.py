"""The top-level status of a node."""

from threading import Thread

import Database
import Environment
from EncryptedStream import (
    PeerAddress,
    PublicKey,
    PrivateKey,
)
from Topology import initialize as topology_init
from typing import Optional, List, Any
from Event import (
    Event,
    EventMessagePost,
)
from Serial import MemorySerializer


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
            PublicKey.from_public_bytes(item._key) for item in peer_key_items
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
                if isinstance(event._inner, EventMessagePost):
                    blob = MemorySerializer()
                    event.serialize(blob)

                    self._database.write([
                        Database.EventItem(
                            event._timestamp,
                            '',
                            blob._blob,
                        )
                    ])

    def get_messages(
            self,
            start: Optional[int],
            end: Optional[int]
    ) -> List[Event]:
        """Gets a list of every event that occurred between the timestamps."""
        # TODO: from database
        return []
