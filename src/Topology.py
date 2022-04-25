"""Network topology manager.

Since the network is decentralized, this function manages the network
state of a single node, rather than explicitly controlling the overall
state of the network.

"""

from abc import ABC
from typing import List
import random

from EncryptedStream import EncryptedStream, PublicKey, PrivateKey

PORT_NUMBER = 18457


class NodeState(ABC):
    """The network state of a single node."""

    def run(self) -> 'NodeState':
        pass


class StableState(NodeState):
    """Stable state.

    State in which we have exactly two connections to other nodes.
    (They're technically allowed to be connections to the same node if
    there are only two nodes on the network at any given time.)

    """

    def __init__(
            self,
            predecessor: EncryptedStream,
            successor: EncryptedStream,
    ):
        self._pred = predecessor
        self._succ = successor

    def run(self) -> NodeState:
        pass


class HubState(NodeState):
    """Hub state.

    State with three connections to other nodes, which is used when
    another node tries to join the network by connecting to us while
    we're in stable state.

    """

    def __init__(
            self,
            predecessor: EncryptedStream,
            successor: EncryptedStream,
            extra: EncryptedStream,
    ):
        self._pred = predecessor
        self._succ = successor
        self._extra = extra

    def run(self) -> NodeState:
        pass


class SpokeState(NodeState):
    """Spoke state.

    Spoke state, with one connection to another node, which we use
    when we're joining the network.

    """

    def __init__(
            self,
            entry_point: EncryptedStream,
    ):
        self._entry_point = entry_point

    def run(self) -> NodeState:
        pass


class SolitaryState(NodeState):
    """Solitary state.

    State with zero connections to other nodes, which we use when
    we're the only one online.

    """

    def __init__(self) -> None:
        pass

    def run(self) -> NodeState:
        pass


def initialize(
        peer_addrs: List[str],
        peer_keys: List[PublicKey],
        private_key: PrivateKey,
) -> NodeState:
    """Connects to the chat network, and returns a new NodeState.

    Attempts to connect to a list of peer addresses in a random order,
    and only connects to peers whose public keys are approved
    according to the `peer_keys` list. Uses `private_key` to
    authenticate to the peers.

    """
    peer_addrs_shuf = peer_addrs.copy()
    random.shuffle(peer_addrs_shuf)
    for addr in peer_addrs_shuf:
        try:
            connection = EncryptedStream.connect(
                addr,
                PORT_NUMBER,
                private_key,
                lambda key: key in peer_keys
            )
            return SpokeState(entry_point=connection)
        except ConnectionRefusedError or TimeoutError as _err:
            # Peer is offline, just try other peers.
            id(_err)
            pass
    return SolitaryState()


def topology_test() -> None:
    print('Hello World!')


if __name__ == '__main__':
    topology_test()
