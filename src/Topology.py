"""Network topology manager.

Since the network is decentralized, this function manages the network
state of a single node, rather than explicitly controlling the overall
state of the network.

"""

from abc import ABC, abstractmethod
from io import BufferedReader
from typing import List, cast
import random
import select
import sys

from EncryptedStream import (
    EncryptedStream,
    EncryptedListener,
    PublicKey,
    PrivateKey,
    PeerAddress,
)
from Packets import Packet


class NodeState(ABC):
    """The network state of a single node."""

    @abstractmethod
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
            info: 'NodeInfo',
            predecessor: EncryptedStream,
            successor: EncryptedStream,
    ):
        self._info = info
        self._pred = predecessor
        self._succ = successor

    def run(self) -> NodeState:
        """Run the state until it progresses to another state.

        The stable state:
        - Receives messages from the predecessor, and propagates them
          to its successor. (Synchronization messages.)
        - Receives input from the user.
        - Awaits connections from the outside world, and when one is
          found, progresses to the hub state.

        """
        print('Entering stable state')

        readable, writable, exception = select.select(
            [                   # read
                self._pred,
                self._info.listener._sock,
            ],
            [],                 # write
            [],                 # except
        )

        if self._pred in readable:
            # Message received
            packet = Packet.deserialize(cast(BufferedReader, self._pred))
            self.interpret_packet(packet)
        if self._info.listener._sock in readable:
            # Connection received
            conn, addr = self._info.listener.accept()
            return HubState(self._info, self._pred, self._succ, conn, addr)

        return self

    def interpret_packet(self, packet: Packet):
        # TODO: implement this.
        pass


class HubState(NodeState):
    """Hub state.

    State with three connections to other nodes, which is used when
    another node tries to join the network by connecting to us while
    we're in stable state.

    """

    def __init__(
            self,
            info: 'NodeInfo',
            predecessor: EncryptedStream,
            successor: EncryptedStream,
            extra: EncryptedStream,
            extra_addr: 'PeerAddress',
    ):
        self._info = info
        self._pred = predecessor
        self._succ = successor
        self._extra = extra
        self._extra_addr = extra_addr

    def run(self) -> NodeState:
        print('Entering hub state')

        # We send our predecessor node the extra node's address, then
        # we begin accepting data from both the extra node and the
        # predecessor; theoretically, the predecessor should stop
        # sending us data as soon as it receives the extra node's
        # address, but we can't guarantee when exactly that will
        # happen. We stay in this state until the predecessor
        # disconnects from us, at which point we set the extra node as
        # our predecessor and proceed to the stable state.

        # TODO: send the packet.

        # No wait, we can't send the packet here. If we were to send
        # the packet here, then every time the state gets refreshed,
        # we'd send a new routing packet.

        readable, writable, exception = select.select(
            [                   # read
                self._pred,
                self._extra,
            ],
            [],                 # write
            [],                 # accept
        )

        if self._pred in readable:
            # Message received
            packet = Packet.deserialize(cast(BufferedReader, self._pred))
            self.interpret_packet(packet)
        elif self._extra in readable:
            # Message received
            packet = Packet.deserialize(cast(BufferedReader, self._pred))
            self.interpret_packet(packet)

        # We just received a normal message; don't transition to
        # another state.
        return self

    def interpret_packet(self, packet: Packet):
        # TODO: implement this
        pass


class SpokeState(NodeState):
    """Spoke state.

    Spoke state, with one connection to another node, which we use
    when we're joining the network.

    """

    def __init__(
            self,
            info: 'NodeInfo',
            entry_point: EncryptedStream,
    ):
        self._info = info
        self._entry_point = entry_point

    def run(self) -> NodeState:
        print('Entering spoke state')

        # Wait around for an incoming connection, and set it as our
        # predecessor.
        pred, _addr = self._info.listener.accept()
        return StableState(self._info, pred, self._entry_point)


class SolitaryState(NodeState):
    """Solitary state.

    State with zero connections to other nodes, which we use when
    we're the only one online.

    """

    def __init__(
            self,
            info: 'NodeInfo',
    ) -> None:
        self._info = info

    def run(self) -> NodeState:
        """Runs the state until it progresses to another state.

        The solitary state:
        - Receives input from the user.
        - Awaits connections from the outside world, and when one is
          found, progresses to the stable state.
        """
        print('Entering solitary state')

        pred, pred_addr = self._info.listener.accept()
        print(f'Got new connection from {pred_addr}, trying to connect back')
        succ = EncryptedStream.connect(
            self._info.local_addr,
            pred_addr,
            self._info.private_key,
            lambda k: k in self._info.allowed_keys,
        )

        return StableState(
            info=self._info,
            predecessor=pred,
            successor=succ,
        )


class NodeInfo:
    def __init__(
            self,
            listener: EncryptedListener,
            local_addr: PeerAddress,
            allowed_keys: List[PublicKey],
            private_key: PrivateKey,
    ) -> None:
        self.listener = listener
        self.local_addr = local_addr
        self.allowed_keys = allowed_keys
        self.private_key = private_key


def initialize(
        my_addr: PeerAddress,
        peer_addrs: List[PeerAddress],
        peer_keys: List[PublicKey],
        private_key: PrivateKey,
) -> NodeState:
    """Connects to the chat network, and returns a new NodeState.

    Attempts to connect to a list of peer addresses in a random order,
    and only connects to peers whose public keys are approved
    according to the `peer_keys` list. Uses `private_key` to
    authenticate to the peers.

    """
    listener = EncryptedListener(
        my_addr,
        private_key,
        lambda key: key in peer_keys
    )

    node_info = NodeInfo(
        listener=listener,
        local_addr=my_addr,
        allowed_keys=peer_keys,
        private_key=private_key,
    )

    peer_addrs_shuf = peer_addrs.copy()
    random.shuffle(peer_addrs_shuf)
    for addr in peer_addrs_shuf:
        try:
            connection = EncryptedStream.connect(
                my_addr,
                addr,
                private_key,
                lambda key: key in peer_keys
            )
            print(f'Note: connected to peer {addr}')

            return SpokeState(
                info=node_info,
                entry_point=connection,
            )
        except ConnectionRefusedError or TimeoutError as err:
            # Peer is offline, just try other peers and don't report
            # the error.
            print(f'Note: peer {addr} is unreachable: {err}')
            id(err)
            pass
    return SolitaryState(
        info=node_info,
    )


def topology_test() -> None:
    local_addr_str = sys.argv[1]
    peer_addrs_str = sys.argv[2:]

    def parse_addr(addr: str) -> PeerAddress:
        host, port = addr.split(':', maxsplit=1)
        return host, int(port)

    local_addr = parse_addr(local_addr_str)
    peer_addrs = list(map(parse_addr, peer_addrs_str))

    state = initialize(
        local_addr,
        peer_addrs,
        [],
        PrivateKey.generate()
    )
    while True:
        state = state.run()


if __name__ == '__main__':
    topology_test()
