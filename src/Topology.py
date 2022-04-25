"""Network topology manager.

Since the network is decentralized, this function manages the network
state of a single node, rather than explicitly controlling the overall
state of the network.

"""

from abc import ABC


class NodeState(ABC):
    """The network state of a single node."""

    def __init__(self) -> None:
        pass


class StableState(NodeState):
    """Stable state.

    State in which we have exactly two connections to other nodes.
    (They're technically allowed to be connections to the same node if
    there are only two nodes on the network at any given time.)

    """

    def __init__(self):
        pass


class HubState(NodeState):
    """Hub state.

    State with three connections to other nodes, which is used when
    another node tries to join the network by connecting to us while
    we're in stable state.

    """

    def __init__(self):
        pass


class SpokeState(NodeState):
    """Spoke state.

    Spoke state, with one connection to another node, which we use
    when we're joining the network.

    """

    def __init__(self):
        pass


class SolitaryState(NodeState):
    """Solitary state.

    State with zero connections to other nodes, which we use when
    we're the only one online.

    """

    def __init__(self):
        pass


def topology_test() -> None:
    print('Hello World!')


if __name__ == '__main__':
    topology_test()
