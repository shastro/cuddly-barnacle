"""Network topology manager.

Since the network is decentralized, this function manages the network
state of a single node, rather than explicitly controlling the overall
state of the network.

"""


class NodeState:
    """The network state of a single node."""

    # Probably need to plan this out with an activitiy diagram or
    # something. It needs to include:
    # - Stable state, with exactly two connections to other nodes.
    #   (They're technically allowed to be connections to the same
    #   node if there are only two nodes on the network at any given
    #   time.)
    # - Spoke state, with one connection to another node, which we use
    #   when we're joining the network.
    # - Hub state, with three connections to other nodes, which is
    #   used when another node tries to join the network by connecting
    #   to us while we're in stable state.
    # - Solitary state, with zero connections to other nodes, which we
    #   use when we're the only one online.
    pass


def topology_test() -> None:
    print('Hello World!')


if __name__ == '__main__':
    topology_test()
