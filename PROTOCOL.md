# Chat² Network Protocol

## Event types

### Message

A user sends a text message onto the channel. This can optionally
contain markup, attachments, et cetera.

### Invite

A user authorizes another user to join the channel. The authorizing
user provides the new user's public key, and the username that they
will use to connect.

### Ban

Either an administrator revokes an arbitrary user's permission to read
and post messages, or a user revokes their own permission to do the
same (i.e., permanently leaves the channel).

### Enter

A user signals that they are online. This message should automatically
be sent by a client as soon as it completes its initialization phase.

### Part

A user signals that they are no longer online, optionally with a
parting message.

## The Network

### Peer locating

In the first step of connecting to a channel, a node tries to find any
and all other nodes that are online in the channel.

### History comparisons

Next, the connecting node picks a random subset of nodes, and compares
its message history with those nodes.

#### Need update

#### Has new

### Publish message
