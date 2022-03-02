# Chat² Network Protocol

<!-- TODO: Introduction. Define what a channel is, and what ports and
     transport-level protocols the network uses. -->

This document defines the network concepts and protocol of the Chat²
network, an end-to-end encrypted, decentralized, distributed chat
system.

## Definitions

### Channel

A channel is the user-visible manifestation of a Chat² network. A
channel is meant to mimic the functionality that would exist in, say,
a single Discord, Matrix, or IRC channel. At minimum, a channel
contains a list of *events,* which can represent both the standard
messages that users type onto the channel as well as changes in the
channel configuration, such as changing the channel topic, adding or
removing members from the channel, users changing nicknames, and other
events.

Most Chat² clients should be capable of connecting to more than one
channel at once, to provide an experience closer to a traditional chat
network. Clients may also be capable of grouping channels into related
folders; mechanisms for doing so is currently optional and
implementation-defined.

### User ID

A User ID is a string that is intended to uniquely identify and
provide contact details for a particular person, who may be a member
of zero or more networks. It consists of a base-64 encoded string that
contains at least the following information:
- The peer's username. In the current model, this cannot be changed.
- The peer's public key.
- Zero or more IP addresses that can be used to reach the peer. By
  default, this should be the last 8 IP addresses that the peer was
  known to use, in order from most recent to least recent. This field
  may be omitted (i.e., 0 addresses) if the peer is known to be behind
  a firewall that prohibits outside accesses; however, this should not
  be the default, and should be a user-settable option.
- Possibly a simple checksum. User IDs are likely to be copied and
  pasted between applications by users, and we need to make sure they
  don't accidentally omit part of the user ID, for example.

The standard use for user IDs is to invite people to a new channel.
Somewhere in a Chat² client's user interface there must some mechanism
that a user can use to copy their user ID string to the system
clipboard; they can then send this to another user who is on a
channel, who can "invite" that user ID to the channel.

### Channel ID

## Basic networking details

All communications on the Chat² network are expected to take place
using TCP/IP, on port number 18457.

<!-- TODO: talk about key exchange protocols, etc. -->

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
