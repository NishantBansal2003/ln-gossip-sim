# ln-gossip-sim

Lightning Network gossip simulator for regtest. Connects to LN nodes over the
Bolt 8 Noise protocol, exchanges init/ping/pong messages, and talks to bitcoind
via RPC.

## Requirements

This project was built and tested with the following setup:

- **Rust:** 1.95.0 (stable). Older versions may work but are not tested.
- **Bitcoin Core:** v30.0 on regtest. Other recent versions should work, but
  are not tested.
- **Lightning node:** tested with CLN, LND, and Eclair built from their
  respective `master` branches.

## Build

```
cargo build
```

## Usage

Start the daemon (requires a running bitcoind on regtest):

```
ln-gossip-simd --rpc-url http://127.0.0.1:18443 --rpc-user user --rpc-pass password
```

A single daemon hosts many independent node identities. Pass `--node-index <N>`
(any non-negative integer) right after the binary to pick which one a command
acts as; the same index is always the same node, and different indices look
like distinct peers. Connect a node first — the other commands require it to be
up. The exceptions are `mine` and `stop`, which act on the chain and the daemon
as a whole and so take no `--node-index`.

```
# Connect to a node (brings node N up)
ln-gossip-sim-cli --node-index 7 connect <pubkey_hex> <host:port>

# List connected peers
ln-gossip-sim-cli --node-index 7 peers

# Show node and chain info
ln-gossip-sim-cli --node-index 7 info

# Disconnect a peer
ln-gossip-sim-cli --node-index 7 disconnect <pubkey_hex>

# Mine blocks to a 2-of-2 P2WSH address (LN-like funding output). Acts on the
# chain, not a node, so no --node-index.
ln-gossip-sim-cli mine <blocks>

# Send a channel_announcement to a connected peer (node N's single identity
# on both sides)
ln-gossip-sim-cli --node-index 7 send-channel-announcement <pubkey_hex>

# Send a channel_announcement between node N's two distinct identities
ln-gossip-sim-cli --node-index 7 send-channel-announcement2 <pubkey_hex>

# Send a channel_update for an announced channel (scid as printed by
# send-channel-announcement, e.g. 539268x845x1) to a connected peer. Signed by
# the channel's node_id_1.
ln-gossip-sim-cli --node-index 7 send-channel-update <pubkey_hex> <scid>

# Send a node_announcement to a connected peer, for node N's node_id_1. Run
# this after send-channel-announcement2, since a peer only accepts a
# node_announcement whose node_id already appears in a previously announced
# channel.
ln-gossip-sim-cli --node-index 7 send-node-announcement <pubkey_hex>

# Decode a type-prefixed hex message and send it to a connected peer. The
# message type must have a codec; unknown types are rejected.
ln-gossip-sim-cli --node-index 7 send-message <pubkey_hex> <message_hex>

# Stop the whole daemon (not node-scoped, so no --node-index)
ln-gossip-sim-cli stop
```

The daemon listens on `/tmp/ln-gossip-sim.sock` for CLI commands and can be
stopped with `Ctrl+C` or the `stop` command.
