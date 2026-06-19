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

Use the CLI:

```
# Connect to a node
ln-gossip-sim-cli connect <pubkey_hex> <host:port>

# List connected peers
ln-gossip-sim-cli peers

# Show node and chain info
ln-gossip-sim-cli info

# Disconnect a peer
ln-gossip-sim-cli disconnect <pubkey_hex>

# Mine blocks to a 2-of-2 P2WSH address (LN-like funding output)
ln-gossip-sim-cli mine <blocks>

# Send a channel_announcement to a connected peer (same node ID on both sides)
ln-gossip-sim-cli send-channel-announcement <pubkey_hex>

# Send a channel_announcement with two distinct node IDs
ln-gossip-sim-cli send-channel-announcement2 <pubkey_hex>

# Send a channel_update for an announced channel (scid as printed by
# send-channel-announcement, e.g. 539268x845x1) to a connected peer
ln-gossip-sim-cli send-channel-update <pubkey_hex> <scid>

# Send a node_announcement to a connected peer. Run this after
# send-channel-announcement-2, since a peer only accepts a node_announcement
# whose node_id already appears in a previously announced channel.
ln-gossip-sim-cli send-node-announcement <pubkey_hex>

# Decode a type-prefixed hex message and send it to a connected peer. The
# message type must have a codec; unknown types are rejected.
ln-gossip-sim-cli send-message <pubkey_hex> <message_hex>

# Stop the daemon
ln-gossip-sim-cli stop
```

The daemon listens on `/tmp/ln-gossip-sim.sock` for CLI commands and can be
stopped with `Ctrl+C` or the `stop` command.
