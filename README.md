# ln-gossip-sim

Lightning Network gossip simulator for regtest. Connects to LN nodes over the
Bolt 8 Noise protocol, exchanges init/ping/pong messages, and talks to bitcoind
via RPC.

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

# Send a channel_announcement to a connected peer
ln-gossip-sim-cli sendchannelannouncement <pubkey_hex>

# Stop the daemon
ln-gossip-sim-cli stop
```

The daemon listens on `/tmp/ln-gossip-sim.sock` for CLI commands and can be
stopped with `Ctrl+C` or the `stop` command.
