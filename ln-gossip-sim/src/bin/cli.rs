use clap::{Parser, Subcommand};
use ln_gossip_sim::SOCK_PATH;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;

#[derive(Parser)]
#[command(
    name = "ln-gossip-sim-cli",
    about = "Control a running ln-gossip-simd daemon"
)]
struct Cli {
    /// Which node identity the command runs as. Required for node-scoped
    /// commands; a node becomes "up" once you `connect` it to a peer, and other
    /// node-scoped commands require it to be up. Not used by `stop`, which
    /// shuts down the whole daemon. Pass it right after the binary:
    /// `ln-gossip-sim-cli --node-index <N> ...`.
    #[arg(long)]
    node_index: Option<u32>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Connect to a Lightning node
    Connect {
        /// Node public key (hex)
        pubkey: String,
        /// Address as host:port
        addr: String,
    },
    /// Disconnect from a Lightning node
    Disconnect {
        /// Node public key (hex)
        pubkey: String,
    },
    /// List connected peers
    Peers,
    /// Show chain and node info
    Info,
    /// Mine blocks to a 2-of-2 P2WSH address
    Mine {
        /// Number of blocks to mine
        blocks: usize,
    },
    /// Send a `channel_announcement` to a connected peer
    SendChannelAnnouncement {
        /// Node public key (hex) of connected peer
        pubkey: String,
    },
    /// Send a `channel_announcement` with two distinct node IDs to a connected peer
    SendChannelAnnouncement2 {
        /// Node public key (hex) of connected peer
        pubkey: String,
    },
    /// Send a `channel_update` for an announced channel to a connected peer
    SendChannelUpdate {
        /// Node public key (hex) of connected peer
        pubkey: String,
        /// Short channel ID as printed by send-channel-announcement (e.g. 539268x845x1)
        scid: String,
    },
    /// Send a `node_announcement` to a connected peer
    SendNodeAnnouncement {
        /// Node public key (hex) of connected peer
        pubkey: String,
    },
    /// Decode a type-prefixed hex message and send it to a connected peer
    SendMessage {
        /// Node public key (hex) of connected peer
        pubkey: String,
        /// Wire message as hex (with 2-byte type prefix)
        message: String,
    },
    /// Stop the daemon
    Stop,
}

fn main() {
    let cli = Cli::parse();

    let cmd = match &cli.command {
        Command::Connect { pubkey, addr } => format!("connect {pubkey} {addr}"),
        Command::Disconnect { pubkey } => format!("disconnect {pubkey}"),
        Command::Peers => "peers".to_string(),
        Command::Info => "info".to_string(),
        Command::SendChannelAnnouncement { pubkey } => {
            format!("sendchannelannouncement {pubkey}")
        }
        Command::SendChannelAnnouncement2 { pubkey } => {
            format!("sendchannelannouncement2 {pubkey}")
        }
        Command::SendChannelUpdate { pubkey, scid } => {
            format!("sendchannelupdate {pubkey} {scid}")
        }
        Command::SendNodeAnnouncement { pubkey } => {
            format!("sendnodeannouncement {pubkey}")
        }
        Command::SendMessage { pubkey, message } => {
            format!("sendmessage {pubkey} {message}")
        }
        // `mine` and `stop` act on the daemon/chain as a whole, not on a single
        // node identity, so they are not node-scoped and carry no index prefix.
        Command::Mine { blocks } => {
            return send_global(cli.node_index, "mine", &format!("mine {blocks}"))
        }
        Command::Stop => return send_global(cli.node_index, "stop", "stop"),
    };
    // Node-scoped commands must be told which node they act as, and the index
    // is sent as a prefix the daemon parses off the front of the command.
    let Some(node_index) = cli.node_index else {
        eprintln!("--node-index <N> is required for this command");
        std::process::exit(1);
    };
    send(&format!("{node_index} {cmd}"));
}

/// Send a command that acts on the daemon/chain as a whole, warning if the
/// caller passed a `--node-index` it will ignore.
fn send_global(node_index: Option<u32>, name: &str, cmd: &str) {
    if node_index.is_some() {
        eprintln!("Warning: --node-index is ignored by `{name}` (it is not node-scoped)");
    }
    send(cmd);
}

fn send(cmd: &str) {
    let Ok(mut stream) = UnixStream::connect(SOCK_PATH) else {
        eprintln!("Cannot connect to daemon. Is ln-gossip-simd running?");
        std::process::exit(1);
    };

    if let Err(e) = stream.write_all(cmd.as_bytes()) {
        eprintln!("Failed to send command: {e}");
        std::process::exit(1);
    }
    let _ = stream.write_all(b"\n");
    let _ = stream.shutdown(std::net::Shutdown::Write);

    for line in BufReader::new(&stream).lines() {
        match line {
            Ok(l) => println!("{l}"),
            Err(_) => break,
        }
    }
}
