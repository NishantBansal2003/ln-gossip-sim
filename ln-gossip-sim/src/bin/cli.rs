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
        Command::Mine { blocks } => format!("mine {blocks}"),
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
        Command::Stop => "stop".to_string(),
    };

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
