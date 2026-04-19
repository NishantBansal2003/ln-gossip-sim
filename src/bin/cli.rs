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
        Command::Stop => "stop".to_string(),
    };

    let mut stream = match UnixStream::connect(SOCK_PATH) {
        Ok(s) => s,
        Err(_) => {
            eprintln!("Cannot connect to daemon. Is ln-gossip-simd running?");
            std::process::exit(1);
        }
    };

    if let Err(e) = stream.write_all(cmd.as_bytes()) {
        eprintln!("Failed to send command: {e}");
        std::process::exit(1);
    }
    let _ = stream.write_all(b"\n");
    let _ = stream.shutdown(std::net::Shutdown::Write);

    for line in BufReader::new(&stream).lines() {
        match line {
            Ok(l) => println!("{}", l),
            Err(_) => break,
        }
    }
}
