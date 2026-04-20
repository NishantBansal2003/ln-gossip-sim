use bitcoin::secp256k1::{PublicKey, Secp256k1};
use clap::Parser;
use lightning::ln::peer_handler::{
    ErroringMessageHandler, IgnoringMessageHandler, MessageHandler, PeerManager,
};
use lightning::routing::gossip::{NetworkGraph, P2PGossipSync};
use lightning::sign::KeysManager;
use ln_gossip_sim::bitcoind::BitcoindClient;
use ln_gossip_sim::gossip::GossipBroadcaster;
use ln_gossip_sim::log::SimLogger;
use ln_gossip_sim::{SOCK_PATH, keepalive, keys, log_error, log_info, noise, types};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::sync::{Mutex, watch};

#[derive(Parser)]
#[command(name = "ln-gossip-simd", about = "LN gossip simulator daemon")]
struct Args {
    /// bitcoind RPC URL (e.g. http://127.0.0.1:18443)
    #[arg(long)]
    rpc_url: String,
    /// bitcoind RPC user
    #[arg(long)]
    rpc_user: String,
    /// bitcoind RPC password
    #[arg(long)]
    rpc_pass: String,
}

struct Daemon {
    node_id: PublicKey,
    peer_manager: Arc<types::PeerMgr>,
    #[allow(dead_code)]
    gossip_broadcaster: Arc<GossipBroadcaster>,
    bitcoind: Arc<BitcoindClient>,
    logger: Arc<SimLogger>,
    stop_tx: watch::Sender<bool>,
    keepalive_handle: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl Daemon {
    fn new(bitcoind: Arc<BitcoindClient>) -> (Arc<Self>, watch::Receiver<bool>) {
        let logger = Arc::new(SimLogger);
        let cur = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();

        let keys_manager = Arc::new(KeysManager::new(
            &keys::SEED,
            cur.as_secs(),
            cur.subsec_nanos(),
            true,
        ));

        let secp = Secp256k1::new();
        let node_id = PublicKey::from_secret_key(&secp, &keys_manager.get_node_secret_key());
        log_info!(logger, "Node ID: {node_id}");

        let network_graph = Arc::new(NetworkGraph::new(
            bitcoin::Network::Regtest,
            Arc::clone(&logger),
        ));
        let gossip_sync = Arc::new(P2PGossipSync::new(
            Arc::clone(&network_graph),
            None::<Arc<dyn lightning::routing::utxo::UtxoLookup + Send + Sync>>,
            Arc::clone(&logger),
        ));

        let gossip_broadcaster = Arc::new(GossipBroadcaster::new());

        let peer_manager: Arc<types::PeerMgr> = Arc::new(PeerManager::new(
            MessageHandler {
                chan_handler: ErroringMessageHandler::new(),
                route_handler: Arc::clone(&gossip_sync),
                onion_message_handler: IgnoringMessageHandler {},
                custom_message_handler: IgnoringMessageHandler {},
                send_only_message_handler: Arc::clone(&gossip_broadcaster),
            },
            cur.as_secs() as u32,
            &keys::EPHEMERAL,
            Arc::clone(&logger),
            Arc::clone(&keys_manager),
        ));

        let (stop_tx, stop_rx) = watch::channel(false);

        let daemon = Arc::new(Self {
            node_id,
            peer_manager,
            gossip_broadcaster,
            bitcoind,
            logger,
            stop_tx,
            keepalive_handle: Mutex::new(None),
        });
        (daemon, stop_rx)
    }

    fn shutdown(&self) {
        log_info!(self.logger, "Shutting down");
        self.peer_manager.disconnect_all_peers();
        let _ = self.stop_tx.send(true);
    }

    async fn handle_command(self: &Arc<Self>, line: &str) -> String {
        let parts: Vec<&str> = line.split_whitespace().collect();
        match parts.first().copied() {
            Some("connect") => self.cmd_connect(&parts).await,
            Some("disconnect") => self.cmd_disconnect(&parts),
            Some("peers") => self.cmd_peers(),
            Some("info") => self.cmd_info().await,
            Some("mine") => self.cmd_mine(&parts).await,
            Some("stop") => {
                self.shutdown();
                "Stopping daemon\n".to_string()
            }
            Some(other) => format!("Unknown command: {other}\n"),
            None => String::new(),
        }
    }

    async fn cmd_connect(&self, parts: &[&str]) -> String {
        if parts.len() != 3 {
            return "Usage: connect <pubkey_hex> <host:port>\n".to_string();
        }

        let pubkey = match hex::decode(parts[1])
            .ok()
            .and_then(|b| PublicKey::from_slice(&b).ok())
        {
            Some(pk) => pk,
            None => return "Invalid pubkey\n".to_string(),
        };

        let addr: SocketAddr = match parts[2].parse() {
            Ok(a) => a,
            Err(_) => return "Invalid address\n".to_string(),
        };

        match noise::connect(&self.peer_manager, pubkey, addr, &self.logger).await {
            Some(_) => {
                self.ensure_keepalive().await;
                format!("Connected to {pubkey}\n")
            }
            None => "Connection failed\n".to_string(),
        }
    }

    /// Spawns the keepalive timer if not already running.
    async fn ensure_keepalive(&self) {
        let mut handle = self.keepalive_handle.lock().await;
        if handle.as_ref().is_some_and(|h| !h.is_finished()) {
            return;
        }
        *handle = Some(keepalive::spawn(&self.peer_manager, &self.logger));
    }

    fn cmd_disconnect(&self, parts: &[&str]) -> String {
        if parts.len() != 2 {
            return "Usage: disconnect <pubkey_hex>\n".to_string();
        }

        let pubkey = match hex::decode(parts[1])
            .ok()
            .and_then(|b| PublicKey::from_slice(&b).ok())
        {
            Some(pk) => pk,
            None => return "Invalid pubkey\n".to_string(),
        };

        self.peer_manager.disconnect_by_node_id(pubkey);
        format!("Disconnected {pubkey}\n")
    }

    async fn cmd_info(&self) -> String {
        let btc = Arc::clone(&self.bitcoind);
        let (blocks, hash, balance) = tokio::task::spawn_blocking(move || {
            (btc.block_count(), btc.best_block_hash(), btc.balance())
        })
        .await
        .unwrap_or((0, "unknown".to_string(), "0 BTC".to_string()));
        let peers = self.peer_manager.list_peers().len();
        format!(
            "[LN] node={} peers={peers}\n[Bitcoin] chain=regtest blocks={blocks} best={hash} balance={balance}\n",
            self.node_id
        )
    }

    async fn cmd_mine(&self, parts: &[&str]) -> String {
        let blocks: usize = match parts.get(1).and_then(|s| s.parse().ok()) {
            Some(n) => n,
            None => return "Usage: mine <blocks>\n".to_string(),
        };
        let btc = Arc::clone(&self.bitcoind);
        tokio::task::spawn_blocking(move || btc.mine(blocks))
            .await
            .unwrap_or_else(|e| format!("Task failed: {e}\n"))
    }

    fn cmd_peers(&self) -> String {
        let peers = self.peer_manager.list_peers();
        if peers.is_empty() {
            return "No connected peers\n".to_string();
        }
        peers
            .iter()
            .map(|p| {
                format!(
                    "{} inbound={} features={:?}\n",
                    p.counterparty_node_id, p.is_inbound_connection, p.init_features,
                )
            })
            .collect()
    }
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let bitcoind = match BitcoindClient::new(&args.rpc_url, &args.rpc_user, &args.rpc_pass) {
        Ok(b) => Arc::new(b),
        Err(e) => {
            eprintln!("Failed to connect to bitcoind: {e}");
            std::process::exit(1);
        }
    };

    let (daemon, mut stop_rx) = Daemon::new(bitcoind);
    log_info!(daemon.logger, "Connected to bitcoind at {}", args.rpc_url);

    let _ = std::fs::remove_file(SOCK_PATH);
    let listener = match UnixListener::bind(SOCK_PATH) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Failed to bind unix socket: {e}");
            std::process::exit(1);
        }
    };
    log_info!(daemon.logger, "Listening on {}", SOCK_PATH);

    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);

    loop {
        tokio::select! {
            accept = listener.accept() => {
                let (stream, _) = match accept {
                    Ok(s) => s,
                    Err(e) => {
                        log_error!(daemon.logger, "Accept error: {e}");
                        continue;
                    }
                };
                let d = Arc::clone(&daemon);
                tokio::spawn(async move {
                    let (reader, mut writer) = stream.into_split();
                    let mut lines = BufReader::new(reader).lines();
                    while let Ok(Some(line)) = lines.next_line().await {
                        let resp = d.handle_command(&line).await;
                        let _ = writer.write_all(resp.as_bytes()).await;
                    }
                });
            }
            _ = &mut ctrl_c => {
                daemon.shutdown();
                break;
            }
            _ = stop_rx.changed() => {
                break;
            }
        }
    }

    let _ = std::fs::remove_file(SOCK_PATH);
}
