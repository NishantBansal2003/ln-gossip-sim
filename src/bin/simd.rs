use bitcoin::secp256k1::{PublicKey, Secp256k1};
use lightning::ln::peer_handler::PeerManager;
use lightning::routing::gossip::{NetworkGraph, P2PGossipSync};
use lightning::sign::KeysManager;
use ln_gossip_sim::log::SimLogger;
use ln_gossip_sim::{SOCK_PATH, keepalive, keys, log_error, log_info, noise, types};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::sync::watch;

struct Daemon {
    peer_manager: Arc<types::PeerMgr>,
    logger: Arc<SimLogger>,
    stop_tx: watch::Sender<bool>,
}

impl Daemon {
    fn new() -> (Arc<Self>, watch::Receiver<bool>) {
        let logger = Arc::new(SimLogger);
        let cur = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();

        let keys_manager = Arc::new(KeysManager::new(
            &keys::SEED,
            cur.as_secs(),
            cur.subsec_nanos(),
            true,
        ));

        let secp = Secp256k1::new();
        log_info!(
            logger,
            "Node ID: {}",
            PublicKey::from_secret_key(&secp, &keys_manager.get_node_secret_key())
        );

        let network_graph = Arc::new(NetworkGraph::new(
            bitcoin::Network::Regtest,
            Arc::clone(&logger),
        ));
        let gossip_sync = Arc::new(P2PGossipSync::new(
            Arc::clone(&network_graph),
            None::<Arc<dyn lightning::routing::utxo::UtxoLookup + Send + Sync>>,
            Arc::clone(&logger),
        ));

        let peer_manager: Arc<types::PeerMgr> = Arc::new(PeerManager::new_routing_only(
            Arc::clone(&gossip_sync),
            cur.as_secs() as u32,
            &keys::EPHEMERAL,
            Arc::clone(&logger),
            Arc::clone(&keys_manager),
        ));

        let (stop_tx, stop_rx) = watch::channel(false);

        let daemon = Arc::new(Self {
            peer_manager,
            logger,
            stop_tx,
        });
        (daemon, stop_rx)
    }

    fn shutdown(&self) {
        log_info!(self.logger, "Shutting down");
        self.peer_manager.disconnect_all_peers();
        let _ = self.stop_tx.send(true);
    }

    async fn handle_command(&self, line: &str) -> String {
        let parts: Vec<&str> = line.split_whitespace().collect();
        match parts.first().copied() {
            Some("connect") => self.cmd_connect(&parts).await,
            Some("disconnect") => self.cmd_disconnect(&parts),
            Some("peers") => self.cmd_peers(),
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
            Some(_) => format!("Connected to {pubkey}\n"),
            None => "Connection failed\n".to_string(),
        }
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
    let (daemon, mut stop_rx) = Daemon::new();
    let _keepalive = keepalive::spawn(&daemon.peer_manager, &daemon.logger);

    let _ = std::fs::remove_file(SOCK_PATH);
    let listener = UnixListener::bind(SOCK_PATH).expect("Failed to bind unix socket");
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
