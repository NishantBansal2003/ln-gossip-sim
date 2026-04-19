#[macro_use]
mod log;
mod keepalive;
mod keys;
mod noise;
mod types;

use bitcoin::secp256k1::{PublicKey, Secp256k1};
use lightning::ln::peer_handler::PeerManager;
use lightning::routing::gossip::{NetworkGraph, P2PGossipSync};
use lightning::sign::KeysManager;
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: {} <node_pubkey_hex> <host:port>", args[0]);
        std::process::exit(1);
    }

    let their_node_id = {
        let bytes = hex::decode(&args[1]).expect("Invalid hex");
        PublicKey::from_slice(&bytes).expect("Invalid pubkey")
    };
    let addr: SocketAddr = args[2].parse().expect("Invalid address");
    let logger = Arc::new(log::SimLogger);

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
        "Our node ID: {}",
        PublicKey::from_secret_key(&secp, &keys_manager.get_node_secret_key())
    );

    let network_graph = Arc::new(NetworkGraph::new(
        bitcoin::Network::Bitcoin,
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

    let mut conn = match noise::connect(&peer_manager, their_node_id, addr, &logger).await {
        Some(handle) => handle,
        None => return,
    };

    let keepalive = keepalive::spawn(&peer_manager, &logger);

    tokio::select! {
        _ = &mut conn => log_info!(logger, "Peer disconnected"),
        _ = keepalive => {},
        _ = tokio::signal::ctrl_c() => {
            log_info!(logger, "Shutting down");
            peer_manager.disconnect_all_peers();
        }
    }
}
