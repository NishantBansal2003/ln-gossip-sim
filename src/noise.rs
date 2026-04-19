//! Bolt 8 Noise protocol connection establishment.

use bitcoin::secp256k1::PublicKey;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::types::PeerMgr;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);

/// Perform a Noise_XK handshake and return a handle to the connection task.
/// Returns `None` if TCP connect or handshake fails.
pub async fn connect(
    peer_manager: &Arc<PeerMgr>,
    their_node_id: PublicKey,
    addr: SocketAddr,
    logger: &Arc<crate::log::SimLogger>,
) -> Option<tokio::task::JoinHandle<()>> {
    log_info!(logger, "Connecting to {}@{}", their_node_id, addr);

    let conn_future =
        lightning_net_tokio::connect_outbound(Arc::clone(peer_manager), their_node_id, addr).await;

    let conn_closed = match conn_future {
        Some(future) => future,
        None => {
            log_error!(logger, "TCP connect failed");
            return None;
        }
    };

    let handle = tokio::spawn(conn_closed);
    tokio::time::sleep(HANDSHAKE_TIMEOUT).await;

    let peer = peer_manager
        .list_peers()
        .into_iter()
        .find(|p| p.counterparty_node_id == their_node_id);

    match peer {
        Some(p) => {
            log_info!(
                logger,
                "Peer connected: {} features={:?}",
                p.counterparty_node_id,
                p.init_features
            );
            Some(handle)
        }
        None => {
            log_error!(logger, "Noise handshake failed for {their_node_id}");
            None
        }
    }
}
