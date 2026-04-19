//! Peer keepalive timer.
//!
//! Spawned after the first Noise handshake succeeds. Periodically calls
//! `timer_tick_occurred` (~10s) which sends pings and disconnects
//! unresponsive peers. Exits when all peers disconnect.

use std::sync::Arc;
use std::time::Duration;

use crate::types::PeerMgr;

const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);

/// Spawns the keepalive timer. Exits when all peers disconnect.
pub fn spawn(
    peer_manager: &Arc<PeerMgr>,
    logger: &Arc<crate::log::SimLogger>,
) -> tokio::task::JoinHandle<()> {
    let pm = Arc::clone(peer_manager);
    let logger = Arc::clone(logger);
    tokio::spawn(async move {
        log_info!(logger, "Keepalive started");
        loop {
            tokio::time::sleep(KEEPALIVE_INTERVAL).await;
            pm.timer_tick_occurred();
            pm.process_events();
            if pm.list_peers().is_empty() {
                log_info!(logger, "All peers disconnected, keepalive stopped");
                break;
            }
            log_trace!(logger, "Keepalive tick");
        }
    })
}
