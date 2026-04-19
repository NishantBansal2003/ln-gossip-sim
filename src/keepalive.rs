//! Peer keepalive timer.
//!
//! Periodically calls `timer_tick_occurred` (~10s) which sends pings and
//! disconnects unresponsive peers. Pong replies are handled automatically
//! by `PeerManager`.

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
        loop {
            tokio::time::sleep(KEEPALIVE_INTERVAL).await;
            log_trace!(logger, "Keepalive tick");
            pm.timer_tick_occurred();
            pm.process_events();
            if pm.list_peers().is_empty() {
                log_info!(logger, "All peers disconnected");
                break;
            }
        }
    })
}
