//! Gossip message broadcaster.
//!
//! Implements `SendOnlyMessageHandler` so that we can inject
//! `BroadcastChannelAnnouncement` events into the `PeerManager`
//! event loop, which then forwards them to all connected peers
//! over Noise-encrypted connections.

use std::sync::Mutex;

use bitcoin::secp256k1::PublicKey;
use lightning::ln::msgs::{BaseMessageHandler, Init, MessageSendEvent, SendOnlyMessageHandler};
use lightning::types::features::{InitFeatures, NodeFeatures};

/// Queue that the daemon pushes broadcast events into.
/// `PeerManager::process_events()` drains it and sends to all peers.
pub struct GossipBroadcaster {
    pending: Mutex<Vec<MessageSendEvent>>,
}

impl Default for GossipBroadcaster {
    fn default() -> Self {
        Self::new()
    }
}

impl GossipBroadcaster {
    pub fn new() -> Self {
        Self {
            pending: Mutex::new(Vec::new()),
        }
    }

    /// Enqueue an event for broadcast on the next `process_events()` call.
    pub fn enqueue(&self, event: MessageSendEvent) {
        self.pending.lock().unwrap().push(event);
    }
}

impl BaseMessageHandler for GossipBroadcaster {
    fn peer_disconnected(&self, _their_node_id: PublicKey) {}

    fn peer_connected(
        &self,
        _their_node_id: PublicKey,
        _init: &Init,
        _inbound: bool,
    ) -> Result<(), ()> {
        Ok(())
    }

    fn provided_node_features(&self) -> NodeFeatures {
        NodeFeatures::empty()
    }

    fn provided_init_features(&self, _their_node_id: PublicKey) -> InitFeatures {
        InitFeatures::empty()
    }

    fn get_and_clear_pending_msg_events(&self) -> Vec<MessageSendEvent> {
        let mut pending = self.pending.lock().unwrap();
        std::mem::take(&mut *pending)
    }
}

impl SendOnlyMessageHandler for GossipBroadcaster {}
