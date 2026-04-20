//! Type aliases for the peer management stack.

use lightning::ln::peer_handler::{ErroringMessageHandler, IgnoringMessageHandler, PeerManager};
use lightning::routing::gossip::{NetworkGraph, P2PGossipSync};
use lightning::sign::KeysManager;
use lightning_net_tokio::SocketDescriptor;
use std::sync::Arc;

use crate::gossip::GossipBroadcaster;
use crate::log::SimLogger;

pub type GossipSync = P2PGossipSync<
    Arc<NetworkGraph<Arc<SimLogger>>>,
    Arc<dyn lightning::routing::utxo::UtxoLookup + Send + Sync>,
    Arc<SimLogger>,
>;

/// Routing-only peer manager; no channel or onion message handling.
/// `GossipBroadcaster` lets us inject broadcast events that `process_events()`
/// sends to all peers over Noise connections.
pub type PeerMgr = PeerManager<
    SocketDescriptor,
    ErroringMessageHandler,
    Arc<GossipSync>,
    IgnoringMessageHandler,
    Arc<SimLogger>,
    IgnoringMessageHandler,
    Arc<KeysManager>,
    Arc<GossipBroadcaster>,
>;
