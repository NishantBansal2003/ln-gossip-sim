use bitcoin::secp256k1::PublicKey;
use bolt::{ChannelAnnouncement, ChannelUpdate, Message, NodeAnnouncement, Ping};
use clap::Parser;
use ln_gossip_sim::bitcoind::{BitcoindClient, REGTEST_CHAIN_HASH};
use ln_gossip_sim::conn::{self, NoiseWriter};
use ln_gossip_sim::{SOCK_PATH, keys};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::sync::{Mutex, watch};
use tokio::time::{Duration, interval};

const PING_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Parser)]
#[command(name = "ln-gossip-simd", about = "LN gossip simulator daemon")]
#[allow(clippy::struct_field_names)] // rpc_ prefix matches CLI convention
struct Args {
    #[arg(long)]
    rpc_url: String,
    #[arg(long)]
    rpc_user: String,
    #[arg(long)]
    rpc_pass: String,
}

/// Parses a short channel ID in `block x tx_index x output` form (as printed
/// by send-channel-announcement) into its compact `u64` encoding.
fn parse_scid(s: &str) -> Option<u64> {
    let mut fields = s.split('x');
    let block: u64 = fields.next()?.parse().ok()?;
    let tx_index: u64 = fields.next()?.parse().ok()?;
    let output: u64 = fields.next()?.parse().ok()?;
    if fields.next().is_some() || block > 0xFF_FFFF || tx_index > 0xFF_FFFF || output > 0xFFFF {
        return None;
    }
    Some((block << 40) | (tx_index << 16) | output)
}

/// Handles a single inbound message from a peer, sending any response it
/// requires. Returns `false` if the connection should be torn down (e.g. a
/// send failed).
async fn handle_peer_message(
    peer_id: &PublicKey,
    writer: &Arc<Mutex<NoiseWriter>>,
    raw: &[u8],
) -> bool {
    match Message::decode(raw) {
        Ok(Message::Ping(ping)) => {
            log::info!("Received Ping from {peer_id}");
            let resp = Message::Pong(bolt::Pong::respond_to(&ping));
            if let Err(e) = writer.lock().await.send(&resp.encode()).await {
                log::error!("Peer {peer_id} pong error: {e}");
                return false;
            }
            log::info!("Sent Pong to {peer_id}");
        }
        Ok(Message::Pong(_)) => {
            log::info!("Received Pong from {peer_id}");
        }
        Ok(Message::Warning(_)) => {
            log::info!("Received Warning from {peer_id}");
        }
        Ok(Message::ChannelAnnouncement(ann)) => {
            log::info!(
                "Received channel_announcement scid={} from {peer_id}",
                ann.scid_str()
            );
        }
        Ok(Message::NodeAnnouncement(ann)) => {
            log::info!(
                "Received node_announcement node_id={} from {peer_id}",
                ann.node_id
            );
        }
        Ok(Message::ChannelUpdate(upd)) => {
            log::info!(
                "Received channel_update scid={} from {peer_id}",
                upd.scid_str()
            );
        }
        Ok(Message::QueryChannelRange(query)) => {
            log::info!(
                "Received query_channel_range first_blocknum={} number_of_blocks={} from {peer_id}",
                query.first_blocknum,
                query.number_of_blocks
            );
            // We know no channels: reply covering the full requested range
            // with an empty SCID list and sync_complete set, so the peer sees
            // the range as fully answered.
            let reply = bolt::ReplyChannelRange::from_scids(
                query.chain_hash,
                query.first_blocknum,
                query.number_of_blocks,
                true,
                &[],
            );
            let resp = Message::ReplyChannelRange(Box::new(reply));
            if let Err(e) = writer.lock().await.send(&resp.encode()).await {
                log::error!("Peer {peer_id} reply_channel_range error: {e}");
                return false;
            }
            log::info!("Sent reply_channel_range (0 scids) to {peer_id}");
        }
        Ok(msg) => {
            log::info!("Received msg type {} from {peer_id}", msg.msg_type());
        }
        Err(_) => {
            let mt = u16::from_be_bytes([raw[0], raw[1]]);
            log::info!("Received unknown msg type {mt} from {peer_id}");
        }
    }
    true
}

struct Peer {
    writer: Arc<Mutex<NoiseWriter>>,
    read_handle: tokio::task::JoinHandle<()>,
}

/// One simulated Lightning node hosted by the daemon. Its identity keys are
/// derived on demand from its node index, so a node only needs to track the
/// peers it has connected to.
#[derive(Default)]
struct Node {
    peers: HashMap<PublicKey, Peer>,
}

struct Daemon {
    /// Nodes that are "up": a node appears here once it has at least one peer
    /// connection, and is removed when its last peer disconnects.
    nodes: Mutex<HashMap<u32, Node>>,
    bitcoind: Arc<BitcoindClient>,
    stop_tx: watch::Sender<bool>,
}

impl Daemon {
    fn new(bitcoind: Arc<BitcoindClient>) -> (Arc<Self>, watch::Receiver<bool>) {
        let (stop_tx, stop_rx) = watch::channel(false);
        let daemon = Arc::new(Self {
            nodes: Mutex::new(HashMap::new()),
            bitcoind,
            stop_tx,
        });
        (daemon, stop_rx)
    }

    fn shutdown(&self) {
        log::info!("Shutting down");
        let _ = self.stop_tx.send(true);
    }

    /// Looks up the writer for a connected peer of node `node_index`, returning
    /// a user-facing error string if the node is not up or not connected to the
    /// peer.
    async fn peer_writer(
        &self,
        node_index: u32,
        peer: &PublicKey,
    ) -> Result<Arc<Mutex<NoiseWriter>>, String> {
        let nodes = self.nodes.lock().await;
        let Some(node) = nodes.get(&node_index) else {
            return Err(format!(
                "Node {node_index} is not up. Connect it to a peer first: \
                 cli --node-index {node_index} connect <pubkey> <host:port>\n"
            ));
        };
        let Some(peer) = node.peers.get(peer) else {
            return Err(format!("Node {node_index} not connected to {peer}\n"));
        };
        Ok(Arc::clone(&peer.writer))
    }

    async fn handle_command(self: &Arc<Self>, line: &str) -> String {
        let parts: Vec<&str> = line.split_whitespace().collect();
        // `mine` and `stop` act on the daemon/chain as a whole, so they are not
        // node-scoped and carry no node-index prefix.
        match parts.first().copied() {
            Some("stop") => {
                if parts.len() != 1 {
                    return "Usage: stop\n".to_string();
                }
                self.shutdown();
                return "Stopping daemon\n".to_string();
            }
            Some("mine") => return self.cmd_mine(&parts).await,
            _ => {}
        }
        // Every other command is prefixed by the node index it applies to.
        let Some(idx_str) = parts.first().copied() else {
            return String::new();
        };
        let Ok(node_index) = idx_str.parse::<u32>() else {
            return format!("Invalid node index: {idx_str}\n");
        };
        let args = &parts[1..];
        match args.first().copied() {
            Some("connect") => self.cmd_connect(node_index, args).await,
            Some("disconnect") => self.cmd_disconnect(node_index, args).await,
            Some("sendchannelannouncement") => {
                self.cmd_send_channel_announcement(node_index, args).await
            }
            Some("sendchannelannouncement2") => {
                self.cmd_send_channel_announcement_2(node_index, args).await
            }
            Some("sendchannelupdate") => self.cmd_send_channel_update(node_index, args).await,
            Some("sendnodeannouncement") => self.cmd_send_node_announcement(node_index, args).await,
            Some("sendmessage") => self.cmd_send_message(node_index, args).await,
            Some("peers") => self.cmd_peers(node_index, args).await,
            Some("info") => self.cmd_info(node_index, args).await,
            Some(other) => format!("Unknown command: {other}\n"),
            None => String::new(),
        }
    }

    async fn cmd_connect(self: &Arc<Self>, node_index: u32, parts: &[&str]) -> String {
        if parts.len() != 3 {
            return "Usage: connect <pubkey_hex> <host:port>\n".to_string();
        }
        let Some(pubkey) = hex::decode(parts[1])
            .ok()
            .and_then(|b| PublicKey::from_slice(&b).ok())
        else {
            return "Invalid pubkey\n".to_string();
        };
        let addr: SocketAddr = match parts[2].parse() {
            Ok(a) => a,
            Err(_) => return "Invalid address\n".to_string(),
        };
        // Handshake with this node's own identity, derived from its index.
        let (writer, mut reader, _node_id) =
            match conn::connect(addr, pubkey, keys::node_secret(node_index)).await {
                Ok(parts) => parts,
                Err(e) => return format!("Connection failed: {e}\n"),
            };
        let writer = Arc::new(Mutex::new(writer));
        let ping_writer = Arc::clone(&writer);
        let peer_id = pubkey;
        let daemon = Arc::clone(self);
        let read_handle = tokio::spawn(async move {
            let mut ticker = interval(PING_INTERVAL);
            loop {
                tokio::select! {
                    result = reader.recv() => {
                        match result {
                            Ok(raw) => {
                                if raw.len() < 2 {
                                    log::error!("Peer {peer_id}: message too short");
                                    break;
                                }
                                if !handle_peer_message(&peer_id, &ping_writer, &raw).await {
                                    break;
                                }
                            }
                            Err(e) => {
                                log::error!("Peer {peer_id} read error: {e}");
                                break;
                            }
                        }
                    }
                    _ = ticker.tick() => {
                        let ping = Message::Ping(Ping::new(1));
                        if let Err(e) = ping_writer.lock().await.send(&ping.encode()).await {
                            log::error!("Peer {peer_id} ping error: {e}");
                            break;
                        }
                        log::info!("Sent Ping to {peer_id}");
                    }
                }
            }
            log::info!("Peer {peer_id} disconnected from node {node_index}, removing");
            let mut nodes = daemon.nodes.lock().await;
            if let Some(node) = nodes.get_mut(&node_index) {
                node.peers.remove(&peer_id);
                if node.peers.is_empty() {
                    nodes.remove(&node_index);
                }
            }
        });
        let mut nodes = self.nodes.lock().await;
        nodes
            .entry(node_index)
            .or_default()
            .peers
            .insert(pubkey, Peer { writer, read_handle });
        format!("Node {node_index} ({}) connected to {pubkey}\n", keys::node_id(node_index))
    }

    async fn cmd_disconnect(&self, node_index: u32, parts: &[&str]) -> String {
        if parts.len() != 2 {
            return "Usage: disconnect <pubkey_hex>\n".to_string();
        }
        let Some(pubkey) = hex::decode(parts[1])
            .ok()
            .and_then(|b| PublicKey::from_slice(&b).ok())
        else {
            return "Invalid pubkey\n".to_string();
        };
        let mut nodes = self.nodes.lock().await;
        let Some(node) = nodes.get_mut(&node_index) else {
            return format!("Node {node_index} is not up\n");
        };
        if let Some(peer) = node.peers.remove(&pubkey) {
            peer.read_handle.abort();
            if node.peers.is_empty() {
                nodes.remove(&node_index);
            }
            log::info!("Node {node_index} disconnected peer {pubkey}");
            format!("Node {node_index} disconnected {pubkey}\n")
        } else {
            format!("Node {node_index} not connected to {pubkey}\n")
        }
    }

    async fn cmd_send_channel_announcement(&self, node_index: u32, parts: &[&str]) -> String {
        if parts.len() != 2 {
            return "Usage: sendchannelannouncement <pubkey_hex>\n".to_string();
        }
        let Some(peer_pubkey) = hex::decode(parts[1])
            .ok()
            .and_then(|b| PublicKey::from_slice(&b).ok())
        else {
            return "Invalid pubkey\n".to_string();
        };

        let writer = match self.peer_writer(node_index, &peer_pubkey).await {
            Ok(w) => w,
            Err(e) => return e,
        };

        // Mine 6 blocks to a fresh 2-of-2 P2WSH funding address.
        let btc = Arc::clone(&self.bitcoind);
        let fund_result = tokio::task::spawn_blocking(move || btc.mine_to_funding(6)).await;
        let (_, funding, scid) = match fund_result {
            Ok(Ok(result)) => result,
            Ok(Err(e)) => return format!("Funding failed: {e}\n"),
            Err(e) => return format!("Task failed: {e}\n"),
        };

        // Both node_id_1 and node_id_2 are ours (we own both sides).
        let our_sk = keys::node_secret(node_index);
        let (bitcoin_sk_1, bitcoin_sk_2) = (funding.sk1, funding.sk2);

        let ann = ChannelAnnouncement::new_signed(
            Vec::new(),
            REGTEST_CHAIN_HASH,
            scid,
            &our_sk,
            &our_sk,
            &bitcoin_sk_1,
            &bitcoin_sk_2,
        );

        let msg = Message::ChannelAnnouncement(Box::new(ann.clone()));
        if let Err(e) = writer.lock().await.send(&msg.encode()).await {
            return format!("Send failed: {e}\n");
        }

        log::info!(
            "Node {node_index} sent channel_announcement scid={} to {peer_pubkey}",
            ann.scid_str()
        );
        format!(
            "Sent channel_announcement scid={} to {peer_pubkey}\n",
            ann.scid_str()
        )
    }

    async fn cmd_send_channel_announcement_2(&self, node_index: u32, parts: &[&str]) -> String {
        if parts.len() != 2 {
            return "Usage: sendchannelannouncement2 <pubkey_hex>\n".to_string();
        }
        let Some(peer_pubkey) = hex::decode(parts[1])
            .ok()
            .and_then(|b| PublicKey::from_slice(&b).ok())
        else {
            return "Invalid pubkey\n".to_string();
        };

        let writer = match self.peer_writer(node_index, &peer_pubkey).await {
            Ok(w) => w,
            Err(e) => return e,
        };

        // Mine 6 blocks to a fresh 2-of-2 P2WSH funding address.
        let btc = Arc::clone(&self.bitcoind);
        let fund_result = tokio::task::spawn_blocking(move || btc.mine_to_funding(6)).await;
        let (_, funding, scid) = match fund_result {
            Ok(Ok(result)) => result,
            Ok(Err(e)) => return format!("Funding failed: {e}\n"),
            Err(e) => return format!("Task failed: {e}\n"),
        };

        // node_id_1 and node_id_2 are two distinct node identities. BOLT 7
        // requires node_id_1 < node_id_2 lexicographically, so order the two
        // node secrets by their public keys.
        let secp = bitcoin::secp256k1::Secp256k1::signing_only();
        let sk_a = keys::node_secret(node_index);
        let sk_b = keys::node_secret_2(node_index);
        let (node_sk_1, node_sk_2) = if PublicKey::from_secret_key(&secp, &sk_a)
            < PublicKey::from_secret_key(&secp, &sk_b)
        {
            (sk_a, sk_b)
        } else {
            (sk_b, sk_a)
        };
        let (bitcoin_sk_1, bitcoin_sk_2) = (funding.sk1, funding.sk2);

        let ann = ChannelAnnouncement::new_signed(
            Vec::new(),
            REGTEST_CHAIN_HASH,
            scid,
            &node_sk_1,
            &node_sk_2,
            &bitcoin_sk_1,
            &bitcoin_sk_2,
        );

        let msg = Message::ChannelAnnouncement(Box::new(ann.clone()));
        if let Err(e) = writer.lock().await.send(&msg.encode()).await {
            return format!("Send failed: {e}\n");
        }

        log::info!(
            "Node {node_index} sent channel_announcement (distinct node IDs) scid={} to {peer_pubkey}",
            ann.scid_str()
        );
        format!(
            "Sent channel_announcement (distinct node IDs) scid={} to {peer_pubkey}\n",
            ann.scid_str()
        )
    }

    async fn cmd_send_channel_update(&self, node_index: u32, parts: &[&str]) -> String {
        if parts.len() != 3 {
            return "Usage: sendchannelupdate <pubkey_hex> <scid>\n".to_string();
        }
        let Some(peer_pubkey) = hex::decode(parts[1])
            .ok()
            .and_then(|b| PublicKey::from_slice(&b).ok())
        else {
            return "Invalid pubkey\n".to_string();
        };
        // scid as printed by send-channel-announcement, e.g. "539268x845x1".
        let Some(scid) = parse_scid(parts[2]) else {
            return "Invalid scid (expected block x tx x output)\n".to_string();
        };

        let writer = match self.peer_writer(node_index, &peer_pubkey).await {
            Ok(w) => w,
            Err(e) => return e,
        };

        // Update the channel announced by send-channel-announcement-2, which
        // uses two distinct node IDs ordered so node_id_1 < node_id_2. The
        // channel_flags direction bit is 0, so this update belongs to node_id_1
        // and must be signed by that node's key.
        let secp = bitcoin::secp256k1::Secp256k1::signing_only();
        let sk_a = keys::node_secret(node_index);
        let sk_b = keys::node_secret_2(node_index);
        let node_sk_1 = if PublicKey::from_secret_key(&secp, &sk_a)
            < PublicKey::from_secret_key(&secp, &sk_b)
        {
            sk_a
        } else {
            sk_b
        };

        // Forwarding policy with conservative defaults accepted by CLN, LND,
        // and Eclair:
        //   message_flags = 1  -> bit 0 set: htlc_maximum_msat is present (required).
        //   channel_flags = 0  -> direction node_id_1, channel enabled.
        // timestamp = 0 to exercise the zero-timestamp edge case.
        let update = ChannelUpdate::new_signed(
            REGTEST_CHAIN_HASH,
            scid,
            0,             // timestamp
            1,             // message_flags
            0,             // channel_flags
            40,            // cltv_expiry_delta
            1,             // htlc_minimum_msat
            1_000,         // fee_base_msat
            1,             // fee_proportional_millionths
            4_294_967_295, // htlc_maximum_msat
            &node_sk_1,
        );

        let msg = Message::ChannelUpdate(Box::new(update.clone()));
        if let Err(e) = writer.lock().await.send(&msg.encode()).await {
            return format!("Send failed: {e}\n");
        }

        log::info!(
            "Node {node_index} sent channel_update scid={} to {peer_pubkey}",
            update.scid_str()
        );
        format!(
            "Sent channel_update scid={} to {peer_pubkey}\n",
            update.scid_str()
        )
    }

    async fn cmd_send_node_announcement(&self, node_index: u32, parts: &[&str]) -> String {
        if parts.len() != 2 {
            return "Usage: sendnodeannouncement <pubkey_hex>\n".to_string();
        }
        let Some(peer_pubkey) = hex::decode(parts[1])
            .ok()
            .and_then(|b| PublicKey::from_slice(&b).ok())
        else {
            return "Invalid pubkey\n".to_string();
        };

        let writer = match self.peer_writer(node_index, &peer_pubkey).await {
            Ok(w) => w,
            Err(e) => return e,
        };

        // Announce node_id_1 from send-channel-announcement-2 (the lesser of the
        // two node keys). Peers only accept a node_announcement whose node_id
        // appears in a previously announced channel, so this must match the key
        // used there.
        let secp = bitcoin::secp256k1::Secp256k1::signing_only();
        let sk_a = keys::node_secret(node_index);
        let sk_b = keys::node_secret_2(node_index);
        let node_sk_1 = if PublicKey::from_secret_key(&secp, &sk_a)
            < PublicKey::from_secret_key(&secp, &sk_b)
        {
            sk_a
        } else {
            sk_b
        };

        let ann = NodeAnnouncement::default_signed(&node_sk_1);

        let msg = Message::NodeAnnouncement(Box::new(ann.clone()));
        if let Err(e) = writer.lock().await.send(&msg.encode()).await {
            return format!("Send failed: {e}\n");
        }

        log::info!(
            "Node {node_index} sent node_announcement node_id={} to {peer_pubkey}",
            ann.node_id
        );
        format!(
            "Sent node_announcement node_id={} to {peer_pubkey}\n",
            ann.node_id
        )
    }

    /// Decodes a caller-supplied type-prefixed hex message and forwards it to a
    /// connected peer. The message is decoded (and thus validated) before being
    /// re-encoded and sent. Messages whose type has no codec are rejected with
    /// an "unknown message type" error so the caller knows to add one.
    async fn cmd_send_message(&self, node_index: u32, parts: &[&str]) -> String {
        if parts.len() != 3 {
            return "Usage: sendmessage <pubkey_hex> <message_hex>\n".to_string();
        }
        let Some(peer_pubkey) = hex::decode(parts[1])
            .ok()
            .and_then(|b| PublicKey::from_slice(&b).ok())
        else {
            return "Invalid pubkey\n".to_string();
        };
        let Ok(bytes) = hex::decode(parts[2]) else {
            return "Invalid message hex\n".to_string();
        };

        // Decode (and validate) the message before sending. Unknown types have
        // no codec yet: an unknown even type fails to decode, while an unknown
        // odd type decodes to `Message::Unknown`. Reject both so the caller adds
        // the corresponding codec rather than sending an unparsed blob.
        let wire = match Message::decode(&bytes) {
            Ok(Message::Unknown { msg_type, .. })
            | Err(bolt::BoltError::UnknownEvenType(msg_type)) => {
                return format!(
                    "Unknown message type {msg_type}: add the corresponding codec for it\n"
                );
            }
            Ok(msg) => msg.encode(),
            Err(e) => return format!("Decode failed: {e}\n"),
        };

        let writer = match self.peer_writer(node_index, &peer_pubkey).await {
            Ok(w) => w,
            Err(e) => return e,
        };

        if let Err(e) = writer.lock().await.send(&wire).await {
            return format!("Send failed: {e}\n");
        }

        let msg_type = u16::from_be_bytes([wire[0], wire[1]]);
        log::info!("Node {node_index} sent message type {msg_type} to {peer_pubkey}");
        format!("Sent message type {msg_type} to {peer_pubkey}\n")
    }

    async fn cmd_peers(&self, node_index: u32, parts: &[&str]) -> String {
        if parts.len() != 1 {
            return "Usage: peers\n".to_string();
        }
        let nodes = self.nodes.lock().await;
        let Some(node) = nodes.get(&node_index) else {
            return format!("Node {node_index} is not up (no peers)\n");
        };
        let mut out = String::new();
        for pk in node.peers.keys() {
            use std::fmt::Write;
            let _ = writeln!(out, "{pk}");
        }
        out
    }

    async fn cmd_info(&self, node_index: u32, parts: &[&str]) -> String {
        if parts.len() != 1 {
            return "Usage: info\n".to_string();
        }
        let btc = Arc::clone(&self.bitcoind);
        let Ok((blocks, hash, balance)) = tokio::task::spawn_blocking(move || {
            (btc.block_count(), btc.best_block_hash(), btc.balance())
        })
        .await
        else {
            return "Failed to query bitcoind\n".to_string();
        };
        let nodes = self.nodes.lock().await;
        let (up, peer_count) = match nodes.get(&node_index) {
            Some(node) => (true, node.peers.len()),
            None => (false, 0),
        };
        format!(
            "[LN] node_index={node_index} node={} up={up} peers={peer_count}\n[Bitcoin] chain=regtest blocks={blocks} best={hash} balance={balance}\n",
            keys::node_id(node_index)
        )
    }

    async fn cmd_mine(&self, parts: &[&str]) -> String {
        if parts.len() != 2 {
            return "Usage: mine <blocks>\n".to_string();
        }
        let Some(blocks) = parts[1].parse::<usize>().ok() else {
            return "Usage: mine <blocks>\n".to_string();
        };
        let btc = Arc::clone(&self.bitcoind);
        tokio::task::spawn_blocking(move || btc.mine(blocks))
            .await
            .unwrap_or_else(|e| format!("Task failed: {e}\n"))
    }
}

#[tokio::main]
async fn main() {
    ln_gossip_sim::log::init();
    let args = Args::parse();
    let bitcoind = match BitcoindClient::new(&args.rpc_url, &args.rpc_user, &args.rpc_pass) {
        Ok(b) => Arc::new(b),
        Err(e) => {
            eprintln!("Failed to connect to bitcoind: {e}");
            std::process::exit(1);
        }
    };
    let (daemon, mut stop_rx) = Daemon::new(bitcoind);
    log::info!("Connected to bitcoind at {}", args.rpc_url);

    let _ = std::fs::remove_file(SOCK_PATH);
    let listener = match UnixListener::bind(SOCK_PATH) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Failed to bind unix socket: {e}");
            std::process::exit(1);
        }
    };
    log::info!("Listening on {SOCK_PATH}");

    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);

    loop {
        tokio::select! {
            accept = listener.accept() => {
                let (stream, _) = match accept {
                    Ok(s) => s,
                    Err(e) => {
                        log::error!("Accept error: {e}");
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
