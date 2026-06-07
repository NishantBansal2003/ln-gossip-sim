use bitcoin::secp256k1::PublicKey;
use bolt::{ChannelAnnouncement, ChannelUpdate, Message, Ping};
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
    #[allow(dead_code)] // Used when sending gossip/announcement messages.
    writer: Arc<Mutex<NoiseWriter>>,
    read_handle: tokio::task::JoinHandle<()>,
}

struct Daemon {
    node_id: PublicKey,
    peers: Mutex<HashMap<PublicKey, Peer>>,
    bitcoind: Arc<BitcoindClient>,
    stop_tx: watch::Sender<bool>,
}

impl Daemon {
    fn new(bitcoind: Arc<BitcoindClient>) -> (Arc<Self>, watch::Receiver<bool>) {
        let node_id = keys::node_id();
        log::info!("Node ID: {node_id}");
        let (stop_tx, stop_rx) = watch::channel(false);
        let daemon = Arc::new(Self {
            node_id,
            peers: Mutex::new(HashMap::new()),
            bitcoind,
            stop_tx,
        });
        (daemon, stop_rx)
    }

    fn shutdown(&self) {
        log::info!("Shutting down");
        let _ = self.stop_tx.send(true);
    }

    async fn handle_command(self: &Arc<Self>, line: &str) -> String {
        let parts: Vec<&str> = line.split_whitespace().collect();
        match parts.first().copied() {
            Some("connect") => self.cmd_connect(&parts).await,
            Some("disconnect") => self.cmd_disconnect(&parts).await,
            Some("sendchannelannouncement") => self.cmd_send_channel_announcement(&parts).await,
            Some("sendchannelannouncement2") => self.cmd_send_channel_announcement_2(&parts).await,
            Some("sendchannelupdate") => self.cmd_send_channel_update(&parts).await,
            Some("peers") => self.cmd_peers().await,
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

    async fn cmd_connect(self: &Arc<Self>, parts: &[&str]) -> String {
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
        let (writer, mut reader, _node_id) =
            match conn::connect(addr, pubkey, keys::node_secret()).await {
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
            log::info!("Peer {peer_id} disconnected, removing from peer list");
            daemon.peers.lock().await.remove(&peer_id);
        });
        let mut peers = self.peers.lock().await;
        peers.insert(
            pubkey,
            Peer {
                writer,
                read_handle,
            },
        );
        format!("Connected to {pubkey}\n")
    }

    async fn cmd_disconnect(&self, parts: &[&str]) -> String {
        if parts.len() != 2 {
            return "Usage: disconnect <pubkey_hex>\n".to_string();
        }
        let Some(pubkey) = hex::decode(parts[1])
            .ok()
            .and_then(|b| PublicKey::from_slice(&b).ok())
        else {
            return "Invalid pubkey\n".to_string();
        };
        let mut peers = self.peers.lock().await;
        if let Some(peer) = peers.remove(&pubkey) {
            peer.read_handle.abort();
            log::info!("Disconnected peer {pubkey}");
            format!("Disconnected {pubkey}\n")
        } else {
            format!("Not connected to {pubkey}\n")
        }
    }

    async fn cmd_send_channel_announcement(&self, parts: &[&str]) -> String {
        if parts.len() != 2 {
            return "Usage: sendchannelannouncement <pubkey_hex>\n".to_string();
        }
        let Some(peer_pubkey) = hex::decode(parts[1])
            .ok()
            .and_then(|b| PublicKey::from_slice(&b).ok())
        else {
            return "Invalid pubkey\n".to_string();
        };

        // Check if peer is connected.
        let writer = {
            let peers = self.peers.lock().await;
            let Some(peer) = peers.get(&peer_pubkey) else {
                return format!("Not connected to {peer_pubkey}\n");
            };
            Arc::clone(&peer.writer)
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
        let our_sk = keys::node_secret();
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
            "Sent channel_announcement scid={} to {peer_pubkey}",
            ann.scid_str()
        );
        format!(
            "Sent channel_announcement scid={} to {peer_pubkey}\n",
            ann.scid_str()
        )
    }

    async fn cmd_send_channel_announcement_2(&self, parts: &[&str]) -> String {
        if parts.len() != 2 {
            return "Usage: sendchannelannouncement2 <pubkey_hex>\n".to_string();
        }
        let Some(peer_pubkey) = hex::decode(parts[1])
            .ok()
            .and_then(|b| PublicKey::from_slice(&b).ok())
        else {
            return "Invalid pubkey\n".to_string();
        };

        // Check if peer is connected.
        let writer = {
            let peers = self.peers.lock().await;
            let Some(peer) = peers.get(&peer_pubkey) else {
                return format!("Not connected to {peer_pubkey}\n");
            };
            Arc::clone(&peer.writer)
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
        let sk_a = keys::node_secret();
        let sk_b = keys::node_secret_2();
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
            "Sent channel_announcement (distinct node IDs) scid={} to {peer_pubkey}",
            ann.scid_str()
        );
        format!(
            "Sent channel_announcement (distinct node IDs) scid={} to {peer_pubkey}\n",
            ann.scid_str()
        )
    }

    async fn cmd_send_channel_update(&self, parts: &[&str]) -> String {
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

        // Check if peer is connected.
        let writer = {
            let peers = self.peers.lock().await;
            let Some(peer) = peers.get(&peer_pubkey) else {
                return format!("Not connected to {peer_pubkey}\n");
            };
            Arc::clone(&peer.writer)
        };

        // Update the channel announced by send-channel-announcement-2, which
        // uses two distinct node IDs ordered so node_id_1 < node_id_2. The
        // channel_flags direction bit is 0, so this update belongs to node_id_1
        // and must be signed by that node's key.
        let secp = bitcoin::secp256k1::Secp256k1::signing_only();
        let sk_a = keys::node_secret();
        let sk_b = keys::node_secret_2();
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
            "Sent channel_update scid={} to {peer_pubkey}",
            update.scid_str()
        );
        format!(
            "Sent channel_update scid={} to {peer_pubkey}\n",
            update.scid_str()
        )
    }

    async fn cmd_peers(&self) -> String {
        let peers = self.peers.lock().await;
        if peers.is_empty() {
            return "No connected peers\n".to_string();
        }
        let mut out = String::new();
        for pk in peers.keys() {
            use std::fmt::Write;
            let _ = writeln!(out, "{pk}");
        }
        out
    }

    async fn cmd_info(&self) -> String {
        let btc = Arc::clone(&self.bitcoind);
        let Ok((blocks, hash, balance)) = tokio::task::spawn_blocking(move || {
            (btc.block_count(), btc.best_block_hash(), btc.balance())
        })
        .await
        else {
            return "Failed to query bitcoind\n".to_string();
        };
        let peers = self.peers.lock().await;
        format!(
            "[LN] node={} peers={}\n[Bitcoin] chain=regtest blocks={blocks} best={hash} balance={balance}\n",
            self.node_id,
            peers.len()
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
