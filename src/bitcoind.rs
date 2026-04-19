//! Bitcoin Core RPC client wrapper.

use bitcoin::Address;
use bitcoin::key::PrivateKey;
use bitcoin::secp256k1::{Secp256k1, rand};
use corepc_client::client_sync::Auth;
use corepc_client::client_sync::v30::Client;

const WALLET_NAME: &str = "ln-gossip-sim";

/// Wrapper around `corepc-client` for bitcoind RPC.
pub struct BitcoindClient {
    client: Client,
}

impl BitcoindClient {
    /// Connect to bitcoind, verify regtest, and ensure the
    /// `ln-gossip-sim` wallet exists.
    pub fn new(url: &str, user: &str, pass: &str) -> Result<Self, String> {
        let auth = Auth::UserPass(user.to_string(), pass.to_string());

        // Use the base URL first to check chain and set up wallet.
        let base =
            Client::new_with_auth(url, auth.clone()).map_err(|e| format!("RPC auth error: {e}"))?;

        let info = base
            .get_blockchain_info()
            .map_err(|e| format!("getblockchaininfo failed: {e}"))?;
        if info.chain != "regtest" {
            return Err(format!("Expected regtest, got {}", info.chain));
        }

        // Ensure wallet exists: try load, then create as fallback.
        if base.load_wallet(WALLET_NAME).is_err() {
            let _ = base.create_wallet(WALLET_NAME);
        }

        // Connect with wallet-scoped URL.
        let wallet_url = format!("{}/wallet/{}", url.trim_end_matches('/'), WALLET_NAME);
        let client = Client::new_with_auth(&wallet_url, auth)
            .map_err(|e| format!("RPC wallet auth error: {e}"))?;

        Ok(Self { client })
    }

    pub fn block_count(&self) -> u64 {
        self.client.get_block_count().map(|c| c.0).unwrap_or(0)
    }

    pub fn best_block_hash(&self) -> String {
        self.client
            .best_block_hash()
            .map(|h| h.to_string())
            .unwrap_or_else(|_| "unknown".to_string())
    }

    pub fn balance(&self) -> String {
        self.client
            .get_balance()
            .map(|b| b.0.to_string())
            .unwrap_or_else(|_| "0 BTC".to_string())
    }

    pub fn mine(&self, blocks: usize) -> String {
        match self.mine_to_funding(blocks) {
            Ok(msg) => msg,
            Err(e) => format!("{e}\n"),
        }
    }

    /// Create a fresh 2-of-2 P2WSH address from two random keys.
    /// Returns (address, pubkey1, pubkey2) so callers can reference the keys
    /// later (e.g. for channel announcements / UtxoLookup).
    /// Keys are imported with private keys so the wallet fully owns the output.
    pub fn new_funding_address(&self) -> Result<(Address, String, String), String> {
        let secp = Secp256k1::new();
        let (sk1, _) = secp.generate_keypair(&mut rand::thread_rng());
        let (sk2, _) = secp.generate_keypair(&mut rand::thread_rng());

        let priv1 = PrivateKey::new(sk1, bitcoin::Network::Regtest);
        let priv2 = PrivateKey::new(sk2, bitcoin::Network::Regtest);
        let pub1 = bitcoin::PublicKey::from_private_key(&secp, &priv1);
        let pub2 = bitcoin::PublicKey::from_private_key(&secp, &priv2);

        // Sort keys lexicographically (BOLT #3).
        let (w1, w2, p1, p2) = if pub1 < pub2 {
            (priv1.to_wif(), priv2.to_wif(), pub1, pub2)
        } else {
            (priv2.to_wif(), priv1.to_wif(), pub2, pub1)
        };

        // Descriptor with private keys so the wallet fully owns it.
        let desc = format!("wsh(multi(2,{w1},{w2}))");
        let info: serde_json::Value = self
            .client
            .call(
                "getdescriptorinfo",
                &[serde_json::Value::String(desc.clone())],
            )
            .map_err(|e| format!("getdescriptorinfo: {e}"))?;
        let checksum = info["checksum"].as_str().ok_or("missing checksum")?;
        let desc_full = format!("{desc}#{checksum}");

        // Derive the P2WSH address.
        let addrs: serde_json::Value = self
            .client
            .call(
                "deriveaddresses",
                &[serde_json::Value::String(desc_full.clone())],
            )
            .map_err(|e| format!("deriveaddresses: {e}"))?;
        let addr = addrs[0]
            .as_str()
            .ok_or("missing address in deriveaddresses")?
            .parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>()
            .map_err(|e| format!("parse address: {e}"))?
            .assume_checked();

        // Import with private keys -- wallet can track and spend.
        let result: serde_json::Value = self
            .client
            .call(
                "importdescriptors",
                &[serde_json::json!([{
                    "desc": desc_full,
                    "timestamp": "now",
                    "active": false
                }])],
            )
            .map_err(|e| format!("importdescriptors: {e}"))?;
        if let Some(false) = result[0]["success"].as_bool() {
            return Err(format!("importdescriptors: {}", result[0]["error"]));
        }

        Ok((addr, p1.to_string(), p2.to_string()))
    }

    fn mine_to_funding(&self, blocks: usize) -> Result<String, String> {
        let (addr, _, _) = self.new_funding_address()?;

        let r = self
            .client
            .generate_to_address(blocks, &addr)
            .map_err(|e| format!("generatetoaddress: {e}"))?;

        Ok(format!("Mined {} block(s) to {addr}\n", r.0.len()))
    }
}
