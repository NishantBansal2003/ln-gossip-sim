//! Bitcoin Core RPC client wrapper.

use bitcoin::Address;
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

    /// Create a fresh 2-of-2 P2WSH address from two wallet keys.
    /// Returns (address, key1, key2) so callers can reference the keys
    /// later (e.g. for channel announcements / UtxoLookup).
    pub fn new_funding_address(&self) -> Result<(Address, String, String), String> {
        let a1 = self
            .client
            .new_address()
            .map_err(|e| format!("address: {e}"))?;
        let a2 = self
            .client
            .new_address()
            .map_err(|e| format!("address: {e}"))?;

        // addmultisigaddress with bech32 = native P2WSH, wallet-controlled.
        let result: serde_json::Value = self
            .client
            .call(
                "addmultisigaddress",
                &[
                    serde_json::Value::from(2),
                    serde_json::json!([a1.to_string(), a2.to_string()]),
                    serde_json::Value::String(String::new()),
                    serde_json::Value::String("bech32".to_string()),
                ],
            )
            .map_err(|e| format!("addmultisigaddress: {e}"))?;

        let addr = result["address"]
            .as_str()
            .ok_or("missing address in response")?
            .parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>()
            .map_err(|e| format!("parse address: {e}"))?
            .assume_checked();

        Ok((addr, a1.to_string(), a2.to_string()))
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
