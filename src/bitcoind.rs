//! Bitcoin Core RPC client wrapper.

use corepc_client::client_sync::Auth;
use corepc_client::client_sync::v17::Client;

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
}
