//! Bitcoin Core RPC client wrapper.

use bitcoin::Address;
use bitcoin::key::PrivateKey;
use bitcoin::secp256k1::{Secp256k1, SecretKey, rand};
use corepc_client::client_sync::Auth;
use corepc_client::client_sync::v30::Client;

use crate::error::Error;

const WALLET_NAME: &str = "ln-gossip-sim";

/// Bitcoin regtest genesis block hash (little-endian, as used in BOLT messages).
pub const REGTEST_CHAIN_HASH: [u8; 32] = [
    0x06, 0x22, 0x6e, 0x46, 0x11, 0x1a, 0x0b, 0x59, 0xca, 0xaf, 0x12, 0x60, 0x43, 0xeb, 0x5b, 0xbf,
    0x28, 0xc3, 0x4f, 0x3a, 0x5e, 0x33, 0x2a, 0x1f, 0xc7, 0xb2, 0xb7, 0x3c, 0xf1, 0x88, 0x91, 0x0f,
];

/// Keypair material from a 2-of-2 P2WSH funding address.
/// Keys are sorted lexicographically per BOLT #3.
pub struct FundingKeys {
    pub address: Address,
    pub sk1: SecretKey,
    pub sk2: SecretKey,
    pub pk1: bitcoin::PublicKey,
    pub pk2: bitcoin::PublicKey,
}

/// Wrapper around `corepc-client` for bitcoind RPC.
pub struct BitcoindClient {
    client: Client,
}

impl BitcoindClient {
    /// Connect to bitcoind, verify regtest, and ensure the
    /// `ln-gossip-sim` wallet exists.
    ///
    /// # Errors
    ///
    /// Returns an error if the RPC connection fails, the chain is not regtest,
    /// or wallet creation fails.
    pub fn new(url: &str, user: &str, pass: &str) -> Result<Self, Error> {
        let auth = Auth::UserPass(user.to_string(), pass.to_string());

        // Use the base URL first to check chain and set up wallet.
        let base =
            Client::new_with_auth(url, auth.clone()).map_err(|e| Error::Rpc(e.to_string()))?;

        let info: serde_json::Value = base
            .call("getblockchaininfo", &[])
            .map_err(|e| Error::Rpc(e.to_string()))?;
        let chain = info["chain"]
            .as_str()
            .ok_or_else(|| Error::Rpc("missing chain field".into()))?;
        if chain != "regtest" {
            return Err(Error::Chain(format!("expected regtest, got {chain}")));
        }

        // Ensure wallet exists: try load, then create as fallback.
        // load_wallet fails both when the wallet doesn't exist and when it's
        // already loaded; only create if it truly doesn't exist yet.
        if let Err(e) = base.load_wallet(WALLET_NAME) {
            let msg = e.to_string();
            if msg.contains("already loaded") {
                // Wallet is already loaded from a previous run -- nothing to do.
            } else {
                base.create_wallet(WALLET_NAME)
                    .map_err(|e| Error::Rpc(format!("create wallet: {e}")))?;
            }
        }

        // Connect with wallet-scoped URL.
        let wallet_url = format!("{}/wallet/{}", url.trim_end_matches('/'), WALLET_NAME);
        let client =
            Client::new_with_auth(&wallet_url, auth).map_err(|e| Error::Rpc(e.to_string()))?;

        Ok(Self { client })
    }

    pub fn block_count(&self) -> u64 {
        self.client.get_block_count().map_or(0, |c| c.0)
    }

    pub fn best_block_hash(&self) -> String {
        self.client
            .best_block_hash()
            .map_or_else(|_| "unknown".to_string(), |h| h.to_string())
    }

    pub fn balance(&self) -> String {
        self.client
            .get_balance()
            .map_or_else(|_| "0 BTC".to_string(), |b| b.0.to_string())
    }

    pub fn mine(&self, blocks: usize) -> String {
        match self.mine_to_funding(blocks) {
            Ok((msg, _, _)) => msg,
            Err(e) => format!("{e}\n"),
        }
    }

    /// Create a fresh 2-of-2 P2WSH address from two random keys.
    /// Returns `FundingKeys` with the address, secret keys, and public keys
    /// (sorted lexicographically per BOLT 3).
    /// Keys are imported with private keys so the wallet fully owns the output.
    ///
    /// # Errors
    ///
    /// Returns an error if descriptor creation, address derivation, or import fails.
    pub fn new_funding_address(&self) -> Result<FundingKeys, Error> {
        let secp = Secp256k1::new();
        let (sk1, _) = secp.generate_keypair(&mut rand::thread_rng());
        let (sk2, _) = secp.generate_keypair(&mut rand::thread_rng());

        let priv1 = PrivateKey::new(sk1, bitcoin::Network::Regtest);
        let priv2 = PrivateKey::new(sk2, bitcoin::Network::Regtest);
        let pub1 = bitcoin::PublicKey::from_private_key(&secp, &priv1);
        let pub2 = bitcoin::PublicKey::from_private_key(&secp, &priv2);

        // Sort keys lexicographically (BOLT #3).
        let (w1, w2, sorted_sk1, sorted_sk2, p1, p2) = if pub1 < pub2 {
            (priv1.to_wif(), priv2.to_wif(), sk1, sk2, pub1, pub2)
        } else {
            (priv2.to_wif(), priv1.to_wif(), sk2, sk1, pub2, pub1)
        };

        // Descriptor with private keys so the wallet fully owns it.
        let desc = format!("wsh(multi(2,{w1},{w2}))");
        let info: serde_json::Value = self
            .client
            .call(
                "getdescriptorinfo",
                &[serde_json::Value::String(desc.clone())],
            )
            .map_err(|e| Error::Descriptor(e.to_string()))?;
        let checksum = info["checksum"]
            .as_str()
            .ok_or_else(|| Error::Descriptor("missing checksum".into()))?;
        let desc_full = format!("{desc}#{checksum}");

        // Derive the P2WSH address.
        let addrs: serde_json::Value = self
            .client
            .call(
                "deriveaddresses",
                &[serde_json::Value::String(desc_full.clone())],
            )
            .map_err(|e| Error::Address(e.to_string()))?;
        let addr = addrs[0]
            .as_str()
            .ok_or_else(|| Error::Address("missing address in deriveaddresses".into()))?
            .parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>()
            .map_err(|e| Error::Address(e.to_string()))?
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
            .map_err(|e| Error::Descriptor(e.to_string()))?;
        if let Some(false) = result[0]["success"].as_bool() {
            return Err(Error::Descriptor(format!(
                "importdescriptors: {}",
                result[0]["error"]
            )));
        }

        Ok(FundingKeys {
            address: addr,
            sk1: sorted_sk1,
            sk2: sorted_sk2,
            pk1: p1,
            pk2: p2,
        })
    }

    /// Mine `blocks` blocks to a fresh 2-of-2 P2WSH funding address.
    ///
    /// Returns the human-readable result string, the `FundingKeys`, and
    /// the `short_channel_id` derived from the first mined block's coinbase.
    ///
    /// # Errors
    ///
    /// Returns an error if address creation or mining RPC calls fail.
    pub fn mine_to_funding(&self, blocks: usize) -> Result<(String, FundingKeys, u64), Error> {
        let funding = self.new_funding_address()?;

        let r = self
            .client
            .generate_to_address(blocks, &funding.address)
            .map_err(|e| Error::Rpc(e.to_string()))?;

        // The first mined block's coinbase (tx_index=0) pays to our address.
        // Derive the SCID from that block.
        let first_hash = r.0[0].clone();
        let block: serde_json::Value = self
            .client
            .call("getblock", &[serde_json::Value::String(first_hash.clone())])
            .map_err(|e| Error::Rpc(e.to_string()))?;
        let block_height = block["height"]
            .as_u64()
            .ok_or_else(|| Error::Rpc("block has no height".into()))?;

        // Coinbase is always tx_index 0. Find the output that pays to our
        // funding address (on regtest with segwit, output 0 is the witness
        // commitment OP_RETURN, so the actual payout may be at index 1+).
        let coinbase_txid = block["tx"][0]
            .as_str()
            .ok_or_else(|| Error::Rpc("block has no coinbase txid".into()))?;
        let coinbase: serde_json::Value = self
            .client
            .call(
                "getrawtransaction",
                &[
                    serde_json::Value::String(coinbase_txid.to_string()),
                    serde_json::json!(true),
                    serde_json::Value::String(first_hash),
                ],
            )
            .map_err(|e| Error::Rpc(e.to_string()))?;
        let vout = coinbase["vout"]
            .as_array()
            .ok_or_else(|| Error::Rpc("coinbase has no vout".into()))?;
        let addr_str = funding.address.to_string();
        let output_index = vout
            .iter()
            .position(|o| o["scriptPubKey"]["address"].as_str() == Some(&addr_str))
            .ok_or_else(|| Error::Rpc("funding output not found in coinbase".into()))?;

        let scid = (block_height << 40) | (output_index as u64);

        let msg = format!("Mined {} block(s) to {}\n", r.0.len(), funding.address);

        Ok((msg, funding, scid))
    }
}
