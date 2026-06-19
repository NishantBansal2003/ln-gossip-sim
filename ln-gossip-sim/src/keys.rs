//! Deterministic per-node cryptographic keys.
//!
//! Each node is identified by a small integer "node index". All of a node's
//! keys are derived deterministically from that index, so a given index always
//! maps to the same node identity across runs, and distinct indices map to
//! distinct identities. This lets several `simd` instances act as different
//! Lightning nodes without any randomness or stored key material.

use bitcoin::hashes::{Hash, sha256};
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};

/// Domain-separation tag mixed into every derived key so these secrets can't
/// collide with hashes produced elsewhere.
const KEY_DOMAIN: &[u8] = b"ln-gossip-sim-node";

/// Derives a deterministic secret key for `(index, slot)`.
///
/// `slot` distinguishes the several keys a single node may need: slot 0 is the
/// node's primary identity, slot 1 a secondary identity used by the two-party
/// `channel_announcement` flows.
///
/// # Panics
///
/// Never panics in practice: a SHA-256 digest is a valid secp256k1 secret key
/// except with negligible probability (digest zero or >= curve order).
fn derive(index: u32, slot: u8) -> SecretKey {
    let mut data = Vec::with_capacity(KEY_DOMAIN.len() + 5);
    data.extend_from_slice(KEY_DOMAIN);
    data.extend_from_slice(&index.to_be_bytes());
    data.push(slot);
    let hash = sha256::Hash::hash(&data);
    SecretKey::from_slice(&hash.to_byte_array())
        .expect("sha256 digest is a valid secp256k1 secret key")
}

/// Returns the primary node secret key for `index`.
#[must_use]
pub fn node_secret(index: u32) -> SecretKey {
    derive(index, 0)
}

/// Returns a second, distinct secret key for `index`.
///
/// Used by `channel_announcement` flows that need two different node IDs owned
/// by the same daemon.
#[must_use]
pub fn node_secret_2(index: u32) -> SecretKey {
    derive(index, 1)
}

/// Returns the public key (node ID) for `index`.
#[must_use]
pub fn node_id(index: u32) -> PublicKey {
    let secp = Secp256k1::new();
    PublicKey::from_secret_key(&secp, &node_secret(index))
}
