//! Fixed cryptographic keys for deterministic node identity.

use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};

/// Seed used to derive node keys.
pub const SEED: [u8; 32] = [0x11; 32];

/// Seed used to derive a second, distinct node identity.
///
/// Used by `channel_announcement` flows that need two different node IDs.
pub const SEED_2: [u8; 32] = [0x22; 32];

/// Returns the node's static secret key derived from `SEED`.
///
/// # Panics
///
/// Never panics in practice — `SEED` is a hardcoded valid 32-byte key.
#[must_use]
pub fn node_secret() -> SecretKey {
    SecretKey::from_slice(&SEED).expect("SEED is a valid 32-byte secret key")
}

/// Returns a second, distinct static secret key derived from `SEED_2`.
///
/// # Panics
///
/// Never panics in practice — `SEED_2` is a hardcoded valid 32-byte key.
#[must_use]
pub fn node_secret_2() -> SecretKey {
    SecretKey::from_slice(&SEED_2).expect("SEED_2 is a valid 32-byte secret key")
}

/// Returns the node's public key (node ID).
#[must_use]
pub fn node_id() -> PublicKey {
    let secp = Secp256k1::new();
    PublicKey::from_secret_key(&secp, &node_secret())
}
