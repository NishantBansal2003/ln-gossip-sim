//! Fixed cryptographic keys for deterministic node identity.

/// Seed passed to `KeysManager`; the node secret key is derived from this via HKDF.
pub const SEED: [u8; 32] = [0x11; 32];

/// Entropy for `PeerManager` to derive per-connection ephemeral Noise keys.
pub const EPHEMERAL: [u8; 32] = [0x12; 32];
