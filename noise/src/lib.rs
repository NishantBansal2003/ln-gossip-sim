//! BOLT 8 `Noise_XK` transport layer.
//!
//! Implements the `Noise_XK` handshake and encrypted transport using
//! secp256k1 ECDH, ChaCha20-Poly1305, and SHA-256.

pub mod cipher;
pub mod connection;
pub mod error;
pub mod handshake;

pub use cipher::{NoiseCipher, RecvCipher, SendCipher};
pub use connection::{ConnectionError, NoiseConnection};
pub use error::NoiseError;
pub use handshake::NoiseHandshake;

#[cfg(test)]
mod tests;
