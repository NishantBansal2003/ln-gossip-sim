//! Crate-wide error types.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("RPC: {0}")]
    Rpc(String),

    #[error("address: {0}")]
    Address(String),

    #[error("descriptor: {0}")]
    Descriptor(String),

    #[error("chain: {0}")]
    Chain(String),
}
