pub mod bitcoind;
pub mod conn;
pub mod error;
pub mod keys;
pub mod log;

// Re-export sub-crates for convenience.
pub use bolt;
pub use noise;

/// Unix socket path for daemon-to-CLI communication.
pub const SOCK_PATH: &str = "/tmp/ln-gossip-sim.sock";
