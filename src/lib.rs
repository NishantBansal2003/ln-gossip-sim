#[macro_use]
pub mod log;
pub mod bitcoind;
pub mod error;
pub mod gossip;
pub mod keepalive;
pub mod keys;
pub mod noise;
pub mod types;

/// Unix socket path used for daemon <-> CLI communication.
pub const SOCK_PATH: &str = "/tmp/ln-gossip-sim.sock";
