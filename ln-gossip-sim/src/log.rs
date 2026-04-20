/// Initialize the logger. Call once at startup.
/// Set `RUST_LOG` env var to control level (default: `info`).
pub fn init() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_millis()
        .init();
}
