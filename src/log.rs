use lightning::util::logger::{Logger, Record};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct SimLogger;

impl Logger for SimLogger {
    fn log(&self, record: Record) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        eprintln!(
            "[{:.3}] {:<5} {}",
            now.as_secs_f64(),
            record.level,
            record.args
        );
    }
}

#[macro_export]
macro_rules! log_info  { ($l:expr, $($a:tt)*) => { { use lightning::util::logger::Logger as _; lightning::log_info!($l, $($a)*) } } }
#[macro_export]
macro_rules! log_error { ($l:expr, $($a:tt)*) => { { use lightning::util::logger::Logger as _; lightning::log_error!($l, $($a)*) } } }
#[macro_export]
macro_rules! log_trace { ($l:expr, $($a:tt)*) => { { use lightning::util::logger::Logger as _; lightning::log_trace!($l, $($a)*) } } }
