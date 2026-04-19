use chrono::Utc;
use lightning::util::logger::{Logger, Record};

pub struct SimLogger;

impl Logger for SimLogger {
    fn log(&self, record: Record) {
        let now = Utc::now().format("%Y-%m-%d %H:%M:%S%.3f");
        eprintln!("[{}] {:<5} {}", now, record.level, record.args);
    }
}

#[macro_export]
macro_rules! log_info  { ($l:expr, $($a:tt)*) => { { use lightning::util::logger::Logger as _; lightning::log_info!($l, $($a)*) } } }
#[macro_export]
macro_rules! log_error { ($l:expr, $($a:tt)*) => { { use lightning::util::logger::Logger as _; lightning::log_error!($l, $($a)*) } } }
#[macro_export]
macro_rules! log_trace { ($l:expr, $($a:tt)*) => { { use lightning::util::logger::Logger as _; lightning::log_trace!($l, $($a)*) } } }
