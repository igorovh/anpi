pub mod maintenance;
pub mod scheduler;
pub mod ssl;
pub mod state;
pub mod writer;

use serde::Serialize;

use crate::models::Status;
use crate::util::{format_ms, format_ts};

/// Live update pushed to dashboards over SSE.
#[derive(Clone, Debug, Serialize)]
pub struct MonitorEvent {
    pub monitor_id: i64,
    #[serde(skip)]
    pub public: bool,
    pub status: Status,
    pub latency: String,
    pub message: String,
    pub ts: i64,
    pub time: String,
}

impl MonitorEvent {
    pub fn new(monitor_id: i64, public: bool, status: Status, latency_ms: Option<f64>, message: &str, ts: i64) -> Self {
        Self {
            monitor_id,
            public,
            status,
            latency: format_ms(latency_ms),
            message: message.to_string(),
            ts,
            time: format_ts(ts),
        }
    }

    /// Public pages must not leak error details such as internal IPs.
    pub fn redacted(&self) -> Self {
        Self { message: String::new(), ..self.clone() }
    }
}
