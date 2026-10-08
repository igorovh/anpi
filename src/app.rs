use std::sync::Arc;

use tokio::sync::broadcast;

use crate::config::Config;
use crate::db::Db;
use crate::monitor::MonitorEvent;
use crate::monitor::maintenance::MaintenanceCache;
use crate::monitor::writer::Writer;

/// Shared state for the scheduler, background jobs and the web layer.
pub struct Ctx {
    pub db: Db,
    pub config: Config,
    pub writer: Writer,
    pub events: broadcast::Sender<Arc<MonitorEvent>>,
    pub maintenance: MaintenanceCache,
}

impl Ctx {
    pub fn new(db: Db, config: Config) -> Arc<Self> {
        let (events, _) = broadcast::channel(1024);
        Arc::new(Self { writer: Writer::spawn(db.clone()), db, config, events, maintenance: MaintenanceCache::default() })
    }
}
