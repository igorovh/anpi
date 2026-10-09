use std::sync::{Arc, RwLock};

use tokio::sync::broadcast;

use crate::auth::sso::{self, AuthRuntime, PanelSso};
use crate::config::Config;
use crate::db::Db;
use crate::monitor::MonitorEvent;
use crate::monitor::maintenance::MaintenanceCache;
use crate::monitor::writer::Writer;
use crate::store;

pub const LOGO_KEY: &str = "logo";

/// Name and logo shown in the header, footer and page titles.
#[derive(Clone, Debug, PartialEq)]
pub struct Branding {
    pub site_name: String,
    pub logo_version: Option<i64>,
}

impl Default for Branding {
    fn default() -> Self {
        Self { site_name: "anpi".into(), logo_version: None }
    }
}

impl Branding {
    pub async fn load(db: &Db) -> sqlx::Result<Self> {
        let site_name = store::settings::get(db, "site_name").await?.filter(|s| !s.trim().is_empty());
        Ok(Self {
            site_name: site_name.unwrap_or_else(|| Self::default().site_name),
            logo_version: store::assets::version(db, LOGO_KEY).await?,
        })
    }
}

/// Shared state for the scheduler, background jobs and the web layer.
pub struct Ctx {
    pub db: Db,
    pub config: Config,
    pub writer: Writer,
    pub events: broadcast::Sender<Arc<MonitorEvent>>,
    pub maintenance: MaintenanceCache,
    pub branding: RwLock<Branding>,
    pub auth: RwLock<AuthRuntime>,
}

impl Ctx {
    pub fn new(db: Db, config: Config) -> Arc<Self> {
        let (events, _) = broadcast::channel(1024);
        Arc::new(Self { writer: Writer::spawn(db.clone()), db, config, events, maintenance: MaintenanceCache::default(), branding: RwLock::default(), auth: RwLock::default() })
    }
}

impl Ctx {
    pub fn branding(&self) -> Branding {
        self.branding.read().expect("branding lock").clone()
    }

    pub fn auth(&self) -> AuthRuntime {
        self.auth.read().expect("auth lock").clone()
    }

    /// Re-reads SSO settings; a new provider client also drops cached discovery data.
    pub async fn reload_auth(&self) -> sqlx::Result<()> {
        let panel = PanelSso::load(&self.db).await?;
        *self.auth.write().expect("auth lock") = sso::resolve(&self.config, &panel);
        Ok(())
    }

    pub fn base_url(&self) -> Option<String> {
        self.auth().base_url
    }

    pub fn secure_cookies(&self) -> bool {
        self.base_url().is_some_and(|u| u.starts_with("https://"))
    }

    pub async fn reload_branding(&self) -> sqlx::Result<()> {
        let b = Branding::load(&self.db).await?;
        *self.branding.write().expect("branding lock") = b;
        Ok(())
    }
}
