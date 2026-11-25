use std::sync::atomic::AtomicI64;
use std::sync::{Arc, RwLock};

use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

use crate::auth::sso::{self, AuthRuntime, PanelSso};
use crate::config::Config;
use crate::db::Db;
use crate::monitor::MonitorEvent;
use crate::monitor::maintenance::MaintenanceCache;
use crate::monitor::writer::Writer;
use crate::store;

pub const LOGO_KEY: &str = "logo";
pub const FAVICON_KEY: &str = "favicon";
pub const CSS_KEY: &str = "custom_css";
pub const THEMES: [&str; 3] = ["system", "light", "dark"];

/// Name, images, stylesheet and theme defaults applied to every page.
#[derive(Clone, Debug, PartialEq)]
pub struct Branding {
    pub site_name: String,
    pub logo_version: Option<i64>,
    pub favicon_version: Option<i64>,
    pub css_version: Option<i64>,
    pub default_theme: String,
    pub show_powered_by: bool,
}

impl Default for Branding {
    fn default() -> Self {
        Self {
            site_name: "anpi".into(),
            logo_version: None,
            favicon_version: None,
            css_version: None,
            default_theme: "system".into(),
            show_powered_by: true,
        }
    }
}

impl Branding {
    pub async fn load(db: &Db) -> sqlx::Result<Self> {
        let d = Self::default();
        let site_name = store::settings::get(db, "site_name")
            .await?
            .filter(|s| !s.trim().is_empty());
        let default_theme = store::settings::get(db, "default_theme")
            .await?
            .filter(|t| THEMES.contains(&t.as_str()));
        Ok(Self {
            site_name: site_name.unwrap_or(d.site_name),
            logo_version: store::assets::version(db, LOGO_KEY).await?,
            favicon_version: store::assets::version(db, FAVICON_KEY).await?,
            css_version: store::assets::version(db, CSS_KEY).await?,
            default_theme: default_theme.unwrap_or(d.default_theme),
            show_powered_by: store::settings::get(db, "show_powered_by")
                .await?
                .as_deref()
                != Some("0"),
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
    /// When the last check of any monitor finished; `/healthz` fails when it gets old.
    pub last_check: AtomicI64,
    pub heartbeat: RwLock<Option<crate::selfcheck::PingResult>>,
    /// Cancelled on shutdown so long-lived responses such as live updates end.
    pub shutdown: CancellationToken,
}

impl Ctx {
    pub fn new(db: Db, config: Config) -> Arc<Self> {
        let (events, _) = broadcast::channel(1024);
        Arc::new(Self {
            writer: Writer::spawn(db.clone()),
            db,
            config,
            events,
            maintenance: MaintenanceCache::default(),
            branding: RwLock::default(),
            auth: RwLock::default(),
            last_check: AtomicI64::new(crate::util::now_ms()),
            heartbeat: RwLock::default(),
            shutdown: CancellationToken::new(),
        })
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
