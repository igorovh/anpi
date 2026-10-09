use std::sync::Arc;

use super::oidc::Oidc;
use crate::config::{Config, OidcConfig};
use crate::db::Db;
use crate::store::settings;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SsoSource {
    Off,
    Panel,
    Env,
}

/// SSO settings edited in the panel; environment variables override them.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct PanelSso {
    pub enabled: bool,
    pub base_url: String,
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    pub required_role: String,
    pub scopes: String,
}

impl PanelSso {
    pub async fn load(db: &Db) -> sqlx::Result<Self> {
        let get = |k: &'static str| async move { settings::get(db, k).await.map(Option::unwrap_or_default) };
        Ok(Self {
            enabled: get("oidc_enabled").await? == "1",
            base_url: get("base_url").await?,
            issuer: get("oidc_issuer").await?,
            client_id: get("oidc_client_id").await?,
            client_secret: get("oidc_client_secret").await?,
            required_role: get("oidc_required_role").await?,
            scopes: get("oidc_scopes").await?,
        })
    }

    pub async fn save(&self, db: &Db) -> sqlx::Result<()> {
        settings::set(db, "oidc_enabled", if self.enabled { "1" } else { "0" }).await?;
        settings::set(db, "base_url", &self.base_url).await?;
        settings::set(db, "oidc_issuer", &self.issuer).await?;
        settings::set(db, "oidc_client_id", &self.client_id).await?;
        settings::set(db, "oidc_client_secret", &self.client_secret).await?;
        settings::set(db, "oidc_required_role", &self.required_role).await?;
        settings::set(db, "oidc_scopes", &self.scopes).await
    }

    pub fn oidc_config(&self) -> Option<OidcConfig> {
        let opt = |s: &str| Some(s.trim().to_string()).filter(|s| !s.is_empty());
        Some(OidcConfig {
            issuer: opt(&self.issuer)?.trim_end_matches('/').to_string(),
            client_id: opt(&self.client_id)?,
            client_secret: opt(&self.client_secret),
            scopes: opt(&self.scopes).unwrap_or_else(|| "openid profile email".into()),
            required_role: opt(&self.required_role),
        })
    }
}

/// Emergency switch for the CLI: turns panel-configured SSO off so passwords work again.
pub async fn disable(db: &Db) -> sqlx::Result<()> {
    settings::set(db, "oidc_enabled", "0").await
}

pub fn normalize_base_url(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    let u = url::Url::parse(trimmed).map_err(|_| "Public URL must be a full address like https://status.example.com".to_string())?;
    if !matches!(u.scheme(), "http" | "https") || u.host_str().is_none() {
        return Err("Public URL must start with http:// or https://".into());
    }
    Ok(trimmed.to_string())
}

#[derive(Clone)]
pub struct AuthRuntime {
    pub oidc: Option<Arc<Oidc>>,
    pub base_url: Option<String>,
    pub source: SsoSource,
}

impl Default for AuthRuntime {
    fn default() -> Self {
        Self { oidc: None, base_url: None, source: SsoSource::Off }
    }
}

/// Environment variables win; panel settings apply only when enabled and complete.
pub fn resolve(config: &Config, panel: &PanelSso) -> AuthRuntime {
    let panel_base = Some(panel.base_url.clone()).filter(|b| !b.is_empty());
    let base_url = config.base_url.clone().or(panel_base);
    let (oidc_cfg, source) = match (&config.oidc, panel.enabled) {
        (Some(env), _) => (Some(env.clone()), SsoSource::Env),
        (None, true) => match panel.oidc_config() {
            Some(cfg) => (Some(cfg), SsoSource::Panel),
            None => (None, SsoSource::Off),
        },
        (None, false) => (None, SsoSource::Off),
    };
    let oidc = match (oidc_cfg, &base_url) {
        (Some(cfg), Some(base)) => Some(Arc::new(Oidc::new(cfg, format!("{base}/auth/oidc/callback")))),
        _ => None,
    };
    let source = if oidc.is_some() { source } else { SsoSource::Off };
    AuthRuntime { oidc, base_url, source }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn config(pairs: &[(&str, &str)]) -> Config {
        Config::from_map(&pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect::<HashMap<_, _>>()).unwrap()
    }

    fn panel(enabled: bool) -> PanelSso {
        PanelSso {
            enabled,
            base_url: "https://status.example.com".into(),
            issuer: "https://kc/realms/r/".into(),
            client_id: "anpi".into(),
            ..Default::default()
        }
    }

    #[test]
    fn panel_settings_apply_only_when_enabled() {
        assert_eq!(resolve(&config(&[]), &panel(false)).source, SsoSource::Off);
        let on = resolve(&config(&[]), &panel(true));
        assert_eq!(on.source, SsoSource::Panel);
        assert_eq!(on.base_url.as_deref(), Some("https://status.example.com"));
    }

    #[test]
    fn environment_overrides_the_panel() {
        let env = config(&[("ANPI_OIDC_ISSUER", "https://env/realms/x"), ("ANPI_OIDC_CLIENT_ID", "envc"), ("ANPI_BASE_URL", "https://env.example")]);
        let r = resolve(&env, &panel(false));
        assert_eq!(r.source, SsoSource::Env, "env enables SSO even if the panel switch is off");
        assert_eq!(r.base_url.as_deref(), Some("https://env.example"));
    }

    #[test]
    fn incomplete_settings_never_lock_people_out() {
        let mut p = panel(true);
        p.client_id.clear();
        assert_eq!(resolve(&config(&[]), &p).source, SsoSource::Off);
        let mut p = panel(true);
        p.base_url.clear();
        assert_eq!(resolve(&config(&[]), &p).source, SsoSource::Off, "a redirect URL is required");
    }

    #[test]
    fn base_url_is_normalized() {
        assert_eq!(normalize_base_url(" https://s.example.com/ ").unwrap(), "https://s.example.com");
        assert_eq!(normalize_base_url("").unwrap(), "");
        assert!(normalize_base_url("status.example.com").is_err());
    }
}
