use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context, bail};

#[derive(Clone, Debug)]
pub struct OidcConfig {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub scopes: String,
    pub required_role: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub bind: SocketAddr,
    pub database_path: PathBuf,
    pub base_url: Option<String>,
    pub trust_proxy: bool,
    /// Header holding the visitor's address, set by a proxy such as Cloudflare (`CF-Connecting-IP`).
    pub client_ip_header: Option<http::HeaderName>,
    /// Certificate and key files; anpi serves HTTPS itself when both are set.
    pub tls: Option<(PathBuf, PathBuf)>,
    pub max_concurrent_checks: usize,
    pub oidc: Option<OidcConfig>,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        Self::from_map(&std::env::vars().collect())
    }

    pub fn from_map(env: &HashMap<String, String>) -> anyhow::Result<Self> {
        let get = |k: &str| env.get(k).map(|v| v.trim().to_string()).filter(|v| !v.is_empty());

        let bind = get("ANPI_BIND")
            .unwrap_or_else(|| "0.0.0.0:3000".into())
            .parse()
            .context("ANPI_BIND must be an address like 0.0.0.0:3000")?;

        let database_path = match get("ANPI_DATABASE") {
            Some(p) => PathBuf::from(p),
            None => PathBuf::from(get("ANPI_DATA_DIR").unwrap_or_else(|| "./data".into())).join("anpi.db"),
        };

        let base_url = get("ANPI_BASE_URL").map(|u| u.trim_end_matches('/').to_string());
        if let Some(u) = &base_url {
            url::Url::parse(u).context("ANPI_BASE_URL must be a full URL, e.g. https://status.example.com")?;
        }

        let trust_proxy = get("ANPI_TRUST_PROXY").is_some_and(|v| parse_bool(&v));
        let client_ip_header = get("ANPI_CLIENT_IP_HEADER")
            .map(|h| http::HeaderName::try_from(h.as_str()).with_context(|| format!("ANPI_CLIENT_IP_HEADER {h:?} is not a valid header name")))
            .transpose()?;
        let tls = match (get("ANPI_TLS_CERT"), get("ANPI_TLS_KEY")) {
            (Some(cert), Some(key)) => Some((PathBuf::from(cert), PathBuf::from(key))),
            (None, None) => None,
            _ => bail!("set both ANPI_TLS_CERT and ANPI_TLS_KEY to serve HTTPS"),
        };
        let max_concurrent_checks = match get("ANPI_MAX_CONCURRENT_CHECKS") {
            Some(v) => v.parse().context("ANPI_MAX_CONCURRENT_CHECKS must be a number")?,
            None => 64,
        };

        let oidc = match get("ANPI_OIDC_ISSUER") {
            None => None,
            Some(issuer) => {
                let Some(client_id) = get("ANPI_OIDC_CLIENT_ID") else {
                    bail!("ANPI_OIDC_CLIENT_ID is required when ANPI_OIDC_ISSUER is set");
                };
                if base_url.is_none() {
                    bail!("ANPI_BASE_URL is required when OIDC is enabled (used for the redirect URL)");
                }
                Some(OidcConfig {
                    issuer: issuer.trim_end_matches('/').to_string(),
                    client_id,
                    client_secret: get("ANPI_OIDC_CLIENT_SECRET"),
                    scopes: get("ANPI_OIDC_SCOPES").unwrap_or_else(|| "openid profile email".into()),
                    required_role: get("ANPI_OIDC_REQUIRED_ROLE"),
                })
            }
        };

        Ok(Self { bind, database_path, base_url, trust_proxy, client_ip_header, tls, max_concurrent_checks, oidc })
    }

    pub fn secure_cookies(&self) -> bool {
        self.base_url.as_deref().is_some_and(|u| u.starts_with("https://"))
    }

    pub fn sso_only(&self) -> bool {
        self.oidc.is_some()
    }

    pub fn oidc_redirect_url(&self) -> Option<String> {
        self.base_url.as_ref().map(|b| format!("{b}/auth/oidc/callback"))
    }
}

pub fn parse_bool(v: &str) -> bool {
    matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn defaults_without_env() {
        let c = Config::from_map(&env(&[])).unwrap();
        assert_eq!(c.bind.to_string(), "0.0.0.0:3000");
        assert!(c.database_path.ends_with("anpi.db"));
        assert!(c.oidc.is_none());
        assert!(!c.secure_cookies());
        assert!(!c.sso_only());
    }

    #[test]
    fn oidc_requires_client_id_and_base_url() {
        let err = Config::from_map(&env(&[("ANPI_OIDC_ISSUER", "https://kc/realms/x")])).unwrap_err();
        assert!(err.to_string().contains("CLIENT_ID"));

        let err = Config::from_map(&env(&[
            ("ANPI_OIDC_ISSUER", "https://kc/realms/x"),
            ("ANPI_OIDC_CLIENT_ID", "anpi"),
        ]))
        .unwrap_err();
        assert!(err.to_string().contains("ANPI_BASE_URL"));
    }

    #[test]
    fn oidc_enables_sso_only_mode() {
        let c = Config::from_map(&env(&[
            ("ANPI_OIDC_ISSUER", "https://kc/realms/x/"),
            ("ANPI_OIDC_CLIENT_ID", "anpi"),
            ("ANPI_BASE_URL", "https://status.example.com/"),
        ]))
        .unwrap();
        assert!(c.sso_only());
        assert!(c.secure_cookies());
        assert_eq!(c.oidc.as_ref().unwrap().issuer, "https://kc/realms/x");
        assert_eq!(c.oidc_redirect_url().unwrap(), "https://status.example.com/auth/oidc/callback");
    }

    #[test]
    fn tls_needs_both_files_and_header_names_are_checked() {
        let c = Config::from_map(&env(&[("ANPI_TLS_CERT", "/c.pem"), ("ANPI_TLS_KEY", "/k.pem"), ("ANPI_CLIENT_IP_HEADER", "CF-Connecting-IP")])).unwrap();
        assert_eq!(c.tls, Some((PathBuf::from("/c.pem"), PathBuf::from("/k.pem"))));
        assert_eq!(c.client_ip_header.unwrap().as_str(), "cf-connecting-ip");
        assert!(Config::from_map(&env(&[("ANPI_TLS_CERT", "/c.pem")])).unwrap_err().to_string().contains("both"));
        assert!(Config::from_map(&env(&[("ANPI_CLIENT_IP_HEADER", "bad header")])).is_err());
    }

    #[test]
    fn invalid_bind_is_rejected() {
        assert!(Config::from_map(&env(&[("ANPI_BIND", "nope")])).is_err());
    }
}
