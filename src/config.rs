use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
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
    /// Peers whose forwarding headers are believed; private networks by default, any peer with a client IP header.
    pub trusted_proxies: Vec<Cidr>,
    /// Certificate and key files; anpi serves HTTPS itself when both are set.
    pub tls: Option<(PathBuf, PathBuf)>,
    /// URL pinged every minute while anpi is healthy; overrides the panel setting.
    pub heartbeat_url: Option<String>,
    pub max_concurrent_checks: usize,
    pub oidc: Option<OidcConfig>,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        Self::from_map(&std::env::vars().collect())
    }

    pub fn from_map(env: &HashMap<String, String>) -> anyhow::Result<Self> {
        let get = |k: &str| {
            env.get(k)
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        };

        let bind = get("ANPI_BIND")
            .unwrap_or_else(|| "0.0.0.0:3000".into())
            .parse()
            .context("ANPI_BIND must be an address like 0.0.0.0:3000")?;

        let database_path = match get("ANPI_DATABASE") {
            Some(p) => PathBuf::from(p),
            None => PathBuf::from(get("ANPI_DATA_DIR").unwrap_or_else(|| "./data".into()))
                .join("anpi.db"),
        };

        let base_url = get("ANPI_BASE_URL").map(|u| u.trim_end_matches('/').to_string());
        if let Some(u) = &base_url {
            url::Url::parse(u)
                .context("ANPI_BASE_URL must be a full URL, e.g. https://status.example.com")?;
        }

        let trust_proxy = get("ANPI_TRUST_PROXY").is_some_and(|v| parse_bool(&v));
        let client_ip_header = get("ANPI_CLIENT_IP_HEADER")
            .map(|h| {
                http::HeaderName::try_from(h.as_str()).with_context(|| {
                    format!("ANPI_CLIENT_IP_HEADER {h:?} is not a valid header name")
                })
            })
            .transpose()?;
        let trusted_proxies = match get("ANPI_TRUSTED_PROXIES") {
            Some(v) => v
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|s| {
                    Cidr::parse(s).with_context(|| {
                        format!("ANPI_TRUSTED_PROXIES entry {s:?} is not an address or CIDR range")
                    })
                })
                .collect::<anyhow::Result<_>>()?,
            // CF-Connecting-IP setups often face the internet directly and rely on a firewall instead.
            None if client_ip_header.is_some() => vec![Cidr::any()],
            None => Cidr::private_defaults(),
        };
        let heartbeat_url = get("ANPI_HEARTBEAT_URL");
        if let Some(u) = &heartbeat_url {
            url::Url::parse(u).context("ANPI_HEARTBEAT_URL must be a full URL")?;
        }
        let tls = match (get("ANPI_TLS_CERT"), get("ANPI_TLS_KEY")) {
            (Some(cert), Some(key)) => Some((PathBuf::from(cert), PathBuf::from(key))),
            (None, None) => None,
            _ => bail!("set both ANPI_TLS_CERT and ANPI_TLS_KEY to serve HTTPS"),
        };
        let max_concurrent_checks = match get("ANPI_MAX_CONCURRENT_CHECKS") {
            Some(v) => v
                .parse()
                .context("ANPI_MAX_CONCURRENT_CHECKS must be a number")?,
            None => 64,
        };

        let oidc = match get("ANPI_OIDC_ISSUER") {
            None => None,
            Some(issuer) => {
                let Some(client_id) = get("ANPI_OIDC_CLIENT_ID") else {
                    bail!("ANPI_OIDC_CLIENT_ID is required when ANPI_OIDC_ISSUER is set");
                };
                if base_url.is_none() {
                    bail!(
                        "ANPI_BASE_URL is required when OIDC is enabled (used for the redirect URL)"
                    );
                }
                Some(OidcConfig {
                    issuer: issuer.trim_end_matches('/').to_string(),
                    client_id,
                    client_secret: get("ANPI_OIDC_CLIENT_SECRET"),
                    scopes: get("ANPI_OIDC_SCOPES")
                        .unwrap_or_else(|| "openid profile email".into()),
                    required_role: get("ANPI_OIDC_REQUIRED_ROLE"),
                })
            }
        };

        Ok(Self {
            bind,
            database_path,
            base_url,
            trust_proxy,
            client_ip_header,
            trusted_proxies,
            tls,
            heartbeat_url,
            max_concurrent_checks,
            oidc,
        })
    }

    pub fn secure_cookies(&self) -> bool {
        self.base_url
            .as_deref()
            .is_some_and(|u| u.starts_with("https://"))
    }

    pub fn is_trusted_proxy(&self, peer: IpAddr) -> bool {
        self.trusted_proxies.iter().any(|c| c.contains(peer))
    }

    pub fn trusts_any_peer(&self) -> bool {
        self.trusted_proxies.iter().any(|c| c.prefix == 0)
    }

    pub fn sso_only(&self) -> bool {
        self.oidc.is_some()
    }

    pub fn oidc_redirect_url(&self) -> Option<String> {
        self.base_url
            .as_ref()
            .map(|b| format!("{b}/auth/oidc/callback"))
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Cidr {
    net: IpAddr,
    prefix: u8,
}

impl Cidr {
    /// Accepts `*` (any peer), a single address or `address/prefix`.
    pub fn parse(s: &str) -> Option<Self> {
        if s == "*" {
            return Some(Self::any());
        }
        let (addr, prefix) = match s.split_once('/') {
            Some((a, p)) => (a.parse::<IpAddr>().ok()?, Some(p.parse::<u8>().ok()?)),
            None => (s.parse::<IpAddr>().ok()?, None),
        };
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = prefix.unwrap_or(max);
        (prefix <= max).then_some(Self { net: addr, prefix })
    }

    fn any() -> Self {
        Self {
            net: IpAddr::from([0u8; 16]),
            prefix: 0,
        }
    }

    pub fn private_defaults() -> Vec<Self> {
        [
            "127.0.0.0/8",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "100.64.0.0/10",
            "169.254.0.0/16",
            "::1/128",
            "fc00::/7",
            "fe80::/10",
        ]
        .iter()
        .filter_map(|s| Self::parse(s))
        .collect()
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        if self.prefix == 0 {
            return true;
        }
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
            v4 => v4,
        };
        match (self.net, ip) {
            (IpAddr::V4(n), IpAddr::V4(a)) => {
                let mask = u32::MAX << (32 - u32::from(self.prefix));
                u32::from(n) & mask == u32::from(a) & mask
            }
            (IpAddr::V6(n), IpAddr::V6(a)) => {
                let mask = u128::MAX << (128 - u32::from(self.prefix));
                u128::from(n) & mask == u128::from(a) & mask
            }
            _ => false,
        }
    }
}

pub fn parse_bool(v: &str) -> bool {
    matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
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
        let err =
            Config::from_map(&env(&[("ANPI_OIDC_ISSUER", "https://kc/realms/x")])).unwrap_err();
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
        assert_eq!(
            c.oidc_redirect_url().unwrap(),
            "https://status.example.com/auth/oidc/callback"
        );
    }

    #[test]
    fn tls_needs_both_files_and_header_names_are_checked() {
        let c = Config::from_map(&env(&[
            ("ANPI_TLS_CERT", "/c.pem"),
            ("ANPI_TLS_KEY", "/k.pem"),
            ("ANPI_CLIENT_IP_HEADER", "CF-Connecting-IP"),
        ]))
        .unwrap();
        assert_eq!(
            c.tls,
            Some((PathBuf::from("/c.pem"), PathBuf::from("/k.pem")))
        );
        assert_eq!(c.client_ip_header.unwrap().as_str(), "cf-connecting-ip");
        assert!(
            Config::from_map(&env(&[("ANPI_TLS_CERT", "/c.pem")]))
                .unwrap_err()
                .to_string()
                .contains("both")
        );
        assert!(Config::from_map(&env(&[("ANPI_CLIENT_IP_HEADER", "bad header")])).is_err());
    }

    #[test]
    fn trusted_proxies_default_to_private_networks() {
        let c = Config::from_map(&env(&[])).unwrap();
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "172.20.0.5",
            "192.168.1.1",
            "::1",
            "fd00::5",
            "::ffff:10.0.0.1",
        ] {
            assert!(c.is_trusted_proxy(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["203.0.113.5", "172.32.0.1", "2001:db8::1", "0.0.0.0"] {
            assert!(!c.is_trusted_proxy(ip.parse().unwrap()), "{ip}");
        }
        let c = Config::from_map(&env(&[(
            "ANPI_TRUSTED_PROXIES",
            "173.245.48.0/20, 2400:cb00::/32",
        )]))
        .unwrap();
        assert!(c.is_trusted_proxy("173.245.50.1".parse().unwrap()));
        assert!(c.is_trusted_proxy("2400:cb00:1::1".parse().unwrap()));
        assert!(
            !c.is_trusted_proxy("127.0.0.1".parse().unwrap()),
            "the list replaces the defaults"
        );
        let any = Config::from_map(&env(&[("ANPI_TRUSTED_PROXIES", "*")])).unwrap();
        assert!(any.is_trusted_proxy("203.0.113.5".parse().unwrap()));
        let cf = Config::from_map(&env(&[("ANPI_CLIENT_IP_HEADER", "CF-Connecting-IP")])).unwrap();
        assert!(
            cf.trusts_any_peer(),
            "the header keeps working behind a firewall"
        );
        assert!(Config::from_map(&env(&[("ANPI_TRUSTED_PROXIES", "10.0.0.0/33")])).is_err());
        assert!(Config::from_map(&env(&[("ANPI_TRUSTED_PROXIES", "nope")])).is_err());
    }

    #[test]
    fn invalid_bind_is_rejected() {
        assert!(Config::from_map(&env(&[("ANPI_BIND", "nope")])).is_err());
    }
}
