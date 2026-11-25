use std::collections::HashSet;
use std::net::IpAddr;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use http::Method;
use http::header::{AUTHORIZATION, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::OnceCell;

use crate::checks::http::{RequestSpec, send};
use crate::config::OidcConfig;
use crate::util::{constant_time_eq, hmac_sha256, random_token, sha256_b64url};

const PENDING_TTL: Duration = Duration::from_secs(600);

#[derive(Clone, Debug, Deserialize)]
pub struct Discovery {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    #[serde(default)]
    pub end_session_endpoint: Option<String>,
}

/// Sign-in state kept in a signed cookie, so unauthenticated visitors cannot fill server memory.
#[derive(Serialize, Deserialize)]
struct Pending {
    nonce: String,
    verifier: String,
    next: String,
    created: i64,
}

#[derive(Debug)]
pub struct Login {
    pub issuer: String,
    pub subject: String,
    pub username: String,
    pub id_token: String,
    pub next: String,
}

pub struct Oidc {
    cfg: OidcConfig,
    redirect_url: String,
    discovery: OnceCell<Discovery>,
    key: [u8; 32],
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// id_token signatures are not checked, so provider URLs must use TLS; plain HTTP only on loopback.
pub fn check_provider_url(raw: &str) -> Result<(), String> {
    let u = url::Url::parse(raw).map_err(|e| format!("invalid provider URL {raw:?}: {e}"))?;
    let loopback = match u.host() {
        Some(url::Host::Domain(d)) => d == "localhost",
        Some(url::Host::Ipv4(ip)) => IpAddr::V4(ip).is_loopback(),
        Some(url::Host::Ipv6(ip)) => IpAddr::V6(ip).is_loopback(),
        None => false,
    };
    match u.scheme() {
        "https" => Ok(()),
        "http" if loopback => Ok(()),
        _ => Err(format!("provider URL {raw} must use https://")),
    }
}

impl Oidc {
    pub fn new(cfg: OidcConfig, redirect_url: String) -> Self {
        Self {
            cfg,
            redirect_url,
            discovery: OnceCell::new(),
            key: rand::random(),
        }
    }

    fn spec(method: Method, url: &str) -> Result<RequestSpec, String> {
        let mut spec = RequestSpec::new(method, url::Url::parse(url).map_err(|e| e.to_string())?);
        // A redirect would re-send the code, PKCE verifier and client secret to another host.
        spec.max_redirects = 0;
        Ok(spec)
    }

    async fn get_json(url: &str) -> Result<Value, String> {
        let r = send(&Self::spec(Method::GET, url)?)
            .await
            .map_err(|e| e.to_string())?;
        if r.status != 200 {
            return Err(format!("HTTP {} from {url}", r.status));
        }
        serde_json::from_slice(&r.body).map_err(|e| format!("invalid JSON from {url}: {e}"))
    }

    pub fn requires_role(&self) -> bool {
        self.cfg.required_role.is_some()
    }

    pub async fn discovery(&self) -> Result<&Discovery, String> {
        self.discovery
            .get_or_try_init(|| async {
                check_provider_url(&self.cfg.issuer)?;
                let url = format!("{}/.well-known/openid-configuration", self.cfg.issuer);
                let d: Discovery = serde_json::from_value(Self::get_json(&url).await?)
                    .map_err(|e| format!("discovery document: {e}"))?;
                if d.issuer.trim_end_matches('/') != self.cfg.issuer {
                    return Err(format!(
                        "issuer mismatch: configured {}, provider says {}",
                        self.cfg.issuer, d.issuer
                    ));
                }
                check_provider_url(&d.authorization_endpoint)?;
                check_provider_url(&d.token_endpoint)?;
                Ok(d)
            })
            .await
    }

    fn seal(&self, state: &str, pending: &Pending) -> String {
        let body = URL_SAFE_NO_PAD.encode(serde_json::to_vec(pending).unwrap_or_default());
        let signed = format!("{state}.{body}");
        let mac = URL_SAFE_NO_PAD.encode(hmac_sha256(&self.key, signed.as_bytes()));
        format!("{signed}.{mac}")
    }

    fn open(&self, cookie: &str, state: &str) -> Option<Pending> {
        let (signed, mac) = cookie.rsplit_once('.')?;
        let expected = URL_SAFE_NO_PAD.encode(hmac_sha256(&self.key, signed.as_bytes()));
        if !constant_time_eq(mac.as_bytes(), expected.as_bytes()) {
            return None;
        }
        let (cookie_state, body) = signed.split_once('.')?;
        if !constant_time_eq(cookie_state.as_bytes(), state.as_bytes()) {
            return None;
        }
        let p: Pending = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(body).ok()?).ok()?;
        let age = unix_now() - p.created;
        (0..PENDING_TTL.as_secs() as i64)
            .contains(&age)
            .then_some(p)
    }

    /// Returns the provider URL to redirect to and the signed value to store in the browser.
    pub async fn begin(&self, next: &str) -> Result<(String, String), String> {
        let d = self.discovery().await?;
        let state = random_token(24);
        let pending = Pending {
            nonce: random_token(24),
            verifier: random_token(48),
            next: next.to_string(),
            created: unix_now(),
        };
        let mut url = url::Url::parse(&d.authorization_endpoint).map_err(|e| e.to_string())?;
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.cfg.client_id)
            .append_pair("redirect_uri", &self.redirect_url)
            .append_pair("scope", &self.cfg.scopes)
            .append_pair("state", &state)
            .append_pair("nonce", &pending.nonce)
            .append_pair("code_challenge", &sha256_b64url(&pending.verifier))
            .append_pair("code_challenge_method", "S256");
        Ok((url.to_string(), self.seal(&state, &pending)))
    }

    /// `cookie` is the value `begin` returned; it is only accepted together with its own `state`.
    pub async fn complete(&self, code: &str, state: &str, cookie: &str) -> Result<Login, String> {
        let pending = self
            .open(cookie, state)
            .ok_or("login session expired, please try again")?;
        let d = self.discovery().await?;

        let form = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "authorization_code")
            .append_pair("code", code)
            .append_pair("redirect_uri", &self.redirect_url)
            .append_pair("client_id", &self.cfg.client_id)
            .append_pair("code_verifier", &pending.verifier)
            .finish();
        let mut spec = Self::spec(Method::POST, &d.token_endpoint)?
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(form);
        if let Some(secret) = &self.cfg.client_secret {
            let creds = format!(
                "{}:{}",
                urlencoding::encode(&self.cfg.client_id),
                urlencoding::encode(secret)
            );
            spec = spec.header(AUTHORIZATION, &format!("Basic {}", STANDARD.encode(creds)));
        }
        let resp = send(&spec)
            .await
            .map_err(|e| format!("token request failed: {e}"))?;
        let tokens: Value = serde_json::from_slice(&resp.body)
            .map_err(|_| format!("token endpoint returned HTTP {}", resp.status))?;
        if resp.status != 200 {
            let err = tokens
                .get("error_description")
                .or(tokens.get("error"))
                .and_then(Value::as_str)
                .unwrap_or("unknown error");
            return Err(format!("token endpoint: {err}"));
        }
        let id_token = tokens
            .get("id_token")
            .and_then(Value::as_str)
            .ok_or("no id_token in token response")?;
        // Tokens come straight from the token endpoint over TLS, which OIDC Core 3.1.3.7 accepts in place of signature checks.
        let claims = decode_jwt_payload(id_token)?;
        validate_id_token(
            &claims,
            &d.issuer,
            &self.cfg.client_id,
            &pending.nonce,
            unix_now(),
        )?;

        if let Some(role) = &self.cfg.required_role {
            let access = tokens
                .get("access_token")
                .and_then(Value::as_str)
                .and_then(|t| decode_jwt_payload(t).ok());
            let sources: Vec<&Value> = std::iter::once(&claims).chain(access.as_ref()).collect();
            if !collect_roles(&sources, &self.cfg.client_id).contains(role) {
                return Err(format!("your account lacks the required role \"{role}\""));
            }
        }

        let subject = claims
            .get("sub")
            .and_then(Value::as_str)
            .ok_or("id_token has no sub")?
            .to_string();
        let username = ["preferred_username", "email", "name"]
            .iter()
            .find_map(|k| {
                claims
                    .get(*k)
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
            })
            .unwrap_or(&subject)
            .to_string();
        Ok(Login {
            issuer: d.issuer.clone(),
            subject,
            username,
            id_token: id_token.to_string(),
            next: pending.next,
        })
    }

    pub async fn logout_url(
        &self,
        id_token: Option<&str>,
        post_logout_redirect: &str,
    ) -> Option<String> {
        let endpoint = self.discovery().await.ok()?.end_session_endpoint.clone()?;
        let mut url = url::Url::parse(&endpoint).ok()?;
        {
            let mut q = url.query_pairs_mut();
            q.append_pair("client_id", &self.cfg.client_id)
                .append_pair("post_logout_redirect_uri", post_logout_redirect);
            if let Some(t) = id_token {
                q.append_pair("id_token_hint", t);
            }
        }
        Some(url.to_string())
    }
}

pub fn decode_jwt_payload(token: &str) -> Result<Value, String> {
    let payload = token.split('.').nth(1).ok_or("malformed JWT")?;
    let bytes = URL_SAFE_NO_PAD
        .decode(payload.trim_end_matches('='))
        .map_err(|_| "malformed JWT payload")?;
    serde_json::from_slice(&bytes).map_err(|_| "malformed JWT claims".to_string())
}

pub fn validate_id_token(
    claims: &Value,
    issuer: &str,
    client_id: &str,
    nonce: &str,
    now: i64,
) -> Result<(), String> {
    let iss = claims
        .get("iss")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if iss.trim_end_matches('/') != issuer.trim_end_matches('/') {
        return Err(format!("id_token issuer {iss:?} does not match {issuer:?}"));
    }
    let aud_ok = match claims.get("aud") {
        Some(Value::String(a)) => a == client_id,
        Some(Value::Array(a)) => a.iter().any(|v| v.as_str() == Some(client_id)),
        _ => false,
    };
    if !aud_ok {
        return Err("id_token audience does not include this client".into());
    }
    if let Some(Value::Array(a)) = claims.get("aud")
        && a.len() > 1
        && claims.get("azp").and_then(Value::as_str) != Some(client_id)
    {
        return Err("id_token azp does not match this client".into());
    }
    let exp = claims
        .get("exp")
        .and_then(Value::as_i64)
        .ok_or("id_token has no exp")?;
    if exp + 60 < now {
        return Err("id_token has expired".into());
    }
    if claims.get("nonce").and_then(Value::as_str) != Some(nonce) {
        return Err("id_token nonce mismatch".into());
    }
    Ok(())
}

/// Keycloak puts roles in `realm_access.roles` and `resource_access.<client>.roles`; groups may be mapped too.
pub fn collect_roles(sources: &[&Value], client_id: &str) -> HashSet<String> {
    let mut roles = HashSet::new();
    let mut add = |v: Option<&Value>| {
        for r in v
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            roles.insert(r.trim_start_matches('/').to_string());
        }
    };
    for c in sources {
        add(c.pointer("/realm_access/roles"));
        add(c
            .get("resource_access")
            .and_then(|r| r.get(client_id))
            .and_then(|r| r.get("roles")));
        add(c.get("groups"));
        add(c.get("roles"));
    }
    roles
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn claims() -> Value {
        json!({ "iss": "https://kc/realms/r", "aud": "anpi", "exp": 1000, "nonce": "n1", "sub": "u1" })
    }

    #[test]
    fn valid_id_token_passes() {
        assert!(validate_id_token(&claims(), "https://kc/realms/r/", "anpi", "n1", 900).is_ok());
    }

    #[test]
    fn each_claim_is_enforced() {
        let check = |patch: Value, now: i64| {
            let mut c = claims();
            for (k, v) in patch.as_object().unwrap() {
                c[k] = v.clone();
            }
            validate_id_token(&c, "https://kc/realms/r", "anpi", "n1", now)
        };
        assert!(
            check(json!({"iss": "https://evil"}), 900)
                .unwrap_err()
                .contains("issuer")
        );
        assert!(
            check(json!({"aud": "other"}), 900)
                .unwrap_err()
                .contains("audience")
        );
        assert!(
            check(json!({"aud": ["other", "anpi"]}), 900)
                .unwrap_err()
                .contains("azp")
        );
        assert!(check(json!({"aud": ["other", "anpi"], "azp": "anpi"}), 900).is_ok());
        assert!(
            check(json!({"nonce": "replayed"}), 900)
                .unwrap_err()
                .contains("nonce")
        );
        assert!(check(json!({}), 1061).unwrap_err().contains("expired"));
        assert!(
            check(json!({}), 1059).is_ok(),
            "60s clock skew is tolerated"
        );
    }

    #[test]
    fn roles_are_collected_from_keycloak_claims() {
        let id = json!({ "groups": ["/ops"] });
        let access = json!({
            "realm_access": { "roles": ["offline_access", "monitoring"] },
            "resource_access": { "anpi": { "roles": ["admin"] }, "other": { "roles": ["ignored"] } }
        });
        let roles = collect_roles(&[&id, &access], "anpi");
        assert!(roles.contains("monitoring") && roles.contains("admin") && roles.contains("ops"));
        assert!(
            !roles.contains("ignored"),
            "roles of other clients must not count"
        );
    }

    #[tokio::test]
    async fn sign_in_state_is_signed_and_bound_to_the_state() {
        let cfg = OidcConfig {
            issuer: "https://kc".into(),
            client_id: "anpi".into(),
            client_secret: None,
            scopes: "openid".into(),
            required_role: None,
        };
        let oidc = Oidc::new(cfg, "https://s/auth/oidc/callback".into());
        let d = Discovery {
            issuer: "https://kc".into(),
            authorization_endpoint: "https://kc/auth".into(),
            token_endpoint: "https://kc/token".into(),
            end_session_endpoint: None,
        };
        oidc.discovery.set(d).unwrap();
        let (_, cookie) = oidc.begin("/admin").await.unwrap();
        let state = cookie.split('.').next().unwrap();
        assert_eq!(oidc.open(&cookie, state).unwrap().next, "/admin");
        assert!(oidc.open(&cookie, "other-state").is_none());
        let forged = cookie.replacen('.', ".x", 1);
        assert!(
            oidc.open(&forged, state).is_none(),
            "tampering breaks the MAC"
        );
        let other = Oidc::new(oidc.cfg.clone(), oidc.redirect_url.clone());
        assert!(
            other.open(&cookie, state).is_none(),
            "keys are per instance"
        );
    }

    #[test]
    fn provider_urls_must_use_tls_outside_loopback() {
        assert!(check_provider_url("https://kc/realms/r").is_ok());
        assert!(check_provider_url("http://127.0.0.1:8080/realms/r").is_ok());
        assert!(check_provider_url("http://localhost/realms/r").is_ok());
        assert!(check_provider_url("http://kc.example.com/realms/r").is_err());
        assert!(check_provider_url("ftp://kc/realms/r").is_err());
    }

    #[test]
    fn jwt_payload_decoding() {
        let payload = URL_SAFE_NO_PAD.encode(br#"{"sub":"x"}"#);
        assert_eq!(
            decode_jwt_payload(&format!("h.{payload}.s")).unwrap()["sub"],
            "x"
        );
        assert!(decode_jwt_payload("garbage").is_err());
    }
}
