use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use http::Method;
use http::header::{AUTHORIZATION, CONTENT_TYPE};
use serde::Deserialize;
use serde_json::Value;
use tokio::sync::OnceCell;

use crate::checks::http::{RequestSpec, send};
use crate::config::OidcConfig;
use crate::util::{random_token, sha256_b64url};

const PENDING_TTL: Duration = Duration::from_secs(600);
const MAX_PENDING: usize = 10_000;

#[derive(Debug)]
pub enum BeginError {
    /// Too many sign-ins are in progress; refuse rather than grow without bound.
    Busy,
    Provider(String),
}

#[derive(Clone, Debug, Deserialize)]
pub struct Discovery {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    #[serde(default)]
    pub end_session_endpoint: Option<String>,
}

struct Pending {
    nonce: String,
    verifier: String,
    next: String,
    created: Instant,
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
    pending: Mutex<HashMap<String, Pending>>,
}

impl Oidc {
    pub fn new(cfg: OidcConfig, redirect_url: String) -> Self {
        Self { cfg, redirect_url, discovery: OnceCell::new(), pending: Mutex::new(HashMap::new()) }
    }

    async fn get_json(url: &str) -> Result<Value, String> {
        let spec = RequestSpec::new(Method::GET, url::Url::parse(url).map_err(|e| e.to_string())?);
        let r = send(&spec).await.map_err(|e| e.to_string())?;
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
                let url = format!("{}/.well-known/openid-configuration", self.cfg.issuer);
                let d: Discovery = serde_json::from_value(Self::get_json(&url).await?).map_err(|e| format!("discovery document: {e}"))?;
                if d.issuer.trim_end_matches('/') != self.cfg.issuer {
                    return Err(format!("issuer mismatch: configured {}, provider says {}", self.cfg.issuer, d.issuer));
                }
                Ok(d)
            })
            .await
    }

    /// Returns the provider URL to redirect to and the state value to bind to the browser.
    pub async fn begin(&self, next: &str) -> Result<(String, String), BeginError> {
        {
            let mut pending = self.pending.lock().expect("oidc lock");
            pending.retain(|_, p| p.created.elapsed() < PENDING_TTL);
            if pending.len() >= MAX_PENDING {
                return Err(BeginError::Busy);
            }
        }
        let d = self.discovery().await.map_err(BeginError::Provider)?;
        let state = random_token(24);
        let nonce = random_token(24);
        let verifier = random_token(48);
        let mut url = url::Url::parse(&d.authorization_endpoint).map_err(|e| BeginError::Provider(e.to_string()))?;
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.cfg.client_id)
            .append_pair("redirect_uri", &self.redirect_url)
            .append_pair("scope", &self.cfg.scopes)
            .append_pair("state", &state)
            .append_pair("nonce", &nonce)
            .append_pair("code_challenge", &sha256_b64url(&verifier))
            .append_pair("code_challenge_method", "S256");
        let mut pending = self.pending.lock().expect("oidc lock");
        pending.insert(state.clone(), Pending { nonce, verifier, next: next.to_string(), created: Instant::now() });
        Ok((url.to_string(), state))
    }

    pub async fn complete(&self, code: &str, state: &str) -> Result<Login, String> {
        let pending = self
            .pending
            .lock()
            .expect("oidc lock")
            .remove(state)
            .filter(|p| p.created.elapsed() < PENDING_TTL)
            .ok_or("login session expired, please try again")?;
        let d = self.discovery().await?;

        let form = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "authorization_code")
            .append_pair("code", code)
            .append_pair("redirect_uri", &self.redirect_url)
            .append_pair("client_id", &self.cfg.client_id)
            .append_pair("code_verifier", &pending.verifier)
            .finish();
        let mut spec = RequestSpec::new(Method::POST, url::Url::parse(&d.token_endpoint).map_err(|e| e.to_string())?)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(form);
        if let Some(secret) = &self.cfg.client_secret {
            let creds = format!("{}:{}", urlencoding::encode(&self.cfg.client_id), urlencoding::encode(secret));
            spec = spec.header(AUTHORIZATION, &format!("Basic {}", STANDARD.encode(creds)));
        }
        let resp = send(&spec).await.map_err(|e| format!("token request failed: {e}"))?;
        let tokens: Value = serde_json::from_slice(&resp.body).map_err(|_| format!("token endpoint returned HTTP {}", resp.status))?;
        if resp.status != 200 {
            let err = tokens.get("error_description").or(tokens.get("error")).and_then(Value::as_str).unwrap_or("unknown error");
            return Err(format!("token endpoint: {err}"));
        }
        let id_token = tokens.get("id_token").and_then(Value::as_str).ok_or("no id_token in token response")?;
        // Tokens come straight from the token endpoint over TLS, which OIDC Core 3.1.3.7 accepts in place of signature checks.
        let claims = decode_jwt_payload(id_token)?;
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
        validate_id_token(&claims, &d.issuer, &self.cfg.client_id, &pending.nonce, now)?;

        if let Some(role) = &self.cfg.required_role {
            let access = tokens.get("access_token").and_then(Value::as_str).and_then(|t| decode_jwt_payload(t).ok());
            let sources: Vec<&Value> = std::iter::once(&claims).chain(access.as_ref()).collect();
            if !collect_roles(&sources, &self.cfg.client_id).contains(role) {
                return Err(format!("your account lacks the required role \"{role}\""));
            }
        }

        let subject = claims.get("sub").and_then(Value::as_str).ok_or("id_token has no sub")?.to_string();
        let username = ["preferred_username", "email", "name"]
            .iter()
            .find_map(|k| claims.get(*k).and_then(Value::as_str).filter(|s| !s.is_empty()))
            .unwrap_or(&subject)
            .to_string();
        Ok(Login { issuer: d.issuer.clone(), subject, username, id_token: id_token.to_string(), next: pending.next })
    }

    pub async fn logout_url(&self, id_token: Option<&str>, post_logout_redirect: &str) -> Option<String> {
        let endpoint = self.discovery().await.ok()?.end_session_endpoint.clone()?;
        let mut url = url::Url::parse(&endpoint).ok()?;
        {
            let mut q = url.query_pairs_mut();
            q.append_pair("client_id", &self.cfg.client_id).append_pair("post_logout_redirect_uri", post_logout_redirect);
            if let Some(t) = id_token {
                q.append_pair("id_token_hint", t);
            }
        }
        Some(url.to_string())
    }
}

pub fn decode_jwt_payload(token: &str) -> Result<Value, String> {
    let payload = token.split('.').nth(1).ok_or("malformed JWT")?;
    let bytes = URL_SAFE_NO_PAD.decode(payload.trim_end_matches('=')).map_err(|_| "malformed JWT payload")?;
    serde_json::from_slice(&bytes).map_err(|_| "malformed JWT claims".to_string())
}

pub fn validate_id_token(claims: &Value, issuer: &str, client_id: &str, nonce: &str, now: i64) -> Result<(), String> {
    let iss = claims.get("iss").and_then(Value::as_str).unwrap_or_default();
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
    let exp = claims.get("exp").and_then(Value::as_i64).ok_or("id_token has no exp")?;
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
        for r in v.and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str) {
            roles.insert(r.trim_start_matches('/').to_string());
        }
    };
    for c in sources {
        add(c.pointer("/realm_access/roles"));
        add(c.get("resource_access").and_then(|r| r.get(client_id)).and_then(|r| r.get("roles")));
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
        assert!(check(json!({"iss": "https://evil"}), 900).unwrap_err().contains("issuer"));
        assert!(check(json!({"aud": "other"}), 900).unwrap_err().contains("audience"));
        assert!(check(json!({"aud": ["other", "anpi"]}), 900).unwrap_err().contains("azp"));
        assert!(check(json!({"aud": ["other", "anpi"], "azp": "anpi"}), 900).is_ok());
        assert!(check(json!({"nonce": "replayed"}), 900).unwrap_err().contains("nonce"));
        assert!(check(json!({}), 1061).unwrap_err().contains("expired"));
        assert!(check(json!({}), 1059).is_ok(), "60s clock skew is tolerated");
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
        assert!(!roles.contains("ignored"), "roles of other clients must not count");
    }

    #[tokio::test]
    async fn pending_sign_ins_are_capped() {
        let cfg = OidcConfig { issuer: "https://kc".into(), client_id: "anpi".into(), client_secret: None, scopes: "openid".into(), required_role: None };
        let oidc = Oidc::new(cfg, "https://s/auth/oidc/callback".into());
        let d = Discovery { issuer: "https://kc".into(), authorization_endpoint: "https://kc/auth".into(), token_endpoint: "https://kc/token".into(), end_session_endpoint: None };
        oidc.discovery.set(d).unwrap();
        for _ in 0..MAX_PENDING {
            assert!(oidc.begin("/admin").await.is_ok());
        }
        assert!(matches!(oidc.begin("/admin").await, Err(BeginError::Busy)), "unauthenticated requests cannot grow the map further");
        assert_eq!(oidc.pending.lock().unwrap().len(), MAX_PENDING);
    }

    #[test]
    fn jwt_payload_decoding() {
        let payload = URL_SAFE_NO_PAD.encode(br#"{"sub":"x"}"#);
        assert_eq!(decode_jwt_payload(&format!("h.{payload}.s")).unwrap()["sub"], "x");
        assert!(decode_jwt_payload("garbage").is_err());
    }
}
