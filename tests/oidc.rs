//! Keycloak-style SSO against a mock provider that enforces PKCE and client authentication.

mod common;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use common::{Client, app, config, serve};
use serde_json::{Value, json};

#[derive(Default)]
struct Idp {
    issuer: String,
    nonce: String,
    challenge: String,
    roles: Vec<String>,
    nonce_override: Option<String>,
}

type Shared = Arc<Mutex<Idp>>;

fn jwt(claims: Value) -> String {
    format!("{}.{}.sig", URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256"}"#), URL_SAFE_NO_PAD.encode(claims.to_string()))
}

async fn token(State(idp): State<Shared>, headers: HeaderMap, Form(f): Form<HashMap<String, String>>) -> (StatusCode, Json<Value>) {
    let idp = idp.lock().unwrap();
    let auth = headers.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or_default();
    let pkce_ok = f.get("code_verifier").is_some_and(|v| anpi::util::sha256_b64url(v) == idp.challenge);
    if auth != format!("Basic {}", STANDARD.encode("anpi:s3cret")) || f.get("code").map(String::as_str) != Some("good-code") || !pkce_ok {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": "invalid_grant", "error_description": "bad code, verifier or client" })));
    }
    let now = anpi::util::now_ms() / 1000;
    let id_token = jwt(json!({
        "iss": idp.issuer, "aud": "anpi", "exp": now + 300, "sub": "kc-user-1",
        "nonce": idp.nonce_override.clone().unwrap_or(idp.nonce.clone()), "preferred_username": "igor",
    }));
    let access_token = jwt(json!({ "realm_access": { "roles": idp.roles } }));
    (StatusCode::OK, Json(json!({ "id_token": id_token, "access_token": access_token, "token_type": "Bearer" })))
}

async fn start_idp() -> (String, Shared) {
    let idp: Shared = Arc::default();
    let router = Router::new()
        .route(
            "/realms/test/.well-known/openid-configuration",
            get(|State(idp): State<Shared>| async move {
                let iss = idp.lock().unwrap().issuer.clone();
                Json(json!({
                    "issuer": iss,
                    "authorization_endpoint": format!("{iss}/auth"),
                    "token_endpoint": format!("{iss}/token"),
                    "end_session_endpoint": format!("{iss}/logout"),
                }))
            }),
        )
        .route("/realms/test/token", post(token))
        .with_state(idp.clone());
    let addr = serve(router).await;
    let issuer = format!("http://{addr}/realms/test");
    idp.lock().unwrap().issuer = issuer.clone();
    (issuer, idp)
}

async fn sso_app(issuer: &str, role: Option<&str>) -> anpi::App {
    let mut pairs = vec![
        ("ANPI_OIDC_ISSUER", issuer),
        ("ANPI_OIDC_CLIENT_ID", "anpi"),
        ("ANPI_OIDC_CLIENT_SECRET", "s3cret"),
        ("ANPI_BASE_URL", "http://localhost"),
    ];
    if let Some(r) = role {
        pairs.push(("ANPI_OIDC_REQUIRED_ROLE", r));
    }
    app(config(&pairs)).await
}

/// Starts a login and returns the query of the provider redirect, like a browser following it.
async fn begin(c: &mut Client, idp: &Shared, next: &str) -> HashMap<String, String> {
    let r = c.get(&format!("/auth/oidc/login?next={}", urlencoding::encode(next))).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    let url = url::Url::parse(&r.location()).unwrap();
    assert!(url.path().ends_with("/auth"));
    let q: HashMap<String, String> = url.query_pairs().into_owned().collect();
    let mut i = idp.lock().unwrap();
    i.nonce = q["nonce"].clone();
    i.challenge = q["code_challenge"].clone();
    q
}

#[tokio::test]
async fn full_sign_in_and_sign_out() {
    let (issuer, idp) = start_idp().await;
    let app = sso_app(&issuer, None).await;
    let mut c = Client::new(anpi::web::router(app.state.clone()));

    let q = begin(&mut c, &idp, "/admin/settings").await;
    assert_eq!(q["redirect_uri"], "http://localhost/auth/oidc/callback");
    assert_eq!(q["code_challenge_method"], "S256");
    assert_eq!(q["response_type"], "code");

    let r = c.get(&format!("/auth/oidc/callback?code=good-code&state={}", q["state"])).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
    assert_eq!(r.location(), "/admin/settings");
    let page = c.get("/admin").await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(page.body.contains("igor"));

    // A second login maps to the same account instead of creating a duplicate.
    let q = begin(&mut c, &idp, "/admin").await;
    c.get(&format!("/auth/oidc/callback?code=good-code&state={}", q["state"])).await;
    assert_eq!(anpi::store::users::count(&app.ctx.db).await.unwrap(), 1);

    let csrf = c.csrf().await;
    let out = c.post("/logout", &[("csrf", &csrf)]).await;
    assert!(out.location().starts_with(&format!("{issuer}/logout?")), "{}", out.location());
    assert!(out.location().contains("id_token_hint="));
    assert_eq!(c.get("/admin").await.status, StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn callback_must_come_from_the_browser_that_started_it() {
    let (issuer, idp) = start_idp().await;
    let app = sso_app(&issuer, None).await;
    let mut victim = Client::new(anpi::web::router(app.state.clone()));
    let mut attacker = Client::new(anpi::web::router(app.state.clone()));

    let q = begin(&mut attacker, &idp, "/admin").await;
    let r = victim.get(&format!("/auth/oidc/callback?code=good-code&state={}", q["state"])).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert!(!victim.cookies.contains_key(anpi::web::SESSION_COOKIE));
}

#[tokio::test]
async fn replayed_nonce_and_missing_role_are_rejected() {
    let (issuer, idp) = start_idp().await;
    let app = sso_app(&issuer, Some("monitoring")).await;
    let mut c = Client::new(anpi::web::router(app.state.clone()));

    idp.lock().unwrap().roles = vec!["monitoring".into()];
    idp.lock().unwrap().nonce_override = Some("stale".into());
    let q = begin(&mut c, &idp, "/admin").await;
    let r = c.get(&format!("/auth/oidc/callback?code=good-code&state={}", q["state"])).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert!(r.body.contains("nonce"), "{}", r.body);

    idp.lock().unwrap().nonce_override = None;
    idp.lock().unwrap().roles = vec!["offline_access".into()];
    let q = begin(&mut c, &idp, "/admin").await;
    let r = c.get(&format!("/auth/oidc/callback?code=good-code&state={}", q["state"])).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert!(r.body.contains("required role"), "{}", r.body);

    let q = begin(&mut c, &idp, "/admin").await;
    let r = c.get(&format!("/auth/oidc/callback?code=bad-code&state={}", q["state"])).await;
    assert!(r.body.contains("bad code"), "provider errors are surfaced: {}", r.body);
    assert_eq!(anpi::store::users::count(&app.ctx.db).await.unwrap(), 0);

    idp.lock().unwrap().roles = vec!["monitoring".into()];
    let q = begin(&mut c, &idp, "/admin").await;
    let r = c.get(&format!("/auth/oidc/callback?code=good-code&state={}", q["state"])).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);

    let reused = c.get(&format!("/auth/oidc/callback?code=good-code&state={}", q["state"])).await;
    assert_eq!(reused.status, StatusCode::UNAUTHORIZED, "a state can only be used once");
}

#[tokio::test]
async fn sso_mode_disables_local_accounts() {
    let (issuer, _) = start_idp().await;
    let app = sso_app(&issuer, None).await;
    assert!(app.state.setup_code.lock().unwrap().is_none(), "no setup code in SSO mode");
    let mut c = Client::new(anpi::web::router(app.state.clone()));

    let login = c.get("/login").await;
    assert!(login.body.contains("Continue with SSO") && !login.body.contains("type=\"password\""));
    assert_eq!(c.post("/login", &[("username", "a"), ("password", "b")]).await.status, StatusCode::NOT_FOUND);
    assert_eq!(c.get("/setup").await.location(), "/login");
}
