//! The panel as a browser sees it: setup, sign-in, CSRF, public visibility and headers.

mod common;

use axum::http::StatusCode;
use common::{Client, app, config, signed_in};

#[tokio::test]
async fn first_run_requires_the_setup_code_from_the_log() {
    let app = app(config(&[])).await;
    let mut c = Client::new(anpi::web::router(app.state.clone()));

    let r = c.get("/admin").await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert_eq!(r.location(), "/login?next=%2Fadmin");
    assert_eq!(c.get("/login").await.location(), "/setup", "no accounts yet");

    let wrong = c
        .post("/setup", &[("setup_code", "guess"), ("username", "eve"), ("password", "a-long-password"), ("password2", "a-long-password")])
        .await;
    assert_eq!(wrong.status, StatusCode::BAD_REQUEST);
    assert!(wrong.body.contains("Wrong setup code"));

    let mut c = signed_in(&app).await;
    let dash = c.get("/admin").await;
    assert_eq!(dash.status, StatusCode::OK);
    assert!(dash.body.contains("No monitors yet"));

    let mut other = Client::new(anpi::web::router(app.state.clone()));
    assert_eq!(other.get("/setup").await.location(), "/login", "setup closes after the first account");
}

#[tokio::test]
async fn sign_in_is_rate_limited_per_ip() {
    let app = app(config(&[])).await;
    signed_in(&app).await;
    let mut c = Client::new(anpi::web::router(app.state.clone()));

    let bad = c.post("/login", &[("username", "admin"), ("password", "nope")]).await;
    assert_eq!(bad.status, StatusCode::UNAUTHORIZED);
    assert!(bad.body.contains("Invalid username or password"));
    let unknown = c.post("/login", &[("username", "ghost"), ("password", "nope")]).await;
    assert!(unknown.body.contains("Invalid username or password"), "same message for unknown users");

    for _ in 0..8 {
        c.post("/login", &[("username", "admin"), ("password", "nope")]).await;
    }
    let blocked = c.post("/login", &[("username", "admin"), ("password", "a-long-password")]).await;
    assert_eq!(blocked.status, StatusCode::TOO_MANY_REQUESTS, "even the right password waits out the lockout");

    app.state.limiter.reset("0.0.0.0".parse().unwrap());
    let ok = c.post("/login", &[("username", "admin"), ("password", "a-long-password"), ("next", "/admin/settings")]).await;
    assert_eq!(ok.status, StatusCode::SEE_OTHER);
    assert_eq!(ok.location(), "/admin/settings");
    let evil = c.post("/login", &[("username", "admin"), ("password", "a-long-password"), ("next", "//evil.example")]).await;
    assert_eq!(evil.location(), "/admin", "open redirects are refused");
}

#[tokio::test]
async fn state_changing_requests_need_csrf_token_and_same_origin() {
    let app = app(config(&[])).await;
    let mut c = signed_in(&app).await;
    let form = [("name", "x"), ("kind", "http"), ("url", "https://example.com"), ("interval_s", "60"), ("retry_interval_s", "30"),
        ("timeout_s", "10"), ("failure_threshold", "3"), ("expected_status", "200-299"), ("ssl_warn_days", "14")];

    let r = c.post("/admin/monitors", &form).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "missing token");

    let csrf = c.csrf().await;
    let mut with_token = form.to_vec();
    with_token.push(("csrf", &csrf));
    let cross = c.post_with("/admin/monitors", &with_token, Some("https://evil.example")).await;
    assert_eq!(cross.status, StatusCode::FORBIDDEN, "foreign Origin");

    let ok = c.post_with("/admin/monitors", &with_token, Some("http://localhost")).await;
    assert_eq!(ok.status, StatusCode::SEE_OTHER, "{}", ok.body);
    assert_eq!(anpi::store::monitors::list(&app.ctx.db).await.unwrap().len(), 1);
}

#[tokio::test]
async fn monitor_lifecycle_through_the_panel() {
    let app = app(config(&[])).await;
    let mut c = signed_in(&app).await;
    let csrf = c.csrf().await;
    let base = |name: &'static str, public: bool| {
        let mut f = vec![("csrf", csrf.clone()), ("name", name.to_string()), ("kind", "http".into()), ("url", "https://example.com/health".into()),
            ("ip_family", "v6".into()), ("interval_s", "60".into()), ("retry_interval_s", "20".into()), ("timeout_s", "10".into()),
            ("failure_threshold", "3".into()), ("expected_status", "200-299".into()), ("ssl_warn_days", "14".into()),
            ("method", "GET".into()), ("content_kind", "none".into()), ("active", "on".into())];
        if public {
            f.push(("public", "on".into()));
        }
        f
    };
    let as_refs = |f: &Vec<(&'static str, String)>| f.iter().map(|(k, v)| (*k, v.clone())).collect::<Vec<_>>();

    let invalid: Vec<(&str, String)> = as_refs(&base("Broken", false)).into_iter().map(|(k, v)| if k == "url" { (k, "not a url".into()) } else { (k, v) }).collect();
    let r = c.post("/admin/monitors", &invalid.iter().map(|(k, v)| (*k, v.as_str())).collect::<Vec<_>>()).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert!(r.body.contains("URL must be a full address") && r.body.contains("Broken"), "form keeps input and explains");

    for (name, public) in [("Public API", true), ("Internal DB", false)] {
        let f = as_refs(&base(name, public));
        let r = c.post("/admin/monitors", &f.iter().map(|(k, v)| (*k, v.as_str())).collect::<Vec<_>>()).await;
        assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
    }
    let monitors = anpi::store::monitors::list(&app.ctx.db).await.unwrap();
    let public = monitors.iter().find(|m| m.name == "Public API").unwrap();
    assert_eq!(public.ip_family, "v6");
    assert!(app.scheduler.is_running(public.id).await, "saving starts the check loop");

    let detail = c.get(&format!("/admin/monitors/{}", public.id)).await;
    assert!(detail.status.is_success() && detail.body.contains("Response time"));

    let mut anon = Client::new(anpi::web::router(app.state.clone()));
    let page = anon.get("/").await;
    assert!(page.body.contains("Public API") && !page.body.contains("Internal DB"), "private monitors stay private");
    let json = anon.get("/api/status.json").await;
    assert!(json.body.contains("Public API") && !json.body.contains("Internal DB"));

    let r = c.post(&format!("/admin/monitors/{}/toggle", public.id), &[("csrf", &csrf)]).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert!(!app.scheduler.is_running(public.id).await, "pausing stops checks");

    c.post(&format!("/admin/monitors/{}/delete", public.id), &[("csrf", &csrf)]).await;
    assert!(anpi::store::monitors::get(&app.ctx.db, public.id).await.unwrap().is_none());
    app.scheduler.shutdown().await;
}

#[tokio::test]
async fn sign_out_invalidates_the_session_server_side() {
    let app = app(config(&[])).await;
    let mut c = signed_in(&app).await;
    let stolen = c.cookies.clone();
    let csrf = c.csrf().await;
    assert_eq!(c.post("/logout", &[("csrf", &csrf)]).await.status, StatusCode::SEE_OTHER);

    let mut thief = Client::new(anpi::web::router(app.state.clone()));
    thief.cookies = stolen;
    assert_eq!(thief.get("/admin").await.status, StatusCode::SEE_OTHER, "old cookie no longer works");
}

#[tokio::test]
async fn password_change_signs_out_other_sessions() {
    let app = app(config(&[])).await;
    let mut a = signed_in(&app).await;
    let mut b = Client::new(anpi::web::router(app.state.clone()));
    b.post("/login", &[("username", "admin"), ("password", "a-long-password")]).await;
    assert_eq!(b.get("/admin").await.status, StatusCode::OK);

    let csrf = a.csrf().await;
    let r = a
        .post("/admin/account/password", &[("csrf", &csrf), ("current", "a-long-password"), ("new_password", "another-long-one"), ("confirm", "another-long-one")])
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
    assert_eq!(a.get("/admin").await.status, StatusCode::OK, "the device that changed it stays signed in");
    assert_eq!(b.get("/admin").await.status, StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn responses_carry_security_headers_and_assets_are_embedded() {
    let app = app(config(&[])).await;
    let mut c = Client::new(anpi::web::router(app.state.clone()));
    let r = c.get("/").await;
    let csp = r.headers.get("content-security-policy").unwrap().to_str().unwrap();
    assert!(csp.contains("script-src 'self'") && csp.contains("frame-ancestors 'none'"));
    assert_eq!(r.headers.get("x-frame-options").unwrap(), "DENY");
    assert!(!r.body.contains("style=\""), "inline styles would be blocked by the CSP");

    let css = c.get("/static/app.css").await;
    assert_eq!(css.status, StatusCode::OK);
    assert!(css.headers.get("content-type").unwrap().to_str().unwrap().starts_with("text/css"));
    assert!(css.body.contains("Zen Kaku Gothic New"));
    assert_eq!(c.get("/static/fonts/zkg-300-latin.woff2").await.status, StatusCode::OK);
    assert_eq!(c.get("/static/../Cargo.toml").await.status, StatusCode::NOT_FOUND);
    assert_eq!(c.get("/healthz").await.body, "ok");
}

#[tokio::test]
async fn kuma_import_through_the_panel_starts_monitors() {
    let app = app(config(&[])).await;
    let mut c = signed_in(&app).await;
    let csrf = c.csrf().await;
    let json = r#"{"monitorList":[{"name":"Imported","type":"http","url":"http://127.0.0.1:9/","interval":60,"active":true}],"notificationList":[]}"#;
    let r = c.post("/admin/import", &[("csrf", &csrf), ("json", json)]).await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(r.body.contains("Imported 1 monitor"), "{}", r.body);
    let m = &anpi::store::monitors::list(&app.ctx.db).await.unwrap()[0];
    assert!(app.scheduler.is_running(m.id).await);

    let bad = c.post("/admin/import", &[("csrf", &csrf), ("json", "{}")]).await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);
    app.scheduler.shutdown().await;
}
