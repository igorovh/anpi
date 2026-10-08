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
    assert!(css.body.contains("IBM Plex Sans JP"));
    assert_eq!(c.get("/static/fonts/plex-400-latin.woff2").await.status, StatusCode::OK);
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

#[tokio::test]
async fn groups_and_public_names_shape_the_status_page() {
    let app = app(config(&[])).await;
    let mut c = signed_in(&app).await;
    let csrf = c.csrf().await;
    for name in ["Website", "API"] {
        assert_eq!(c.post("/admin/groups", &[("csrf", &csrf), ("name", name)]).await.status, StatusCode::SEE_OTHER);
    }
    let groups = anpi::store::groups::list(&app.ctx.db).await.unwrap();
    let (web, api) = (groups[0].id, groups[1].id);
    assert_eq!(groups[0].name, "Website", "new groups are appended in order");

    let db = &app.ctx.db;
    let mk = |name: &str, group: Option<i64>, public_name: &str| anpi::models::MonitorInput {
        public: true,
        active: false,
        group_id: group,
        public_name: public_name.into(),
        ..anpi::models::MonitorInput::http(name, "https://example.com")
    };
    anpi::store::monitors::create(db, &mk("api-prod-eu-1", Some(api), "Public API")).await.unwrap();
    anpi::store::monitors::create(db, &mk("landing", Some(web), "")).await.unwrap();
    anpi::store::monitors::create(db, &mk("loose", None, "")).await.unwrap();

    // Moving API above Website through the panel reorders the page.
    let r = c.post(&format!("/admin/groups/{api}"), &[("csrf", &csrf), ("name", "Public API group"), ("sort_order", "1")]).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);

    let page = Client::new(anpi::web::router(app.state.clone())).get("/").await.body;
    assert!(!page.contains("api-prod-eu-1"), "internal names stay private");
    let pos = |s: &str| page.find(s).unwrap_or_else(|| panic!("{s} missing"));
    assert!(pos("Public API group") < pos("Website") && pos("Website") < pos("Other"), "groups follow sort order, ungrouped last");
    assert!(pos("Public API") < pos("landing") && pos("landing") < pos("loose"));

    let json = Client::new(anpi::web::router(app.state.clone())).get("/api/status.json").await.body;
    assert!(json.contains(r#""group":"Public API group""#), "{json}");

    c.post(&format!("/admin/groups/{web}/delete"), &[("csrf", &csrf)]).await;
    let landing = anpi::store::monitors::list(db).await.unwrap().into_iter().find(|m| m.name == "landing").unwrap();
    assert_eq!(landing.group_id, None, "deleting a group keeps its monitors");
}

#[tokio::test]
async fn site_name_and_logo_can_be_changed_safely() {
    let app = app(config(&[])).await;
    let mut c = signed_in(&app).await;
    let csrf = c.csrf().await;

    c.post("/admin/branding", &[("csrf", &csrf), ("site_name", "igorovh status")]).await;
    let page = Client::new(anpi::web::router(app.state.clone())).get("/").await.body;
    assert!(page.contains("<title>Service status · igorovh status</title>"));
    assert!(page.contains("powered by"), "footer credit stays");

    let fake = c.post_multipart("/admin/branding/logo", &[("csrf", &csrf)], ("logo", "logo.png", b"<html><script>alert(1)</script>")).await;
    assert_eq!(fake.status, StatusCode::BAD_REQUEST, "type comes from the bytes, not the file name");
    let no_csrf = c.post_multipart("/admin/branding/logo", &[], ("logo", "l.svg", b"<svg xmlns='http://www.w3.org/2000/svg'/>")).await;
    assert_eq!(no_csrf.status, StatusCode::FORBIDDEN);
    let big = vec![0x89u8; 600 * 1024];
    assert_ne!(c.post_multipart("/admin/branding/logo", &[("csrf", &csrf)], ("logo", "big.png", &big)).await.status, StatusCode::SEE_OTHER);

    let svg = b"<svg xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script><circle r='4'/></svg>";
    let ok = c.post_multipart("/admin/branding/logo", &[("csrf", &csrf)], ("logo", "logo.svg", svg)).await;
    assert_eq!(ok.status, StatusCode::SEE_OTHER, "{}", ok.body);

    let mut anon = Client::new(anpi::web::router(app.state.clone()));
    let page = anon.get("/").await.body;
    let src_start = page.find("/brand/logo?v=").expect("logo in header");
    let src: String = page[src_start..].chars().take_while(|c| *c != '"').collect();
    let logo = anon.get(&src).await;
    assert_eq!(logo.headers.get("content-type").unwrap(), "image/svg+xml");
    assert!(logo.headers.get("content-security-policy").unwrap().to_str().unwrap().contains("sandbox"), "scripts in SVG cannot run");

    c.post("/admin/branding/logo/delete", &[("csrf", &csrf)]).await;
    assert_eq!(anon.get("/brand/logo").await.status, StatusCode::NOT_FOUND);
    assert!(anon.get("/").await.body.contains("&gt;^&lt;"), "falls back to the bird");
}

#[tokio::test]
async fn stale_session_cookie_is_not_treated_as_signed_in() {
    let app = app(config(&[])).await;
    let mut c = Client::new(anpi::web::router(app.state.clone()));
    c.cookies.insert(anpi::web::SESSION_COOKIE.into(), "expired-or-forged".into());
    let page = c.get("/").await.body;
    assert!(page.contains(">sign in<") && !page.contains(">dashboard<"));
}

#[tokio::test]
async fn sub_monitors_roll_up_into_their_parent() {
    use anpi::models::{MonitorInput, NewHeartbeat, Status, Timings};
    let app = app(config(&[])).await;
    let mut c = signed_in(&app).await;
    let csrf = c.csrf().await;
    let db = &app.ctx.db;

    let r = c.post("/admin/monitors", &[("csrf", &csrf), ("name", "API"), ("kind", "aggregate"), ("public", "on"), ("active", "on")]).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
    let api = anpi::store::monitors::list(db).await.unwrap()[0].id;
    assert!(!app.scheduler.is_running(api).await, "aggregates run no checks");

    let child = |name: &str| MonitorInput { public: true, active: true, parent_id: Some(api), ..MonitorInput::http(name, "https://example.com") };
    let badges = anpi::store::monitors::create(db, &child("Badges")).await.unwrap();
    let emotes = anpi::store::monitors::create(db, &child("Emotes")).await.unwrap();
    let beat = |id, status| NewHeartbeat {
        monitor_id: id, ts: anpi::util::now_ms(), status, status_code: None, timings: Timings::default(),
        remote_ip: None, message: String::new(), cert_expires_at: None,
    };
    anpi::store::heartbeats::insert_batch(db, &[beat(badges, Status::Up), beat(emotes, Status::Pending)]).await.unwrap();

    let page = Client::new(anpi::web::router(app.state.clone())).get("/").await.body;
    let api_row = &page[page.find(&format!(r#"data-monitor="{api}""#)).unwrap()..];
    let api_row = &api_row[..api_row.find("</article>").unwrap()];
    assert!(api_row.contains("Degraded") && api_row.contains("2 components"), "parent shows the worst child: {api_row}");
    assert!(page.contains(&format!(r#"data-parent="{api}""#)));
    let json = Client::new(anpi::web::router(app.state.clone())).get("/api/status.json").await.body;
    assert!(json.contains(&format!(r#""parent":{api}"#)));

    // Only one level of nesting: a child cannot become a parent, and a parent cannot be nested.
    let nested = c.post("/admin/monitors", &[("csrf", &csrf), ("name", "deep"), ("kind", "aggregate"), ("parent_id", &badges.to_string())]).await;
    assert!(nested.body.contains("only one level"), "{}", nested.body);
    let other = anpi::store::monitors::create(db, &MonitorInput::http("Other", "https://example.com")).await.unwrap();
    let move_parent = c.post(&format!("/admin/monitors/{api}"), &[("csrf", &csrf), ("name", "API"), ("kind", "aggregate"), ("parent_id", &other.to_string())]).await;
    assert!(move_parent.body.contains("has sub-monitors"), "{}", move_parent.body);
    let own = c.post(&format!("/admin/monitors/{other}"), &[("csrf", &csrf), ("name", "Other"), ("kind", "aggregate"), ("parent_id", &other.to_string())]).await;
    assert!(own.body.contains("own parent"), "{}", own.body);

    c.post(&format!("/admin/monitors/{api}/delete"), &[("csrf", &csrf)]).await;
    let orphan = anpi::store::monitors::get(db, badges).await.unwrap().unwrap();
    assert_eq!(orphan.parent_id, None, "deleting a parent keeps its sub-monitors");
    app.scheduler.shutdown().await;
}

#[tokio::test]
async fn asset_urls_change_with_their_content() {
    let app = app(config(&[])).await;
    let page = Client::new(anpi::web::router(app.state.clone())).get("/").await.body;
    let v = anpi::web::asset_version();
    assert_eq!(v.len(), 12);
    assert!(page.contains(&format!("/static/app.css?v={v}")), "stylesheet URL carries the content hash");
    assert_ne!(v, env!("CARGO_PKG_VERSION"));
}
