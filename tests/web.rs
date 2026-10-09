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

#[tokio::test]
async fn dragging_moves_monitors_between_groups_and_parents() {
    use anpi::models::MonitorInput;
    let app = app(config(&[])).await;
    let mut c = signed_in(&app).await;
    let csrf = c.csrf().await;
    let db = &app.ctx.db;

    let r = c.post("/admin/groups", &[("csrf", &csrf), ("name", "Twitch Enhancer"), ("next", "/admin")]).await;
    assert_eq!(r.location(), "/admin?notice=created", "creating a group from the dashboard returns there");
    let group = anpi::store::groups::list(db).await.unwrap()[0].id;
    assert!(c.get("/admin").await.body.contains("drop monitors here"), "empty groups stay visible as drop targets");

    let api = anpi::store::monitors::create(db, &MonitorInput::http("API health", "https://example.com/health")).await.unwrap();
    let badges = anpi::store::monitors::create(db, &MonitorInput::http("Badges", "https://example.com/badges")).await.unwrap();
    let mv = |id: i64| format!("/admin/monitors/{id}/move");

    let r = c.post(&mv(api), &[("csrf", &csrf), ("group_id", &group.to_string()), ("parent_id", "")]).await;
    assert!(r.status.is_success(), "{}", r.body);
    let r = c.post(&mv(badges), &[("csrf", &csrf), ("group_id", ""), ("parent_id", &api.to_string())]).await;
    assert!(r.status.is_success(), "{}", r.body);
    let b = anpi::store::monitors::get(db, badges).await.unwrap().unwrap();
    assert_eq!((b.parent_id, b.group_id), (Some(api), Some(group)), "a nested monitor joins its parent's group");

    let r = c.post(&mv(api), &[("csrf", &csrf), ("group_id", ""), ("parent_id", &badges.to_string())]).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert!(r.body.contains("sub-monitor"), "{}", r.body);

    // Moving the parent out of the group takes its sub-monitors along.
    c.post(&mv(api), &[("csrf", &csrf), ("group_id", ""), ("parent_id", "")]).await;
    let b = anpi::store::monitors::get(db, badges).await.unwrap().unwrap();
    assert_eq!((b.parent_id, b.group_id), (Some(api), None));

    let forged = c.post(&mv(api), &[("csrf", "nope"), ("group_id", &group.to_string())]).await;
    assert_eq!(forged.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn run_check_now_tests_unsaved_settings() {
    let app = app(config(&[])).await;
    let mut c = signed_in(&app).await;
    let csrf = c.csrf().await;
    let target = common::Target::start().await;
    *target.body.lock().unwrap() = r#"{"status":"degraded"}"#.into();
    let form = |expected: &str| {
        vec![("csrf", csrf.clone()), ("name", "t".into()), ("kind", "http".into()), ("url", target.url("/health")),
             ("expected_status", "200-299".into()), ("content_kind", "json_path".into()), ("content_value", "$.status".into()),
             ("content_expected", expected.to_string()), ("timeout_s", "5".into())]
    };
    let r = c.post("/admin/monitors/test", &form("ok").iter().map(|(k, v)| (*k, v.as_str())).collect::<Vec<_>>()).await;
    let v: serde_json::Value = serde_json::from_str(&r.body).unwrap();
    assert_eq!(v["ok"], false);
    assert!(v["message"].as_str().unwrap().contains("degraded"));
    assert_eq!(v["status_code"], 200);
    assert!(v["preview"].as_str().unwrap().contains("degraded"), "the body is shown to help fix the rule");

    let r = c.post("/admin/monitors/test", &form("degraded").iter().map(|(k, v)| (*k, v.as_str())).collect::<Vec<_>>()).await;
    assert_eq!(serde_json::from_str::<serde_json::Value>(&r.body).unwrap()["ok"], true);
    assert!(anpi::store::monitors::list(&app.ctx.db).await.unwrap().is_empty(), "testing saves nothing");

    let bad = c.post("/admin/monitors/test", &[("csrf", &csrf), ("name", "t"), ("kind", "http"), ("url", "nope")]).await;
    assert!(serde_json::from_str::<serde_json::Value>(&bad.body).unwrap()["error"].as_str().unwrap().contains("URL"));
}

#[tokio::test]
async fn login_redirect_cannot_be_bent_to_another_site() {
    let app = app(config(&[])).await;
    signed_in(&app).await;
    for evil in ["/\t/evil.example", "/\t\\evil.example", "/\\evil.example", "/\r\n/evil.example"] {
        let mut c = Client::new(anpi::web::router(app.state.clone()));
        let r = c.post("/login", &[("username", "admin"), ("password", "a-long-password"), ("next", evil)]).await;
        assert_eq!(r.status, StatusCode::SEE_OTHER);
        assert_eq!(r.location(), "/admin", "{evil:?}");
    }
}

#[tokio::test]
async fn spoofed_forwarded_for_does_not_reset_the_login_limit() {
    let app = app(config(&[("ANPI_TRUST_PROXY", "true")])).await;
    signed_in(&app).await;
    let router = anpi::web::router(app.state.clone());
    let attempt = |spoof: String, password: &'static str| {
        let router = router.clone();
        async move {
            let body = url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs([("username", "admin"), ("password", password)])
                .finish();
            let req = axum::http::Request::post("/login")
                .header("host", "localhost")
                .header("content-type", "application/x-www-form-urlencoded")
                // The client controls everything before the address its proxy appends last.
                .header("x-forwarded-for", format!("{spoof}, 198.51.100.7"))
                .body(axum::body::Body::from(body))
                .unwrap();
            tower::ServiceExt::oneshot(router, req).await.unwrap().status()
        }
    };
    for i in 0..10 {
        attempt(format!("10.0.0.{i}"), "wrong-password").await;
    }
    assert_eq!(attempt("10.9.9.9".into(), "a-long-password").await, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn incidents_are_limited_publicly_and_paginated_in_the_panel() {
    use anpi::models::MonitorInput;
    use anpi::store::heartbeats::{close_incident, create_incident};
    let app = app(config(&[])).await;
    let db = &app.ctx.db;
    let mut c = signed_in(&app).await;
    let public = anpi::store::monitors::create(db, &MonitorInput { public: true, public_name: "Website".into(), ..MonitorInput::http("web-prod-7", "https://example.com") })
        .await
        .unwrap();
    let private = anpi::store::monitors::create(db, &MonitorInput::http("secret-db", "https://example.com")).await.unwrap();
    let now = anpi::util::now_ms();
    // 22 finished incidents plus one ongoing that started before all of them.
    for i in 0..22 {
        let id = create_incident(db, public, now - 60_000 * (100 - i), &format!("closed #{i}")).await.unwrap();
        close_incident(db, id, now - 60_000 * (99 - i)).await.unwrap();
    }
    create_incident(db, public, now - 60_000 * 500, "still down").await.unwrap();
    create_incident(db, private, now, "private outage").await.unwrap();

    let page = Client::new(anpi::web::router(app.state.clone())).get("/").await.body;
    assert_eq!(page.matches("<li>").count(), 10, "default of 10 recent incidents");
    let first = page.find("ongoing").unwrap();
    assert!(first < page.find("was down for").unwrap(), "ongoing incidents come first");
    assert!(page.contains("Showing the 10 most recent incidents"));
    assert!(page.contains("Website") && !page.contains("web-prod-7"), "public names only");
    assert!(!page.contains("private outage") && !page.contains("secret-db"));

    let detail = c.get(&format!("/admin/monitors/{public}?ip=3")).await.body;
    assert!(detail.contains("page 3 of 3") && detail.contains("23 incidents"), "10 per page");
    assert!(detail.contains("?range=24h&#38;ip=2&#38;cp=1#incidents"), "newer link keeps the other lists");
    assert_eq!(detail.matches("closed #").count(), 3);
    assert!(c.get(&format!("/admin/monitors/{public}?ip=99")).await.body.contains("page 3 of 3"), "out of range clamps");

    let all = c.get("/admin/incidents").await.body;
    assert!(all.contains("24 incidents") && all.contains("secret-db"), "the panel sees every monitor");
    let ongoing = c.get("/admin/incidents?ongoing=1").await.body;
    assert_eq!(ongoing.matches("ongoing</span>").count(), 2);
    assert!(!ongoing.contains("closed #"));

    let csrf = c.csrf().await;
    let r = c.post("/admin/settings", &[("csrf", &csrf), ("status_title", "S"), ("raw_retention_hours", "24"), ("hourly_retention_days", "365"),
        ("incident_retention_days", "365"), ("incidents_shown", "0")]).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
    let hidden = Client::new(anpi::web::router(app.state.clone())).get("/").await.body;
    assert!(!hidden.contains("Recent incidents") && !hidden.contains("#incidents"), "0 hides the section and its nav link");
}

#[tokio::test]
async fn configuration_export_and_import_through_the_panel() {
    use anpi::models::MonitorInput;
    let app = app(config(&[])).await;
    let db = &app.ctx.db;
    let mut c = signed_in(&app).await;
    let csrf = c.csrf().await;
    let old = anpi::store::monitors::create(db, &MonitorInput { public_name: "Site".into(), ..MonitorInput::http("Website", "http://127.0.0.1:9/") })
        .await
        .unwrap();
    app.scheduler.reload(old).await.unwrap();

    let anon = Client::new(anpi::web::router(app.state.clone())).get("/admin/export").await;
    assert_eq!(anon.status, StatusCode::SEE_OTHER, "export needs a session");
    let export = c.get("/admin/export").await;
    assert_eq!(export.status, StatusCode::OK);
    assert!(export.headers.get("content-disposition").unwrap().to_str().unwrap().starts_with("attachment; filename=\"anpi-config-"));
    assert!(export.body.contains("\"anpi_export\": 1") && export.body.contains("\"public_name\": \"Site\""));

    let merged = c.post("/admin/import", &[("csrf", &csrf), ("json", &export.body), ("mode", "merge")]).await;
    assert!(merged.body.contains("Imported 1 monitor"), "{}", merged.body);
    let all = anpi::store::monitors::list(db).await.unwrap();
    assert_eq!(all.len(), 2);
    let duplicate = all.iter().map(|m| m.id).max().unwrap();
    assert!(app.scheduler.is_running(duplicate).await, "merged monitors start right away");

    let unconfirmed = c.post("/admin/import", &[("csrf", &csrf), ("json", &export.body), ("mode", "replace")]).await;
    assert_eq!(unconfirmed.status, StatusCode::BAD_REQUEST);
    assert_eq!(anpi::store::monitors::list(db).await.unwrap().len(), 2, "nothing is deleted without confirmation");

    let replaced = c.post("/admin/import", &[("csrf", &csrf), ("json", &export.body), ("mode", "replace"), ("confirm_replace", "on")]).await;
    assert!(replaced.body.contains("Imported 1 monitor"), "{}", replaced.body);
    let now = anpi::store::monitors::list(db).await.unwrap();
    assert_eq!(now.len(), 1);
    assert!(!now.iter().any(|m| m.id == duplicate), "the duplicate is gone");
    assert!(!app.scheduler.is_running(duplicate).await, "checks of replaced monitors stop");
    assert!(app.scheduler.is_running(now[0].id).await, "imported monitors start");
    app.scheduler.shutdown().await;
}
