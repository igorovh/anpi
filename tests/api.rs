//! The JSON API used by the Terraform provider: token handling and the life cycle of each resource.

mod common;

use axum::http::StatusCode;
use common::{Client, app, config, signed_in};
use serde_json::json;

/// Creates a token through the panel, the way an admin would, and reads it from the page.
async fn panel_token(c: &mut Client, name: &str) -> String {
    let csrf = c.csrf().await;
    let r = c.post("/admin/api-tokens", &[("csrf", &csrf), ("name", name)]).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let start = r.body.find("anpi_").expect("new token is shown once");
    r.body[start..].split('<').next().unwrap().to_string()
}

#[tokio::test]
async fn requests_need_a_valid_token_and_revoking_it_locks_the_api() {
    let app = app(config(&[])).await;
    let mut c = signed_in(&app).await;

    let (s, body) = c.api("GET", "/api/v1/monitors", "", None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert!(body["error"].as_str().unwrap().contains("Bearer"));
    assert_eq!(c.api("GET", "/api/v1/monitors", "anpi_guess", None).await.0, StatusCode::UNAUTHORIZED);

    let token = panel_token(&mut c, "terraform").await;
    let (s, info) = c.api("GET", "/api/v1/info", &token, None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(info["token"], "terraform");
    assert!(!c.get("/admin/settings").await.body.contains(&token), "the token is shown only once");

    let mut anon = Client::new(anpi::web::router(app.state.clone()));
    assert_eq!(anon.api("GET", "/api/v1/monitors", &token, None).await.0, StatusCode::OK, "no session cookie needed");
    assert_eq!(anon.get("/admin").await.status, StatusCode::SEE_OTHER, "a token does not open the panel");

    let id = anpi::store::api_tokens::list(&app.ctx.db).await.unwrap()[0].id;
    let csrf = c.csrf().await;
    c.post(&format!("/admin/api-tokens/{id}/delete"), &[("csrf", &csrf)]).await;
    assert_eq!(c.api("GET", "/api/v1/monitors", &token, None).await.0, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn monitors_groups_and_channels_round_trip() {
    let app = app(config(&[])).await;
    let db = app.ctx.db.clone();
    let (_, token) = anpi::store::api_tokens::create(&db, "ci").await.unwrap();
    let mut c = Client::new(anpi::web::router(app.state.clone()));

    let (s, group) = c.api("POST", "/api/v1/groups", &token, Some(json!({ "name": "Product" }))).await;
    assert_eq!(s, StatusCode::CREATED);
    let group_id = group["id"].as_i64().unwrap();

    let channel = json!({ "name": "hook", "kind": "webhook", "config": { "url": "https://hooks.example.com/anpi" } });
    let (s, ch) = c.api("POST", "/api/v1/notification-channels", &token, Some(channel)).await;
    assert_eq!(s, StatusCode::CREATED, "{ch}");
    assert_eq!((ch["active"].as_bool(), ch["config"]["url"].as_str()), (Some(true), Some("https://hooks.example.com/anpi")));
    let channel_id = ch["id"].as_i64().unwrap();
    let (s, err) = c.api("POST", "/api/v1/notification-channels", &token, Some(json!({ "name": "x", "kind": "webhook" }))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert!(err["error"].as_str().unwrap().contains("URL"));

    let api = json!({ "name": "API", "kind": "http", "target": "https://example.com/health", "group_id": group_id,
        "channel_ids": [channel_id], "interval_s": 30, "public": true });
    let (s, m) = c.api("POST", "/api/v1/monitors", &token, Some(api)).await;
    assert_eq!(s, StatusCode::CREATED, "{m}");
    let api_id = m["id"].as_i64().unwrap();
    assert_eq!((m["retry_interval_s"].as_i64(), m["expected_status"].as_str(), m["active"].as_bool()), (Some(60), Some("200-299"), Some(true)), "defaults match the panel");
    assert_eq!(m["channel_ids"], json!([channel_id]));
    assert!(app.scheduler.is_running(api_id).await, "creating starts the check loop");

    let (s, push) = c.api("POST", "/api/v1/monitors", &token, Some(json!({ "name": "Backup", "kind": "push", "parent_id": api_id }))).await;
    assert_eq!(s, StatusCode::CREATED, "{push}");
    assert!(push["push_token"].as_str().is_some_and(|t| !t.is_empty()));
    let push_id = push["id"].as_i64().unwrap();

    for (bad, why) in [
        (json!({ "name": "x", "kind": "http", "target": "example.com" }), "URL"),
        (json!({ "name": "x", "kind": "tcp", "target": "db" }), "Port"),
        (json!({ "name": "x", "kind": "http", "target": "https://e.com", "group_id": 999 }), "group"),
        (json!({ "name": "x", "kind": "http", "target": "https://e.com", "parent_id": push_id }), "one level"),
        (json!({ "name": "x", "kind": "http", "target": "https://e.com", "channel_ids": [999] }), "channel 999"),
        (json!({ "name": "x", "kind": "http", "target": "https://e.com", "intervall_s": 30 }), "unknown field"),
    ] {
        let (s, err) = c.api("POST", "/api/v1/monitors", &token, Some(bad)).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert!(err["error"].as_str().unwrap().contains(why), "{why}: {err}");
    }

    // A fetched monitor can be edited and sent back as it is.
    let (_, mut fetched) = c.api("GET", &format!("/api/v1/monitors/{api_id}"), &token, None).await;
    fetched["active"] = json!(false);
    let (s, updated) = c.api("PUT", &format!("/api/v1/monitors/{api_id}"), &token, Some(fetched)).await;
    assert_eq!(s, StatusCode::OK, "{updated}");
    assert_eq!((updated["active"].as_bool(), updated["interval_s"].as_i64()), (Some(false), Some(30)));
    assert!(!app.scheduler.is_running(api_id).await, "pausing stops checks");

    let (_, again) = c.api("PUT", &format!("/api/v1/monitors/{push_id}"), &token, Some(json!({ "name": "Backup job", "kind": "push" }))).await;
    assert_eq!(again["push_token"], push["push_token"], "the push URL survives updates");
    assert_eq!(again["parent_id"], json!(null), "PUT replaces the whole monitor");

    let (_, list) = c.api("GET", "/api/v1/monitors", &token, None).await;
    assert_eq!(list.as_array().unwrap().len(), 2);

    let (_, g) = c.api("PUT", &format!("/api/v1/groups/{group_id}"), &token, Some(json!({ "name": "Platform" }))).await;
    assert_eq!((g["name"].as_str(), g["sort_order"].as_i64()), (Some("Platform"), group["sort_order"].as_i64()), "order is kept when left out");

    assert_eq!(c.api("DELETE", &format!("/api/v1/groups/{group_id}"), &token, None).await.0, StatusCode::NO_CONTENT);
    let (_, m) = c.api("GET", &format!("/api/v1/monitors/{api_id}"), &token, None).await;
    assert_eq!(m["group_id"], json!(null), "monitors of a deleted group become ungrouped");
    assert_eq!(c.api("DELETE", &format!("/api/v1/notification-channels/{channel_id}"), &token, None).await.0, StatusCode::NO_CONTENT);
    assert_eq!(c.api("DELETE", &format!("/api/v1/monitors/{api_id}"), &token, None).await.0, StatusCode::NO_CONTENT);
    assert_eq!(c.api("GET", &format!("/api/v1/monitors/{api_id}"), &token, None).await.0, StatusCode::NOT_FOUND);
    assert_eq!(c.api("DELETE", &format!("/api/v1/monitors/{api_id}"), &token, None).await.0, StatusCode::NOT_FOUND);
    assert_eq!(c.api("GET", "/api/v1/nope", &token, None).await.0, StatusCode::NOT_FOUND);
    app.scheduler.shutdown().await;
}

#[tokio::test]
async fn maintenance_windows_take_rfc3339_times() {
    let app = app(config(&[])).await;
    let db = app.ctx.db.clone();
    let (_, token) = anpi::store::api_tokens::create(&db, "ci").await.unwrap();
    let mut c = Client::new(anpi::web::router(app.state.clone()));
    let (_, m) = c.api("POST", "/api/v1/monitors", &token, Some(json!({ "name": "db", "kind": "tcp", "target": "db.local", "port": 5432, "active": false }))).await;
    let monitor_id = m["id"].as_i64().unwrap();

    let window = json!({ "title": "Upgrade", "starts_at": "2030-05-02T00:00:00+02:00", "ends_at": "2030-05-02T01:00:00+02:00", "monitor_ids": [monitor_id] });
    let (s, w) = c.api("POST", "/api/v1/maintenances", &token, Some(window)).await;
    assert_eq!(s, StatusCode::CREATED, "{w}");
    assert_eq!((w["starts_at"].as_str(), w["monitor_ids"].clone()), (Some("2030-05-01T22:00:00Z"), json!([monitor_id])));
    let id = w["id"].as_i64().unwrap();

    let all = json!({ "title": "Move", "starts_at": "2030-05-01T22:00:00Z", "ends_at": "2030-05-01T23:30:00Z", "all_monitors": true });
    let (s, w) = c.api("PUT", &format!("/api/v1/maintenances/{id}"), &token, Some(all)).await;
    assert_eq!(s, StatusCode::OK, "{w}");
    assert_eq!((w["title"].as_str(), w["all_monitors"].as_bool(), w["monitor_ids"].clone()), (Some("Move"), Some(true), json!([])));

    let backwards = json!({ "title": "x", "starts_at": "2030-05-01T22:00:00Z", "ends_at": "2030-05-01T21:00:00Z", "all_monitors": true });
    assert_eq!(c.api("POST", "/api/v1/maintenances", &token, Some(backwards)).await.0, StatusCode::BAD_REQUEST);
    let local = json!({ "title": "x", "starts_at": "2030-05-01 22:00", "ends_at": "2030-05-01T23:00:00Z", "all_monitors": true });
    assert_eq!(c.api("POST", "/api/v1/maintenances", &token, Some(local)).await.0, StatusCode::BAD_REQUEST);

    assert_eq!(c.api("DELETE", &format!("/api/v1/maintenances/{id}"), &token, None).await.0, StatusCode::NO_CONTENT);
    assert!(anpi::store::maintenance::list(&db).await.unwrap().is_empty());
    app.scheduler.shutdown().await;
}
