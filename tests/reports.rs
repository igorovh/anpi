//! Periodic reports and anpi watching itself: /healthz, the runtime log and the heartbeat.

mod common;

use std::sync::atomic::Ordering;

use anpi::models::{MonitorInput, NewHeartbeat, Status};
use anpi::report::{self, Frequency, ReportSettings};
use anpi::store;
use anpi::util::{DAY_MS, now_ms};
use axum::http::StatusCode;
use common::{Client, Target, Webhook, add_webhook_channel, app, config, signed_in};

fn beat(monitor_id: i64, ts: i64, status: Status) -> NewHeartbeat {
    NewHeartbeat { monitor_id, ts, status, status_code: None, timings: Default::default(), remote_ip: None, message: String::new(), cert_expires_at: None }
}

fn quiet(name: &str) -> MonitorInput {
    MonitorInput { active: true, ..MonitorInput::http(name, "https://example.com") }
}

#[tokio::test]
async fn report_counts_checks_incidents_and_coverage() {
    let db = anpi::db::open_memory().await.unwrap();
    let to = now_ms() - 60_000;
    let from = to - DAY_MS;
    let product = store::groups::create(&db, "Product", 0).await.unwrap();
    let api = store::monitors::create(&db, &MonitorInput { group_id: Some(product), ..quiet("API") }).await.unwrap();
    let search = store::monitors::create(&db, &MonitorInput { group_id: Some(product), parent_id: Some(api), ..quiet("Search") }).await.unwrap();
    let web = store::monitors::create(&db, &quiet("Web")).await.unwrap();
    store::monitors::create(&db, &quiet("Cron")).await.unwrap();
    let paused = store::monitors::create(&db, &MonitorInput { active: false, ..quiet("Old") }).await.unwrap();

    let mut beats = Vec::new();
    for i in 0..100 {
        let ts = from + 1 + i * 60_000;
        beats.push(beat(api, ts, if i < 2 { Status::Down } else { Status::Up }));
        beats.push(beat(search, ts, Status::Up));
        beats.push(beat(web, ts, Status::Up));
        beats.push(beat(paused, ts, Status::Down));
    }
    for i in 0..5 {
        beats.push(beat(web, from + 10 + i, Status::Pending));
    }
    beats.push(beat(web, from - 1000, Status::Down));
    store::heartbeats::insert_batch(&db, &beats).await.unwrap();

    let inc = store::heartbeats::create_incident(&db, api, from + 60_000, "HTTP 503").await.unwrap();
    store::heartbeats::close_incident(&db, inc, from + 11 * 60_000).await.unwrap();
    let old = store::heartbeats::create_incident(&db, web, from - 3 * DAY_MS, "old").await.unwrap();
    store::heartbeats::close_incident(&db, old, from - 2 * DAY_MS).await.unwrap();
    store::heartbeats::create_incident(&db, search, to - 30 * 60_000, "timeout").await.unwrap();
    sqlx::query("INSERT INTO runtime (started_at, last_seen) VALUES (?, ?)").bind(from - DAY_MS).bind(to).execute(&db).await.unwrap();

    let r = report::build(&db, "anpi", Frequency::Daily, from, to, 0).await.unwrap();
    assert_eq!(r.monitors, 4, "paused monitors are left out");
    assert_eq!(r.not_checked, vec!["Cron".to_string()]);
    assert_eq!(r.checks, 305, "pending checks count as checks, older ones do not");
    assert!((r.uptime.unwrap() - 298.0 / 3.0).abs() < 1e-9, "pending checks do not count against uptime");
    assert_eq!(r.incidents, 2, "the incident before the period is left out");
    assert_eq!(r.down_now.len(), 1);
    assert_eq!(r.down_now[0].monitor, "Product › API › Search");
    let names: Vec<&str> = r.problems.iter().map(|l| l.monitor.as_str()).collect();
    assert_eq!(names, ["Product › API", "Product › API › Search"], "worst uptime first");
    assert_eq!(r.problems[0].longest_ms, 10 * 60_000);
    assert_eq!(r.healthy, 1);
    assert_eq!((r.coverage, r.gaps.len()), (100.0, 0));

    sqlx::query("UPDATE runtime SET last_seen = ?").bind(to - 3 * 3_600_000).execute(&db).await.unwrap();
    let r = report::build(&db, "anpi", Frequency::Daily, from, to, 0).await.unwrap();
    assert_eq!(r.gaps.len(), 1, "anpi stopped three hours before the end");
    assert!(r.body().contains("anpi was not running for 2h 57m"), "{}", r.body());
}

#[tokio::test]
async fn scheduled_reports_go_out_once_per_slot() {
    let app = app(config(&[])).await;
    let db = &app.ctx.db;
    let hook = Webhook::start().await;
    let channel = add_webhook_channel(db, &hook.url()).await;
    store::monitors::create(db, &quiet("Web")).await.unwrap();
    ReportSettings { frequency: Frequency::Daily, hour: 8, channels: vec![channel], ..Default::default() }.save(db).await.unwrap();

    let now = now_ms();
    assert!(!report::tick(&app.ctx, now).await.unwrap(), "enabling does not send a report for a slot already past");
    assert!(!report::tick(&app.ctx, now + 60_000).await.unwrap());
    assert!(report::tick(&app.ctx, now + DAY_MS).await.unwrap(), "the next slot sends");
    assert!(!report::tick(&app.ctx, now + DAY_MS + 60_000).await.unwrap(), "only once");
    assert!(report::tick(&app.ctx, now + 4 * DAY_MS).await.unwrap(), "after anpi was off, the missed report is caught up");
    assert!(!report::tick(&app.ctx, now + 4 * DAY_MS + 60_000).await.unwrap(), "only the latest missed slot");

    let got = hook.received.lock().unwrap().clone();
    assert_eq!(got.len(), 2);
    assert_eq!(got[0]["event"], "report");
    assert_eq!(got[0]["report"]["frequency"], "daily");
    assert_eq!(got[0]["report"]["monitors"], 1);
    assert!(got[0]["title"].as_str().unwrap().contains("daily report"));
    assert!(got[0]["message"].as_str().unwrap().contains("Monitoring coverage"));
}

#[tokio::test]
async fn reports_can_be_scheduled_and_sent_from_the_panel() {
    let app = app(config(&[])).await;
    let db = &app.ctx.db;
    let mut c = signed_in(&app).await;
    let csrf = c.csrf().await;
    let hook = Webhook::start().await;
    let channel = add_webhook_channel(db, &hook.url()).await.to_string();

    let none = c.post("/admin/settings/reports", &[("csrf", &csrf), ("frequency", "weekly"), ("action", "send")]).await;
    assert_eq!(none.status, StatusCode::BAD_REQUEST, "no channel ticked and no default channel");
    assert!(none.body.contains("No channel to send to"));

    let sent = c.post("/admin/settings/reports", &[("csrf", &csrf), ("frequency", "weekly"), ("weekday", "4"), ("hour", "9"), ("tz_offset", "-120"), ("channels", &channel), ("action", "send")]).await;
    assert_eq!(sent.location(), "/admin/settings?notice=report-sent#reports");
    assert_eq!(hook.count("report"), 1);

    let s = ReportSettings::load(db).await.unwrap();
    assert_eq!((s.frequency, s.weekday, s.hour, s.tz_offset_min), (Frequency::Weekly, 4, 9, -120));
    assert_eq!(s.last_sent, s.due(now_ms()).unwrap(), "a new schedule waits for its next slot");
    let page = c.get("/admin/settings").await.body;
    assert!(page.contains("Next report: Fri"), "next slot shown in the chosen time zone");
}

#[tokio::test]
async fn healthz_fails_when_checks_stop() {
    let app = app(config(&[])).await;
    let mut c = Client::new(anpi::web::router(app.state.clone()));
    app.ctx.last_check.store(now_ms() - 3 * 3_600_000, Ordering::Relaxed);
    assert_eq!(c.get("/healthz").await.status, StatusCode::OK, "without monitors there is nothing to check");

    store::monitors::create(&app.ctx.db, &MonitorInput { interval_s: 60, ..quiet("Web") }).await.unwrap();
    let r = c.get("/healthz").await;
    assert_eq!(r.status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(r.body.contains("no check has finished for 180 minutes"), "{}", r.body);

    app.ctx.last_check.store(now_ms(), Ordering::Relaxed);
    assert_eq!(c.get("/healthz").await.status, StatusCode::OK);
}

#[tokio::test]
async fn heartbeat_url_is_tested_from_the_panel() {
    let app = app(config(&[])).await;
    let mut c = signed_in(&app).await;
    let csrf = c.csrf().await;
    let target = Target::start().await;

    let bad = c.post("/admin/settings/heartbeat", &[("csrf", &csrf), ("url", "ftp://nope"), ("action", "save")]).await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);

    let ok = c.post("/admin/settings/heartbeat", &[("csrf", &csrf), ("url", &target.url("/ping")), ("action", "test")]).await;
    assert_eq!(ok.location(), "/admin/settings?notice=heartbeat-ok#self-monitoring");
    assert!(c.get("/admin/settings").await.body.contains("Last ping OK"));

    target.set_status(500);
    let failed = c.post("/admin/settings/heartbeat", &[("csrf", &csrf), ("url", &target.url("/ping")), ("action", "test")]).await;
    assert!(failed.body.contains("The heartbeat ping failed: HTTP 500"), "{}", failed.body);
    assert_eq!(anpi::selfcheck::heartbeat_url(&app.ctx).await.unwrap(), target.url("/ping"));
}

#[tokio::test]
async fn heartbeat_url_from_the_environment_wins() {
    let app = app(config(&[("ANPI_HEARTBEAT_URL", "https://hc-ping.com/abc")])).await;
    store::settings::set(&app.ctx.db, anpi::selfcheck::HEARTBEAT_URL_KEY, "https://other.example").await.unwrap();
    assert_eq!(anpi::selfcheck::heartbeat_url(&app.ctx).await.unwrap(), "https://hc-ping.com/abc");
    let mut c = signed_in(&app).await;
    assert!(c.get("/admin/settings").await.body.contains("set by ANPI_HEARTBEAT_URL"));
}
