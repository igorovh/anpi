//! End-to-end monitoring: real checks, state transitions, incidents and notifications.

mod common;

use std::time::Duration;

use anpi::models::{MonitorInput, Status};
use anpi::store;
use anpi::util::now_ms;
use common::{Client, Target, Webhook, add_webhook_channel, app, config, tls_server, wait_for};

fn fast(name: &str, url: &str) -> MonitorInput {
    MonitorInput { interval_s: 1, retry_interval_s: 1, timeout_s: 2, failure_threshold: 2, ..MonitorInput::http(name, url) }
}

async fn statuses(db: &anpi::db::Db, id: i64) -> Vec<Status> {
    let mut v: Vec<Status> = store::heartbeats::recent(db, id, 100).await.unwrap().iter().map(|b| b.status()).collect();
    v.reverse();
    v
}

#[tokio::test]
async fn outage_alerts_once_then_recovers_once() {
    let app = app(config(&[])).await;
    let db = app.ctx.db.clone();
    let target = Target::start().await;
    let hook = Webhook::start().await;
    let channel = add_webhook_channel(&db, &hook.url()).await;
    let id = store::monitors::create(&db, &fast("api", &target.url("/"))).await.unwrap();
    store::monitors::set_channels(&db, id, &[channel]).await.unwrap();
    app.scheduler.reload(id).await.unwrap();

    wait_for("first up", Duration::from_secs(5), || async {
        app.ctx.writer.flush().await;
        statuses(&db, id).await.contains(&Status::Up)
    })
    .await;

    target.set_status(500);
    wait_for("down alert", Duration::from_secs(8), || async { hook.count("down") == 1 }).await;
    app.ctx.writer.flush().await;
    let seen = statuses(&db, id).await;
    let first_fail = seen.iter().position(|s| *s != Status::Up).unwrap();
    assert_eq!(seen[first_fail], Status::Pending, "one failure is only pending with threshold 2: {seen:?}");
    let incident = store::heartbeats::open_incident(&db, id).await.unwrap().expect("incident opened");
    assert!(incident.message.contains("HTTP 500"));

    // Staying down must not repeat the alert.
    tokio::time::sleep(Duration::from_millis(2200)).await;
    assert_eq!(hook.count("down"), 1);

    target.set_status(200);
    wait_for("recovery alert", Duration::from_secs(5), || async { hook.count("up") == 1 }).await;
    assert!(store::heartbeats::open_incident(&db, id).await.unwrap().is_none(), "incident closed");
    let up = hook.received.lock().unwrap().iter().find(|v| v["event"] == "up").cloned().unwrap();
    assert_eq!(up["monitor"]["name"], "api");
    app.scheduler.shutdown().await;
}

#[tokio::test]
async fn maintenance_window_suppresses_alerts() {
    let app = app(config(&[])).await;
    let db = app.ctx.db.clone();
    let target = Target::start().await;
    target.set_status(503);
    let hook = Webhook::start().await;
    let channel = add_webhook_channel(&db, &hook.url()).await;
    let id = store::monitors::create(&db, &MonitorInput { failure_threshold: 1, ..fast("api", &target.url("/")) }).await.unwrap();
    store::monitors::set_channels(&db, id, &[channel]).await.unwrap();
    store::maintenance::create(&db, "upgrade", now_ms() - 1000, now_ms() + 60_000, false, &[id]).await.unwrap();
    app.ctx.maintenance.reload(&db, now_ms()).await.unwrap();
    app.scheduler.reload(id).await.unwrap();

    wait_for("three checks", Duration::from_secs(6), || async {
        app.ctx.writer.flush().await;
        statuses(&db, id).await.len() >= 3
    })
    .await;
    assert!(statuses(&db, id).await.iter().all(|s| *s == Status::Maintenance));
    assert!(store::heartbeats::open_incident(&db, id).await.unwrap().is_none());
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(hook.events().is_empty(), "no alerts during maintenance: {:?}", hook.events());
    app.scheduler.shutdown().await;
}

#[tokio::test]
async fn push_monitor_goes_down_when_pushes_stop() {
    let app = app(config(&[])).await;
    let db = app.ctx.db.clone();
    let hook = Webhook::start().await;
    let channel = add_webhook_channel(&db, &hook.url()).await;
    let input = MonitorInput { kind: "push".into(), interval_s: 1, failure_threshold: 1, ..MonitorInput::http("backup", "") };
    let id = store::monitors::create(&db, &input).await.unwrap();
    store::monitors::set_channels(&db, id, &[channel]).await.unwrap();
    let token = store::monitors::get(&db, id).await.unwrap().unwrap().push_token.expect("token generated");
    app.scheduler.reload(id).await.unwrap();

    let mut c = Client::new(anpi::web::router(app.state.clone()));
    let r = c.get(&format!("/api/push/{token}?status=up&msg=backup%20done&ping=1234")).await;
    assert_eq!(r.status, 200, "{}", r.body);
    wait_for("push recorded", Duration::from_secs(3), || async {
        app.ctx.writer.flush().await;
        store::heartbeats::recent(&db, id, 1).await.unwrap().first().is_some_and(|b| b.message == "backup done" && b.total_ms == Some(1234.0))
    })
    .await;

    wait_for("missed push alert", Duration::from_secs(4), || async { hook.count("down") == 1 }).await;
    let down = hook.received.lock().unwrap()[0].clone();
    assert!(down["message"].as_str().unwrap().contains("no push received"));

    assert_eq!(c.get("/api/push/wrong-token").await.status, 404);
    app.scheduler.stop(id).await;
    assert_eq!(c.get(&format!("/api/push/{token}")).await.status, 404, "paused monitors reject pushes");
}

#[tokio::test]
async fn expiring_certificate_warns_once_per_threshold() {
    let app = app(config(&[])).await;
    let db = app.ctx.db.clone();
    let hook = Webhook::start().await;
    let channel = add_webhook_channel(&db, &hook.url()).await;
    let (addr, _) = tls_server(5).await;
    let input = MonitorInput { ignore_tls: true, ..fast("shop", &format!("https://localhost:{}/", addr.port())) };
    let id = store::monitors::create(&db, &input).await.unwrap();
    store::monitors::set_channels(&db, id, &[channel]).await.unwrap();
    app.scheduler.reload(id).await.unwrap();

    wait_for("ssl warning", Duration::from_secs(5), || async { hook.count("ssl_expiring") == 1 }).await;
    tokio::time::sleep(Duration::from_millis(2500)).await;
    assert_eq!(hook.count("ssl_expiring"), 1, "same threshold must not re-alert on every check");
    let m = store::monitors::get(&db, id).await.unwrap().unwrap();
    assert_eq!(m.ssl_notified_days, Some(7), "5 days left crosses the 7-day step");

    // A restart must remember what was already sent.
    app.scheduler.reload(id).await.unwrap();
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(hook.count("ssl_expiring"), 1);
    app.scheduler.shutdown().await;
}

#[tokio::test]
async fn restart_does_not_resend_down_alert() {
    let app = app(config(&[])).await;
    let db = app.ctx.db.clone();
    let target = Target::start().await;
    target.set_status(500);
    let hook = Webhook::start().await;
    let channel = add_webhook_channel(&db, &hook.url()).await;
    let id = store::monitors::create(&db, &MonitorInput { failure_threshold: 1, ..fast("api", &target.url("/")) }).await.unwrap();
    store::monitors::set_channels(&db, id, &[channel]).await.unwrap();
    app.scheduler.reload(id).await.unwrap();
    wait_for("down alert", Duration::from_secs(4), || async { hook.count("down") == 1 }).await;

    app.scheduler.shutdown().await;
    app.scheduler.reload(id).await.unwrap();
    tokio::time::sleep(Duration::from_millis(2500)).await;
    assert_eq!(hook.count("down"), 1, "state is restored from history after restart");
    app.scheduler.shutdown().await;
}
