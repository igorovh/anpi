//! Real network checks against local servers: status codes, timings, timeouts, redirects,
//! IPv4/IPv6 selection, TLS and response content.

mod common;

use std::time::Duration;

use anpi::checks;
use anpi::models::{Monitor, MonitorInput};
use common::{Target, tls_server};

async fn monitor(input: MonitorInput) -> Monitor {
    let db = anpi::db::open_memory().await.unwrap();
    let id = anpi::store::monitors::create(&db, &input).await.unwrap();
    anpi::store::monitors::get(&db, id).await.unwrap().unwrap()
}

fn http(url: &str) -> MonitorInput {
    MonitorInput { timeout_s: 2, ..MonitorInput::http("t", url) }
}

#[tokio::test]
async fn healthy_endpoint_reports_status_and_phase_timings() {
    let t = Target::start().await;
    let out = checks::run(&monitor(http(&t.url("/health"))).await).await;
    assert!(out.ok, "{}", out.message);
    assert_eq!(out.status_code, Some(200));
    assert_eq!(out.remote_ip.as_deref(), Some("127.0.0.1"));
    assert_eq!(out.timings.dns_ms, Some(0.0), "IP literal needs no DNS");
    let total = out.timings.total_ms.unwrap();
    let ttfb = out.timings.ttfb_ms.unwrap();
    assert!(out.timings.connect_ms.is_some() && ttfb > 0.0 && total >= ttfb);
    assert!(out.timings.tls_ms.is_none(), "plain HTTP has no TLS phase");
}

#[tokio::test]
async fn unexpected_status_fails_with_a_clear_message() {
    let t = Target::start().await;
    t.set_status(503);
    let out = checks::run(&monitor(http(&t.url("/"))).await).await;
    assert!(!out.ok);
    assert_eq!(out.status_code, Some(503));
    assert!(out.message.contains("HTTP 503") && out.message.contains("expected 200-299"), "{}", out.message);

    let accepting = MonitorInput { expected_status: "200-299,503".into(), ..http(&t.url("/")) };
    assert!(checks::run(&monitor(accepting).await).await.ok);
}

#[tokio::test]
async fn slow_server_times_out_and_names_the_phase() {
    let t = Target::start().await;
    t.delay_ms.store(3000, std::sync::atomic::Ordering::SeqCst);
    let m = monitor(MonitorInput { timeout_s: 1, ..http(&t.url("/")) }).await;
    let started = std::time::Instant::now();
    let out = checks::run(&m).await;
    assert!(started.elapsed() < Duration::from_millis(2500), "must not wait for the slow server");
    assert!(!out.ok);
    assert!(out.message.starts_with("request: timed out after 1.0s"), "{}", out.message);
    assert!(out.timings.connect_ms.is_some(), "phases reached before the timeout are kept");
}

#[tokio::test]
async fn redirects_are_followed_only_when_enabled() {
    let t = Target::start().await;
    assert!(checks::run(&monitor(http(&t.url("/redirect"))).await).await.ok);

    let no_follow = MonitorInput { follow_redirects: false, ..http(&t.url("/redirect")) };
    let out = checks::run(&monitor(no_follow).await).await;
    assert_eq!(out.status_code, Some(302));
    assert!(!out.ok);

    let out = checks::run(&monitor(http(&t.url("/loop"))).await).await;
    assert!(out.message.contains("too many redirects"), "{}", out.message);
}

#[tokio::test]
async fn ip_family_choice_is_respected() {
    // The target listens on 127.0.0.1 only, so "localhost" works over IPv4 and fails over IPv6.
    let t = Target::start().await;
    let url = format!("http://localhost:{}/", t.addr.port());

    let v4 = checks::run(&monitor(MonitorInput { ip_family: "v4".into(), ..http(&url) }).await).await;
    assert!(v4.ok, "{}", v4.message);
    assert_eq!(v4.remote_ip.as_deref(), Some("127.0.0.1"));

    let v6 = checks::run(&monitor(MonitorInput { ip_family: "v6".into(), timeout_s: 5, ..http(&url) }).await).await;
    assert!(!v6.ok);
    assert!(v6.message.contains("IPv6") || v6.message.contains("AAAA"), "{}", v6.message);

    let auto = checks::run(&monitor(MonitorInput { ip_family: "auto".into(), timeout_s: 5, ..http(&url) }).await).await;
    assert!(auto.ok, "auto falls back to IPv4: {}", auto.message);

    let literal = checks::run(&monitor(MonitorInput { ip_family: "v6".into(), ..http(&t.url("/")) }).await).await;
    assert!(literal.message.contains("not an IPv6 address"), "{}", literal.message);
}

#[tokio::test]
async fn tls_certificate_is_verified_and_its_expiry_recorded() {
    let (addr, expires_at) = tls_server(40).await;
    let url = format!("https://localhost:{}/", addr.port());

    let strict = checks::run(&monitor(http(&url)).await).await;
    assert!(!strict.ok);
    assert!(strict.message.starts_with("TLS: invalid certificate"), "{}", strict.message);

    let lenient = checks::run(&monitor(MonitorInput { ignore_tls: true, ..http(&url) }).await).await;
    assert!(lenient.ok, "{}", lenient.message);
    assert_eq!(lenient.cert_expires_at, Some(expires_at));
    assert!(lenient.timings.tls_ms.is_some());
}

#[tokio::test]
async fn response_content_rules_are_applied() {
    let t = Target::start().await;
    *t.body.lock().unwrap() = r#"{"db":{"status":"degraded"}}"#.into();
    let json = |expected: &str| MonitorInput {
        content_kind: "json_path".into(),
        content_value: "$.db.status".into(),
        content_expected: expected.into(),
        ..http(&t.url("/"))
    };
    let out = checks::run(&monitor(json("ok")).await).await;
    assert!(!out.ok && out.message.contains("degraded"), "{}", out.message);
    assert!(checks::run(&monitor(json("degraded")).await).await.ok);

    let keyword = MonitorInput { content_kind: "not_contains".into(), content_value: "degraded".into(), ..http(&t.url("/")) };
    assert!(!checks::run(&monitor(keyword).await).await.ok);
}

#[tokio::test]
async fn tcp_check_distinguishes_open_and_closed_ports() {
    let t = Target::start().await;
    let open = checks::tcp::check("127.0.0.1", t.addr.port(), anpi::models::IpFamily::Auto, Duration::from_secs(2)).await;
    assert!(open.ok, "{}", open.message);

    let closed_port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let closed = checks::tcp::check("127.0.0.1", closed_port, anpi::models::IpFamily::Auto, Duration::from_secs(5)).await;
    assert!(!closed.ok);
    assert!(closed.message.starts_with("connect:"), "{}", closed.message);
}

#[tokio::test]
async fn websocket_handshake_message_and_reply_check() {
    let addr = common::ws_echo_server().await;
    let ws = |send: &str, kind: &str, value: &str| MonitorInput {
        kind: "websocket".into(),
        body: send.into(),
        content_kind: kind.into(),
        content_value: value.into(),
        ..http(&format!("ws://{addr}/socket"))
    };

    let plain = checks::run(&monitor(ws("", "none", "")).await).await;
    assert!(plain.ok, "{}", plain.message);
    assert_eq!(plain.status_code, Some(101));
    assert!(plain.timings.ttfb_ms.is_some(), "handshake time is recorded");

    let echo = checks::run(&monitor(ws("ping", "contains", "echo: ping")).await).await;
    assert!(echo.ok, "{}", echo.message);
    assert_eq!(echo.preview.as_deref(), Some("echo: ping"));

    let wrong = checks::run(&monitor(ws("ping", "contains", "pong")).await).await;
    assert!(!wrong.ok && wrong.message.contains("pong"), "{}", wrong.message);

    // Waiting for a reply that never comes ends at the timeout and says so.
    let silent = checks::run(&monitor(MonitorInput { timeout_s: 1, ..ws("", "contains", "x") }).await).await;
    assert!(!silent.ok && silent.message.contains("waiting for a message"), "{}", silent.message);

    let refused = checks::run(&monitor(MonitorInput { target: "ws://127.0.0.1:9/".into(), ..ws("", "none", "") }).await).await;
    assert!(!refused.ok && refused.message.starts_with("connect:"), "{}", refused.message);
}

#[tokio::test]
async fn secure_websocket_verifies_tls() {
    // The TLS test server answers plain HTTP, so the WebSocket upgrade itself fails after TLS succeeds.
    let (addr, expires) = tls_server(30).await;
    let url = format!("wss://localhost:{}/", addr.port());
    let strict = checks::run(&monitor(MonitorInput { kind: "websocket".into(), ..http(&url) }).await).await;
    assert!(strict.message.starts_with("TLS: invalid certificate"), "{}", strict.message);
    let lenient = checks::run(&monitor(MonitorInput { kind: "websocket".into(), ignore_tls: true, ..http(&url) }).await).await;
    assert!(lenient.message.starts_with("handshake:"), "{}", lenient.message);
    assert_eq!(lenient.cert_expires_at, Some(expires), "certificate is read even when the upgrade fails");
}
