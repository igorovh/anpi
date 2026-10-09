//! `anpi demo`: fills an empty database with example monitors and a month of history.

use crate::db::Db;
use crate::models::{MonitorInput, NewHeartbeat, Status, Timings};
use crate::stats::AGG_UNTIL_KEY;
use crate::store;
use crate::util::{DAY_MS, HOUR_MS, floor_hour, now_ms};

/// Small deterministic generator so the demo looks the same every time.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> f64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        (self.0 >> 11) as f64 / (1u64 << 53) as f64
    }
}

struct Spec {
    input: MonitorInput,
    base_ms: f64,
    /// Share of failed checks; 1.0 means always down.
    flaky: f64,
    children: Vec<Spec>,
}

fn http(name: &str, url: &str) -> MonitorInput {
    MonitorInput { public: true, ..MonitorInput::http(name, url) }
}

fn specs(product: i64, infra: i64) -> Vec<Spec> {
    let leaf = |input: MonitorInput, base_ms: f64, flaky: f64| Spec { input, base_ms, flaky, children: vec![] };
    vec![
        leaf(
            MonitorInput { group_id: Some(product), content_kind: "contains".into(), content_value: "Example Domain".into(), ..http("Website", "https://example.com/") },
            140.0,
            0.002,
        ),
        Spec {
            input: MonitorInput { kind: "aggregate".into(), group_id: Some(product), ..http("API", "") },
            base_ms: 0.0,
            flaky: 0.0,
            children: vec![
                leaf(
                    MonitorInput {
                        group_id: Some(product),
                        content_kind: "json_path".into(),
                        content_value: "$.status.indicator".into(),
                        public_name: "Status".into(),
                        ..http("Status endpoint", "https://www.githubstatus.com/api/v2/status.json")
                    },
                    190.0,
                    0.004,
                ),
                leaf(
                    MonitorInput { group_id: Some(product), content_kind: "contains".into(), content_value: "DuckDuckGo".into(), ..http("Search", "https://duckduckgo.com/") },
                    120.0,
                    0.006,
                ),
                leaf(
                    MonitorInput { kind: "websocket".into(), group_id: Some(product), ..http("Realtime", "wss://echo.websocket.org/") },
                    230.0,
                    0.01,
                ),
            ],
        },
        leaf(MonitorInput { group_id: Some(product), ..http("Checkout", "https://httpbin.org/status/503") }, 420.0, 1.0),
        leaf(
            MonitorInput { kind: "tcp".into(), target: "1.1.1.1".into(), port: Some(53), ip_family: "v4".into(), group_id: Some(infra), ..http("Cloudflare DNS", "") },
            15.0,
            0.0,
        ),
        leaf(
            MonitorInput {
                kind: "dns".into(),
                target: "example.com".into(),
                dns_server: "1.1.1.1".into(),
                group_id: Some(infra),
                public: false,
                ..http("example.com A record", "")
            },
            25.0,
            0.0,
        ),
        leaf(MonitorInput { kind: "push".into(), interval_s: 86_400, group_id: Some(infra), public: false, ..http("Nightly backup", "") }, 0.0, 0.0),
    ]
}

async fn history(db: &Db, id: i64, s: &Spec, rng: &mut Rng, now: i64, cut: i64) -> anyhow::Result<()> {
    let http_like = matches!(s.input.kind.as_str(), "http" | "websocket");
    let mut outages = Vec::new();
    if s.flaky >= 0.004 && s.flaky < 1.0 {
        let start = floor_hour(now - ((3.0 + rng.next() * 25.0) as i64) * DAY_MS);
        let minutes = 4 + (rng.next() * 36.0) as i64;
        outages.push(start);
        store::heartbeats::create_incident(db, id, start + 7 * 60_000, "HTTP 502 Bad Gateway (expected 200-299)").await?;
        let inc: i64 = sqlx::query_scalar("SELECT MAX(id) FROM incidents").fetch_one(db).await?;
        store::heartbeats::close_incident(db, inc, start + 7 * 60_000 + minutes * 60_000).await?;
    }
    let mut tx = db.begin().await?;
    let mut hour = floor_hour(now - 30 * DAY_MS);
    while hour < cut {
        let down = if s.flaky >= 1.0 {
            60
        } else if outages.contains(&hour) {
            5 + (rng.next() * 30.0) as i64
        } else if rng.next() < s.flaky {
            1 + (rng.next() * 2.0) as i64
        } else {
            0
        };
        let evening = matches!((hour / HOUR_MS) % 24, 18..=21);
        let lat = s.base_ms * (1.0 + 0.25 * rng.next()) * if evening { 1.3 } else { 1.0 };
        sqlx::query(
            "INSERT INTO heartbeats_hourly (monitor_id, hour, up, down, total, avg_total_ms, min_total_ms, max_total_ms,
                avg_dns_ms, avg_connect_ms, avg_tls_ms, avg_ttfb_ms) VALUES (?, ?, ?, ?, 60, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(id)
        .bind(hour)
        .bind(60 - down)
        .bind(down)
        .bind((down < 60).then_some(lat))
        .bind(lat * 0.7)
        .bind(lat * 1.8)
        .bind(lat * 0.08)
        .bind(lat * 0.15)
        .bind(http_like.then_some(lat * 0.22))
        .bind(http_like.then_some(lat * 0.45))
        .execute(&mut *tx)
        .await?;
        hour += HOUR_MS;
    }
    tx.commit().await?;

    let mut beats = Vec::new();
    let mut ts = cut;
    while ts < now - 120_000 {
        let failing = s.flaky >= 1.0 || rng.next() < s.flaky / 3.0;
        let lat = s.base_ms * (0.85 + 0.4 * rng.next()) * if rng.next() < 0.01 { 3.0 } else { 1.0 };
        beats.push(NewHeartbeat {
            monitor_id: id,
            ts,
            status: if failing { Status::Down } else { Status::Up },
            status_code: http_like.then_some(if failing { 503 } else { 200 }),
            timings: Timings {
                dns_ms: Some(lat * 0.08),
                connect_ms: Some(lat * 0.15),
                tls_ms: http_like.then_some(lat * 0.22),
                ttfb_ms: http_like.then_some(lat * 0.45),
                total_ms: Some(lat),
            },
            remote_ip: Some("93.184.215.14".into()),
            message: if failing { "HTTP 503 Service Unavailable (expected 200-299)".into() } else { "200 OK".into() },
            cert_expires_at: http_like.then_some(now + 64 * DAY_MS),
        });
        ts += 120_000;
    }
    store::heartbeats::insert_batch(db, &beats).await?;
    Ok(())
}

/// Seeds an empty database; refuses to touch one that already has monitors.
pub async fn seed(db: &Db) -> anyhow::Result<usize> {
    anyhow::ensure!(store::monitors::list(db).await?.is_empty(), "this database already has monitors; point ANPI_DATA_DIR at an empty directory");
    let now = now_ms();
    let cut = floor_hour(now - DAY_MS);
    let product = store::groups::create(db, "Product", 10).await?;
    let infra = store::groups::create(db, "Infrastructure", 20).await?;
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let mut created = 0;
    for spec in specs(product, infra) {
        let id = store::monitors::create(db, &spec.input).await?;
        created += 1;
        if spec.input.kind != "push" && spec.input.kind != "aggregate" {
            history(db, id, &spec, &mut rng, now, cut).await?;
        }
        for child in &spec.children {
            let child_input = MonitorInput { parent_id: Some(id), ..child.input.clone() };
            let cid = store::monitors::create(db, &child_input).await?;
            created += 1;
            history(db, cid, child, &mut rng, now, cut).await?;
        }
    }
    store::settings::set(db, AGG_UNTIL_KEY, &cut.to_string()).await?;
    store::settings::set(db, "status_title", "Example status").await?;
    Ok(created)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn demo_fills_an_empty_database_once() {
        let db = crate::db::open_memory().await.unwrap();
        let n = seed(&db).await.unwrap();
        assert_eq!(n, 9);
        let monitors = store::monitors::list(&db).await.unwrap();
        let api = monitors.iter().find(|m| m.name == "API").unwrap();
        assert_eq!(monitors.iter().filter(|m| m.parent_id == Some(api.id)).count(), 3);
        let up = crate::stats::uptime_all(&db, now_ms() - 30 * DAY_MS).await.unwrap();
        let website = monitors.iter().find(|m| m.name == "Website").unwrap();
        assert!(up[&website.id] > 99.0 && up[&website.id] < 100.0, "history spans raw and hourly data");
        assert!(seed(&db).await.is_err(), "never overwrites an existing setup");
    }
}
