//! Retention must shrink the database without changing what the charts and uptime numbers say.

use anpi::models::{MonitorInput, NewHeartbeat, Status, Timings};
use anpi::retention::run_once;
use anpi::stats;
use anpi::store::{self, settings::AppSettings};
use anpi::util::{DAY_MS, HOUR_MS, floor_hour};

const NOW: i64 = 1_790_000_000_000 + 30 * 60_000;

async fn seeded(days: i64) -> (anpi::db::Db, i64, i64) {
    let db = anpi::db::open_memory().await.unwrap();
    let id = store::monitors::create(&db, &MonitorInput::http("m", "https://x")).await.unwrap();
    let start = floor_hour(NOW) - days * DAY_MS;
    let mut beats = Vec::new();
    let mut t = start;
    let mut i = 0;
    // One check a minute; every 20th fails and every 50th is pending, which must not count either way.
    while t < NOW {
        let status = if i % 50 == 0 { Status::Pending } else if i % 20 == 0 { Status::Down } else { Status::Up };
        let total = if status == Status::Up { Some(100.0) } else { Some(5000.0) };
        beats.push(NewHeartbeat {
            monitor_id: id,
            ts: t,
            status,
            status_code: None,
            timings: Timings { dns_ms: Some(10.0), total_ms: total, ..Default::default() },
            remote_ip: None,
            message: String::new(),
            cert_expires_at: None,
        });
        t += 60_000;
        i += 1;
    }
    store::heartbeats::insert_batch(&db, &beats).await.unwrap();
    (db, id, start)
}

async fn raw_count(db: &anpi::db::Db) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM heartbeats").fetch_one(db).await.unwrap()
}

#[tokio::test]
async fn rollup_preserves_uptime_and_latency_while_pruning_raw_rows() {
    let (db, id, _) = seeded(3).await;
    let before_7d = stats::uptime_all(&db, NOW - 7 * DAY_MS).await.unwrap()[&id];
    let before_24h = stats::uptime_all(&db, NOW - DAY_MS).await.unwrap()[&id];
    let raw_before = raw_count(&db).await;

    let report = run_once(&db, NOW, &AppSettings::default()).await.unwrap();

    assert_eq!(report.aggregated_until, floor_hour(NOW));
    assert!(report.raw_deleted > 0);
    let oldest: i64 = sqlx::query_scalar("SELECT MIN(ts) FROM heartbeats").fetch_one(&db).await.unwrap();
    assert!(oldest >= NOW - DAY_MS, "raw rows older than 24h are gone");
    assert!(raw_count(&db).await < raw_before / 2);

    let after_7d = stats::uptime_all(&db, NOW - 7 * DAY_MS).await.unwrap()[&id];
    let after_24h = stats::uptime_all(&db, NOW - DAY_MS).await.unwrap()[&id];
    assert!((after_7d - before_7d).abs() < 1e-9, "7d uptime unchanged: {before_7d} vs {after_7d}");
    assert!((after_24h - before_24h).abs() < 0.2, "24h uptime within hour rounding: {before_24h} vs {after_24h}");

    let hourly: Vec<(i64, i64, i64, f64)> =
        sqlx::query_as("SELECT up, down, total, avg_total_ms FROM heartbeats_hourly WHERE monitor_id = ? ORDER BY hour LIMIT 1")
            .bind(id)
            .fetch_all(&db)
            .await
            .unwrap()
            .into_iter()
            .map(|(u, d, t, a): (i64, i64, i64, Option<f64>)| (u, d, t, a.unwrap()))
            .collect();
    let (up, down, total, avg) = hourly[0];
    assert_eq!(total, 60);
    assert!(up + down < total, "pending checks are neither up nor down");
    assert_eq!(avg, 100.0, "latency averages only successful checks");
}

#[tokio::test]
async fn running_twice_never_double_counts() {
    let (db, id, _) = seeded(2).await;
    run_once(&db, NOW, &AppSettings::default()).await.unwrap();
    let first: i64 = sqlx::query_scalar("SELECT SUM(total) FROM heartbeats_hourly").fetch_one(&db).await.unwrap();
    let up_first = stats::uptime_all(&db, NOW - 7 * DAY_MS).await.unwrap()[&id];

    let second = run_once(&db, NOW, &AppSettings::default()).await.unwrap();
    assert_eq!(second.raw_deleted, 0, "nothing new to prune at the same instant");
    run_once(&db, NOW + 60_000, &AppSettings::default()).await.unwrap();
    let again: i64 = sqlx::query_scalar("SELECT SUM(total) FROM heartbeats_hourly").fetch_one(&db).await.unwrap();
    assert_eq!(first, again);
    assert_eq!(up_first, stats::uptime_all(&db, NOW - 7 * DAY_MS).await.unwrap()[&id]);
}

#[tokio::test]
async fn hours_still_being_written_are_not_rolled_up() {
    let (db, _, _) = seeded(1).await;
    // Two minutes past the hour: the previous hour may still have heartbeats in the writer's batch.
    let early = floor_hour(NOW) + 60_000;
    let r = run_once(&db, early, &AppSettings::default()).await.unwrap();
    assert_eq!(r.aggregated_until, floor_hour(NOW) - HOUR_MS);
}

#[tokio::test]
async fn hourly_history_and_old_incidents_expire() {
    let (db, id, _) = seeded(3).await;
    let old = NOW - 3 * DAY_MS;
    let inc = store::heartbeats::create_incident(&db, id, old, "x").await.unwrap();
    store::heartbeats::close_incident(&db, inc, old + 1000).await.unwrap();
    store::heartbeats::create_incident(&db, id, old, "still open").await.unwrap();

    let short = AppSettings { hourly_retention_days: 2, incident_retention_days: 1, ..AppSettings::default() };
    let r = run_once(&db, NOW, &short).await.unwrap();

    assert!(r.hourly_deleted > 0);
    let oldest_hour: i64 = sqlx::query_scalar("SELECT MIN(hour) FROM heartbeats_hourly").fetch_one(&db).await.unwrap();
    assert!(oldest_hour >= NOW - 2 * DAY_MS);
    assert_eq!(r.incidents_deleted, 1);
    assert!(store::heartbeats::open_incident(&db, id).await.unwrap().is_some(), "open incidents are kept");
}

#[tokio::test]
async fn charts_read_seamlessly_across_the_rollup_boundary() {
    let (db, id, start) = seeded(2).await;
    run_once(&db, NOW, &AppSettings::default()).await.unwrap();
    let points = stats::series(&db, id, start, HOUR_MS).await.unwrap();
    assert!(points.len() >= 47, "one point per hour across raw and aggregated data, got {}", points.len());
    assert!(points.windows(2).all(|w| w[1].t > w[0].t), "sorted without duplicates");
    assert!(points.iter().all(|p| p.total_ms == Some(100.0)));
    assert!(points.iter().any(|p| p.down > 0));
}
