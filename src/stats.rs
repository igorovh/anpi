//! Reads combine hourly aggregates (before `agg_until`) with raw heartbeats (after it),
//! so results stay correct whatever the raw retention is.

use std::collections::{BTreeMap, HashMap};

use crate::db::Db;
use crate::store::settings;

pub const AGG_UNTIL_KEY: &str = "agg_until";

pub async fn agg_until(db: &Db) -> sqlx::Result<i64> {
    Ok(settings::get(db, AGG_UNTIL_KEY).await?.and_then(|v| v.parse().ok()).unwrap_or(0))
}

/// Uptime percentage per monitor since `since`; Pending and Maintenance are excluded.
pub async fn uptime_all(db: &Db, since: i64) -> sqlx::Result<HashMap<i64, f64>> {
    let cut = agg_until(db).await?;
    let mut acc: HashMap<i64, (i64, i64)> = HashMap::new();
    let hourly: Vec<(i64, i64, i64)> = sqlx::query_as(
        "SELECT monitor_id, SUM(up), SUM(up + down) FROM heartbeats_hourly WHERE hour >= ? AND hour < ? GROUP BY monitor_id",
    )
    .bind(since)
    .bind(cut)
    .fetch_all(db)
    .await?;
    let raw: Vec<(i64, i64, i64)> = sqlx::query_as(
        "SELECT monitor_id, SUM(status = 1), SUM(status IN (0, 1)) FROM heartbeats WHERE ts >= ? GROUP BY monitor_id",
    )
    .bind(since.max(cut))
    .fetch_all(db)
    .await?;
    for (id, up, total) in hourly.into_iter().chain(raw) {
        let e = acc.entry(id).or_default();
        e.0 += up;
        e.1 += total;
    }
    Ok(acc.into_iter().filter(|(_, (_, t))| *t > 0).map(|(id, (u, t))| (id, u as f64 * 100.0 / t as f64)).collect())
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Point {
    pub t: i64,
    pub total_ms: Option<f64>,
    pub dns_ms: Option<f64>,
    pub connect_ms: Option<f64>,
    pub tls_ms: Option<f64>,
    pub ttfb_ms: Option<f64>,
    pub up: i64,
    pub down: i64,
}

fn avg(a: Option<f64>, b: Option<f64>) -> Option<f64> {
    match (a, b) {
        (Some(x), Some(y)) => Some((x + y) / 2.0),
        (x, y) => x.or(y),
    }
}

type Row = (i64, Option<f64>, Option<f64>, Option<f64>, Option<f64>, Option<f64>, i64, i64);

/// Latency series (successful checks only) and up/down counts bucketed by `bucket_ms`.
pub async fn series(db: &Db, monitor_id: i64, since: i64, bucket_ms: i64) -> sqlx::Result<Vec<Point>> {
    let cut = agg_until(db).await?;
    let hourly: Vec<Row> = sqlx::query_as(
        "SELECT (hour / ?1) * ?1 AS b, AVG(avg_total_ms), AVG(avg_dns_ms), AVG(avg_connect_ms), AVG(avg_tls_ms),
                AVG(avg_ttfb_ms), SUM(up), SUM(down)
         FROM heartbeats_hourly WHERE monitor_id = ?2 AND hour >= ?3 AND hour < ?4 GROUP BY b ORDER BY b",
    )
    .bind(bucket_ms)
    .bind(monitor_id)
    .bind(since)
    .bind(cut)
    .fetch_all(db)
    .await?;
    let raw: Vec<Row> = sqlx::query_as(
        "SELECT (ts / ?1) * ?1 AS b,
                AVG(CASE WHEN status = 1 THEN total_ms END), AVG(CASE WHEN status = 1 THEN dns_ms END),
                AVG(CASE WHEN status = 1 THEN connect_ms END), AVG(CASE WHEN status = 1 THEN tls_ms END),
                AVG(CASE WHEN status = 1 THEN ttfb_ms END), SUM(status = 1), SUM(status = 0)
         FROM heartbeats WHERE monitor_id = ?2 AND ts >= ?3 GROUP BY b ORDER BY b",
    )
    .bind(bucket_ms)
    .bind(monitor_id)
    .bind(since.max(cut))
    .fetch_all(db)
    .await?;
    let mut map: BTreeMap<i64, Point> = BTreeMap::new();
    for (t, total, dns, connect, tls, ttfb, up, down) in hourly.into_iter().chain(raw) {
        let p = Point { t, total_ms: total, dns_ms: dns, connect_ms: connect, tls_ms: tls, ttfb_ms: ttfb, up, down };
        map.entry(t)
            .and_modify(|e| {
                e.total_ms = avg(e.total_ms, p.total_ms);
                e.dns_ms = avg(e.dns_ms, p.dns_ms);
                e.connect_ms = avg(e.connect_ms, p.connect_ms);
                e.tls_ms = avg(e.tls_ms, p.tls_ms);
                e.ttfb_ms = avg(e.ttfb_ms, p.ttfb_ms);
                e.up += p.up;
                e.down += p.down;
            })
            .or_insert(p);
    }
    Ok(map.into_values().collect())
}

/// Up/total counts per monitor per bucket, for status bars.
pub async fn buckets_all(db: &Db, since: i64, bucket_ms: i64) -> sqlx::Result<HashMap<i64, BTreeMap<i64, (i64, i64)>>> {
    let cut = agg_until(db).await?;
    let hourly: Vec<(i64, i64, i64, i64)> = sqlx::query_as(
        "SELECT monitor_id, (hour / ?1) * ?1 AS b, SUM(up), SUM(up + down) FROM heartbeats_hourly
         WHERE hour >= ?2 AND hour < ?3 GROUP BY monitor_id, b",
    )
    .bind(bucket_ms)
    .bind(since)
    .bind(cut)
    .fetch_all(db)
    .await?;
    let raw: Vec<(i64, i64, i64, i64)> = sqlx::query_as(
        "SELECT monitor_id, (ts / ?1) * ?1 AS b, SUM(status = 1), SUM(status IN (0, 1)) FROM heartbeats
         WHERE ts >= ?2 GROUP BY monitor_id, b",
    )
    .bind(bucket_ms)
    .bind(since.max(cut))
    .fetch_all(db)
    .await?;
    let mut out: HashMap<i64, BTreeMap<i64, (i64, i64)>> = HashMap::new();
    for (id, b, up, total) in hourly.into_iter().chain(raw) {
        let e = out.entry(id).or_default().entry(b).or_default();
        e.0 += up;
        e.1 += total;
    }
    Ok(out)
}
