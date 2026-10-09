//! anpi watching itself: health for `/healthz`, a log of when it was running, and an outbound heartbeat.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use http::Method;

use crate::app::Ctx;
use crate::checks::http::{RequestSpec, send};
use crate::db::Db;
use crate::store::settings;
use crate::util::now_ms;

pub const TICK: Duration = Duration::from_secs(60);
/// A missed tick plus margin; a longer silence counts as anpi not running.
const SLACK_MS: i64 = 150_000;
/// Gaps shorter than this (a quick restart) are not worth reporting.
pub const MIN_GAP_MS: i64 = 3 * 60_000;
pub const HEARTBEAT_URL_KEY: &str = "heartbeat_url";

/// Checks are stale when none finished for twice the shortest interval (at least ten minutes).
pub fn check_stale(now: i64, last_check: i64, min_interval_s: Option<i64>) -> Result<(), String> {
    let Some(interval) = min_interval_s else { return Ok(()) };
    let limit = (interval * 2 * 1000 + 120_000).max(10 * 60_000);
    let quiet = now - last_check;
    if quiet > limit {
        return Err(format!("no check has finished for {} minutes", quiet / 60_000));
    }
    Ok(())
}

pub async fn health(ctx: &Ctx) -> Result<(), String> {
    let min_interval: Option<i64> = sqlx::query_scalar("SELECT MIN(interval_s) FROM monitors WHERE active = 1 AND kind <> 'aggregate'")
        .fetch_one(&ctx.db)
        .await
        .map_err(|_| "database unavailable".to_string())?;
    check_stale(now_ms(), ctx.last_check.load(Ordering::Relaxed), min_interval)
}

/// Covered share of `[from, to)` and the gaps in it, from `(started_at, last_seen)` rows sorted by start.
/// The window starts no earlier than the first row, so time before anpi was installed does not count.
pub fn coverage(rows: &[(i64, i64)], from: i64, to: i64) -> (f64, Vec<(i64, i64)>) {
    let Some(first) = rows.first() else { return (100.0, Vec::new()) };
    let start = from.max(first.0);
    if to <= start {
        return (100.0, Vec::new());
    }
    let mut gaps = Vec::new();
    let mut cursor = start;
    for &(s, e) in rows {
        let (s, e) = (s.max(start), (e + SLACK_MS).min(to));
        if e <= cursor {
            continue;
        }
        if s > cursor {
            gaps.push((cursor, s.min(to)));
        }
        cursor = cursor.max(e);
        if cursor >= to {
            break;
        }
    }
    if cursor < to {
        gaps.push((cursor, to));
    }
    let missing: i64 = gaps.iter().map(|(a, b)| b - a).sum();
    let pct = 100.0 * (to - start - missing) as f64 / (to - start) as f64;
    gaps.retain(|(a, b)| b - a >= MIN_GAP_MS);
    (pct, gaps)
}

pub async fn runtime_rows(db: &Db, from: i64, to: i64) -> sqlx::Result<Vec<(i64, i64)>> {
    // The first row ever marks the install, which bounds the coverage window.
    let first: Option<(i64, i64)> = sqlx::query_as("SELECT started_at, last_seen FROM runtime ORDER BY started_at LIMIT 1").fetch_optional(db).await?;
    let mut rows: Vec<(i64, i64)> = sqlx::query_as("SELECT started_at, last_seen FROM runtime WHERE last_seen + ? >= ? AND started_at < ? ORDER BY started_at")
        .bind(SLACK_MS)
        .bind(from)
        .bind(to)
        .fetch_all(db)
        .await?;
    if let Some(f) = first
        && rows.first() != Some(&f)
    {
        rows.insert(0, (f.0, f.0));
    }
    Ok(rows)
}

#[derive(Clone, Debug)]
pub struct PingResult {
    pub at: i64,
    pub result: Result<u16, String>,
}

pub async fn heartbeat_url(ctx: &Ctx) -> Option<String> {
    if let Some(u) = &ctx.config.heartbeat_url {
        return Some(u.clone());
    }
    settings::get(&ctx.db, HEARTBEAT_URL_KEY).await.ok().flatten().filter(|u| !u.trim().is_empty())
}

pub async fn ping(url: &str) -> Result<u16, String> {
    let url = url::Url::parse(url).map_err(|e| format!("invalid URL: {e}"))?;
    let mut spec = RequestSpec::new(Method::GET, url).header(http::header::USER_AGENT, concat!("anpi/", env!("CARGO_PKG_VERSION")));
    spec.timeout = Duration::from_secs(10);
    let r = send(&spec).await.map_err(|e| e.to_string())?;
    if (200..300).contains(&r.status) { Ok(r.status) } else { Err(format!("HTTP {}", r.status)) }
}

/// Every minute: extend the runtime log while healthy and ping the heartbeat URL.
pub fn spawn(ctx: Arc<Ctx>) {
    tokio::spawn(async move {
        let mut row: Option<i64> = None;
        let mut last_ok = 0;
        let mut tick = tokio::time::interval(TICK);
        loop {
            tick.tick().await;
            let now = now_ms();
            let healthy = health(&ctx).await;
            if let Err(e) = &healthy {
                tracing::warn!(reason = %e, "anpi is unhealthy");
                continue;
            }
            row = match row.filter(|_| now - last_ok <= SLACK_MS) {
                Some(id) => sqlx::query("UPDATE runtime SET last_seen = ? WHERE id = ?").bind(now).bind(id).execute(&ctx.db).await.ok().map(|_| id),
                None => sqlx::query_scalar("INSERT INTO runtime (started_at, last_seen) VALUES (?, ?) RETURNING id")
                    .bind(now)
                    .bind(now)
                    .fetch_one(&ctx.db)
                    .await
                    .ok(),
            };
            last_ok = now;
            if let Some(url) = heartbeat_url(&ctx).await {
                let result = ping(&url).await;
                if let Err(e) = &result {
                    tracing::warn!(error = %e, "heartbeat ping failed");
                }
                *ctx.heartbeat.write().expect("heartbeat lock") = Some(PingResult { at: now, result });
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIN: i64 = 60_000;

    #[test]
    fn stale_checks_depend_on_the_shortest_interval() {
        assert!(check_stale(100 * MIN, 0, None).is_ok(), "no active monitors, nothing to check");
        assert!(check_stale(9 * MIN, 0, Some(60)).is_ok(), "at least ten minutes of grace");
        assert!(check_stale(11 * MIN, 0, Some(60)).unwrap_err().contains("11 minutes"));
        assert!(check_stale(100 * MIN, 0, Some(3600)).is_ok(), "an hourly monitor gets two hours");
        assert!(check_stale(123 * MIN, 0, Some(3600)).is_err());
    }

    #[test]
    fn coverage_finds_gaps_and_ignores_time_before_install() {
        let day = 24 * 60 * MIN;
        let rows = [(0, 10 * 60 * MIN), (12 * 60 * MIN, day)];
        let (pct, gaps) = coverage(&rows, 0, day);
        assert_eq!(gaps.len(), 1);
        let (a, b) = gaps[0];
        assert!((b - a - (2 * 60 * MIN - SLACK_MS)).abs() < 1, "two hours minus the slack");
        assert!(pct > 91.0 && pct < 92.0, "{pct}");

        let (pct, gaps) = coverage(&[(5 * day, 6 * day)], 0, 6 * day);
        assert_eq!((pct, gaps.len()), (100.0, 0), "the week before the install is not a gap");

        let (_, gaps) = coverage(&[(0, 60 * MIN), (61 * MIN, day)], 0, day);
        assert!(gaps.is_empty(), "a quick restart is not reported");

        let (pct, gaps) = coverage(&[(0, 60 * MIN)], 0, 3 * 60 * MIN);
        assert_eq!(gaps.len(), 1, "silence up to the end of the period counts");
        assert!(pct < 40.0);
        assert_eq!(coverage(&[], 0, day), (100.0, Vec::new()));
    }
}
