use std::sync::Arc;
use std::time::Duration;

use crate::app::Ctx;
use crate::db::Db;
use crate::stats::{AGG_UNTIL_KEY, agg_until};
use crate::store::settings::{self, AppSettings};
use crate::util::{DAY_MS, HOUR_MS, floor_hour, now_ms};

#[derive(Debug, Default, PartialEq)]
pub struct Report {
    pub aggregated_until: i64,
    pub raw_deleted: u64,
    pub hourly_deleted: u64,
    pub incidents_deleted: u64,
}

/// Rolls finished hours into `heartbeats_hourly`, then prunes data past its retention.
/// Raw rows are only deleted once aggregated, so no history is lost.
pub async fn run_once(db: &Db, now: i64, s: &AppSettings) -> sqlx::Result<Report> {
    let mut report = Report::default();
    // Leave a margin so heartbeats still in the writer's batch are not skipped.
    let target = floor_hour(now - 2 * 60_000);
    let mut cut = agg_until(db).await?;
    if cut == 0 {
        let oldest: Option<i64> = sqlx::query_scalar("SELECT MIN(ts) FROM heartbeats").fetch_one(db).await?;
        cut = oldest.map(floor_hour).unwrap_or(target);
    }
    if target > cut {
        let mut tx = db.begin().await?;
        sqlx::query(
            "INSERT OR REPLACE INTO heartbeats_hourly (monitor_id, hour, up, down, total, avg_total_ms, min_total_ms,
                max_total_ms, avg_dns_ms, avg_connect_ms, avg_tls_ms, avg_ttfb_ms)
             SELECT monitor_id, (ts / ?1) * ?1, SUM(status = 1), SUM(status = 0), COUNT(*),
                AVG(CASE WHEN status = 1 THEN total_ms END), MIN(CASE WHEN status = 1 THEN total_ms END),
                MAX(CASE WHEN status = 1 THEN total_ms END), AVG(CASE WHEN status = 1 THEN dns_ms END),
                AVG(CASE WHEN status = 1 THEN connect_ms END), AVG(CASE WHEN status = 1 THEN tls_ms END),
                AVG(CASE WHEN status = 1 THEN ttfb_ms END)
             FROM heartbeats WHERE ts >= ?2 AND ts < ?3 GROUP BY 1, 2",
        )
        .bind(HOUR_MS)
        .bind(cut)
        .bind(target)
        .execute(&mut *tx)
        .await?;
        sqlx::query("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value")
            .bind(AGG_UNTIL_KEY)
            .bind(target.to_string())
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        cut = target;
    } else if settings::get(db, AGG_UNTIL_KEY).await?.is_none() {
        settings::set(db, AGG_UNTIL_KEY, &cut.to_string()).await?;
    }
    report.aggregated_until = cut;

    let raw_cut = (now - s.raw_retention_hours.max(1) * HOUR_MS).min(cut);
    loop {
        let n = sqlx::query("DELETE FROM heartbeats WHERE id IN (SELECT id FROM heartbeats WHERE ts < ? LIMIT 5000)")
            .bind(raw_cut)
            .execute(db)
            .await?
            .rows_affected();
        report.raw_deleted += n;
        if n < 5000 {
            break;
        }
    }
    report.hourly_deleted = sqlx::query("DELETE FROM heartbeats_hourly WHERE hour < ?")
        .bind(now - s.hourly_retention_days.max(1) * DAY_MS)
        .execute(db)
        .await?
        .rows_affected();
    let incident_cut = now - s.incident_retention_days.max(1) * DAY_MS;
    report.incidents_deleted = sqlx::query("DELETE FROM incidents WHERE ended_at IS NOT NULL AND ended_at < ?")
        .bind(incident_cut)
        .execute(db)
        .await?
        .rows_affected();
    sqlx::query("DELETE FROM maintenances WHERE ends_at < ?").bind(incident_cut).execute(db).await?;
    sqlx::query("DELETE FROM sessions WHERE expires_at < ?").bind(now).execute(db).await?;
    if report.raw_deleted + report.hourly_deleted > 0 {
        sqlx::query("PRAGMA incremental_vacuum").execute(db).await?;
    }
    Ok(report)
}

pub fn spawn(ctx: Arc<Ctx>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(600));
        loop {
            tick.tick().await;
            let result = async {
                let s = AppSettings::load(&ctx.db).await?;
                ctx.maintenance.reload(&ctx.db, now_ms()).await?;
                run_once(&ctx.db, now_ms(), &s).await
            }
            .await;
            match result {
                Ok(r) if r.raw_deleted + r.hourly_deleted + r.incidents_deleted > 0 => tracing::info!(?r, "retention"),
                Ok(_) => {}
                Err(e) => tracing::error!(error = %e, "retention job failed"),
            }
        }
    });
}
