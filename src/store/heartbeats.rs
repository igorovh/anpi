use std::collections::HashMap;

use crate::db::Db;
use crate::models::{Heartbeat, Incident, NewHeartbeat};

pub async fn insert_batch(db: &Db, beats: &[NewHeartbeat]) -> sqlx::Result<()> {
    let mut tx = db.begin().await?;
    for b in beats {
        sqlx::query(
            "INSERT INTO heartbeats (monitor_id, ts, status, status_code, dns_ms, connect_ms, tls_ms, ttfb_ms,
                total_ms, remote_ip, message, cert_expires_at)
             SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM monitors WHERE id = ?)",
        )
        .bind(b.monitor_id)
        .bind(b.ts)
        .bind(b.status.as_i64())
        .bind(b.status_code.map(i64::from))
        .bind(b.timings.dns_ms)
        .bind(b.timings.connect_ms)
        .bind(b.timings.tls_ms)
        .bind(b.timings.ttfb_ms)
        .bind(b.timings.total_ms)
        .bind(&b.remote_ip)
        .bind(&b.message)
        .bind(b.cert_expires_at)
        .bind(b.monitor_id)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await
}

pub async fn recent(db: &Db, monitor_id: i64, limit: i64) -> sqlx::Result<Vec<Heartbeat>> {
    sqlx::query_as("SELECT * FROM heartbeats WHERE monitor_id = ? ORDER BY ts DESC LIMIT ?")
        .bind(monitor_id)
        .bind(limit)
        .fetch_all(db)
        .await
}

/// Last `per_monitor` heartbeats for every monitor, oldest first.
pub async fn recent_all(db: &Db, per_monitor: i64) -> sqlx::Result<HashMap<i64, Vec<Heartbeat>>> {
    let rows: Vec<Heartbeat> = sqlx::query_as(
        "SELECT id, monitor_id, ts, status, status_code, dns_ms, connect_ms, tls_ms, ttfb_ms, total_ms, remote_ip,
                message, cert_expires_at
         FROM (SELECT *, ROW_NUMBER() OVER (PARTITION BY monitor_id ORDER BY ts DESC) AS rn FROM heartbeats)
         WHERE rn <= ? ORDER BY monitor_id, ts",
    )
    .bind(per_monitor)
    .fetch_all(db)
    .await?;
    let mut map: HashMap<i64, Vec<Heartbeat>> = HashMap::new();
    for r in rows {
        map.entry(r.monitor_id).or_default().push(r);
    }
    Ok(map)
}

pub async fn latest_cert_expiry(db: &Db, monitor_id: i64) -> sqlx::Result<Option<i64>> {
    sqlx::query_scalar(
        "SELECT cert_expires_at FROM heartbeats WHERE monitor_id = ? AND cert_expires_at IS NOT NULL
         ORDER BY ts DESC LIMIT 1",
    )
    .bind(monitor_id)
    .fetch_optional(db)
    .await
}

pub async fn open_incident(db: &Db, monitor_id: i64) -> sqlx::Result<Option<Incident>> {
    sqlx::query_as("SELECT * FROM incidents WHERE monitor_id = ? AND ended_at IS NULL ORDER BY started_at DESC LIMIT 1")
        .bind(monitor_id)
        .fetch_optional(db)
        .await
}

pub async fn create_incident(db: &Db, monitor_id: i64, started_at: i64, message: &str) -> sqlx::Result<i64> {
    sqlx::query_scalar("INSERT INTO incidents (monitor_id, started_at, message) VALUES (?, ?, ?) RETURNING id")
        .bind(monitor_id)
        .bind(started_at)
        .bind(message)
        .fetch_one(db)
        .await
}

pub async fn close_incident(db: &Db, id: i64, ended_at: i64) -> sqlx::Result<()> {
    sqlx::query("UPDATE incidents SET ended_at = ? WHERE id = ?").bind(ended_at).bind(id).execute(db).await?;
    Ok(())
}

pub async fn incidents_for(db: &Db, monitor_id: i64, limit: i64) -> sqlx::Result<Vec<Incident>> {
    sqlx::query_as("SELECT * FROM incidents WHERE monitor_id = ? ORDER BY started_at DESC LIMIT ?")
        .bind(monitor_id)
        .bind(limit)
        .fetch_all(db)
        .await
}

pub async fn public_incidents_since(db: &Db, since: i64) -> sqlx::Result<Vec<(Incident, String)>> {
    let rows: Vec<(i64, i64, i64, Option<i64>, String, String)> = sqlx::query_as(
        "SELECT i.id, i.monitor_id, i.started_at, i.ended_at, i.message, m.name
         FROM incidents i JOIN monitors m ON m.id = i.monitor_id
         WHERE m.public = 1 AND (i.ended_at IS NULL OR i.ended_at >= ?)
         ORDER BY i.started_at DESC LIMIT 20",
    )
    .bind(since)
    .fetch_all(db)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, monitor_id, started_at, ended_at, message, name)| {
            (Incident { id, monitor_id, started_at, ended_at, message }, name)
        })
        .collect())
}
