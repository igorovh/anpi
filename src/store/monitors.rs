use crate::db::Db;
use crate::models::{Monitor, MonitorInput, MonitorKind};
use crate::util::{now_ms, random_token};

pub async fn list(db: &Db) -> sqlx::Result<Vec<Monitor>> {
    sqlx::query_as("SELECT * FROM monitors ORDER BY name COLLATE NOCASE").fetch_all(db).await
}

pub async fn list_public(db: &Db) -> sqlx::Result<Vec<Monitor>> {
    sqlx::query_as("SELECT * FROM monitors WHERE public = 1 ORDER BY name COLLATE NOCASE").fetch_all(db).await
}

pub async fn list_active(db: &Db) -> sqlx::Result<Vec<Monitor>> {
    sqlx::query_as("SELECT * FROM monitors WHERE active = 1").fetch_all(db).await
}

pub async fn get(db: &Db, id: i64) -> sqlx::Result<Option<Monitor>> {
    sqlx::query_as("SELECT * FROM monitors WHERE id = ?").bind(id).fetch_optional(db).await
}

pub async fn get_by_push_token(db: &Db, token: &str) -> sqlx::Result<Option<Monitor>> {
    sqlx::query_as("SELECT * FROM monitors WHERE push_token = ?").bind(token).fetch_optional(db).await
}

pub async fn create(db: &Db, m: &MonitorInput) -> sqlx::Result<i64> {
    let now = now_ms();
    let push_token = (m.kind == MonitorKind::Push.as_str()).then(|| random_token(24));
    let id = sqlx::query_scalar(
        "INSERT INTO monitors (name, kind, target, port, method, headers, body, interval_s, retry_interval_s,
            timeout_s, failure_threshold, expected_status, ip_family, follow_redirects, ignore_tls, content_kind,
            content_value, content_expected, ssl_warn_days, dns_record_type, dns_server, push_token, active, public,
            created_at, updated_at, group_id, public_name, parent_id)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id",
    )
    .bind(&m.name)
    .bind(&m.kind)
    .bind(&m.target)
    .bind(m.port)
    .bind(&m.method)
    .bind(&m.headers)
    .bind(&m.body)
    .bind(m.interval_s)
    .bind(m.retry_interval_s)
    .bind(m.timeout_s)
    .bind(m.failure_threshold)
    .bind(&m.expected_status)
    .bind(&m.ip_family)
    .bind(m.follow_redirects)
    .bind(m.ignore_tls)
    .bind(&m.content_kind)
    .bind(&m.content_value)
    .bind(&m.content_expected)
    .bind(m.ssl_warn_days)
    .bind(&m.dns_record_type)
    .bind(&m.dns_server)
    .bind(push_token)
    .bind(m.active)
    .bind(m.public)
    .bind(now)
    .bind(now)
    .bind(m.group_id)
    .bind(m.public_name.trim())
    .bind(m.parent_id)
    .fetch_one(db)
    .await?;
    Ok(id)
}

pub async fn update(db: &Db, id: i64, m: &MonitorInput) -> sqlx::Result<()> {
    sqlx::query(
        "UPDATE monitors SET name = ?, kind = ?, target = ?, port = ?, method = ?, headers = ?, body = ?,
            interval_s = ?, retry_interval_s = ?, timeout_s = ?, failure_threshold = ?, expected_status = ?,
            ip_family = ?, follow_redirects = ?, ignore_tls = ?, content_kind = ?, content_value = ?,
            content_expected = ?, ssl_warn_days = ?, dns_record_type = ?, dns_server = ?, active = ?, public = ?,
            push_token = CASE WHEN ? = 'push' THEN COALESCE(push_token, ?) ELSE push_token END,
            group_id = ?, public_name = ?, parent_id = ?, updated_at = ?
         WHERE id = ?",
    )
    .bind(&m.name)
    .bind(&m.kind)
    .bind(&m.target)
    .bind(m.port)
    .bind(&m.method)
    .bind(&m.headers)
    .bind(&m.body)
    .bind(m.interval_s)
    .bind(m.retry_interval_s)
    .bind(m.timeout_s)
    .bind(m.failure_threshold)
    .bind(&m.expected_status)
    .bind(&m.ip_family)
    .bind(m.follow_redirects)
    .bind(m.ignore_tls)
    .bind(&m.content_kind)
    .bind(&m.content_value)
    .bind(&m.content_expected)
    .bind(m.ssl_warn_days)
    .bind(&m.dns_record_type)
    .bind(&m.dns_server)
    .bind(m.active)
    .bind(m.public)
    .bind(&m.kind)
    .bind(random_token(24))
    .bind(m.group_id)
    .bind(m.public_name.trim())
    .bind(m.parent_id)
    .bind(now_ms())
    .bind(id)
    .execute(db)
    .await?;
    Ok(())
}

pub async fn set_active(db: &Db, id: i64, active: bool) -> sqlx::Result<()> {
    sqlx::query("UPDATE monitors SET active = ?, updated_at = ? WHERE id = ?")
        .bind(active)
        .bind(now_ms())
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn delete(db: &Db, id: i64) -> sqlx::Result<()> {
    sqlx::query("DELETE FROM monitors WHERE id = ?").bind(id).execute(db).await?;
    Ok(())
}

pub async fn set_ssl_notified(db: &Db, id: i64, days: Option<i64>, expiry: Option<i64>) -> sqlx::Result<()> {
    sqlx::query("UPDATE monitors SET ssl_notified_days = ?, ssl_notified_expiry = ? WHERE id = ?")
        .bind(days)
        .bind(expiry)
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn channel_ids(db: &Db, monitor_id: i64) -> sqlx::Result<Vec<i64>> {
    sqlx::query_scalar("SELECT channel_id FROM monitor_notifications WHERE monitor_id = ?")
        .bind(monitor_id)
        .fetch_all(db)
        .await
}

pub async fn set_channels(db: &Db, monitor_id: i64, channel_ids: &[i64]) -> sqlx::Result<()> {
    let mut tx = db.begin().await?;
    sqlx::query("DELETE FROM monitor_notifications WHERE monitor_id = ?").bind(monitor_id).execute(&mut *tx).await?;
    for cid in channel_ids {
        sqlx::query("INSERT OR IGNORE INTO monitor_notifications (monitor_id, channel_id) VALUES (?, ?)")
            .bind(monitor_id)
            .bind(cid)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await
}

/// Moves a monitor; a parent drags its sub-monitors into the same group.
pub async fn move_to(db: &Db, id: i64, group_id: Option<i64>, parent_id: Option<i64>) -> sqlx::Result<()> {
    let mut tx = db.begin().await?;
    sqlx::query("UPDATE monitors SET group_id = ?, parent_id = ?, updated_at = ? WHERE id = ?")
        .bind(group_id)
        .bind(parent_id)
        .bind(now_ms())
        .bind(id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE monitors SET group_id = ? WHERE parent_id = ?").bind(group_id).bind(id).execute(&mut *tx).await?;
    tx.commit().await
}
