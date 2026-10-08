use crate::db::Db;
use crate::models::NotificationChannel;
use crate::util::now_ms;

pub async fn list(db: &Db) -> sqlx::Result<Vec<NotificationChannel>> {
    sqlx::query_as("SELECT * FROM notification_channels ORDER BY name COLLATE NOCASE").fetch_all(db).await
}

pub async fn get(db: &Db, id: i64) -> sqlx::Result<Option<NotificationChannel>> {
    sqlx::query_as("SELECT * FROM notification_channels WHERE id = ?").bind(id).fetch_optional(db).await
}

pub async fn for_monitor(db: &Db, monitor_id: i64) -> sqlx::Result<Vec<NotificationChannel>> {
    sqlx::query_as(
        "SELECT c.* FROM notification_channels c JOIN monitor_notifications mn ON mn.channel_id = c.id
         WHERE mn.monitor_id = ? AND c.active = 1",
    )
    .bind(monitor_id)
    .fetch_all(db)
    .await
}

pub async fn default_ids(db: &Db) -> sqlx::Result<Vec<i64>> {
    sqlx::query_scalar("SELECT id FROM notification_channels WHERE is_default = 1").fetch_all(db).await
}

pub async fn create(db: &Db, name: &str, kind: &str, config: &str, active: bool, is_default: bool) -> sqlx::Result<i64> {
    sqlx::query_scalar(
        "INSERT INTO notification_channels (name, kind, config, active, is_default, created_at)
         VALUES (?, ?, ?, ?, ?, ?) RETURNING id",
    )
    .bind(name)
    .bind(kind)
    .bind(config)
    .bind(active)
    .bind(is_default)
    .bind(now_ms())
    .fetch_one(db)
    .await
}

pub async fn update(db: &Db, id: i64, name: &str, kind: &str, config: &str, active: bool, is_default: bool) -> sqlx::Result<()> {
    sqlx::query("UPDATE notification_channels SET name = ?, kind = ?, config = ?, active = ?, is_default = ? WHERE id = ?")
        .bind(name)
        .bind(kind)
        .bind(config)
        .bind(active)
        .bind(is_default)
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn delete(db: &Db, id: i64) -> sqlx::Result<()> {
    sqlx::query("DELETE FROM notification_channels WHERE id = ?").bind(id).execute(db).await?;
    Ok(())
}
