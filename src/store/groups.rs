use crate::db::Db;
use crate::models::MonitorGroup;
use crate::util::now_ms;

pub async fn list(db: &Db) -> sqlx::Result<Vec<MonitorGroup>> {
    sqlx::query_as("SELECT * FROM monitor_groups ORDER BY sort_order, name COLLATE NOCASE").fetch_all(db).await
}

pub async fn create(db: &Db, name: &str, sort_order: i64) -> sqlx::Result<i64> {
    sqlx::query_scalar("INSERT INTO monitor_groups (name, sort_order, created_at) VALUES (?, ?, ?) RETURNING id")
        .bind(name)
        .bind(sort_order)
        .bind(now_ms())
        .fetch_one(db)
        .await
}

pub async fn update(db: &Db, id: i64, name: &str, sort_order: i64) -> sqlx::Result<()> {
    sqlx::query("UPDATE monitor_groups SET name = ?, sort_order = ? WHERE id = ?")
        .bind(name)
        .bind(sort_order)
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

/// Monitors in a deleted group become ungrouped (ON DELETE SET NULL).
pub async fn delete(db: &Db, id: i64) -> sqlx::Result<()> {
    sqlx::query("DELETE FROM monitor_groups WHERE id = ?").bind(id).execute(db).await?;
    Ok(())
}

pub async fn next_sort_order(db: &Db) -> sqlx::Result<i64> {
    let max: Option<i64> = sqlx::query_scalar("SELECT MAX(sort_order) FROM monitor_groups").fetch_one(db).await?;
    Ok(max.map_or(10, |m| m + 10))
}
