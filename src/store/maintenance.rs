use crate::db::Db;
use crate::models::Maintenance;
use crate::util::now_ms;

pub async fn list(db: &Db) -> sqlx::Result<Vec<Maintenance>> {
    sqlx::query_as("SELECT * FROM maintenances ORDER BY starts_at DESC").fetch_all(db).await
}

/// Windows that have not ended yet, with their monitor ids.
pub async fn upcoming_with_monitors(db: &Db, now: i64) -> sqlx::Result<Vec<(Maintenance, Vec<i64>)>> {
    let windows: Vec<Maintenance> =
        sqlx::query_as("SELECT * FROM maintenances WHERE ends_at > ?").bind(now).fetch_all(db).await?;
    let mut out = Vec::with_capacity(windows.len());
    for w in windows {
        let ids = monitor_ids(db, w.id).await?;
        out.push((w, ids));
    }
    Ok(out)
}

pub async fn monitor_ids(db: &Db, id: i64) -> sqlx::Result<Vec<i64>> {
    sqlx::query_scalar("SELECT monitor_id FROM maintenance_monitors WHERE maintenance_id = ?").bind(id).fetch_all(db).await
}

pub async fn create(db: &Db, title: &str, starts_at: i64, ends_at: i64, all: bool, monitors: &[i64]) -> sqlx::Result<i64> {
    let mut tx = db.begin().await?;
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO maintenances (title, starts_at, ends_at, all_monitors, created_at) VALUES (?, ?, ?, ?, ?) RETURNING id",
    )
    .bind(title)
    .bind(starts_at)
    .bind(ends_at)
    .bind(all)
    .bind(now_ms())
    .fetch_one(&mut *tx)
    .await?;
    for m in monitors {
        sqlx::query("INSERT OR IGNORE INTO maintenance_monitors (maintenance_id, monitor_id) VALUES (?, ?)")
            .bind(id)
            .bind(m)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(id)
}

pub async fn delete(db: &Db, id: i64) -> sqlx::Result<()> {
    sqlx::query("DELETE FROM maintenances WHERE id = ?").bind(id).execute(db).await?;
    Ok(())
}
