use crate::db::Db;
use crate::util::now_ms;

pub struct Asset {
    pub content_type: String,
    pub data: Vec<u8>,
    pub updated_at: i64,
}

pub async fn get(db: &Db, key: &str) -> sqlx::Result<Option<Asset>> {
    let row: Option<(String, Vec<u8>, i64)> =
        sqlx::query_as("SELECT content_type, data, updated_at FROM assets WHERE key = ?").bind(key).fetch_optional(db).await?;
    Ok(row.map(|(content_type, data, updated_at)| Asset { content_type, data, updated_at }))
}

pub async fn version(db: &Db, key: &str) -> sqlx::Result<Option<i64>> {
    sqlx::query_scalar("SELECT updated_at FROM assets WHERE key = ?").bind(key).fetch_optional(db).await
}

pub async fn put(db: &Db, key: &str, content_type: &str, data: &[u8]) -> sqlx::Result<i64> {
    let now = now_ms();
    sqlx::query(
        "INSERT INTO assets (key, content_type, data, updated_at) VALUES (?, ?, ?, ?)
         ON CONFLICT(key) DO UPDATE SET content_type = excluded.content_type, data = excluded.data, updated_at = excluded.updated_at",
    )
    .bind(key)
    .bind(content_type)
    .bind(data)
    .bind(now)
    .execute(db)
    .await?;
    Ok(now)
}

pub async fn delete(db: &Db, key: &str) -> sqlx::Result<()> {
    sqlx::query("DELETE FROM assets WHERE key = ?").bind(key).execute(db).await?;
    Ok(())
}
