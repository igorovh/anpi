use crate::db::Db;
use crate::util::{now_ms, random_token, sha256_hex};

pub const PREFIX: &str = "anpi_";
/// `last_used_at` is written at most this often, so API calls do not each cost a write.
const TOUCH_EVERY_MS: i64 = 60_000;

#[derive(Clone, Debug, sqlx::FromRow)]
pub struct ApiToken {
    pub id: i64,
    pub name: String,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
}

pub async fn list(db: &Db) -> sqlx::Result<Vec<ApiToken>> {
    sqlx::query_as("SELECT id, name, created_at, last_used_at FROM api_tokens ORDER BY created_at, id").fetch_all(db).await
}

/// Returns the raw token; only its hash is stored, so it cannot be shown again.
pub async fn create(db: &Db, name: &str) -> sqlx::Result<(i64, String)> {
    let token = format!("{PREFIX}{}", random_token(32));
    let id = sqlx::query_scalar("INSERT INTO api_tokens (name, token_hash, created_at) VALUES (?, ?, ?) RETURNING id")
        .bind(name)
        .bind(sha256_hex(&token))
        .bind(now_ms())
        .fetch_one(db)
        .await?;
    Ok((id, token))
}

pub async fn delete(db: &Db, id: i64) -> sqlx::Result<()> {
    sqlx::query("DELETE FROM api_tokens WHERE id = ?").bind(id).execute(db).await?;
    Ok(())
}

pub async fn verify(db: &Db, token: &str) -> sqlx::Result<Option<ApiToken>> {
    if !token.starts_with(PREFIX) {
        return Ok(None);
    }
    let found: Option<ApiToken> = sqlx::query_as("SELECT id, name, created_at, last_used_at FROM api_tokens WHERE token_hash = ?")
        .bind(sha256_hex(token))
        .fetch_optional(db)
        .await?;
    let now = now_ms();
    if let Some(t) = &found
        && t.last_used_at.is_none_or(|at| now - at >= TOUCH_EVERY_MS)
    {
        sqlx::query("UPDATE api_tokens SET last_used_at = ? WHERE id = ?").bind(now).bind(t.id).execute(db).await?;
    }
    Ok(found)
}
