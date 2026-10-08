use crate::db::Db;
use crate::models::User;
use crate::util::{now_ms, random_token, sha256_hex};

pub const SESSION_TTL_MS: i64 = 7 * 24 * 3_600_000;

pub async fn count(db: &Db) -> sqlx::Result<i64> {
    sqlx::query_scalar("SELECT COUNT(*) FROM users").fetch_one(db).await
}

pub async fn list(db: &Db) -> sqlx::Result<Vec<User>> {
    sqlx::query_as("SELECT * FROM users ORDER BY username").fetch_all(db).await
}

pub async fn by_username(db: &Db, username: &str) -> sqlx::Result<Option<User>> {
    sqlx::query_as("SELECT * FROM users WHERE username = ? COLLATE NOCASE").bind(username).fetch_optional(db).await
}

pub async fn by_id(db: &Db, id: i64) -> sqlx::Result<Option<User>> {
    sqlx::query_as("SELECT * FROM users WHERE id = ?").bind(id).fetch_optional(db).await
}

pub async fn create_local(db: &Db, username: &str, password_hash: &str) -> sqlx::Result<i64> {
    sqlx::query_scalar("INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?) RETURNING id")
        .bind(username)
        .bind(password_hash)
        .bind(now_ms())
        .fetch_one(db)
        .await
}

pub async fn set_password(db: &Db, id: i64, password_hash: &str) -> sqlx::Result<()> {
    sqlx::query("UPDATE users SET password_hash = ? WHERE id = ?").bind(password_hash).bind(id).execute(db).await?;
    Ok(())
}

pub async fn delete(db: &Db, id: i64) -> sqlx::Result<()> {
    sqlx::query("DELETE FROM users WHERE id = ?").bind(id).execute(db).await?;
    Ok(())
}

/// Finds the user linked to an OIDC subject, creating it on first login.
pub async fn upsert_oidc(db: &Db, issuer: &str, subject: &str, preferred_name: &str) -> sqlx::Result<User> {
    if let Some(u) = sqlx::query_as("SELECT * FROM users WHERE oidc_issuer = ? AND oidc_subject = ?")
        .bind(issuer)
        .bind(subject)
        .fetch_optional(db)
        .await?
    {
        return Ok(u);
    }
    let mut username = preferred_name.to_string();
    if by_username(db, &username).await?.is_some() {
        username = format!("{preferred_name}-{}", subject.chars().take(8).collect::<String>());
    }
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO users (username, oidc_issuer, oidc_subject, created_at) VALUES (?, ?, ?, ?) RETURNING id",
    )
    .bind(&username)
    .bind(issuer)
    .bind(subject)
    .bind(now_ms())
    .fetch_one(db)
    .await?;
    Ok(by_id(db, id).await?.expect("just inserted"))
}

pub struct SessionInfo {
    pub user_id: i64,
    pub username: String,
    pub csrf: String,
    pub id_token: Option<String>,
}

/// Returns the raw session token for the cookie; only its hash is stored.
pub async fn create_session(db: &Db, user_id: i64, id_token: Option<&str>) -> sqlx::Result<String> {
    let token = random_token(32);
    let now = now_ms();
    sqlx::query(
        "INSERT INTO sessions (token_hash, user_id, csrf, id_token, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(sha256_hex(&token))
    .bind(user_id)
    .bind(random_token(24))
    .bind(id_token)
    .bind(now)
    .bind(now + SESSION_TTL_MS)
    .execute(db)
    .await?;
    Ok(token)
}

pub async fn session(db: &Db, token: &str) -> sqlx::Result<Option<SessionInfo>> {
    let row: Option<(i64, String, String, Option<String>)> = sqlx::query_as(
        "SELECT s.user_id, u.username, s.csrf, s.id_token FROM sessions s JOIN users u ON u.id = s.user_id
         WHERE s.token_hash = ? AND s.expires_at > ?",
    )
    .bind(sha256_hex(token))
    .bind(now_ms())
    .fetch_optional(db)
    .await?;
    Ok(row.map(|(user_id, username, csrf, id_token)| SessionInfo { user_id, username, csrf, id_token }))
}

pub async fn delete_session(db: &Db, token: &str) -> sqlx::Result<()> {
    sqlx::query("DELETE FROM sessions WHERE token_hash = ?").bind(sha256_hex(token)).execute(db).await?;
    Ok(())
}

pub async fn delete_user_sessions(db: &Db, user_id: i64) -> sqlx::Result<()> {
    sqlx::query("DELETE FROM sessions WHERE user_id = ?").bind(user_id).execute(db).await?;
    Ok(())
}
