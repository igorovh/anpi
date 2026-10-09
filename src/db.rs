use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use anyhow::Context;
use sqlx::SqlitePool;
use sqlx::sqlite::{SqliteAutoVacuum, SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};

pub type Db = SqlitePool;

pub async fn open(path: &Path) -> anyhow::Result<Db> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    let opts = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal)
        .auto_vacuum(SqliteAutoVacuum::Incremental)
        .foreign_keys(true)
        .busy_timeout(Duration::from_secs(10));
    connect(opts, 8, Some(path)).await
}

pub async fn open_memory() -> anyhow::Result<Db> {
    let opts = SqliteConnectOptions::from_str("sqlite::memory:")?.foreign_keys(true);
    // A single connection keeps every query on the same in-memory database.
    connect(opts, 1, None).await
}

async fn connect(opts: SqliteConnectOptions, max: u32, file: Option<&Path>) -> anyhow::Result<Db> {
    let pool = SqlitePoolOptions::new()
        .max_connections(max)
        .min_connections(1)
        .idle_timeout(None)
        .max_lifetime(None)
        .connect_with(opts)
        .await?;
    if let Some(path) = file {
        backup_before_migrations(&pool, path).await.context("backing up the database before upgrading it")?;
    }
    sqlx::migrate!("./migrations").run(&pool).await.context("running migrations")?;
    Ok(pool)
}

/// Copies an existing database to `<file>.before-<version>` when this version will change its schema.
async fn backup_before_migrations(pool: &Db, path: &Path) -> anyhow::Result<Option<PathBuf>> {
    let initialised: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = '_sqlx_migrations')")
        .fetch_one(pool)
        .await?;
    if !initialised {
        return Ok(None);
    }
    let applied: Vec<i64> = sqlx::query_scalar("SELECT version FROM _sqlx_migrations WHERE success = 1").fetch_all(pool).await?;
    if sqlx::migrate!("./migrations").iter().all(|m| applied.contains(&m.version)) {
        return Ok(None);
    }
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "anpi.db".into());
    let dest = path.with_file_name(format!("{name}.before-{}", env!("CARGO_PKG_VERSION")));
    if dest.exists() {
        return Ok(None);
    }
    sqlx::query("VACUUM INTO ?").bind(dest.to_string_lossy().into_owned()).execute(pool).await?;
    tracing::info!(backup = %dest.display(), "database backed up before upgrading its schema");
    Ok(Some(dest))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn backs_up_only_when_migrations_are_pending() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("anpi.db");
        let db = open(&path).await.unwrap();
        assert_eq!(backup_before_migrations(&db, &path).await.unwrap(), None, "up to date: no backup");

        // Pretend the database comes from a version without the newest migration.
        crate::store::groups::create(&db, "kept", 0).await.unwrap();
        sqlx::query("DELETE FROM _sqlx_migrations WHERE version = (SELECT MAX(version) FROM _sqlx_migrations)").execute(&db).await.unwrap();
        let dest = backup_before_migrations(&db, &path).await.unwrap().expect("a backup");
        assert!(dest.file_name().unwrap().to_string_lossy().starts_with("anpi.db.before-"));
        let copy = SqlitePool::connect(&format!("sqlite://{}", dest.display())).await.unwrap();
        let name: String = sqlx::query_scalar("SELECT name FROM monitor_groups").fetch_one(&copy).await.unwrap();
        assert_eq!(name, "kept");
        assert_eq!(backup_before_migrations(&db, &path).await.unwrap(), None, "an existing backup is not overwritten");
    }
}
