use std::path::Path;
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
    connect(opts, 8).await
}

pub async fn open_memory() -> anyhow::Result<Db> {
    let opts = SqliteConnectOptions::from_str("sqlite::memory:")?.foreign_keys(true);
    // A single connection keeps every query on the same in-memory database.
    connect(opts, 1).await
}

async fn connect(opts: SqliteConnectOptions, max: u32) -> anyhow::Result<Db> {
    let pool = SqlitePoolOptions::new()
        .max_connections(max)
        .min_connections(1)
        .idle_timeout(None)
        .max_lifetime(None)
        .connect_with(opts)
        .await?;
    sqlx::migrate!("./migrations").run(&pool).await.context("running migrations")?;
    Ok(pool)
}
