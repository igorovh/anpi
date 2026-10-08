use std::time::Duration;

use tokio::sync::{mpsc, oneshot};

use crate::db::Db;
use crate::models::NewHeartbeat;
use crate::store;

enum Msg {
    Beat(NewHeartbeat),
    Flush(oneshot::Sender<()>),
}

/// Batches heartbeat inserts so many concurrent checks cost one SQLite transaction.
#[derive(Clone)]
pub struct Writer {
    tx: mpsc::Sender<Msg>,
}

impl Writer {
    pub fn spawn(db: Db) -> Self {
        let (tx, rx) = mpsc::channel(4096);
        tokio::spawn(run(db, rx));
        Self { tx }
    }

    pub async fn send(&self, beat: NewHeartbeat) {
        let _ = self.tx.send(Msg::Beat(beat)).await;
    }

    pub async fn flush(&self) {
        let (tx, rx) = oneshot::channel();
        if self.tx.send(Msg::Flush(tx)).await.is_ok() {
            let _ = rx.await;
        }
    }
}

async fn run(db: Db, mut rx: mpsc::Receiver<Msg>) {
    let mut batch: Vec<NewHeartbeat> = Vec::new();
    while let Some(first) = rx.recv().await {
        let mut waiters = Vec::new();
        let mut next = Some(first);
        let deadline = tokio::time::Instant::now() + Duration::from_millis(250);
        while let Some(m) = next.take() {
            match m {
                Msg::Beat(b) => batch.push(b),
                Msg::Flush(w) => waiters.push(w),
            }
            if batch.len() >= 500 || !waiters.is_empty() {
                break;
            }
            next = tokio::time::timeout_at(deadline, rx.recv()).await.ok().flatten();
        }
        if !batch.is_empty() {
            if let Err(e) = store::heartbeats::insert_batch(&db, &batch).await {
                tracing::error!(error = %e, count = batch.len(), "failed to store heartbeats");
            }
            batch.clear();
        }
        for w in waiters {
            let _ = w.send(());
        }
    }
}
