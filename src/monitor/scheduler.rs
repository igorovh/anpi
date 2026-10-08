use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Mutex, RwLock, Semaphore, mpsc};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::MonitorEvent;
use super::ssl;
use super::state::{MonitorState, Transition};
use crate::app::Ctx;
use crate::checks;
use crate::models::{CheckOutcome, Monitor, MonitorKind, NewHeartbeat, Status, Timings};
use crate::notify::{self, EventKind, NotifyEvent};
use crate::store;
use crate::util::now_ms;

#[derive(Debug)]
pub struct PushSignal {
    pub ok: bool,
    pub message: String,
    pub ping_ms: Option<f64>,
}

struct Running {
    cancel: CancellationToken,
    handle: JoinHandle<()>,
    push_token: Option<String>,
}

pub struct Scheduler {
    ctx: Arc<Ctx>,
    tasks: Mutex<HashMap<i64, Running>>,
    push: RwLock<HashMap<String, mpsc::Sender<PushSignal>>>,
    permits: Arc<Semaphore>,
}

impl Scheduler {
    pub fn new(ctx: Arc<Ctx>) -> Arc<Self> {
        let permits = Arc::new(Semaphore::new(ctx.config.max_concurrent_checks.max(1)));
        Arc::new(Self { ctx, tasks: Mutex::new(HashMap::new()), push: RwLock::new(HashMap::new()), permits })
    }

    pub async fn start_all_missing(&self) -> anyhow::Result<()> {
        for m in store::monitors::list_active(&self.ctx.db).await? {
            if !self.is_running(m.id).await {
                self.spawn(m).await;
            }
        }
        Ok(())
    }

    /// Restarts the task for a monitor after it was created, edited, paused or deleted.
    pub async fn reload(&self, id: i64) -> anyhow::Result<()> {
        self.stop(id).await;
        if let Some(m) = store::monitors::get(&self.ctx.db, id).await?
            && m.active
        {
            self.spawn(m).await;
        }
        Ok(())
    }

    pub async fn stop(&self, id: i64) {
        let running = self.tasks.lock().await.remove(&id);
        if let Some(r) = running {
            r.cancel.cancel();
            if let Some(t) = r.push_token {
                self.push.write().await.remove(&t);
            }
            let _ = r.handle.await;
        }
    }

    pub async fn shutdown(&self) {
        let ids: Vec<i64> = self.tasks.lock().await.keys().copied().collect();
        for id in ids {
            self.stop(id).await;
        }
        self.ctx.writer.flush().await;
    }

    pub async fn is_running(&self, id: i64) -> bool {
        self.tasks.lock().await.contains_key(&id)
    }

    /// Returns false when no active push monitor uses this token.
    pub async fn push(&self, token: &str, signal: PushSignal) -> bool {
        let sender = self.push.read().await.get(token).cloned();
        match sender {
            Some(tx) => tx.send(signal).await.is_ok(),
            None => false,
        }
    }

    async fn spawn(&self, m: Monitor) {
        let cancel = CancellationToken::new();
        let (push_rx, push_token) = match (m.kind(), &m.push_token) {
            (MonitorKind::Push, Some(token)) => {
                let (tx, rx) = mpsc::channel(16);
                self.push.write().await.insert(token.clone(), tx);
                (Some(rx), Some(token.clone()))
            }
            _ => (None, None),
        };
        let handle = tokio::spawn(run_monitor(self.ctx.clone(), self.permits.clone(), m.clone(), cancel.clone(), push_rx));
        self.tasks.lock().await.insert(m.id, Running { cancel, handle, push_token });
    }
}

async fn restore_state(ctx: &Ctx, m: &Monitor) -> MonitorState {
    let limit = m.failure_threshold.max(1) + 1;
    match store::heartbeats::recent(&ctx.db, m.id, limit).await {
        Ok(beats) => MonitorState::restore(&beats.iter().map(|b| b.status()).collect::<Vec<_>>()),
        Err(_) => MonitorState::new(),
    }
}

async fn run_monitor(
    ctx: Arc<Ctx>,
    permits: Arc<Semaphore>,
    mut m: Monitor,
    cancel: CancellationToken,
    mut push_rx: Option<mpsc::Receiver<PushSignal>>,
) {
    let mut state = restore_state(&ctx, &m).await;
    let interval = Duration::from_secs(m.interval_s.max(1) as u64);
    let retry_interval = Duration::from_secs(m.retry_interval_s.max(1) as u64);

    // Spread start-up so all monitors don't fire in the same instant.
    let jitter = Duration::from_millis(rand::random::<u64>() % (interval.as_millis() as u64 / 10).clamp(1, 3000));
    tokio::select! {
        _ = cancel.cancelled() => return,
        _ = tokio::time::sleep(jitter) => {}
    }

    loop {
        let outcome = if let Some(rx) = push_rx.as_mut() {
            tokio::select! {
                _ = cancel.cancelled() => return,
                sig = rx.recv() => match sig {
                    None => return,
                    Some(s) => CheckOutcome {
                        ok: s.ok,
                        message: if s.message.is_empty() { if s.ok { "push received".into() } else { "push reported failure".into() } } else { s.message },
                        timings: Timings { total_ms: s.ping_ms, ..Default::default() },
                        ..Default::default()
                    },
                },
                _ = tokio::time::sleep(interval) => CheckOutcome::fail(format!("no push received within {}s", interval.as_secs())),
            }
        } else {
            let Ok(_permit) = permits.acquire().await else { return };
            tokio::select! {
                _ = cancel.cancelled() => return,
                o = checks::run(&m) => o,
            }
        };

        let status = process(&ctx, &mut m, &mut state, outcome).await;

        if push_rx.is_none() {
            let wait = if status == Status::Pending { retry_interval } else { interval };
            tokio::select! {
                _ = cancel.cancelled() => return,
                _ = tokio::time::sleep(wait) => {}
            }
        }
    }
}

pub(crate) async fn process(ctx: &Arc<Ctx>, m: &mut Monitor, state: &mut MonitorState, outcome: CheckOutcome) -> Status {
    let now = now_ms();
    let in_maintenance = ctx.maintenance.active_for(m.id, now);
    let (status, transition) = state.apply(outcome.ok, m.failure_threshold.max(1) as u32, in_maintenance);

    ctx.writer
        .send(NewHeartbeat {
            monitor_id: m.id,
            ts: now,
            status,
            status_code: outcome.status_code,
            timings: outcome.timings.clone(),
            remote_ip: outcome.remote_ip.clone(),
            message: outcome.message.clone(),
            cert_expires_at: outcome.cert_expires_at,
        })
        .await;
    let _ = ctx.events.send(Arc::new(MonitorEvent::new(m.id, m.public, status, outcome.timings.total_ms, &outcome.message, now)));

    match transition {
        Transition::None => {}
        Transition::WentDown => {
            tracing::warn!(monitor = %m.name, reason = %outcome.message, "monitor down");
            if let Ok(None) = store::heartbeats::open_incident(&ctx.db, m.id).await {
                let _ = store::heartbeats::create_incident(&ctx.db, m.id, now, &outcome.message).await;
            }
            spawn_notify(ctx, m, EventKind::Down, outcome.message.clone(), now);
        }
        Transition::Recovered => {
            tracing::info!(monitor = %m.name, "monitor recovered");
            let mut downtime = None;
            if let Ok(Some(inc)) = store::heartbeats::open_incident(&ctx.db, m.id).await {
                let _ = store::heartbeats::close_incident(&ctx.db, inc.id, now).await;
                downtime = Some(now - inc.started_at);
            }
            spawn_notify(ctx, m, EventKind::Up { downtime_ms: downtime }, outcome.message.clone(), now);
        }
    }

    if let Some(expires_at) = outcome.cert_expires_at
        && let Some(step) = ssl::warning_due(m.ssl_warn_days, expires_at, now, m.ssl_notified_days, m.ssl_notified_expiry)
    {
        m.ssl_notified_days = Some(step);
        m.ssl_notified_expiry = Some(expires_at);
        let _ = store::monitors::set_ssl_notified(&ctx.db, m.id, Some(step), Some(expires_at)).await;
        let days_left = ssl::days_left(expires_at, now);
        spawn_notify(ctx, m, EventKind::SslExpiring { days_left, expires_at }, String::new(), now);
    }
    status
}

fn spawn_notify(ctx: &Arc<Ctx>, m: &Monitor, kind: EventKind, message: String, at: i64) {
    let ev = NotifyEvent { kind, monitor_name: m.name.clone(), target: m.display_target(), message, at };
    let db = ctx.db.clone();
    let id = m.id;
    tokio::spawn(async move { notify::notify_monitor(&db, id, ev).await });
}
