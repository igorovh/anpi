pub mod app;
pub mod auth;
pub mod checks;
pub mod config;
pub mod db;
pub mod demo;
pub mod models;
pub mod monitor;
pub mod notify;
pub mod report;
pub mod retention;
pub mod selfcheck;
pub mod stats;
pub mod tls;
pub mod update;
pub mod store;
pub mod util;
pub mod web;

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;

use app::Ctx;
use config::Config;
use monitor::scheduler::Scheduler;

pub struct App {
    pub ctx: Arc<Ctx>,
    pub scheduler: Arc<Scheduler>,
    pub state: web::AppState,
}

/// Builds the full application without binding a socket, so tests can drive it directly.
pub async fn build(config: Config, db: db::Db) -> anyhow::Result<App> {
    let ctx = Ctx::new(db, config);
    ctx.maintenance.reload(&ctx.db, util::now_ms()).await?;
    ctx.reload_branding().await?;
    ctx.reload_auth().await?;
    if ctx.auth().oidc.is_some_and(|o| !o.requires_role()) {
        tracing::warn!("SSO has no required role: every account the identity provider signs in becomes an admin");
    }
    let scheduler = Scheduler::new(ctx.clone());
    let state = web::AppState::new(ctx.clone(), scheduler.clone());
    if ctx.auth().oidc.is_none() && store::users::count(&ctx.db).await? == 0 {
        let code = util::random_token(9);
        tracing::warn!("no accounts yet: open /setup and enter setup code {code}");
        *state.setup_code.lock().expect("setup lock") = Some(code);
    }
    Ok(App { ctx, scheduler, state })
}

pub async fn run(config: Config) -> anyhow::Result<()> {
    run_until(config, shutdown_signal()).await
}

/// How long open requests may take to finish once shutdown starts.
const SHUTDOWN_GRACE: std::time::Duration = std::time::Duration::from_secs(5);

/// Runs the server until `stop` completes; live-update streams close at once, other requests get a short grace period.
pub async fn run_until(config: Config, stop: impl std::future::Future<Output = ()> + Send + 'static) -> anyhow::Result<()> {
    let db = db::open(&config.database_path).await.with_context(|| format!("opening {}", config.database_path.display()))?;
    let bind = config.bind;
    let app = build(config, db).await?;
    let tls = match &app.ctx.config.tls {
        Some((cert, key)) => Some(tls::load(cert, key)?),
        None => None,
    };
    let listener = tokio::net::TcpListener::bind(bind).await.with_context(|| format!("binding {bind}"))?;
    app.scheduler.start_all_missing().await?;
    retention::spawn(app.ctx.clone());
    selfcheck::spawn(app.ctx.clone());
    report::spawn(app.ctx.clone());

    let token = app.ctx.shutdown.clone();
    let signal = {
        let token = token.clone();
        async move {
            stop.await;
            tracing::info!("shutting down");
            token.cancel();
        }
    };
    let service = web::router(app.state.clone()).into_make_service_with_connect_info::<SocketAddr>();
    let served = async {
        match tls {
            Some(acceptor) => {
                tracing::info!("anpi listening on https://{bind}");
                let listener = axum::serve::ListenerExt::tap_io(tls::TlsListener::new(listener, acceptor)?, |_| {});
                axum::serve(listener, service).with_graceful_shutdown(signal).await
            }
            None => {
                tracing::info!("anpi listening on http://{bind}");
                axum::serve(listener, service).with_graceful_shutdown(signal).await
            }
        }
    };
    tokio::select! {
        r = served => r?,
        _ = async { token.cancelled().await; tokio::time::sleep(SHUTDOWN_GRACE).await } => {
            tracing::warn!("requests still open after {}s, stopping anyway", SHUTDOWN_GRACE.as_secs());
        }
    }
    app.scheduler.shutdown().await;
    tracing::info!("stopped");
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = term => {},
    }
}
