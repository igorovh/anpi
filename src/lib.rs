pub mod app;
pub mod auth;
pub mod checks;
pub mod config;
pub mod db;
pub mod demo;
pub mod kuma;
pub mod models;
pub mod monitor;
pub mod notify;
pub mod retention;
pub mod stats;
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
    let db = db::open(&config.database_path).await.with_context(|| format!("opening {}", config.database_path.display()))?;
    let bind = config.bind;
    let app = build(config, db).await?;
    app.scheduler.start_all_missing().await?;
    retention::spawn(app.ctx.clone());

    let listener = tokio::net::TcpListener::bind(bind).await.with_context(|| format!("binding {bind}"))?;
    tracing::info!("anpi listening on http://{bind}");
    axum::serve(listener, web::router(app.state.clone()).into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(shutdown_signal())
        .await?;
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
