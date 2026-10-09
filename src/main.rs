use std::io::BufRead;
use std::process::ExitCode;
use std::time::Duration;

use anpi::config::Config;
use tracing_subscriber::EnvFilter;

const USAGE: &str = "usage:
  anpi                          start the server
  anpi healthcheck              exit 0 if the local server answers /healthz
  anpi reset-password <user>    set a new password (read from stdin)
  anpi disable-sso              turn off SSO set in the panel so passwords work again
  anpi demo                     fill an empty database with example monitors and history";

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_env("ANPI_LOG").unwrap_or_else(|_| EnvFilter::new("info,sqlx=warn,hyper=warn")))
        .init();

    let config = match Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("configuration error: {e:#}");
            return ExitCode::from(2);
        }
    };
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        None | Some("serve") => anpi::run(config).await,
        Some("healthcheck") => healthcheck(&config).await,
        Some("reset-password") => match args.get(1) {
            Some(user) => reset_password(&config, user).await,
            None => Err(anyhow::anyhow!(USAGE)),
        },
        Some("disable-sso") => disable_sso(&config).await,
        Some("demo") => demo(&config).await,
        Some(_) => Err(anyhow::anyhow!(USAGE)),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e:#}");
            ExitCode::FAILURE
        }
    }
}

async fn healthcheck(config: &Config) -> anyhow::Result<()> {
    let port = config.bind.port();
    let url = url::Url::parse(&format!("http://127.0.0.1:{port}/healthz"))?;
    let mut spec = anpi::checks::http::RequestSpec::new(http::Method::GET, url);
    spec.timeout = Duration::from_secs(5);
    let r = anpi::checks::http::send(&spec).await?;
    anyhow::ensure!(r.status == 200, "unhealthy: HTTP {}", r.status);
    Ok(())
}

async fn demo(config: &Config) -> anyhow::Result<()> {
    let db = anpi::db::open(&config.database_path).await?;
    let n = anpi::demo::seed(&db).await?;
    eprintln!("added {n} example monitors with 30 days of history to {}", config.database_path.display());
    Ok(())
}

async fn disable_sso(config: &Config) -> anyhow::Result<()> {
    if config.oidc.is_some() {
        anyhow::bail!("SSO is set through ANPI_OIDC_* environment variables; remove them instead");
    }
    let db = anpi::db::open(&config.database_path).await?;
    anpi::auth::sso::disable(&db).await?;
    eprintln!("SSO turned off; restart anpi and sign in with a password (see `anpi reset-password` if needed)");
    Ok(())
}

async fn reset_password(config: &Config, username: &str) -> anyhow::Result<()> {
    let db = anpi::db::open(&config.database_path).await?;
    let user = anpi::store::users::by_username(&db, username).await?.ok_or_else(|| anyhow::anyhow!("no user named {username}"))?;
    eprintln!("new password for {username}:");
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    let pw = line.trim_end_matches(['\r', '\n']);
    anpi::auth::password::check_strength(pw).map_err(anyhow::Error::msg)?;
    anpi::store::users::set_password(&db, user.id, &anpi::auth::password::hash(pw)?).await?;
    anpi::store::users::delete_user_sessions(&db, user.id).await?;
    eprintln!("password updated; existing sessions were signed out");
    Ok(())
}
