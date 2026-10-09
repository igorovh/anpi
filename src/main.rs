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
  anpi demo                     fill an empty database with example monitors and history
  anpi export [file]            write the configuration as JSON (stdout by default)
  anpi import <file> [--replace]  load a configuration export
  anpi version                  print the version
  anpi update [--check] [--version X.Y.Z] [--no-restart]
                                install the latest release from GitHub and restart the service
  anpi update --rollback        go back to the binary that was replaced";

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_env("ANPI_LOG").unwrap_or_else(|_| EnvFilter::new("info,sqlx=warn,hyper=warn")))
        .init();

    let args: Vec<String> = std::env::args().skip(1).collect();
    // These work without a valid server configuration.
    match args.first().map(String::as_str) {
        Some("version" | "--version" | "-V") => {
            println!("{}", anpi::update::CURRENT);
            return ExitCode::SUCCESS;
        }
        Some("update") => return finish(update(&args[1..]).await),
        _ => {}
    }

    let config = match Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("configuration error: {e:#}");
            return ExitCode::from(2);
        }
    };
    let result = match args.first().map(String::as_str) {
        None | Some("serve") => anpi::run(config).await,
        Some("healthcheck") => healthcheck(&config).await,
        Some("reset-password") => match args.get(1) {
            Some(user) => reset_password(&config, user).await,
            None => Err(anyhow::anyhow!(USAGE)),
        },
        Some("disable-sso") => disable_sso(&config).await,
        Some("demo") => demo(&config).await,
        Some("export") => export(&config, args.get(1)).await,
        Some("import") => match args.get(1) {
            Some(file) => import(&config, file, args.iter().any(|a| a == "--replace")).await,
            None => Err(anyhow::anyhow!(USAGE)),
        },
        Some(_) => Err(anyhow::anyhow!(USAGE)),
    };
    finish(result)
}

fn finish(result: anyhow::Result<()>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e:#}");
            ExitCode::FAILURE
        }
    }
}

async fn update(args: &[String]) -> anyhow::Result<()> {
    use anpi::update::{self, CURRENT, parse_version};
    use anyhow::Context;
    let flag = |f: &str| args.iter().any(|a| a == f);
    let wanted = args.iter().position(|a| a == "--version").map(|i| args.get(i + 1).context(USAGE)).transpose()?;
    if let Some(a) = args.iter().find(|a| a.starts_with("--") && !["--check", "--version", "--no-restart", "--rollback"].contains(&a.as_str())) {
        anyhow::bail!("unknown option {a}\n{USAGE}");
    }
    let exe = std::env::current_exe()?.canonicalize()?;

    if flag("--rollback") {
        update::rollback(&exe)?;
        eprintln!("restored the previous binary; if the database was upgraded, its backup sits next to it as *.before-<version>");
        return restart(flag("--no-restart"));
    }
    let release = update::fetch_release(wanted.map(String::as_str)).await?;
    let latest = release.version()?;
    let current = parse_version(CURRENT).context("unexpected own version")?;
    let tag = release.tag_name.trim_start_matches('v').to_string();

    if flag("--check") {
        println!("installed {CURRENT}, latest {tag}");
        if latest > current {
            println!("changes: {}\nrun `sudo anpi update` to install it", release.html_url);
        }
        return Ok(());
    }
    if wanted.is_none() && latest <= current {
        eprintln!("anpi {CURRENT} is up to date");
        return Ok(());
    }
    if latest == current {
        eprintln!("anpi {CURRENT} is already installed");
        return Ok(());
    }

    let target = update::TARGET.context("self-update supports Linux (x86_64, arm64) and macOS on Apple Silicon; download other builds from the releases page")?;
    let (archive, sum) = release.archive_for(target).with_context(|| format!("release {tag} has no {target} build with a checksum"))?;
    eprintln!("downloading anpi {tag} for {target}…");
    let data = update::download(&archive.browser_download_url, "application/octet-stream", 256 * 1024 * 1024).await?;
    let sum = update::download(&sum.browser_download_url, "application/octet-stream", 4096).await?;
    update::verify_sha256(&data, &String::from_utf8_lossy(&sum))?;
    let binary = update::extract_binary(&data)?;
    update::replace_binary(&exe, &binary)?;

    // Refuse a binary that cannot even report its version, e.g. a wrong architecture.
    let reported = std::process::Command::new(&exe).arg("version").output().ok().map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());
    if reported.as_deref() != Some(tag.as_str()) {
        update::rollback(&exe)?;
        anyhow::bail!("the new binary did not start correctly (reported {reported:?}); kept {CURRENT}");
    }
    eprintln!("updated {CURRENT} → {tag} ({}); the previous binary is kept as {}", exe.display(), update::backup_path(&exe).display());
    restart(flag("--no-restart"))
}

/// Restarts the systemd unit if one is running; otherwise says what to do.
fn restart(skip: bool) -> anyhow::Result<()> {
    use std::process::Command;
    let under_systemd = std::path::Path::new("/run/systemd/system").exists();
    let active = under_systemd && Command::new("systemctl").args(["is-active", "--quiet", "anpi"]).status().is_ok_and(|s| s.success());
    if skip || !active {
        eprintln!("restart anpi to run the new version");
        return Ok(());
    }
    let ok = Command::new("systemctl").args(["restart", "anpi"]).status().is_ok_and(|s| s.success());
    anyhow::ensure!(ok, "the binary was replaced but `systemctl restart anpi` failed; run it yourself");
    eprintln!("restarted anpi.service");
    Ok(())
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

async fn export(config: &Config, file: Option<&String>) -> anyhow::Result<()> {
    let db = anpi::db::open(&config.database_path).await?;
    let json = serde_json::to_string_pretty(&anpi::web::backup::export(&db).await?)?;
    match file {
        Some(path) => {
            std::fs::write(path, json)?;
            eprintln!("configuration written to {path}; it contains secrets, keep it private");
        }
        None => println!("{json}"),
    }
    Ok(())
}

async fn import(config: &Config, file: &str, replace: bool) -> anyhow::Result<()> {
    let json = std::fs::read_to_string(file)?;
    let db = anpi::db::open(&config.database_path).await?;
    let report = anpi::web::backup::import(&db, &json, replace).await.map_err(anyhow::Error::msg)?;
    eprintln!(
        "imported {} monitors, {} channels and {} groups; restart anpi to start the new checks",
        report.monitors_created, report.channels_created, report.groups_created
    );
    for line in report.warnings.iter().chain(&report.skipped) {
        eprintln!("  - {line}");
    }
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
