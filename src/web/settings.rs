use askama::Template;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::Form;
use serde::Deserialize;

use super::auth_routes::CsrfForm;
use super::views::Layout;
use super::{AppError, AppResult, AppState, CurrentUser, render};
use crate::auth::oidc::Oidc;
use crate::auth::password;
use crate::auth::sso::{PanelSso, SsoSource, normalize_base_url};
use crate::kuma::{self, ImportReport};
use crate::store::{self, settings::AppSettings};
use crate::util::{format_ts, now_ms, parse_local_datetime};

#[derive(Deserialize)]
pub struct NoticeQuery {
    notice: Option<String>,
}

pub struct MaintenanceRow {
    pub id: i64,
    pub title: String,
    pub starts: String,
    pub ends: String,
    pub scope: String,
    pub state: &'static str,
}

#[derive(Template)]
#[template(path = "maintenance.html")]
struct MaintenancePage {
    layout: Layout,
    rows: Vec<MaintenanceRow>,
    monitors: Vec<(i64, String)>,
    error: Option<String>,
}

async fn maintenance_response(st: &AppState, user: &CurrentUser, notice: Option<&str>, error: Option<String>) -> AppResult<Response> {
    let now = now_ms();
    let monitors = store::monitors::list(st.db()).await?;
    let names: std::collections::HashMap<i64, String> = monitors.iter().map(|m| (m.id, m.name.clone())).collect();
    let mut rows = Vec::new();
    for w in store::maintenance::list(st.db()).await? {
        let scope = if w.all_monitors {
            "All monitors".to_string()
        } else {
            let ids = store::maintenance::monitor_ids(st.db(), w.id).await?;
            ids.iter().filter_map(|i| names.get(i).cloned()).collect::<Vec<_>>().join(", ")
        };
        let state = if now < w.starts_at {
            "scheduled"
        } else if now < w.ends_at {
            "active"
        } else {
            "ended"
        };
        rows.push(MaintenanceRow { id: w.id, title: w.title, starts: format_ts(w.starts_at), ends: format_ts(w.ends_at), scope, state });
    }
    let status = if error.is_some() { StatusCode::BAD_REQUEST } else { StatusCode::OK };
    let page = MaintenancePage {
        layout: Layout::admin("Maintenance", user, "maintenance").with_notice(notice),
        rows,
        monitors: monitors.into_iter().map(|m| (m.id, m.name)).collect(),
        error,
    };
    Ok((status, render(&page)?).into_response())
}

pub async fn maintenance_page(State(st): State<AppState>, user: CurrentUser, Query(q): Query<NoticeQuery>) -> AppResult<Response> {
    maintenance_response(&st, &user, q.notice.as_deref(), None).await
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub struct MaintenanceForm {
    csrf: String,
    title: String,
    starts_at: String,
    ends_at: String,
    tz_offset: String,
    all_monitors: Option<String>,
    monitors: Vec<i64>,
}

pub async fn create_maintenance(State(st): State<AppState>, user: CurrentUser, Form(f): Form<MaintenanceForm>) -> AppResult<Response> {
    user.check_csrf(&f.csrf)?;
    let offset: i64 = f.tz_offset.parse().unwrap_or(0);
    let parsed = (parse_local_datetime(&f.starts_at, offset), parse_local_datetime(&f.ends_at, offset));
    let error = match parsed {
        _ if f.title.trim().is_empty() => Some("Title is required"),
        (Some(s), Some(e)) if e <= s => Some("End must be after start"),
        (Some(_), Some(_)) if f.all_monitors.is_none() && f.monitors.is_empty() => Some("Pick at least one monitor or choose all"),
        (Some(_), Some(_)) => None,
        _ => Some("Start and end are required"),
    };
    if let Some(e) = error {
        return maintenance_response(&st, &user, None, Some(e.into())).await;
    }
    let (Some(start), Some(end)) = parsed else { unreachable!("validated above") };
    store::maintenance::create(st.db(), f.title.trim(), start, end, f.all_monitors.is_some(), &f.monitors).await?;
    st.ctx.maintenance.reload(st.db(), now_ms()).await?;
    Ok(Redirect::to("/admin/maintenance?notice=created").into_response())
}

pub async fn delete_maintenance(State(st): State<AppState>, user: CurrentUser, Path(id): Path<i64>, Form(f): Form<CsrfForm>) -> AppResult<Response> {
    user.check_csrf(&f.csrf)?;
    store::maintenance::delete(st.db(), id).await?;
    st.ctx.maintenance.reload(st.db(), now_ms()).await?;
    Ok(Redirect::to("/admin/maintenance?notice=deleted").into_response())
}

pub struct UserRow {
    pub id: i64,
    pub username: String,
    pub source: &'static str,
    pub created: String,
    pub is_me: bool,
}

pub struct GroupRow {
    pub id: i64,
    pub name: String,
    pub sort_order: i64,
    pub monitors: usize,
}

#[derive(Template)]
#[template(path = "settings.html")]
struct SettingsPage {
    layout: Layout,
    s: AppSettings,
    sso_source: &'static str,
    sso_panel: PanelSso,
    sso_has_secret: bool,
    sso_redirect: Option<String>,
    sso_open_to_all: bool,
    groups: Vec<GroupRow>,
    users: Vec<UserRow>,
    sso: bool,
    error: Option<String>,
    db_size: String,
}

async fn settings_response(st: &AppState, user: &CurrentUser, notice: Option<&str>, s: Option<AppSettings>, error: Option<String>) -> AppResult<Response> {
    let s = match s {
        Some(s) => s,
        None => AppSettings::load(st.db()).await?,
    };
    let users = store::users::list(st.db())
        .await?
        .into_iter()
        .map(|u| UserRow {
            is_me: u.id == user.id,
            source: if u.oidc_subject.is_some() { "SSO" } else { "password" },
            created: format_ts(u.created_at),
            id: u.id,
            username: u.username,
        })
        .collect();
    let pages: (i64,) = sqlx::query_as("SELECT page_count * page_size FROM pragma_page_count(), pragma_page_size()").fetch_one(st.db()).await?;
    let monitors = store::monitors::list(st.db()).await?;
    let groups = store::groups::list(st.db())
        .await?
        .into_iter()
        .map(|g| GroupRow { monitors: monitors.iter().filter(|m| m.group_id == Some(g.id)).count(), id: g.id, name: g.name, sort_order: g.sort_order })
        .collect();
    let status = if error.is_some() { StatusCode::BAD_REQUEST } else { StatusCode::OK };
    let auth = st.ctx.auth();
    let mut sso_panel = PanelSso::load(st.db()).await?;
    let sso_has_secret = !sso_panel.client_secret.is_empty();
    sso_panel.client_secret.clear();
    let page = SettingsPage {
        layout: Layout::admin("Settings", user, "settings").with_notice(notice),
        s,
        sso_source: match auth.source {
            SsoSource::Env => "env",
            SsoSource::Panel => "panel",
            SsoSource::Off => "off",
        },
        sso_open_to_all: auth.oidc.as_ref().is_some_and(|o| !o.requires_role()),
        sso_redirect: auth.base_url.map(|b| format!("{b}/auth/oidc/callback")),
        sso_panel,
        sso_has_secret,
        groups,
        users,
        sso: st.oidc().is_some(),
        error,
        db_size: format!("{:.1} MB", pages.0 as f64 / 1_048_576.0),
    };
    Ok((status, render(&page)?).into_response())
}

pub async fn settings_page(State(st): State<AppState>, user: CurrentUser, Query(q): Query<NoticeQuery>) -> AppResult<Response> {
    settings_response(&st, &user, q.notice.as_deref(), None, None).await
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub struct SettingsForm {
    csrf: String,
    status_title: String,
    status_description: String,
    raw_retention_hours: String,
    hourly_retention_days: String,
    incident_retention_days: String,
}

impl SettingsForm {
    fn validate(&self) -> Result<AppSettings, String> {
        let num = |v: &str, field: &str, min: i64, max: i64| match v.trim().parse::<i64>() {
            Ok(n) if (min..=max).contains(&n) => Ok(n),
            _ => Err(format!("{field} must be between {min} and {max}")),
        };
        let title = self.status_title.trim();
        if title.is_empty() {
            return Err("Status page title is required".into());
        }
        Ok(AppSettings {
            status_title: title.chars().take(100).collect(),
            status_description: self.status_description.trim().chars().take(1000).collect(),
            raw_retention_hours: num(&self.raw_retention_hours, "Raw history", 1, 24 * 90)?,
            hourly_retention_days: num(&self.hourly_retention_days, "Hourly history", 1, 3650)?,
            incident_retention_days: num(&self.incident_retention_days, "Incident history", 1, 3650)?,
        })
    }
}

pub async fn save_settings(State(st): State<AppState>, user: CurrentUser, Form(f): Form<SettingsForm>) -> AppResult<Response> {
    user.check_csrf(&f.csrf)?;
    match f.validate() {
        Ok(s) => {
            s.save(st.db()).await?;
            Ok(Redirect::to("/admin/settings?notice=saved").into_response())
        }
        Err(e) => {
            let draft = AppSettings {
                status_title: f.status_title.clone(),
                status_description: f.status_description.clone(),
                ..AppSettings::load(st.db()).await?
            };
            settings_response(&st, &user, None, Some(draft), Some(e)).await
        }
    }
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub struct NewUserForm {
    csrf: String,
    username: String,
    password: String,
}

pub async fn create_user(State(st): State<AppState>, user: CurrentUser, Form(f): Form<NewUserForm>) -> AppResult<Response> {
    user.check_csrf(&f.csrf)?;
    if st.oidc().is_some() {
        return Err(AppError::forbidden("Users are managed by the identity provider."));
    }
    let username = f.username.trim();
    let error = if username.is_empty() || username.len() > 64 {
        Some("Username is required (up to 64 characters)".to_string())
    } else if let Err(e) = password::check_strength(&f.password) {
        Some(e)
    } else if store::users::by_username(st.db(), username).await?.is_some() {
        Some("That username is taken".to_string())
    } else {
        None
    };
    if let Some(e) = error {
        return settings_response(&st, &user, None, None, Some(e)).await;
    }
    store::users::create_local(st.db(), username, &password::hash_async(&f.password).await?).await?;
    Ok(Redirect::to("/admin/settings?notice=created").into_response())
}

pub async fn delete_user(State(st): State<AppState>, user: CurrentUser, Path(id): Path<i64>, Form(f): Form<CsrfForm>) -> AppResult<Response> {
    user.check_csrf(&f.csrf)?;
    if id == user.id {
        return Err(AppError::bad_request("You cannot delete your own account."));
    }
    store::users::delete(st.db(), id).await?;
    Ok(Redirect::to("/admin/settings?notice=deleted").into_response())
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub struct PasswordForm {
    csrf: String,
    current: String,
    new_password: String,
    confirm: String,
}

pub async fn change_password(State(st): State<AppState>, user: CurrentUser, Form(f): Form<PasswordForm>) -> AppResult<Response> {
    user.check_csrf(&f.csrf)?;
    let u = store::users::by_id(st.db(), user.id).await?.ok_or_else(AppError::not_found)?;
    let Some(hash) = u.password_hash.as_deref() else {
        return Err(AppError::bad_request("This account signs in with SSO."));
    };
    let current_ok = password::verify_async(&f.current, Some(hash)).await.map_err(|_| AppError(StatusCode::SERVICE_UNAVAILABLE, "Server busy, try again".into()))?;
    let error = if !current_ok {
        Some("Current password is wrong".to_string())
    } else if f.new_password != f.confirm {
        Some("New passwords do not match".to_string())
    } else {
        password::check_strength(&f.new_password).err()
    };
    if let Some(e) = error {
        return settings_response(&st, &user, None, None, Some(e)).await;
    }
    store::users::set_password(st.db(), user.id, &password::hash_async(&f.new_password).await?).await?;
    // Sign out other devices; the current browser keeps a fresh session.
    store::users::delete_user_sessions(st.db(), user.id).await?;
    let token = store::users::create_session(st.db(), user.id, None).await?;
    let jar = axum_extra::extract::CookieJar::new().add(st.session_cookie(token));
    Ok((jar, Redirect::to("/admin/settings?notice=password")).into_response())
}

#[derive(Template)]
#[template(path = "import.html")]
struct ImportPage {
    layout: Layout,
    report: Option<ImportReport>,
    error: Option<String>,
}

pub async fn import_page(user: CurrentUser) -> AppResult<Response> {
    Ok(render(&ImportPage { layout: Layout::admin("Import from Uptime Kuma", &user, "settings"), report: None, error: None })?.into_response())
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub struct ImportForm {
    csrf: String,
    json: String,
}

pub async fn import(State(st): State<AppState>, user: CurrentUser, Form(f): Form<ImportForm>) -> AppResult<Response> {
    user.check_csrf(&f.csrf)?;
    let layout = Layout::admin("Import from Uptime Kuma", &user, "settings");
    match kuma::import(st.db(), &f.json).await {
        Ok(report) => {
            st.scheduler.start_all_missing().await?;
            Ok(render(&ImportPage { layout, report: Some(report), error: None })?.into_response())
        }
        Err(e) => Ok((StatusCode::BAD_REQUEST, render(&ImportPage { layout, report: None, error: Some(e) })?).into_response()),
    }
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub struct SsoForm {
    csrf: String,
    enabled: Option<String>,
    base_url: String,
    issuer: String,
    client_id: String,
    client_secret: String,
    required_role: String,
    scopes: String,
}

impl SsoForm {
    /// Applies the form onto stored settings; an empty secret keeps the stored one.
    fn apply(&self, mut panel: PanelSso) -> Result<PanelSso, String> {
        panel.base_url = normalize_base_url(&self.base_url)?;
        panel.issuer = self.issuer.trim().trim_end_matches('/').to_string();
        panel.client_id = self.client_id.trim().to_string();
        if !self.client_secret.trim().is_empty() {
            panel.client_secret = self.client_secret.trim().to_string();
        }
        panel.required_role = self.required_role.trim().to_string();
        panel.scopes = self.scopes.trim().to_string();
        panel.enabled = self.enabled.is_some();
        if panel.enabled {
            if panel.base_url.is_empty() {
                return Err("Public URL is required for SSO (it builds the redirect address)".into());
            }
            if panel.oidc_config().is_none() {
                return Err("Issuer URL and client ID are required for SSO".into());
            }
        }
        Ok(panel)
    }
}

async fn probe(panel: &PanelSso) -> Result<String, String> {
    let cfg = panel.oidc_config().ok_or("Issuer URL and client ID are required")?;
    let base = if panel.base_url.is_empty() { "http://localhost".to_string() } else { panel.base_url.clone() };
    let oidc = Oidc::new(cfg, format!("{base}/auth/oidc/callback"));
    let d = oidc.discovery().await?;
    Ok(format!("Connected to {}; sign-in goes to {}", d.issuer, d.authorization_endpoint))
}

pub async fn save_sso(State(st): State<AppState>, user: CurrentUser, Form(f): Form<SsoForm>) -> AppResult<Response> {
    user.check_csrf(&f.csrf)?;
    if st.ctx.auth().source == SsoSource::Env {
        return Err(AppError::forbidden("SSO is configured through environment variables on the server."));
    }
    let panel = match f.apply(PanelSso::load(st.db()).await?) {
        Ok(p) => p,
        Err(e) => return settings_response(&st, &user, None, None, Some(e)).await,
    };
    // Never switch password sign-in off unless the provider actually answers.
    if panel.enabled
        && let Err(e) = probe(&panel).await
    {
        let msg = format!("SSO was not enabled because the identity provider could not be reached: {e}");
        return settings_response(&st, &user, None, None, Some(msg)).await;
    }
    panel.save(st.db()).await?;
    st.ctx.reload_auth().await?;
    tracing::warn!(user = %user.username, enabled = panel.enabled, "SSO settings changed");
    Ok(Redirect::to("/admin/settings?notice=saved#sso").into_response())
}

pub async fn test_sso(State(st): State<AppState>, user: CurrentUser, Form(f): Form<SsoForm>) -> AppResult<Response> {
    user.check_csrf(&f.csrf)?;
    let mut panel = PanelSso::load(st.db()).await?;
    let result = match (SsoForm { enabled: None, ..f }).apply(std::mem::take(&mut panel)) {
        Ok(p) => probe(&p).await,
        Err(e) => Err(e),
    };
    Ok(axum::Json(match result {
        Ok(m) => serde_json::json!({ "ok": true, "message": m }),
        Err(e) => serde_json::json!({ "ok": false, "message": e }),
    })
    .into_response())
}
