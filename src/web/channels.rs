use askama::Template;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::Form;
use serde::Deserialize;

use super::auth_routes::CsrfForm;
use super::views::Layout;
use super::{AppError, AppResult, AppState, CurrentUser, render};
use crate::models::NotificationChannel;
use crate::notify::{self, ChannelConfig, EventKind, NotifyEvent};
use crate::store;
use crate::util::now_ms;

#[derive(Deserialize)]
pub struct ListQuery {
    notice: Option<String>,
    error: Option<String>,
}

pub struct ChannelRow {
    pub id: i64,
    pub name: String,
    pub kind_label: &'static str,
    pub active: bool,
    pub is_default: bool,
}

#[derive(Template)]
#[template(path = "channels.html")]
struct ListPage {
    layout: Layout,
    rows: Vec<ChannelRow>,
    error: Option<String>,
}

fn kind_label(kind: &str) -> &'static str {
    notify::KINDS.iter().find(|(k, _)| *k == kind).map(|(_, l)| *l).unwrap_or("Unknown")
}

pub async fn list(State(st): State<AppState>, user: CurrentUser, Query(q): Query<ListQuery>) -> AppResult<Response> {
    let rows = store::notifications::list(st.db())
        .await?
        .into_iter()
        .map(|c| ChannelRow { id: c.id, kind_label: kind_label(&c.kind), name: c.name, active: c.active, is_default: c.is_default })
        .collect();
    // Test failures come back as a short message; it is rendered escaped.
    let error = q.error.map(|e| e.chars().take(300).collect());
    let page = ListPage { layout: Layout::admin("Notifications", &user, "notifications").with_notice(q.notice.as_deref()), rows, error };
    Ok(render(&page)?.into_response())
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub struct ChannelForm {
    pub csrf: String,
    pub name: String,
    pub kind: String,
    pub active: Option<String>,
    pub is_default: Option<String>,
    #[serde(flatten)]
    pub cfg: ChannelConfig,
}

impl ChannelForm {
    pub fn is_kind(&self, k: &str) -> bool {
        self.kind == k
    }
}

#[derive(Template)]
#[template(path = "channel_form.html")]
struct FormPage {
    layout: Layout,
    id: Option<i64>,
    f: ChannelForm,
    kinds: Vec<(&'static str, &'static str)>,
    error: Option<String>,
}

fn form_page(user: &CurrentUser, id: Option<i64>, f: ChannelForm, error: Option<String>) -> AppResult<Response> {
    let status = if error.is_some() { StatusCode::BAD_REQUEST } else { StatusCode::OK };
    let title = if id.is_some() { "Edit notification channel" } else { "New notification channel" };
    let page = FormPage { layout: Layout::admin(title, user, "notifications"), id, f, kinds: notify::KINDS.to_vec(), error };
    Ok((status, render(&page)?).into_response())
}

pub async fn new_form(user: CurrentUser) -> AppResult<Response> {
    let f = ChannelForm { kind: "discord".into(), active: Some("on".into()), ..Default::default() };
    form_page(&user, None, f, None)
}

pub async fn edit_form(State(st): State<AppState>, user: CurrentUser, Path(id): Path<i64>) -> AppResult<Response> {
    let c = store::notifications::get(st.db(), id).await?.ok_or_else(AppError::not_found)?;
    let f = ChannelForm {
        csrf: String::new(),
        name: c.name,
        cfg: ChannelConfig::from_json(&c.config),
        kind: c.kind,
        active: c.active.then(|| "on".into()),
        is_default: c.is_default.then(|| "on".into()),
    };
    form_page(&user, Some(id), f, None)
}

fn validate(f: &ChannelForm) -> Result<(), String> {
    if f.name.trim().is_empty() {
        return Err("Name is required".into());
    }
    f.cfg.validate(&f.kind)
}

pub async fn create(State(st): State<AppState>, user: CurrentUser, Form(f): Form<ChannelForm>) -> AppResult<Response> {
    user.check_csrf(&f.csrf)?;
    if let Err(e) = validate(&f) {
        return form_page(&user, None, f, Some(e));
    }
    store::notifications::create(st.db(), f.name.trim(), &f.kind, &f.cfg.to_json(), f.active.is_some(), f.is_default.is_some()).await?;
    Ok(Redirect::to("/admin/notifications?notice=created").into_response())
}

pub async fn update(State(st): State<AppState>, user: CurrentUser, Path(id): Path<i64>, Form(f): Form<ChannelForm>) -> AppResult<Response> {
    user.check_csrf(&f.csrf)?;
    store::notifications::get(st.db(), id).await?.ok_or_else(AppError::not_found)?;
    if let Err(e) = validate(&f) {
        return form_page(&user, Some(id), f, Some(e));
    }
    store::notifications::update(st.db(), id, f.name.trim(), &f.kind, &f.cfg.to_json(), f.active.is_some(), f.is_default.is_some())
        .await?;
    Ok(Redirect::to("/admin/notifications?notice=saved").into_response())
}

pub async fn delete(State(st): State<AppState>, user: CurrentUser, Path(id): Path<i64>, Form(f): Form<CsrfForm>) -> AppResult<Response> {
    user.check_csrf(&f.csrf)?;
    store::notifications::delete(st.db(), id).await?;
    Ok(Redirect::to("/admin/notifications?notice=deleted").into_response())
}

pub async fn test(State(st): State<AppState>, user: CurrentUser, Path(id): Path<i64>, Form(f): Form<CsrfForm>) -> AppResult<Response> {
    user.check_csrf(&f.csrf)?;
    let c: NotificationChannel = store::notifications::get(st.db(), id).await?.ok_or_else(AppError::not_found)?;
    let ev = NotifyEvent {
        kind: EventKind::Test,
        monitor_name: "anpi".into(),
        parent_name: None,
        target: String::new(),
        message: format!("If you can read this, the \"{}\" channel works.", c.name),
        at: now_ms(),
    };
    match notify::send_channel(&c, &ev).await {
        Ok(()) => Ok(Redirect::to("/admin/notifications?notice=test-sent").into_response()),
        Err(e) => Ok(Redirect::to(&format!("/admin/notifications?error={}", urlencoding::encode(&format!("Test failed: {e}")))).into_response()),
    }
}
