//! JSON REST API under `/api/v1`, authenticated with instance API tokens; the Terraform provider uses it.

use axum::Json;
use axum::Router;
use axum::extract::rejection::JsonRejection;
use axum::extract::{FromRequestParts, Path, State};
use axum::http::request::Parts;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde::de::IgnoredAny;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use super::AppState;
use super::admin::{MonitorForm, validate_with_groups};
use super::branding::validate_group_name;
use crate::models::{Maintenance, Monitor, NotificationChannel};
use crate::notify::ChannelConfig;
use crate::store::{self, api_tokens::ApiToken};
use crate::util::now_ms;

#[derive(Debug)]
pub struct ApiError(pub StatusCode, pub String);

impl ApiError {
    fn not_found() -> Self {
        Self(StatusCode::NOT_FOUND, "Not found".into())
    }

    fn bad_request(msg: impl Into<String>) -> Self {
        Self(StatusCode::BAD_REQUEST, msg.into())
    }

    fn unauthorized() -> Self {
        Self(StatusCode::UNAUTHORIZED, "Missing or invalid API token. Send it as: Authorization: Bearer anpi_…".into())
    }
}

impl<E: std::fmt::Display> From<E> for ApiError {
    fn from(e: E) -> Self {
        tracing::error!(error = %e, "API request failed");
        Self(StatusCode::INTERNAL_SERVER_ERROR, "Internal error".into())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut resp = (self.0, Json(serde_json::json!({ "error": self.1 }))).into_response();
        if self.0 == StatusCode::UNAUTHORIZED {
            resp.headers_mut().insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        }
        resp
    }
}

type ApiResult<T> = Result<T, ApiError>;

/// The API token that authorised the request.
pub struct ApiAuth(pub ApiToken);

impl FromRequestParts<AppState> for ApiAuth {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let value = parts.headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).unwrap_or_default();
        let token = value.split_once(' ').filter(|(scheme, _)| scheme.eq_ignore_ascii_case("bearer")).map(|(_, t)| t.trim());
        match token {
            Some(t) => store::api_tokens::verify(state.db(), t).await?.map(Self).ok_or_else(ApiError::unauthorized),
            None => Err(ApiError::unauthorized()),
        }
    }
}

fn body<T>(payload: Result<Json<T>, JsonRejection>) -> ApiResult<T> {
    payload.map(|Json(v)| v).map_err(|e| ApiError::bad_request(e.body_text()))
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/info", get(info))
        .route("/monitors", get(list_monitors).post(create_monitor))
        .route("/monitors/{id}", get(get_monitor).put(update_monitor).delete(delete_monitor))
        .route("/groups", get(list_groups).post(create_group))
        .route("/groups/{id}", get(get_group).put(update_group).delete(delete_group))
        .route("/notification-channels", get(list_channels).post(create_channel))
        .route("/notification-channels/{id}", get(get_channel).put(update_channel).delete(delete_channel))
        .route("/maintenances", get(list_maintenances).post(create_maintenance))
        .route("/maintenances/{id}", get(get_maintenance).put(update_maintenance).delete(delete_maintenance))
        .fallback(|| async { ApiError::not_found() })
}

async fn info(ApiAuth(t): ApiAuth) -> Json<serde_json::Value> {
    Json(serde_json::json!({ "version": env!("CARGO_PKG_VERSION"), "token": t.name }))
}

// ---- Monitors ----

/// A create or full update; fields left out take the same defaults as the panel form.
#[derive(Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct MonitorBody {
    name: String,
    kind: String,
    target: String,
    port: Option<i64>,
    method: Option<String>,
    headers: String,
    body: String,
    interval_s: Option<i64>,
    retry_interval_s: Option<i64>,
    timeout_s: Option<i64>,
    failure_threshold: Option<i64>,
    expected_status: Option<String>,
    ip_family: Option<String>,
    follow_redirects: Option<bool>,
    ignore_tls: bool,
    content_kind: Option<String>,
    content_value: String,
    content_expected: String,
    ssl_warn_days: Option<i64>,
    dns_record_type: Option<String>,
    dns_server: String,
    active: Option<bool>,
    public: bool,
    public_name: String,
    group_id: Option<i64>,
    parent_id: Option<i64>,
    /// Left out: new monitors get the default channels, updates keep theirs.
    channel_ids: Option<Vec<i64>>,
    // Read-only fields of a response, accepted so a fetched monitor can be sent back.
    id: Option<IgnoredAny>,
    push_token: Option<IgnoredAny>,
}

impl MonitorBody {
    fn to_form(&self) -> MonitorForm {
        let uses_url = matches!(self.kind.as_str(), "http" | "websocket");
        let num = |v: Option<i64>| v.map(|n| n.to_string()).unwrap_or_default();
        let flag = |b: bool| b.then(|| "on".to_string());
        let text = |v: &Option<String>, d: &str| v.clone().unwrap_or_else(|| d.to_string());
        MonitorForm {
            csrf: String::new(),
            name: self.name.clone(),
            kind: self.kind.clone(),
            url: if uses_url { self.target.clone() } else { String::new() },
            host: if uses_url { String::new() } else { self.target.clone() },
            port: num(self.port),
            method: text(&self.method, "GET"),
            headers: self.headers.clone(),
            body: self.body.clone(),
            interval_s: num(self.interval_s),
            retry_interval_s: num(self.retry_interval_s),
            timeout_s: num(self.timeout_s),
            failure_threshold: num(self.failure_threshold),
            expected_status: text(&self.expected_status, "200-299"),
            ip_family: text(&self.ip_family, "auto"),
            follow_redirects: flag(self.follow_redirects.unwrap_or(true)),
            ignore_tls: flag(self.ignore_tls),
            content_kind: text(&self.content_kind, "none"),
            content_value: self.content_value.clone(),
            content_expected: self.content_expected.clone(),
            dns_expected: self.content_expected.clone(),
            ssl_warn_days: num(self.ssl_warn_days),
            dns_record_type: text(&self.dns_record_type, "A"),
            dns_server: self.dns_server.clone(),
            active: flag(self.active.unwrap_or(true)),
            public: flag(self.public),
            channels: Vec::new(),
            group_id: num(self.group_id),
            public_name: self.public_name.clone(),
            parent_id: num(self.parent_id),
        }
    }
}

#[derive(Serialize)]
pub struct MonitorOut {
    id: i64,
    name: String,
    kind: String,
    target: String,
    port: Option<i64>,
    method: String,
    headers: String,
    body: String,
    interval_s: i64,
    retry_interval_s: i64,
    timeout_s: i64,
    failure_threshold: i64,
    expected_status: String,
    ip_family: String,
    follow_redirects: bool,
    ignore_tls: bool,
    content_kind: String,
    content_value: String,
    content_expected: String,
    ssl_warn_days: i64,
    dns_record_type: String,
    dns_server: String,
    active: bool,
    public: bool,
    public_name: String,
    group_id: Option<i64>,
    parent_id: Option<i64>,
    channel_ids: Vec<i64>,
    push_token: Option<String>,
}

async fn monitor_out(st: &AppState, m: Monitor) -> ApiResult<MonitorOut> {
    let mut channel_ids = store::monitors::channel_ids(st.db(), m.id).await?;
    channel_ids.sort_unstable();
    Ok(MonitorOut {
        id: m.id,
        name: m.name,
        kind: m.kind,
        target: m.target,
        port: m.port,
        method: m.method,
        headers: m.headers,
        body: m.body,
        interval_s: m.interval_s,
        retry_interval_s: m.retry_interval_s,
        timeout_s: m.timeout_s,
        failure_threshold: m.failure_threshold,
        expected_status: m.expected_status,
        ip_family: m.ip_family,
        follow_redirects: m.follow_redirects,
        ignore_tls: m.ignore_tls,
        content_kind: m.content_kind,
        content_value: m.content_value,
        content_expected: m.content_expected,
        ssl_warn_days: m.ssl_warn_days,
        dns_record_type: m.dns_record_type,
        dns_server: m.dns_server,
        active: m.active,
        public: m.public,
        public_name: m.public_name,
        group_id: m.group_id,
        parent_id: m.parent_id,
        channel_ids,
        push_token: m.push_token,
    })
}

async fn load_monitor(st: &AppState, id: i64) -> ApiResult<MonitorOut> {
    let m = store::monitors::get(st.db(), id).await?.ok_or_else(ApiError::not_found)?;
    monitor_out(st, m).await
}

async fn check_channels(st: &AppState, ids: &[i64]) -> ApiResult<()> {
    let known: Vec<i64> = store::notifications::list(st.db()).await?.iter().map(|c| c.id).collect();
    match ids.iter().find(|id| !known.contains(id)) {
        Some(id) => Err(ApiError::bad_request(format!("Notification channel {id} does not exist"))),
        None => Ok(()),
    }
}

async fn list_monitors(State(st): State<AppState>, _: ApiAuth) -> ApiResult<Json<Vec<MonitorOut>>> {
    let mut out = Vec::new();
    for m in store::monitors::list(st.db()).await? {
        out.push(monitor_out(&st, m).await?);
    }
    Ok(Json(out))
}

async fn get_monitor(State(st): State<AppState>, _: ApiAuth, Path(id): Path<i64>) -> ApiResult<Json<MonitorOut>> {
    Ok(Json(load_monitor(&st, id).await?))
}

async fn create_monitor(State(st): State<AppState>, _: ApiAuth, payload: Result<Json<MonitorBody>, JsonRejection>) -> ApiResult<Response> {
    let b = body(payload)?;
    let input = validate_with_groups(&st, &b.to_form(), None).await?.map_err(ApiError::bad_request)?;
    let channels = match &b.channel_ids {
        Some(ids) => ids.clone(),
        None => store::notifications::default_ids(st.db()).await?,
    };
    check_channels(&st, &channels).await?;
    let id = store::monitors::create(st.db(), &input).await?;
    store::monitors::set_channels(st.db(), id, &channels).await?;
    st.scheduler.reload(id).await?;
    Ok((StatusCode::CREATED, Json(load_monitor(&st, id).await?)).into_response())
}

async fn update_monitor(
    State(st): State<AppState>,
    _: ApiAuth,
    Path(id): Path<i64>,
    payload: Result<Json<MonitorBody>, JsonRejection>,
) -> ApiResult<Json<MonitorOut>> {
    store::monitors::get(st.db(), id).await?.ok_or_else(ApiError::not_found)?;
    let b = body(payload)?;
    let input = validate_with_groups(&st, &b.to_form(), Some(id)).await?.map_err(ApiError::bad_request)?;
    if let Some(ids) = &b.channel_ids {
        check_channels(&st, ids).await?;
    }
    store::monitors::update(st.db(), id, &input).await?;
    if let Some(ids) = &b.channel_ids {
        store::monitors::set_channels(st.db(), id, ids).await?;
    }
    st.scheduler.reload(id).await?;
    Ok(Json(load_monitor(&st, id).await?))
}

async fn delete_monitor(State(st): State<AppState>, _: ApiAuth, Path(id): Path<i64>) -> ApiResult<StatusCode> {
    store::monitors::get(st.db(), id).await?.ok_or_else(ApiError::not_found)?;
    st.scheduler.stop(id).await;
    store::monitors::delete(st.db(), id).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---- Groups ----

#[derive(Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct GroupBody {
    name: String,
    /// Left out: new groups go last, updates keep their place.
    sort_order: Option<i64>,
    id: Option<IgnoredAny>,
}

#[derive(Serialize)]
pub struct GroupOut {
    id: i64,
    name: String,
    sort_order: i64,
}

async fn load_group(st: &AppState, id: i64) -> ApiResult<GroupOut> {
    let g = store::groups::get(st.db(), id).await?.ok_or_else(ApiError::not_found)?;
    Ok(GroupOut { id: g.id, name: g.name, sort_order: g.sort_order })
}

async fn list_groups(State(st): State<AppState>, _: ApiAuth) -> ApiResult<Json<Vec<GroupOut>>> {
    let groups = store::groups::list(st.db()).await?;
    Ok(Json(groups.into_iter().map(|g| GroupOut { id: g.id, name: g.name, sort_order: g.sort_order }).collect()))
}

async fn get_group(State(st): State<AppState>, _: ApiAuth, Path(id): Path<i64>) -> ApiResult<Json<GroupOut>> {
    Ok(Json(load_group(&st, id).await?))
}

async fn create_group(State(st): State<AppState>, _: ApiAuth, payload: Result<Json<GroupBody>, JsonRejection>) -> ApiResult<Response> {
    let b = body(payload)?;
    let name = validate_group_name(&b.name).map_err(ApiError::bad_request)?;
    let order = match b.sort_order {
        Some(o) => o,
        None => store::groups::next_sort_order(st.db()).await?,
    };
    let id = store::groups::create(st.db(), &name, order).await?;
    Ok((StatusCode::CREATED, Json(load_group(&st, id).await?)).into_response())
}

async fn update_group(
    State(st): State<AppState>,
    _: ApiAuth,
    Path(id): Path<i64>,
    payload: Result<Json<GroupBody>, JsonRejection>,
) -> ApiResult<Json<GroupOut>> {
    let current = load_group(&st, id).await?;
    let b = body(payload)?;
    let name = validate_group_name(&b.name).map_err(ApiError::bad_request)?;
    store::groups::update(st.db(), id, &name, b.sort_order.unwrap_or(current.sort_order)).await?;
    Ok(Json(load_group(&st, id).await?))
}

async fn delete_group(State(st): State<AppState>, _: ApiAuth, Path(id): Path<i64>) -> ApiResult<StatusCode> {
    load_group(&st, id).await?;
    store::groups::delete(st.db(), id).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---- Notification channels ----

#[derive(Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct ChannelBody {
    name: String,
    kind: String,
    active: Option<bool>,
    is_default: bool,
    config: ChannelConfig,
    id: Option<IgnoredAny>,
}

#[derive(Serialize)]
pub struct ChannelOut {
    id: i64,
    name: String,
    kind: String,
    active: bool,
    is_default: bool,
    config: ChannelConfig,
}

impl From<NotificationChannel> for ChannelOut {
    fn from(c: NotificationChannel) -> Self {
        Self { id: c.id, config: ChannelConfig::from_json(&c.config), name: c.name, kind: c.kind, active: c.active, is_default: c.is_default }
    }
}

impl ChannelBody {
    fn validate(&self) -> ApiResult<String> {
        let name = self.name.trim();
        if name.is_empty() {
            return Err(ApiError::bad_request("Name is required"));
        }
        self.config.validate(&self.kind).map_err(ApiError::bad_request)?;
        Ok(name.to_string())
    }
}

async fn load_channel(st: &AppState, id: i64) -> ApiResult<ChannelOut> {
    Ok(store::notifications::get(st.db(), id).await?.ok_or_else(ApiError::not_found)?.into())
}

async fn list_channels(State(st): State<AppState>, _: ApiAuth) -> ApiResult<Json<Vec<ChannelOut>>> {
    Ok(Json(store::notifications::list(st.db()).await?.into_iter().map(ChannelOut::from).collect()))
}

async fn get_channel(State(st): State<AppState>, _: ApiAuth, Path(id): Path<i64>) -> ApiResult<Json<ChannelOut>> {
    Ok(Json(load_channel(&st, id).await?))
}

async fn create_channel(State(st): State<AppState>, _: ApiAuth, payload: Result<Json<ChannelBody>, JsonRejection>) -> ApiResult<Response> {
    let b = body(payload)?;
    let name = b.validate()?;
    let id = store::notifications::create(st.db(), &name, &b.kind, &b.config.to_json(), b.active.unwrap_or(true), b.is_default).await?;
    Ok((StatusCode::CREATED, Json(load_channel(&st, id).await?)).into_response())
}

async fn update_channel(
    State(st): State<AppState>,
    _: ApiAuth,
    Path(id): Path<i64>,
    payload: Result<Json<ChannelBody>, JsonRejection>,
) -> ApiResult<Json<ChannelOut>> {
    load_channel(&st, id).await?;
    let b = body(payload)?;
    let name = b.validate()?;
    store::notifications::update(st.db(), id, &name, &b.kind, &b.config.to_json(), b.active.unwrap_or(true), b.is_default).await?;
    Ok(Json(load_channel(&st, id).await?))
}

async fn delete_channel(State(st): State<AppState>, _: ApiAuth, Path(id): Path<i64>) -> ApiResult<StatusCode> {
    load_channel(&st, id).await?;
    store::notifications::delete(st.db(), id).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---- Maintenance windows ----

#[derive(Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct MaintenanceBody {
    title: String,
    /// RFC 3339, e.g. 2026-05-01T22:00:00Z or 2026-05-02T00:00:00+02:00.
    starts_at: String,
    ends_at: String,
    all_monitors: bool,
    monitor_ids: Vec<i64>,
    id: Option<IgnoredAny>,
}

#[derive(Serialize)]
pub struct MaintenanceOut {
    id: i64,
    title: String,
    starts_at: String,
    ends_at: String,
    all_monitors: bool,
    monitor_ids: Vec<i64>,
}

fn parse_time(v: &str, field: &str) -> ApiResult<i64> {
    let dt = OffsetDateTime::parse(v.trim(), &Rfc3339)
        .map_err(|_| ApiError::bad_request(format!("{field} must be an RFC 3339 time like 2026-05-01T22:00:00Z")))?;
    Ok((dt.unix_timestamp_nanos() / 1_000_000) as i64)
}

fn format_time(ms: i64) -> String {
    OffsetDateTime::from_unix_timestamp_nanos(ms as i128 * 1_000_000).ok().and_then(|d| d.format(&Rfc3339).ok()).unwrap_or_default()
}

struct ValidMaintenance {
    title: String,
    starts_at: i64,
    ends_at: i64,
    monitor_ids: Vec<i64>,
}

impl MaintenanceBody {
    async fn validate(&self, st: &AppState) -> ApiResult<ValidMaintenance> {
        let title = self.title.trim();
        if title.is_empty() {
            return Err(ApiError::bad_request("Title is required"));
        }
        let (starts_at, ends_at) = (parse_time(&self.starts_at, "starts_at")?, parse_time(&self.ends_at, "ends_at")?);
        if ends_at <= starts_at {
            return Err(ApiError::bad_request("ends_at must be after starts_at"));
        }
        if !self.all_monitors && self.monitor_ids.is_empty() {
            return Err(ApiError::bad_request("Set all_monitors or list at least one monitor in monitor_ids"));
        }
        let known: Vec<i64> = store::monitors::list(st.db()).await?.iter().map(|m| m.id).collect();
        if let Some(id) = self.monitor_ids.iter().find(|id| !known.contains(id)) {
            return Err(ApiError::bad_request(format!("Monitor {id} does not exist")));
        }
        let mut monitor_ids = self.monitor_ids.clone();
        monitor_ids.sort_unstable();
        monitor_ids.dedup();
        Ok(ValidMaintenance { title: title.to_string(), starts_at, ends_at, monitor_ids })
    }
}

async fn maintenance_out(st: &AppState, w: Maintenance) -> ApiResult<MaintenanceOut> {
    let mut monitor_ids = store::maintenance::monitor_ids(st.db(), w.id).await?;
    monitor_ids.sort_unstable();
    Ok(MaintenanceOut {
        id: w.id,
        title: w.title,
        starts_at: format_time(w.starts_at),
        ends_at: format_time(w.ends_at),
        all_monitors: w.all_monitors,
        monitor_ids,
    })
}

async fn load_maintenance(st: &AppState, id: i64) -> ApiResult<MaintenanceOut> {
    let w = store::maintenance::get(st.db(), id).await?.ok_or_else(ApiError::not_found)?;
    maintenance_out(st, w).await
}

async fn list_maintenances(State(st): State<AppState>, _: ApiAuth) -> ApiResult<Json<Vec<MaintenanceOut>>> {
    let mut out = Vec::new();
    for w in store::maintenance::list(st.db()).await? {
        out.push(maintenance_out(&st, w).await?);
    }
    Ok(Json(out))
}

async fn get_maintenance(State(st): State<AppState>, _: ApiAuth, Path(id): Path<i64>) -> ApiResult<Json<MaintenanceOut>> {
    Ok(Json(load_maintenance(&st, id).await?))
}

async fn create_maintenance(State(st): State<AppState>, _: ApiAuth, payload: Result<Json<MaintenanceBody>, JsonRejection>) -> ApiResult<Response> {
    let b = body(payload)?;
    let v = b.validate(&st).await?;
    let id = store::maintenance::create(st.db(), &v.title, v.starts_at, v.ends_at, b.all_monitors, &v.monitor_ids).await?;
    st.ctx.maintenance.reload(st.db(), now_ms()).await?;
    Ok((StatusCode::CREATED, Json(load_maintenance(&st, id).await?)).into_response())
}

async fn update_maintenance(
    State(st): State<AppState>,
    _: ApiAuth,
    Path(id): Path<i64>,
    payload: Result<Json<MaintenanceBody>, JsonRejection>,
) -> ApiResult<Json<MaintenanceOut>> {
    load_maintenance(&st, id).await?;
    let b = body(payload)?;
    let v = b.validate(&st).await?;
    store::maintenance::update(st.db(), id, &v.title, v.starts_at, v.ends_at, b.all_monitors, &v.monitor_ids).await?;
    st.ctx.maintenance.reload(st.db(), now_ms()).await?;
    Ok(Json(load_maintenance(&st, id).await?))
}

async fn delete_maintenance(State(st): State<AppState>, _: ApiAuth, Path(id): Path<i64>) -> ApiResult<StatusCode> {
    load_maintenance(&st, id).await?;
    store::maintenance::delete(st.db(), id).await?;
    st.ctx.maintenance.reload(st.db(), now_ms()).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maintenance_times_round_trip_as_utc() {
        let ms = parse_time("2026-05-02T00:00:00+02:00", "starts_at").unwrap();
        assert_eq!(format_time(ms), "2026-05-01T22:00:00Z");
        assert!(parse_time("2026-05-01 22:00", "starts_at").is_err());
    }
}
