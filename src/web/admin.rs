use askama::Template;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum_extra::extract::Form;
use serde::Deserialize;

use super::auth_routes::CsrfForm;
use super::charts::{self, PhaseAvg};
use super::views::{self, Bar, Layout, status_label};
use super::{AppError, AppResult, AppState, CurrentUser, public, render};
use crate::checks::{self, content, dns, status_codes::StatusMatcher};
use crate::models::{ContentKind, IpFamily, Monitor, MonitorGroup, MonitorInput, MonitorKind, Status};
use crate::stats;
use crate::store;
use crate::util::{DAY_MS, HOUR_MS, format_duration_ms, format_ms, format_pct, format_ts, now_ms};

#[derive(Deserialize)]
pub struct NoticeQuery {
    notice: Option<String>,
    range: Option<String>,
}

pub struct MonitorRow {
    pub id: i64,
    pub group_id: Option<i64>,
    pub parent_id: Option<i64>,
    pub name: String,
    pub kind: &'static str,
    pub target: String,
    pub status: Option<Status>,
    pub status_class: &'static str,
    pub status_label: &'static str,
    pub latency: String,
    pub uptime: Option<f64>,
    pub uptime_24h: String,
    pub bars: Vec<Bar>,
    pub cert: Option<(String, &'static str)>,
    pub active: bool,
    pub public: bool,
    pub aggregate: bool,
    pub children: Vec<MonitorRow>,
}

impl MonitorRow {
    /// A parent shows the worst status, lowest uptime and worst bars of itself and its children.
    fn absorb_children(&mut self) {
        if self.children.is_empty() {
            return;
        }
        let own = self.status.filter(|_| self.active);
        let statuses = own.into_iter().chain(self.children.iter().filter(|c| c.active).filter_map(|c| c.status));
        if let Some(worst) = Status::worst(statuses) {
            self.status = Some(worst);
            self.status_class = views::status_class(worst);
            self.status_label = status_label(worst);
        }
        let uptimes = self.uptime.into_iter().chain(self.children.iter().filter_map(|c| c.uptime));
        self.uptime = uptimes.fold(None, |a: Option<f64>, b| Some(a.map_or(b, |a| a.min(b))));
        self.uptime_24h = format_pct(self.uptime);
        let mut strips: Vec<&[Bar]> = self.children.iter().map(|c| c.bars.as_slice()).collect();
        if !self.aggregate {
            strips.push(&self.bars);
        }
        self.bars = views::worst_bars(&strips);
    }
}

#[derive(Template)]
#[template(path = "dashboard.html")]
struct DashboardPage {
    layout: Layout,
    groups: Vec<public::GroupBucket<MonitorRow>>,
    empty: bool,
    count_up: usize,
    count_down: usize,
    count_other: usize,
}

pub async fn dashboard(State(st): State<AppState>, user: CurrentUser, Query(q): Query<NoticeQuery>) -> AppResult<Html<String>> {
    let db = st.db();
    let now = now_ms();
    let monitors = store::monitors::list(db).await?;
    let recent = store::heartbeats::recent_all(db, 40).await?;
    let up24 = stats::uptime_all(db, now - DAY_MS).await?;
    let mut rows = Vec::with_capacity(monitors.len());
    let (mut count_up, mut count_down, mut count_other) = (0, 0, 0);
    for m in monitors {
        let aggregate = m.kind() == MonitorKind::Aggregate;
        let beats = recent.get(&m.id).map(Vec::as_slice).unwrap_or_default();
        let last = beats.last();
        let status = last.map(|b| b.status());
        let (status_class, status_label) = match (m.active, status) {
            (false, _) => ("s-paused", "Paused"),
            (true, None) => ("s-none", if aggregate { "No data" } else { "Waiting" }),
            (true, Some(s)) => (views::status_class(s), status_label(s)),
        };
        if !aggregate {
            match (m.active, status) {
                (true, Some(Status::Up)) => count_up += 1,
                (true, Some(Status::Down)) => count_down += 1,
                _ => count_other += 1,
            }
        }
        let cert_expiry = beats.iter().rev().find_map(|b| b.cert_expires_at);
        let uptime = up24.get(&m.id).copied();
        rows.push(MonitorRow {
            id: m.id,
            group_id: m.group_id,
            parent_id: m.parent_id,
            name: m.name.clone(),
            kind: m.kind().label(),
            target: match m.kind() {
                MonitorKind::Aggregate | MonitorKind::Push => m.display_target(),
                _ => format!("{} · every {}s", m.display_target(), m.interval_s),
            },
            status,
            status_class,
            status_label,
            latency: if aggregate { format_ms(None) } else { format_ms(last.and_then(|b| b.total_ms)) },
            uptime,
            uptime_24h: format_pct(uptime),
            bars: views::heartbeat_bars(beats, 40),
            cert: views::cert_info(cert_expiry, now),
            active: m.active,
            public: m.public,
            aggregate,
            children: Vec::new(),
        });
    }
    let mut rows = views::nest(rows, |r| r.id, |r| r.parent_id, |r| &mut r.children);
    rows.iter_mut().for_each(MonitorRow::absorb_children);
    let all_groups = store::groups::list(db).await?;
    render(&DashboardPage {
        layout: Layout::admin("Monitors", &user, "monitors").with_notice(q.notice.as_deref()),
        empty: rows.is_empty(),
        groups: public::group_buckets(&all_groups, rows, |r| r.group_id),
        count_up,
        count_down,
        count_other,
    })
}

/// Works out where a dragged monitor lands; nesting puts it in its parent's group.
pub fn plan_move(all: &[Monitor], group_ids: &[i64], id: i64, group: Option<i64>, parent: Option<i64>) -> Result<(Option<i64>, Option<i64>), String> {
    if !all.iter().any(|m| m.id == id) {
        return Err("Monitor not found".into());
    }
    match parent {
        Some(p) => {
            let Some(target) = all.iter().find(|m| m.id == p) else { return Err("Target monitor not found".into()) };
            if p == id {
                return Err("A monitor cannot be its own parent".into());
            }
            if target.parent_id.is_some() {
                return Err("That monitor is itself a sub-monitor; only one level of nesting is supported".into());
            }
            if all.iter().any(|m| m.parent_id == Some(id)) {
                return Err("This monitor has sub-monitors, so it cannot be placed under another one".into());
            }
            Ok((target.group_id, Some(p)))
        }
        None => match group {
            Some(g) if !group_ids.contains(&g) => Err("That group no longer exists".into()),
            g => Ok((g, None)),
        },
    }
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub struct MoveForm {
    csrf: String,
    group_id: String,
    parent_id: String,
}

fn parse_opt_id(v: &str) -> Result<Option<i64>, String> {
    match v.trim() {
        "" => Ok(None),
        x => x.parse().map(Some).map_err(|_| "Invalid id".to_string()),
    }
}

pub async fn move_monitor(State(st): State<AppState>, user: CurrentUser, Path(id): Path<i64>, Form(f): Form<MoveForm>) -> AppResult<Response> {
    user.check_csrf(&f.csrf)?;
    let all = store::monitors::list(st.db()).await?;
    let group_ids: Vec<i64> = store::groups::list(st.db()).await?.iter().map(|g| g.id).collect();
    let plan = parse_opt_id(&f.group_id)
        .and_then(|g| parse_opt_id(&f.parent_id).map(|p| (g, p)))
        .and_then(|(g, p)| plan_move(&all, &group_ids, id, g, p));
    match plan {
        Ok((group, parent)) => {
            store::monitors::move_to(st.db(), id, group, parent).await?;
            Ok(axum::Json(serde_json::json!({ "ok": true })).into_response())
        }
        Err(e) => Ok((StatusCode::BAD_REQUEST, axum::Json(serde_json::json!({ "ok": false, "error": e }))).into_response()),
    }
}

/// Runs the check described by the unsaved form and reports the result without storing anything.
pub async fn test_monitor(State(st): State<AppState>, user: CurrentUser, Form(f): Form<MonitorForm>) -> AppResult<Response> {
    user.check_csrf(&f.csrf)?;
    let input = match validate_with_groups(&st, &f, None).await? {
        Ok(i) => i,
        Err(e) => return Ok(axum::Json(serde_json::json!({ "ok": false, "error": e })).into_response()),
    };
    let kind = MonitorKind::parse(&input.kind).unwrap_or(MonitorKind::Http);
    if matches!(kind, MonitorKind::Push | MonitorKind::Aggregate) {
        return Ok(axum::Json(serde_json::json!({ "ok": false, "error": "This type is not checked actively." })).into_response());
    }
    let out = checks::run(&Monitor::draft(&input)).await;
    let t = &out.timings;
    let timings: Vec<(&str, String)> = [("DNS", t.dns_ms), ("Connect", t.connect_ms), ("TLS", t.tls_ms), ("Response", t.ttfb_ms), ("Total", t.total_ms)]
        .into_iter()
        .filter_map(|(k, v)| v.map(|v| (k, format_ms(Some(v)))))
        .collect();
    Ok(axum::Json(serde_json::json!({
        "ok": out.ok,
        "message": out.message,
        "status_code": out.status_code,
        "remote_ip": out.remote_ip,
        "timings": timings,
        "cert": views::cert_info(out.cert_expires_at, now_ms()).map(|(d, _)| d),
        "preview": out.preview,
    }))
    .into_response())
}

pub async fn events(State(st): State<AppState>, _user: CurrentUser) -> impl IntoResponse {
    public::event_stream(&st, false)
}

#[derive(Deserialize, Clone, Debug)]
#[serde(default)]
pub struct MonitorForm {
    pub csrf: String,
    pub name: String,
    pub kind: String,
    pub url: String,
    pub host: String,
    pub port: String,
    pub method: String,
    pub headers: String,
    pub body: String,
    pub interval_s: String,
    pub retry_interval_s: String,
    pub timeout_s: String,
    pub failure_threshold: String,
    pub expected_status: String,
    pub ip_family: String,
    pub follow_redirects: Option<String>,
    pub ignore_tls: Option<String>,
    pub content_kind: String,
    pub content_value: String,
    pub content_expected: String,
    pub dns_expected: String,
    pub ssl_warn_days: String,
    pub dns_record_type: String,
    pub dns_server: String,
    pub active: Option<String>,
    pub public: Option<String>,
    pub channels: Vec<i64>,
    pub group_id: String,
    pub public_name: String,
    pub parent_id: String,
}

impl Default for MonitorForm {
    fn default() -> Self {
        Self::from_monitor_input(&MonitorInput::http("", ""), Vec::new())
    }
}

impl MonitorForm {
    fn from_monitor_input(m: &MonitorInput, channels: Vec<i64>) -> Self {
        let flag = |b: bool| b.then(|| "on".to_string());
        let is_http = m.kind == "http" || m.kind == "websocket";
        Self {
            csrf: String::new(),
            name: m.name.clone(),
            kind: m.kind.clone(),
            url: if is_http { m.target.clone() } else { String::new() },
            host: if is_http { String::new() } else { m.target.clone() },
            port: m.port.map(|p| p.to_string()).unwrap_or_default(),
            method: m.method.clone(),
            headers: m.headers.clone(),
            body: m.body.clone(),
            interval_s: m.interval_s.to_string(),
            retry_interval_s: m.retry_interval_s.to_string(),
            timeout_s: m.timeout_s.to_string(),
            failure_threshold: m.failure_threshold.to_string(),
            expected_status: m.expected_status.clone(),
            ip_family: m.ip_family.clone(),
            follow_redirects: flag(m.follow_redirects),
            ignore_tls: flag(m.ignore_tls),
            content_kind: m.content_kind.clone(),
            content_value: m.content_value.clone(),
            content_expected: if is_http { m.content_expected.clone() } else { String::new() },
            dns_expected: if is_http { String::new() } else { m.content_expected.clone() },
            ssl_warn_days: m.ssl_warn_days.to_string(),
            dns_record_type: m.dns_record_type.clone(),
            dns_server: m.dns_server.clone(),
            active: flag(m.active),
            public: flag(m.public),
            channels,
            group_id: m.group_id.map(|g| g.to_string()).unwrap_or_default(),
            public_name: m.public_name.clone(),
            parent_id: m.parent_id.map(|p| p.to_string()).unwrap_or_default(),
        }
    }

    fn from_monitor(m: &Monitor, channels: Vec<i64>) -> Self {
        let input = MonitorInput {
            name: m.name.clone(),
            kind: m.kind.clone(),
            target: m.target.clone(),
            port: m.port,
            method: m.method.clone(),
            headers: m.headers.clone(),
            body: m.body.clone(),
            interval_s: m.interval_s,
            retry_interval_s: m.retry_interval_s,
            timeout_s: m.timeout_s,
            failure_threshold: m.failure_threshold,
            expected_status: m.expected_status.clone(),
            ip_family: m.ip_family.clone(),
            follow_redirects: m.follow_redirects,
            ignore_tls: m.ignore_tls,
            content_kind: m.content_kind.clone(),
            content_value: m.content_value.clone(),
            content_expected: m.content_expected.clone(),
            ssl_warn_days: m.ssl_warn_days,
            dns_record_type: m.dns_record_type.clone(),
            dns_server: m.dns_server.clone(),
            active: m.active,
            public: m.public,
            group_id: m.group_id,
            public_name: m.public_name.clone(),
            parent_id: m.parent_id,
        };
        Self::from_monitor_input(&input, channels)
    }

    pub fn checked(&self, id: &i64) -> bool {
        self.channels.contains(id)
    }

    pub fn is_kind(&self, k: &str) -> bool {
        self.kind == k
    }

    pub fn in_group(&self, id: &i64) -> bool {
        self.group_id == id.to_string()
    }

    pub fn has_parent(&self, id: &i64) -> bool {
        self.parent_id == id.to_string()
    }

    pub fn is_method(&self, m: &str) -> bool {
        self.method == m
    }

    pub fn is_record(&self, r: &str) -> bool {
        self.dns_record_type == r
    }

    pub fn validate(&self) -> Result<MonitorInput, String> {
        let num = |v: &str, field: &str, min: i64, max: i64| -> Result<i64, String> {
            match v.trim().parse::<i64>() {
                Ok(n) if (min..=max).contains(&n) => Ok(n),
                _ => Err(format!("{field} must be a number between {min} and {max}")),
            }
        };
        // Fields hidden for the chosen type are not submitted, so empty values fall back to defaults.
        let timing = |v: &str, field: &str, min: i64, max: i64, default: i64| {
            if v.trim().is_empty() { Ok(default) } else { num(v, field, min, max) }
        };
        let name = self.name.trim().to_string();
        if name.is_empty() || name.chars().count() > 100 {
            return Err("Name is required (up to 100 characters)".into());
        }
        let kind = MonitorKind::parse(&self.kind).ok_or("Unknown monitor type")?;
        let uses_url = matches!(kind, MonitorKind::Http | MonitorKind::WebSocket);
        let target = if uses_url { self.url.trim() } else { self.host.trim() }.to_string();
        let mut port = None;
        let mut method = "GET".to_string();
        let content_kind = ContentKind::parse(&self.content_kind);
        match kind {
            MonitorKind::Http => {
                let u = url::Url::parse(&target).map_err(|_| "URL must be a full address like https://example.com")?;
                if !matches!(u.scheme(), "http" | "https") || u.host_str().is_none() {
                    return Err("URL must start with http:// or https://".into());
                }
                method = self.method.trim().to_ascii_uppercase();
                if !["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"].contains(&method.as_str()) {
                    return Err("Unsupported HTTP method".into());
                }
                checks::parse_headers(&self.headers)?;
                StatusMatcher::parse(&self.expected_status).map_err(|e| format!("Accepted status codes: {e}"))?;
                content::validate(content_kind, &self.content_value)?;
            }
            MonitorKind::WebSocket => {
                let u = url::Url::parse(&target).map_err(|_| "URL must be a full address like wss://example.com/socket")?;
                if !matches!(u.scheme(), "ws" | "wss") || u.host_str().is_none() {
                    return Err("WebSocket URL must start with ws:// or wss://".into());
                }
                checks::parse_headers(&self.headers)?;
                content::validate(content_kind, &self.content_value)?;
            }
            MonitorKind::Tcp => {
                if target.is_empty() {
                    return Err("Host is required".into());
                }
                port = Some(num(&self.port, "Port", 1, 65535)?);
            }
            MonitorKind::Ping => {
                if target.is_empty() {
                    return Err("Host is required".into());
                }
            }
            MonitorKind::Dns => {
                if target.is_empty() {
                    return Err("Domain name is required".into());
                }
                if !dns::RECORD_TYPES.contains(&self.dns_record_type.as_str()) {
                    return Err("Unsupported DNS record type".into());
                }
                dns::parse_server(&self.dns_server)?;
            }
            MonitorKind::Push | MonitorKind::Aggregate => {}
        }
        Ok(MonitorInput {
            name,
            kind: kind.as_str().into(),
            target: if matches!(kind, MonitorKind::Push | MonitorKind::Aggregate) { String::new() } else { target },
            port,
            method,
            headers: self.headers.trim().to_string(),
            body: self.body.clone(),
            interval_s: timing(&self.interval_s, "Interval", 5, 7 * 86400, 60)?,
            retry_interval_s: timing(&self.retry_interval_s, "Retry interval", 5, 7 * 86400, 60)?,
            timeout_s: timing(&self.timeout_s, "Timeout", 1, 300, 30)?,
            failure_threshold: timing(&self.failure_threshold, "Failures before down", 1, 100, 3)?,
            expected_status: self.expected_status.trim().to_string(),
            ip_family: IpFamily::parse(&self.ip_family).as_str().into(),
            follow_redirects: self.follow_redirects.is_some(),
            ignore_tls: self.ignore_tls.is_some(),
            content_kind: if uses_url { content_kind.as_str().into() } else { "none".into() },
            content_value: self.content_value.clone(),
            content_expected: match kind {
                MonitorKind::Http | MonitorKind::WebSocket => self.content_expected.trim().to_string(),
                MonitorKind::Dns => self.dns_expected.trim().to_string(),
                _ => String::new(),
            },
            ssl_warn_days: timing(&self.ssl_warn_days, "Certificate warning days", 0, 365, 14)?,
            dns_record_type: self.dns_record_type.clone(),
            dns_server: self.dns_server.trim().to_string(),
            active: self.active.is_some(),
            public: self.public.is_some(),
            group_id: match self.group_id.trim() {
                "" => None,
                g => Some(g.parse().map_err(|_| "Unknown group")?),
            },
            public_name: {
                let p = self.public_name.trim();
                if p.chars().count() > 100 {
                    return Err("Public name is limited to 100 characters".into());
                }
                p.to_string()
            },
            parent_id: match self.parent_id.trim() {
                "" => None,
                p => Some(p.parse().map_err(|_| "Unknown parent monitor")?),
            },
        })
    }
}

pub struct ChannelOption {
    pub id: i64,
    pub name: String,
    pub kind: String,
}

#[derive(Template)]
#[template(path = "monitor_form.html")]
struct MonitorFormPage {
    layout: Layout,
    id: Option<i64>,
    f: MonitorForm,
    error: Option<String>,
    channels: Vec<ChannelOption>,
    groups: Vec<MonitorGroup>,
    parents: Vec<(i64, String)>,
    kinds: Vec<(&'static str, &'static str)>,
    record_types: Vec<&'static str>,
}

async fn form_page(st: &AppState, user: &CurrentUser, id: Option<i64>, f: MonitorForm, error: Option<String>) -> AppResult<Response> {
    let channels = store::notifications::list(st.db())
        .await?
        .into_iter()
        .map(|c| ChannelOption {
            id: c.id,
            name: c.name,
            kind: crate::notify::KINDS.iter().find(|(k, _)| *k == c.kind).map_or(c.kind.clone(), |(_, l)| l.to_string()),
        })
        .collect();
    let title = if id.is_some() { "Edit monitor" } else { "New monitor" };
    let status = if error.is_some() { StatusCode::BAD_REQUEST } else { StatusCode::OK };
    let page = MonitorFormPage {
        layout: Layout::admin(title, user, "monitors"),
        id,
        f,
        error,
        channels,
        groups: store::groups::list(st.db()).await?,
        parents: store::monitors::list(st.db())
            .await?
            .into_iter()
            .filter(|m| m.parent_id.is_none() && Some(m.id) != id)
            .map(|m| (m.id, m.name))
            .collect(),
        kinds: MonitorKind::ALL.iter().map(|k| (k.as_str(), k.label())).collect(),
        record_types: dns::RECORD_TYPES.to_vec(),
    };
    Ok((status, render(&page)?).into_response())
}

pub async fn new_monitor(State(st): State<AppState>, user: CurrentUser) -> AppResult<Response> {
    let defaults = store::notifications::default_ids(st.db()).await?;
    let f = MonitorForm { channels: defaults, ..MonitorForm::default() };
    form_page(&st, &user, None, f, None).await
}

/// Checks references to other rows; only one level of nesting is allowed.
async fn validate_with_groups(st: &AppState, f: &MonitorForm, editing: Option<i64>) -> AppResult<Result<MonitorInput, String>> {
    let input = match f.validate() {
        Ok(i) => i,
        Err(e) => return Ok(Err(e)),
    };
    if let Some(g) = input.group_id
        && !store::groups::list(st.db()).await?.iter().any(|x| x.id == g)
    {
        return Ok(Err("That group no longer exists".into()));
    }
    if let Some(p) = input.parent_id {
        let all = store::monitors::list(st.db()).await?;
        let Some(parent) = all.iter().find(|m| m.id == p) else {
            return Ok(Err("The parent monitor no longer exists".into()));
        };
        if Some(p) == editing {
            return Ok(Err("A monitor cannot be its own parent".into()));
        }
        if parent.parent_id.is_some() {
            return Ok(Err("The parent is itself a sub-monitor; only one level of nesting is supported".into()));
        }
        if editing.is_some_and(|id| all.iter().any(|m| m.parent_id == Some(id))) {
            return Ok(Err("This monitor has sub-monitors, so it cannot be placed under another one".into()));
        }
    }
    Ok(Ok(input))
}

pub async fn create_monitor(State(st): State<AppState>, user: CurrentUser, Form(f): Form<MonitorForm>) -> AppResult<Response> {
    user.check_csrf(&f.csrf)?;
    let input = match validate_with_groups(&st, &f, None).await? {
        Ok(i) => i,
        Err(e) => return form_page(&st, &user, None, f, Some(e)).await,
    };
    let id = store::monitors::create(st.db(), &input).await?;
    store::monitors::set_channels(st.db(), id, &f.channels).await?;
    st.scheduler.reload(id).await?;
    Ok(Redirect::to(&format!("/admin/monitors/{id}?notice=created")).into_response())
}

pub async fn edit_monitor(State(st): State<AppState>, user: CurrentUser, Path(id): Path<i64>) -> AppResult<Response> {
    let m = store::monitors::get(st.db(), id).await?.ok_or_else(AppError::not_found)?;
    let channels = store::monitors::channel_ids(st.db(), id).await?;
    form_page(&st, &user, Some(id), MonitorForm::from_monitor(&m, channels), None).await
}

pub async fn update_monitor(State(st): State<AppState>, user: CurrentUser, Path(id): Path<i64>, Form(f): Form<MonitorForm>) -> AppResult<Response> {
    user.check_csrf(&f.csrf)?;
    store::monitors::get(st.db(), id).await?.ok_or_else(AppError::not_found)?;
    let input = match validate_with_groups(&st, &f, Some(id)).await? {
        Ok(i) => i,
        Err(e) => return form_page(&st, &user, Some(id), f, Some(e)).await,
    };
    store::monitors::update(st.db(), id, &input).await?;
    store::monitors::set_channels(st.db(), id, &f.channels).await?;
    st.scheduler.reload(id).await?;
    Ok(Redirect::to(&format!("/admin/monitors/{id}?notice=saved")).into_response())
}

pub async fn toggle_monitor(State(st): State<AppState>, user: CurrentUser, Path(id): Path<i64>, Form(f): Form<CsrfForm>) -> AppResult<Response> {
    user.check_csrf(&f.csrf)?;
    let m = store::monitors::get(st.db(), id).await?.ok_or_else(AppError::not_found)?;
    store::monitors::set_active(st.db(), id, !m.active).await?;
    st.scheduler.reload(id).await?;
    let notice = if m.active { "paused" } else { "resumed" };
    Ok(Redirect::to(&format!("/admin/monitors/{id}?notice={notice}")).into_response())
}

pub async fn delete_monitor(State(st): State<AppState>, user: CurrentUser, Path(id): Path<i64>, Form(f): Form<CsrfForm>) -> AppResult<Response> {
    user.check_csrf(&f.csrf)?;
    st.scheduler.stop(id).await;
    store::monitors::delete(st.db(), id).await?;
    Ok(Redirect::to("/admin?notice=deleted").into_response())
}

pub struct CheckRow {
    pub time: String,
    pub status_class: &'static str,
    pub status_label: &'static str,
    pub code: String,
    pub total: String,
    pub ip: String,
    pub message: String,
}

pub struct ChildRow {
    pub id: i64,
    pub name: String,
    pub status_class: &'static str,
    pub status_label: &'static str,
}

pub struct IncidentRow {
    pub started: String,
    pub duration: String,
    pub ongoing: bool,
    pub message: String,
}

#[derive(Template)]
#[template(path = "monitor_detail.html")]
struct DetailPage {
    layout: Layout,
    m: Monitor,
    kind_label: &'static str,
    target: String,
    status_class: &'static str,
    status_label: &'static str,
    range: String,
    chart: String,
    phase_svg: String,
    phases: Vec<PhaseAvg>,
    uptime_24h: String,
    uptime_7d: String,
    uptime_30d: String,
    avg_latency: String,
    cert: Option<(String, &'static str)>,
    cert_date: String,
    push_url: Option<String>,
    channels: Vec<String>,
    group: Option<String>,
    parent: Option<(i64, String)>,
    children: Vec<ChildRow>,
    facts: Vec<(&'static str, String)>,
    bars: Vec<Bar>,
    incidents: Vec<IncidentRow>,
    checks: Vec<CheckRow>,
}

fn origin(st: &AppState, headers: &HeaderMap) -> String {
    if let Some(b) = st.ctx.base_url() {
        return b;
    }
    let host = headers.get("host").and_then(|h| h.to_str().ok()).unwrap_or("localhost");
    let proto = headers.get("x-forwarded-proto").and_then(|h| h.to_str().ok()).unwrap_or("http");
    format!("{proto}://{host}")
}

pub async fn monitor_detail(
    State(st): State<AppState>,
    user: CurrentUser,
    Path(id): Path<i64>,
    Query(q): Query<NoticeQuery>,
    headers: HeaderMap,
) -> AppResult<Html<String>> {
    let db = st.db();
    let m = store::monitors::get(db, id).await?.ok_or_else(AppError::not_found)?;
    let now = now_ms();
    let (range, since, bucket) = match q.range.as_deref() {
        Some("7d") => ("7d", now - 7 * DAY_MS, HOUR_MS),
        Some("30d") => ("30d", now - 30 * DAY_MS, 4 * HOUR_MS),
        _ => ("24h", now - DAY_MS, 5 * 60_000),
    };
    let points = stats::series(db, id, since, bucket).await?;
    let (phase_svg, phases) = charts::phase_breakdown(&points);
    let (lat_sum, lat_n) = points.iter().filter_map(|p| p.total_ms.map(|t| (t * p.up as f64, p.up))).fold((0.0, 0), |a, b| (a.0 + b.0, a.1 + b.1));
    let up = |since| async move { stats::uptime_all(db, since).await.map(|m| format_pct(m.get(&id).copied())) };
    let recent = store::heartbeats::recent(db, id, 60).await?;
    let mut oldest_first = recent.clone();
    oldest_first.reverse();
    let last_status = recent.first().map(|b| b.status());
    let (status_class, status_label) = match (m.active, last_status) {
        (false, _) => ("s-paused", "Paused"),
        (true, None) => ("s-none", "Waiting for first check"),
        (true, Some(s)) => (views::status_class(s), status_label(s)),
    };
    let cert_expiry = store::heartbeats::latest_cert_expiry(db, id).await?;
    let channel_ids = store::monitors::channel_ids(db, id).await?;
    let channels = store::notifications::list(db).await?.into_iter().filter(|c| channel_ids.contains(&c.id)).map(|c| c.name).collect();
    let incidents = store::heartbeats::incidents_for(db, id, 20)
        .await?
        .into_iter()
        .map(|i| IncidentRow {
            started: format_ts(i.started_at),
            duration: format_duration_ms(i.ended_at.unwrap_or(now) - i.started_at),
            ongoing: i.ended_at.is_none(),
            message: i.message,
        })
        .collect();
    let checks = recent
        .iter()
        .take(50)
        .map(|b| CheckRow {
            time: format_ts(b.ts),
            status_class: views::status_class(b.status()),
            status_label: views::status_label(b.status()),
            code: b.status_code.map(|c| c.to_string()).unwrap_or_default(),
            total: format_ms(b.total_ms),
            ip: b.remote_ip.clone().unwrap_or_default(),
            message: b.message.clone(),
        })
        .collect();
    let all = store::monitors::list(db).await?;
    let latest = store::heartbeats::recent_all(db, 1).await?;
    let parent = m.parent_id.and_then(|p| all.iter().find(|x| x.id == p)).map(|p| (p.id, p.name.clone()));
    let children: Vec<ChildRow> = all
        .iter()
        .filter(|x| x.parent_id == Some(id))
        .map(|x| {
            let st = latest.get(&x.id).and_then(|b| b.last()).map(|b| b.status());
            let (status_class, status_label) = match (x.active, st) {
                (false, _) => ("s-paused", "Paused"),
                (true, None) => ("s-none", "Waiting"),
                (true, Some(s)) => (views::status_class(s), views::status_label(s)),
            };
            ChildRow { id: x.id, name: x.name.clone(), status_class, status_label }
        })
        .collect();
    let push_url = m.push_token.as_ref().filter(|_| m.kind() == MonitorKind::Push).map(|t| format!("{}/api/push/{t}?status=up&msg=OK", origin(&st, &headers)));
    let page = DetailPage {
        layout: Layout::admin(&m.name, &user, "monitors").with_notice(q.notice.as_deref()),
        kind_label: m.kind().label(),
        target: m.display_target(),
        status_class,
        status_label,
        range: range.into(),
        chart: charts::latency_svg(&points, since, now, bucket),
        phase_svg,
        phases,
        uptime_24h: up(now - DAY_MS).await?,
        uptime_7d: up(now - 7 * DAY_MS).await?,
        uptime_30d: up(now - 30 * DAY_MS).await?,
        avg_latency: if lat_n > 0 { format_ms(Some(lat_sum / lat_n as f64)) } else { format_ms(None) },
        cert: views::cert_info(cert_expiry, now),
        cert_date: cert_expiry.map(format_ts).unwrap_or_default(),
        push_url,
        channels,
        group: match m.group_id {
            Some(g) => store::groups::list(db).await?.into_iter().find(|x| x.id == g).map(|x| x.name),
            None => None,
        },
        parent,
        children,
        facts: views::check_facts(&m),
        bars: views::heartbeat_bars(&oldest_first, 60),
        incidents,
        checks,
        m,
    };
    render(&page)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn form(kind: &str, target: &str) -> MonitorForm {
        MonitorForm { name: "x".into(), kind: kind.into(), url: target.into(), host: target.into(), ..MonitorForm::default() }
    }

    #[test]
    fn defaults_produce_a_valid_http_monitor() {
        let i = form("http", "https://example.com/health").validate().unwrap();
        assert_eq!((i.failure_threshold, i.interval_s, i.ip_family.as_str()), (3, 60, "auto"));
        assert!(i.active && i.follow_redirects && !i.public);
    }

    #[test]
    fn http_validation_errors_are_specific() {
        assert!(form("http", "example.com").validate().unwrap_err().contains("URL"));
        assert!(form("http", "ftp://example.com").validate().unwrap_err().contains("http"));
        let f = MonitorForm { expected_status: "abc".into(), ..form("http", "https://e.com") };
        assert!(f.validate().unwrap_err().contains("status"));
        let f = MonitorForm { content_kind: "regex".into(), content_value: "(".into(), ..form("http", "https://e.com") };
        assert!(f.validate().unwrap_err().contains("regex"));
        let f = MonitorForm { interval_s: "1".into(), ..form("http", "https://e.com") };
        assert!(f.validate().unwrap_err().contains("Interval"));
        let f = MonitorForm { name: "  ".into(), ..form("http", "https://e.com") };
        assert!(f.validate().unwrap_err().contains("Name"));
    }

    #[test]
    fn other_kinds_validate_their_own_fields() {
        assert!(form("tcp", "db.local").validate().unwrap_err().contains("Port"));
        assert_eq!(MonitorForm { port: "5432".into(), ..form("tcp", "db.local") }.validate().unwrap().port, Some(5432));
        assert!(form("ping", "").validate().is_err());
        assert!(MonitorForm { dns_server: "dns.google".into(), ..form("dns", "example.com") }.validate().is_err());
        let push = form("push", "ignored").validate().unwrap();
        assert_eq!(push.target, "");
        assert!(form("smoke-signal", "x").validate().is_err());
    }

    #[test]
    fn hidden_fields_fall_back_to_defaults() {
        // What the browser sends for a TCP monitor: HTTP-only and timing fields are disabled.
        let f = MonitorForm {
            name: "db".into(),
            kind: "tcp".into(),
            host: "db.local".into(),
            port: "5432".into(),
            ssl_warn_days: String::new(),
            retry_interval_s: String::new(),
            timeout_s: String::new(),
            ..MonitorForm::default()
        };
        let i = f.validate().unwrap();
        assert_eq!((i.ssl_warn_days, i.retry_interval_s, i.timeout_s), (14, 60, 30));
        let bad = MonitorForm { interval_s: "abc".into(), ..f };
        assert!(bad.validate().is_err(), "typed garbage is still rejected");
    }

    #[test]
    fn aggregate_needs_no_target_or_timing() {
        let f = MonitorForm {
            name: "API".into(),
            kind: "aggregate".into(),
            interval_s: String::new(),
            failure_threshold: String::new(),
            ..MonitorForm::default()
        };
        let i = f.validate().unwrap();
        assert_eq!((i.kind.as_str(), i.target.as_str()), ("aggregate", ""));
    }

    fn mon(id: i64, group: Option<i64>, parent: Option<i64>) -> Monitor {
        let now = 0;
        Monitor {
            id, name: format!("m{id}"), kind: "http".into(), target: String::new(), port: None, method: "GET".into(),
            headers: String::new(), body: String::new(), interval_s: 60, retry_interval_s: 30, timeout_s: 10,
            failure_threshold: 3, expected_status: "200-299".into(), ip_family: "auto".into(), follow_redirects: true,
            ignore_tls: false, content_kind: "none".into(), content_value: String::new(), content_expected: String::new(),
            ssl_warn_days: 14, dns_record_type: "A".into(), dns_server: String::new(), push_token: None, active: true,
            public: false, ssl_notified_days: None, ssl_notified_expiry: None, created_at: now, updated_at: now,
            group_id: group, public_name: String::new(), parent_id: parent,
        }
    }

    #[test]
    fn dropping_on_a_monitor_nests_it_in_that_monitors_group() {
        let all = [mon(1, Some(10), None), mon(2, Some(20), None), mon(3, Some(10), Some(1))];
        assert_eq!(plan_move(&all, &[10, 20], 2, None, Some(1)), Ok((Some(10), Some(1))));
        assert_eq!(plan_move(&all, &[10, 20], 3, Some(20), None), Ok((Some(20), None)), "dropping on a group un-nests");
        assert_eq!(plan_move(&all, &[10, 20], 3, None, None), Ok((None, None)), "no group");
    }

    #[test]
    fn invalid_drops_are_rejected() {
        let all = [mon(1, None, None), mon(2, None, None), mon(3, None, Some(1))];
        assert!(plan_move(&all, &[], 1, None, Some(1)).unwrap_err().contains("own parent"));
        assert!(plan_move(&all, &[], 2, None, Some(3)).unwrap_err().contains("only one level"));
        assert!(plan_move(&all, &[], 1, None, Some(2)).unwrap_err().contains("has sub-monitors"));
        assert!(plan_move(&all, &[], 2, Some(99), None).unwrap_err().contains("no longer exists"));
        assert!(plan_move(&all, &[], 42, None, None).is_err());
    }

    #[test]
    fn content_checks_are_dropped_for_non_http() {
        let f = MonitorForm { content_kind: "contains".into(), content_value: "ok".into(), port: "22".into(), ..form("tcp", "h") };
        assert_eq!(f.validate().unwrap().content_kind, "none");
    }
}
