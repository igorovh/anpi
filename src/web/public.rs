use std::convert::Infallible;
use std::sync::Arc;

use askama::Template;
use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{Html, IntoResponse, Response};
use axum_extra::extract::CookieJar;
use futures_util::Stream;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast::error::RecvError;

use super::views::{self, Bar, Layout, status_label};
use super::{AppResult, AppState, SESSION_COOKIE, render};
use crate::models::{Monitor, MonitorGroup, Status};
use crate::monitor::MonitorEvent;
use crate::monitor::scheduler::PushSignal;
use crate::stats;
use crate::store::{self, settings::AppSettings};
use crate::util::{DAY_MS, floor_day, format_duration_ms, format_pct, format_ts, now_ms};

pub struct PublicMonitor {
    pub id: i64,
    pub name: String,
    pub group_id: Option<i64>,
    pub status: Option<Status>,
    pub status_class: &'static str,
    pub status_label: &'static str,
    pub uptime_24h: String,
    pub uptime_30d: String,
    pub latency_ms: Option<f64>,
    pub last_check: Option<i64>,
    pub bars: Vec<Bar>,
}

pub struct PublicIncident {
    pub monitor: String,
    pub started: String,
    pub duration: String,
    pub ongoing: bool,
}

pub struct PublicGroup {
    pub name: Option<String>,
    pub monitors: Vec<PublicMonitor>,
}

#[derive(Template)]
#[template(path = "status.html")]
struct StatusPage {
    layout: Layout,
    description: String,
    overall_class: &'static str,
    overall_label: &'static str,
    groups: Vec<PublicGroup>,
    incidents: Vec<PublicIncident>,
}

/// Groups in their configured order; ungrouped monitors come last under "Other" if any groups exist.
pub fn group_monitors<T>(groups: &[MonitorGroup], items: Vec<T>, group_of: impl Fn(&T) -> Option<i64>) -> Vec<(Option<String>, Vec<T>)> {
    let mut buckets: Vec<(Option<i64>, Option<String>, Vec<T>)> =
        groups.iter().map(|g| (Some(g.id), Some(g.name.clone()), Vec::new())).collect();
    buckets.push((None, None, Vec::new()));
    for item in items {
        let gid = group_of(&item);
        let idx = buckets.iter().position(|(id, _, _)| *id == gid && gid.is_some()).unwrap_or(buckets.len() - 1);
        buckets[idx].2.push(item);
    }
    let any_grouped = buckets.iter().any(|(id, _, v)| id.is_some() && !v.is_empty());
    buckets
        .into_iter()
        .filter(|(_, _, v)| !v.is_empty())
        .map(|(id, name, v)| (if id.is_none() && any_grouped { Some("Other".to_string()) } else { name }, v))
        .collect()
}

fn overall(monitors: &[PublicMonitor]) -> (&'static str, &'static str, &'static str) {
    let active: Vec<Status> = monitors.iter().filter_map(|m| m.status).collect();
    let down = active.iter().filter(|s| **s == Status::Down).count();
    if active.is_empty() {
        ("s-none", "No data yet", "unknown")
    } else if down == active.len() {
        ("s-down", "Major outage", "outage")
    } else if down > 0 {
        ("s-down", "Partial outage", "partial_outage")
    } else if active.contains(&Status::Pending) {
        ("s-pending", "Degraded performance", "degraded")
    } else if active.contains(&Status::Maintenance) {
        ("s-maint", "Under maintenance", "maintenance")
    } else {
        ("s-up", "All systems operational", "operational")
    }
}

async fn load_public(st: &AppState) -> AppResult<Vec<PublicMonitor>> {
    let db = st.db();
    let now = now_ms();
    let mut monitors: Vec<Monitor> = store::monitors::list_public(db).await?;
    monitors.sort_by_key(|m| m.public_label().to_lowercase());
    let latest = store::heartbeats::recent_all(db, 1).await?;
    let up24 = stats::uptime_all(db, now - DAY_MS).await?;
    let up30 = stats::uptime_all(db, now - 30 * DAY_MS).await?;
    let today = floor_day(now);
    let days = stats::buckets_all(db, today - 29 * DAY_MS, DAY_MS).await?;
    Ok(monitors
        .into_iter()
        .map(|m| {
            let last = latest.get(&m.id).and_then(|v| v.last());
            let status = if m.active { last.map(|b| b.status()) } else { None };
            let (status_class, status_label) = match (m.active, status) {
                (false, _) => ("s-paused", "Paused"),
                (true, None) => ("s-none", "No data"),
                (true, Some(Status::Pending)) => ("s-pending", "Degraded"),
                (true, Some(s)) => (views::status_class(s), status_label(s)),
            };
            PublicMonitor {
                id: m.id,
                name: m.public_label().to_string(),
                group_id: m.group_id,
                status,
                status_class,
                status_label,
                uptime_24h: format_pct(up24.get(&m.id).copied()),
                uptime_30d: format_pct(up30.get(&m.id).copied()),
                latency_ms: last.and_then(|b| b.total_ms),
                last_check: last.map(|b| b.ts),
                bars: views::daily_bars(days.get(&m.id).unwrap_or(&Default::default()), today, 30),
            }
        })
        .collect())
}

pub async fn status_page(State(st): State<AppState>, jar: CookieJar) -> AppResult<Html<String>> {
    let settings = AppSettings::load(st.db()).await?;
    let monitors = load_public(&st).await?;
    let all_groups = store::groups::list(st.db()).await?;
    let now = now_ms();
    let incidents = store::heartbeats::public_incidents_since(st.db(), now - 14 * DAY_MS)
        .await?
        .into_iter()
        .map(|(i, name)| PublicIncident {
            monitor: name,
            started: format_ts(i.started_at),
            duration: format_duration_ms(i.ended_at.unwrap_or(now) - i.started_at),
            ongoing: i.ended_at.is_none(),
        })
        .collect();
    let (overall_class, overall_label, _) = overall(&monitors);
    let groups = group_monitors(&all_groups, monitors, |m| m.group_id)
        .into_iter()
        .map(|(name, monitors)| PublicGroup { name, monitors })
        .collect();
    let mut layout = Layout::bare(&st.ctx.branding(), &settings.status_title);
    layout.signed_in = match jar.get(SESSION_COOKIE) {
        Some(c) => store::users::session(st.db(), c.value()).await?.is_some(),
        None => false,
    };
    layout.nav = "status";
    render(&StatusPage { layout, description: settings.status_description, overall_class, overall_label, groups, incidents })
}

#[derive(Serialize)]
struct StatusJson {
    title: String,
    status: &'static str,
    monitors: Vec<MonitorJson>,
}

#[derive(Serialize)]
struct MonitorJson {
    id: i64,
    name: String,
    group: Option<String>,
    status: &'static str,
    uptime_24h: String,
    uptime_30d: String,
    latency_ms: Option<f64>,
    last_check: Option<i64>,
}

pub async fn status_json(State(st): State<AppState>) -> AppResult<Response> {
    let settings = AppSettings::load(st.db()).await?;
    let monitors = load_public(&st).await?;
    let (_, _, status) = overall(&monitors);
    let groups: std::collections::HashMap<i64, String> =
        store::groups::list(st.db()).await?.into_iter().map(|g| (g.id, g.name)).collect();
    let body = StatusJson {
        title: settings.status_title,
        status,
        monitors: monitors
            .into_iter()
            .map(|m| MonitorJson {
                id: m.id,
                group: m.group_id.and_then(|g| groups.get(&g).cloned()),
                name: m.name,
                status: m.status.map(Status::as_str).unwrap_or("unknown"),
                uptime_24h: m.uptime_24h,
                uptime_30d: m.uptime_30d,
                latency_ms: m.latency_ms.map(|v| v.round()),
                last_check: m.last_check,
            })
            .collect(),
    };
    Ok(([(axum::http::header::CACHE_CONTROL, "public, max-age=30"), (axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")], Json(body))
        .into_response())
}

#[derive(Deserialize)]
pub struct PushQuery {
    status: Option<String>,
    msg: Option<String>,
    ping: Option<String>,
}

pub async fn push(State(st): State<AppState>, Path(token): Path<String>, Query(q): Query<PushQuery>) -> Response {
    let ok = !q.status.as_deref().is_some_and(|s| s.eq_ignore_ascii_case("down"));
    let signal = PushSignal {
        ok,
        message: q.msg.unwrap_or_default().chars().take(500).collect(),
        ping_ms: q.ping.and_then(|p| p.parse().ok()).filter(|p: &f64| p.is_finite() && *p >= 0.0),
    };
    if st.scheduler.push(&token, signal).await {
        Json(serde_json::json!({ "ok": true })).into_response()
    } else {
        (StatusCode::NOT_FOUND, Json(serde_json::json!({ "ok": false, "msg": "monitor not found or paused" }))).into_response()
    }
}

pub fn event_stream(st: &AppState, public_only: bool) -> Sse<impl Stream<Item = Result<Event, Infallible>> + use<>> {
    let rx = st.ctx.events.subscribe();
    let stream = futures_util::stream::unfold(rx, move |mut rx| async move {
        loop {
            match rx.recv().await {
                Ok(ev) => {
                    let ev: Arc<MonitorEvent> = ev;
                    if public_only && !ev.public {
                        continue;
                    }
                    let data = if public_only { ev.redacted() } else { (*ev).clone() };
                    if let Ok(event) = Event::default().json_data(&data) {
                        return Some((Ok(event), rx));
                    }
                }
                Err(RecvError::Lagged(_)) => continue,
                Err(RecvError::Closed) => return None,
            }
        }
    });
    Sse::new(stream).keep_alive(KeepAlive::new().interval(std::time::Duration::from_secs(20)))
}

pub async fn public_events(State(st): State<AppState>) -> impl IntoResponse {
    event_stream(&st, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn g(id: i64, name: &str) -> MonitorGroup {
        MonitorGroup { id, name: name.into(), sort_order: 0, created_at: 0 }
    }

    #[test]
    fn grouping_keeps_group_order_and_puts_ungrouped_last() {
        let groups = [g(2, "Website"), g(1, "API")];
        let items = vec![(1, Some(1)), (2, None), (3, Some(2)), (4, Some(99))];
        let out = group_monitors(&groups, items, |i| i.1);
        let names: Vec<_> = out.iter().map(|(n, v)| (n.clone(), v.iter().map(|i| i.0).collect::<Vec<_>>())).collect();
        assert_eq!(
            names,
            vec![
                (Some("Website".into()), vec![3]),
                (Some("API".into()), vec![1]),
                (Some("Other".into()), vec![2, 4]),
            ],
            "unknown group ids fall back to Other"
        );
    }

    #[test]
    fn without_groups_there_is_no_header() {
        let out = group_monitors(&[g(1, "Empty")], vec![1, 2], |_| None);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, None, "an empty group is hidden and ungrouped items need no header");
    }
}
