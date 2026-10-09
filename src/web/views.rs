use crate::models::{ContentKind, Heartbeat, IpFamily, Monitor, MonitorKind, Status};
use crate::util::{DAY_MS, format_ms, format_pct, format_ts};

use super::{CurrentUser, asset_version};
use crate::app::Branding;

pub struct Layout {
    pub title: String,
    pub site_name: String,
    pub logo_url: Option<String>,
    pub user: Option<String>,
    pub signed_in: bool,
    pub csrf: String,
    pub nav: &'static str,
    pub show_incidents: bool,
    pub notice: Option<String>,
    pub asset_version: &'static str,
}

impl Layout {
    pub fn bare(brand: &Branding, title: &str) -> Self {
        Self {
            title: title.into(),
            site_name: brand.site_name.clone(),
            logo_url: brand.logo_version.map(|v| format!("/brand/logo?v={v}")),
            user: None,
            signed_in: false,
            csrf: String::new(),
            nav: "",
            show_incidents: true,
            notice: None,
            asset_version: asset_version(),
        }
    }

    pub fn admin(title: &str, user: &CurrentUser, nav: &'static str) -> Self {
        Self { user: Some(user.username.clone()), signed_in: true, csrf: user.csrf.clone(), nav, ..Self::bare(&user.brand, title) }
    }

    pub fn with_notice(mut self, notice: Option<&str>) -> Self {
        self.notice = notice.and_then(notice_text).map(str::to_string);
        self
    }
}

/// Only known codes are displayed so query strings cannot inject arbitrary text.
fn notice_text(code: &str) -> Option<&'static str> {
    Some(match code {
        "saved" => "Saved.",
        "created" => "Created.",
        "deleted" => "Deleted.",
        "paused" => "Monitor paused.",
        "resumed" => "Monitor resumed.",
        "bulk-paused" => "Selected monitors paused.",
        "bulk-resumed" => "Selected monitors resumed.",
        "bulk-moved" => "Selected monitors moved.",
        "bulk-deleted" => "Selected monitors deleted.",
        "none-selected" => "No monitors were selected.",
        "test-sent" => "Test notification sent.",
        "password" => "Password changed.",
        _ => return None,
    })
}

pub fn status_label(s: Status) -> &'static str {
    match s {
        Status::Up => "Up",
        Status::Down => "Down",
        Status::Pending => "Pending",
        Status::Maintenance => "Maintenance",
    }
}

#[derive(Clone, Debug)]
pub struct Bar {
    pub class: &'static str,
    pub title: String,
}

fn bar_severity(class: &str) -> u8 {
    match class {
        "s-down" | "b-down" => 4,
        "s-pending" | "b-partial" => 3,
        "s-maint" | "b-minor" => 2,
        "s-up" | "b-up" => 1,
        _ => 0,
    }
}

/// Combines equally long bar strips slot by slot, keeping the most severe bar of each slot.
pub fn worst_bars(strips: &[&[Bar]]) -> Vec<Bar> {
    let len = strips.iter().map(|s| s.len()).max().unwrap_or(0);
    (0..len)
        .map(|i| {
            strips
                .iter()
                .filter_map(|s| i.checked_sub(len - s.len()).and_then(|j| s.get(j)))
                .max_by_key(|b| bar_severity(b.class))
                .cloned()
                .unwrap_or(Bar { class: "hb-empty", title: String::new() })
        })
        .collect()
}

/// Moves rows under their parent row; rows whose parent is missing stay at the top level.
pub fn nest<T>(rows: Vec<T>, id: impl Fn(&T) -> i64, parent: impl Fn(&T) -> Option<i64>, children: impl Fn(&mut T) -> &mut Vec<T>) -> Vec<T> {
    let ids: std::collections::HashSet<i64> = rows.iter().map(&id).collect();
    let (kids, mut top): (Vec<T>, Vec<T>) = rows.into_iter().partition(|r| parent(r).is_some_and(|p| ids.contains(&p)));
    for kid in kids {
        let p = parent(&kid).expect("partitioned on parent");
        if let Some(row) = top.iter_mut().find(|r| id(r) == p) {
            children(row).push(kid);
        }
    }
    top
}

pub fn heartbeat_bars(beats: &[Heartbeat], slots: usize) -> Vec<Bar> {
    let mut bars: Vec<Bar> = (0..slots.saturating_sub(beats.len())).map(|_| Bar { class: "hb-empty", title: String::new() }).collect();
    for b in beats.iter().rev().take(slots).rev() {
        let s = b.status();
        let mut title = format!("{} · {}", format_ts(b.ts), status_label(s));
        if let Some(ms) = b.total_ms {
            title.push_str(&format!(" · {}", format_ms(Some(ms))));
        }
        if !b.message.is_empty() {
            title.push_str(&format!(" · {}", b.message));
        }
        bars.push(Bar { class: status_class(s), title });
    }
    bars
}

pub fn status_class(s: Status) -> &'static str {
    match s {
        Status::Up => "s-up",
        Status::Down => "s-down",
        Status::Pending => "s-pending",
        Status::Maintenance => "s-maint",
    }
}

pub fn uptime_class(pct: Option<f64>) -> &'static str {
    match pct {
        None => "b-none",
        Some(p) if p >= 99.95 => "b-up",
        Some(p) if p >= 99.0 => "b-minor",
        Some(p) if p >= 95.0 => "b-partial",
        Some(_) => "b-down",
    }
}

pub fn daily_bars(days: &std::collections::BTreeMap<i64, (i64, i64)>, today: i64, count: i64) -> Vec<Bar> {
    (0..count)
        .rev()
        .map(|i| {
            let day = today - i * DAY_MS;
            let pct = days.get(&day).filter(|(_, t)| *t > 0).map(|(u, t)| *u as f64 * 100.0 / *t as f64);
            let date = format_ts(day).get(..10).unwrap_or_default().to_string();
            let title = match pct {
                Some(p) => format!("{date} · {}", format_pct(Some(p))),
                None => format!("{date} · no data"),
            };
            Bar { class: uptime_class(pct), title }
        })
        .collect()
}

pub fn cert_info(expires_at: Option<i64>, now: i64) -> Option<(String, &'static str)> {
    let e = expires_at?;
    let days = (e - now).div_euclid(DAY_MS);
    let class = match days {
        d if d < 7 => "cert-bad",
        d if d < 21 => "cert-warn",
        _ => "cert-ok",
    };
    let text = if days < 0 { "expired".to_string() } else { format!("{days}d") };
    Some((text, class))
}

fn is_secret_header(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    ["authorization", "cookie", "token", "secret", "key", "password"].iter().any(|s| n.contains(s))
}

pub fn masked_headers(raw: &str) -> String {
    raw.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(|l| match l.split_once(':') {
            Some((k, _)) if is_secret_header(k) => format!("{}: ••••••", k.trim()),
            _ => l.to_string(),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn describe_expectation(m: &Monitor) -> String {
    let v = &m.content_value;
    let what = if m.kind() == MonitorKind::WebSocket { "reply" } else { "body" };
    match m.content_kind() {
        ContentKind::None if m.kind() == MonitorKind::WebSocket => "handshake succeeds".into(),
        ContentKind::None => "status code only".into(),
        ContentKind::Contains => format!("{what} contains “{v}”"),
        ContentKind::NotContains => format!("{what} does not contain “{v}”"),
        ContentKind::Regex => format!("{what} matches /{v}/"),
        ContentKind::JsonPath if m.content_expected.is_empty() => format!("JSON {v} exists"),
        ContentKind::JsonPath => format!("JSON {v} = {}", m.content_expected),
    }
}

/// Human-readable description of exactly what a monitor checks.
pub fn check_facts(m: &Monitor) -> Vec<(&'static str, String)> {
    let mut f: Vec<(&'static str, String)> = vec![("Type", m.kind().label().to_string())];
    let yes_no = |b: bool| if b { "yes" } else { "no" }.to_string();
    match m.kind() {
        MonitorKind::Http => {
            f.push(("Request", format!("{} {}", m.method, m.target)));
            if !m.headers.trim().is_empty() {
                f.push(("Headers", masked_headers(&m.headers)));
            }
            if !m.body.is_empty() {
                f.push(("Body", m.body.chars().take(200).collect()));
            }
            f.push(("Accepted codes", m.expected_status.clone()));
            f.push(("Expects", describe_expectation(m)));
            f.push(("Follow redirects", yes_no(m.follow_redirects)));
        }
        MonitorKind::WebSocket => {
            f.push(("URL", m.target.clone()));
            if !m.headers.trim().is_empty() {
                f.push(("Headers", masked_headers(&m.headers)));
            }
            f.push(("Sends", if m.body.is_empty() { "nothing".into() } else { m.body.chars().take(200).collect() }));
            f.push(("Expects", describe_expectation(m)));
        }
        MonitorKind::Tcp => f.push(("Connects to", format!("{}:{}", m.target, m.port.unwrap_or(0)))),
        MonitorKind::Ping => f.push(("Pings", m.target.clone())),
        MonitorKind::Dns => {
            f.push(("Query", format!("{} {}", m.dns_record_type, m.target)));
            f.push(("Resolver", if m.dns_server.is_empty() { "system".into() } else { m.dns_server.clone() }));
            if !m.content_expected.is_empty() {
                f.push(("Expects", format!("a record containing {}", m.content_expected)));
            }
        }
        MonitorKind::Push => f.push(("Expects", format!("a push at least every {}s", m.interval_s))),
        MonitorKind::Aggregate => f.push(("Shows", "the worst status of its sub-monitors".into())),
    }
    if matches!(m.kind(), MonitorKind::Http | MonitorKind::WebSocket | MonitorKind::Tcp | MonitorKind::Ping) {
        f.push(("IP version", match m.ip_family() { IpFamily::Auto => "auto (IPv6, then IPv4)", IpFamily::V4 => "IPv4 only", IpFamily::V6 => "IPv6 only" }.into()));
    }
    if matches!(m.kind(), MonitorKind::Http | MonitorKind::WebSocket) {
        f.push(("TLS", if m.ignore_tls { "errors ignored".into() } else { "verified".into() }));
        f.push(("Certificate warning", if m.ssl_warn_days > 0 { format!("{} days before expiry", m.ssl_warn_days) } else { "off".into() }));
    }
    if !matches!(m.kind(), MonitorKind::Push | MonitorKind::Aggregate) {
        f.push(("Interval", format!("every {}s, every {}s while failing", m.interval_s, m.retry_interval_s)));
        f.push(("Timeout", format!("{}s", m.timeout_s)));
    }
    if m.kind() != MonitorKind::Aggregate {
        let n = m.failure_threshold;
        f.push(("Down after", format!("{n} failed check{} in a row", if n == 1 { "" } else { "s" })));
    }
    f
}

/// Page navigation; `link` builds the URL for a page number.
pub struct Pager {
    pub page: i64,
    pub pages: i64,
    pub total: i64,
    pub prev: Option<String>,
    pub next: Option<String>,
}

impl Pager {
    pub fn new(total: i64, per_page: i64, requested: i64, link: impl Fn(i64) -> String) -> Self {
        let pages = ((total + per_page - 1) / per_page.max(1)).max(1);
        let page = requested.clamp(1, pages);
        Self {
            page,
            pages,
            total,
            prev: (page > 1).then(|| link(page - 1)),
            next: (page < pages).then(|| link(page + 1)),
        }
    }

    pub fn is_multi(&self) -> bool {
        self.pages > 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn beat(ts: i64, status: Status) -> Heartbeat {
        Heartbeat {
            id: ts,
            monitor_id: 1,
            ts,
            status: status.as_i64(),
            status_code: None,
            dns_ms: None,
            connect_ms: None,
            tls_ms: None,
            ttfb_ms: None,
            total_ms: Some(42.0),
            remote_ip: None,
            message: "boom".into(),
            cert_expires_at: None,
        }
    }

    #[test]
    fn heartbeat_strip_is_padded_and_keeps_newest() {
        let beats: Vec<_> = (0..5).map(|i| beat(i, if i == 4 { Status::Down } else { Status::Up })).collect();
        let bars = heartbeat_bars(&beats, 8);
        assert_eq!(bars.len(), 8);
        assert_eq!(bars.iter().filter(|b| b.class == "hb-empty").count(), 3);
        assert_eq!(bars.last().unwrap().class, "s-down");
        assert!(bars.last().unwrap().title.contains("boom"));
        assert_eq!(heartbeat_bars(&beats, 3).len(), 3);
        assert_eq!(heartbeat_bars(&beats, 3)[2].class, "s-down");
    }

    #[test]
    fn daily_bars_fill_missing_days() {
        let today = 100 * DAY_MS;
        let days = BTreeMap::from([(today, (99, 100)), (today - 2 * DAY_MS, (10, 10))]);
        let bars = daily_bars(&days, today, 3);
        assert_eq!(bars.iter().map(|b| b.class).collect::<Vec<_>>(), vec!["b-up", "b-none", "b-minor"]);
    }

    #[test]
    fn worst_bars_keep_the_most_severe_slot() {
        let b = |c: &'static str| Bar { class: c, title: c.into() };
        let a = [b("s-up"), b("s-up"), b("hb-empty")];
        let c = [b("s-pending"), b("s-up"), b("s-up")];
        let d = [b("s-up"), b("s-down"), b("s-up")];
        let out: Vec<_> = worst_bars(&[&a, &c, &d]).into_iter().map(|b| b.class).collect();
        assert_eq!(out, vec!["s-pending", "s-down", "s-up"]);
        let days = [b("b-none"), b("b-minor")];
        let more = [b("b-up"), b("b-up")];
        assert_eq!(worst_bars(&[&days, &more]).into_iter().map(|b| b.class).collect::<Vec<_>>(), vec!["b-up", "b-minor"]);
    }

    #[test]
    fn nesting_attaches_children_and_keeps_orphans() {
        #[derive(Debug, PartialEq)]
        struct R {
            id: i64,
            parent: Option<i64>,
            kids: Vec<R>,
        }
        let r = |id, parent| R { id, parent, kids: vec![] };
        let out = nest(vec![r(1, None), r(2, Some(1)), r(3, Some(99)), r(4, Some(1))], |x| x.id, |x| x.parent, |x| &mut x.kids);
        assert_eq!(out.iter().map(|x| x.id).collect::<Vec<_>>(), vec![1, 3], "orphan 3 stays top-level");
        assert_eq!(out[0].kids.iter().map(|x| x.id).collect::<Vec<_>>(), vec![2, 4], "children keep their order");
    }

    #[test]
    fn secret_header_values_are_masked() {
        let out = masked_headers("Authorization: Bearer abc\nX-Api-Key: k\nAccept: application/json");
        assert_eq!(out, "Authorization: ••••••\nX-Api-Key: ••••••\nAccept: application/json");
    }

    #[test]
    fn check_description_spells_out_request_and_expectation() {
        let mut input = crate::models::MonitorInput::http("API", "https://api.example.com/health");
        input.content_kind = "json_path".into();
        input.content_value = "$.status".into();
        input.content_expected = "ok".into();
        let facts = check_facts(&Monitor::draft(&input));
        let get = |k: &str| facts.iter().find(|(n, _)| *n == k).map(|(_, v)| v.clone()).unwrap_or_default();
        assert_eq!(get("Request"), "GET https://api.example.com/health");
        assert_eq!(get("Expects"), "JSON $.status = ok");
        assert_eq!(get("Interval"), "every 60s, every 30s while failing");
        assert_eq!(get("Down after"), "3 failed checks in a row");

        input.kind = "websocket".into();
        input.content_kind = "none".into();
        let facts = check_facts(&Monitor::draft(&input));
        assert!(facts.iter().any(|(k, v)| *k == "Expects" && v == "handshake succeeds"));
        assert!(facts.iter().any(|(k, v)| *k == "Sends" && v == "nothing"));
    }

    #[test]
    fn pager_clamps_and_links() {
        let p = Pager::new(42, 10, 1, |n| format!("?p={n}"));
        assert_eq!((p.page, p.pages, p.prev.as_deref(), p.next.as_deref()), (1, 5, None, Some("?p=2")));
        let last = Pager::new(42, 10, 99, |n| format!("?p={n}"));
        assert_eq!((last.page, last.next.as_deref(), last.prev.as_deref()), (5, None, Some("?p=4")), "out of range clamps to the last page");
        let empty = Pager::new(0, 10, 0, |n| format!("?p={n}"));
        assert_eq!((empty.page, empty.pages, empty.is_multi()), (1, 1, false));
        assert_eq!(Pager::new(10, 10, 1, |n| n.to_string()).pages, 1, "an exact multiple has no empty last page");
    }

    #[test]
    fn unknown_notice_codes_are_ignored() {
        assert_eq!(Layout::bare(&Branding::default(), "x").with_notice(Some("<script>")).notice, None);
        assert_eq!(Layout::bare(&Branding::default(), "x").with_notice(Some("saved")).notice.as_deref(), Some("Saved."));
    }
}
