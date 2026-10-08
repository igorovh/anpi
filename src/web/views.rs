use crate::models::{Heartbeat, Status};
use crate::util::{DAY_MS, format_ms, format_pct, format_ts};

use super::{ASSET_VERSION, CurrentUser};
use crate::app::Branding;

pub struct Layout {
    pub title: String,
    pub site_name: String,
    pub logo_url: Option<String>,
    pub user: Option<String>,
    pub signed_in: bool,
    pub csrf: String,
    pub nav: &'static str,
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
            notice: None,
            asset_version: ASSET_VERSION,
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

pub struct Bar {
    pub class: &'static str,
    pub title: String,
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
    fn unknown_notice_codes_are_ignored() {
        assert_eq!(Layout::bare(&Branding::default(), "x").with_notice(Some("<script>")).notice, None);
        assert_eq!(Layout::bare(&Branding::default(), "x").with_notice(Some("saved")).notice.as_deref(), Some("Saved."));
    }
}
