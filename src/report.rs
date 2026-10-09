//! Daily or weekly summaries sent to notification channels; they double as proof that anpi is alive.

use std::collections::HashMap;
use std::sync::Arc;

use serde::Serialize;

use crate::app::Ctx;
use crate::db::Db;
use crate::notify::{self, EventKind, NotifyEvent};
use crate::selfcheck;
use crate::store::{self, settings};
use crate::util::{DAY_MS, HOUR_MS, floor_day, format_duration_ms, format_pct, now_ms};

/// How many monitors with problems are listed one by one.
const MAX_LISTED: usize = 10;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Frequency {
    Off,
    Daily,
    Weekly,
}

impl Frequency {
    pub fn parse(s: &str) -> Self {
        match s {
            "daily" => Self::Daily,
            "weekly" => Self::Weekly,
            _ => Self::Off,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Daily => "daily",
            Self::Weekly => "weekly",
        }
    }

    pub fn period_ms(self) -> i64 {
        if self == Self::Weekly { 7 * DAY_MS } else { DAY_MS }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ReportSettings {
    pub frequency: Frequency,
    /// 0 = Monday.
    pub weekday: i64,
    pub hour: i64,
    /// Minutes as returned by the browser's `getTimezoneOffset()` (UTC minus local time).
    pub tz_offset_min: i64,
    /// Empty means the default notification channels.
    pub channels: Vec<i64>,
    /// The scheduled time of the last report sent.
    pub last_sent: i64,
}

impl Default for ReportSettings {
    fn default() -> Self {
        Self { frequency: Frequency::Off, weekday: 0, hour: 8, tz_offset_min: 0, channels: Vec::new(), last_sent: 0 }
    }
}

impl ReportSettings {
    pub async fn load(db: &Db) -> sqlx::Result<Self> {
        let d = Self::default();
        let num = |v: Option<String>, def: i64| v.and_then(|v| v.parse().ok()).unwrap_or(def);
        Ok(Self {
            frequency: Frequency::parse(&settings::get(db, "report_frequency").await?.unwrap_or_default()),
            weekday: num(settings::get(db, "report_weekday").await?, d.weekday).clamp(0, 6),
            hour: num(settings::get(db, "report_hour").await?, d.hour).clamp(0, 23),
            tz_offset_min: num(settings::get(db, "report_tz_offset").await?, 0).clamp(-14 * 60, 14 * 60),
            channels: settings::get(db, "report_channels").await?.unwrap_or_default().split(',').filter_map(|v| v.trim().parse().ok()).collect(),
            last_sent: num(settings::get(db, "report_last_sent").await?, 0),
        })
    }

    pub async fn save(&self, db: &Db) -> sqlx::Result<()> {
        settings::set(db, "report_frequency", self.frequency.as_str()).await?;
        settings::set(db, "report_weekday", &self.weekday.to_string()).await?;
        settings::set(db, "report_hour", &self.hour.to_string()).await?;
        settings::set(db, "report_tz_offset", &self.tz_offset_min.to_string()).await?;
        let channels: Vec<String> = self.channels.iter().map(i64::to_string).collect();
        settings::set(db, "report_channels", &channels.join(",")).await?;
        settings::set(db, "report_last_sent", &self.last_sent.to_string()).await
    }

    fn local_shift(&self) -> i64 {
        -self.tz_offset_min * 60_000
    }

    /// The latest scheduled time at or before `now`.
    pub fn due(&self, now: i64) -> Option<i64> {
        let shift = self.local_shift();
        let local = now + shift;
        let day = floor_day(local);
        let mut at = match self.frequency {
            Frequency::Off => return None,
            Frequency::Daily => day + self.hour * HOUR_MS,
            Frequency::Weekly => {
                // 1970-01-01 was a Thursday, index 3 when Monday is 0.
                let weekday = (day / DAY_MS + 3).rem_euclid(7);
                day - (weekday - self.weekday).rem_euclid(7) * DAY_MS + self.hour * HOUR_MS
            }
        };
        if at > local {
            at -= self.frequency.period_ms();
        }
        Some(at - shift)
    }

    pub fn next(&self, now: i64) -> Option<i64> {
        self.due(now).map(|d| d + self.frequency.period_ms())
    }
}

/// Formats `ms` in the report's time zone with a `time` format description.
pub fn format_local(ms: i64, tz_offset_min: i64, format: &str) -> String {
    let Ok(dt) = time::OffsetDateTime::from_unix_timestamp(ms.div_euclid(1000)) else { return String::new() };
    let offset = time::UtcOffset::from_whole_seconds((-tz_offset_min * 60) as i32).unwrap_or(time::UtcOffset::UTC);
    let Ok(fmt) = time::format_description::parse_borrowed::<2>(format) else { return String::new() };
    dt.to_offset(offset).format(&fmt).unwrap_or_default()
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct DownNow {
    pub monitor: String,
    pub since: i64,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct MonitorLine {
    pub monitor: String,
    pub uptime: Option<f64>,
    pub incidents: usize,
    pub downtime_ms: i64,
    pub longest_ms: i64,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ReportData {
    pub frequency: Frequency,
    pub from: i64,
    pub to: i64,
    pub site: String,
    pub monitors: usize,
    pub not_checked: Vec<String>,
    pub checks: i64,
    pub uptime: Option<f64>,
    pub incidents: usize,
    pub downtime_ms: i64,
    pub down_now: Vec<DownNow>,
    pub problems: Vec<MonitorLine>,
    pub healthy: usize,
    pub coverage: f64,
    pub gaps: Vec<(i64, i64)>,
    #[serde(skip)]
    pub tz_offset_min: i64,
}

pub async fn build(db: &Db, site: &str, frequency: Frequency, from: i64, to: i64, tz_offset_min: i64) -> sqlx::Result<ReportData> {
    let all = store::monitors::list(db).await?;
    let groups: HashMap<i64, String> = store::groups::list(db).await?.into_iter().map(|g| (g.id, g.name)).collect();
    let names: HashMap<i64, &str> = all.iter().map(|m| (m.id, m.name.as_str())).collect();
    let label = |m: &crate::models::Monitor| {
        [m.group_id.and_then(|g| groups.get(&g).map(String::as_str)), m.parent_id.and_then(|p| names.get(&p).copied()), Some(m.name.as_str())]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join(" › ")
    };
    let monitors: Vec<_> = all.iter().filter(|m| m.active && m.kind != "aggregate").collect();
    let counts = crate::stats::counts_between(db, from, to).await?;
    let incidents: Vec<(i64, i64, Option<i64>)> =
        sqlx::query_as("SELECT monitor_id, started_at, ended_at FROM incidents WHERE started_at < ? AND (ended_at IS NULL OR ended_at > ?)")
            .bind(to)
            .bind(from)
            .fetch_all(db)
            .await?;
    let open: Vec<(i64, i64)> = sqlx::query_as("SELECT monitor_id, started_at FROM incidents WHERE ended_at IS NULL").fetch_all(db).await?;

    let now = now_ms();
    let (mut up_sum, mut judged_sum, mut checks) = (0, 0, 0);
    let (mut lines, mut not_checked, mut down_now) = (Vec::new(), Vec::new(), Vec::new());
    let (mut incident_total, mut downtime_total) = (0, 0);
    for m in &monitors {
        let (up, judged, total) = counts.get(&m.id).copied().unwrap_or_default();
        up_sum += up;
        judged_sum += judged;
        checks += total;
        let mine: Vec<i64> = incidents
            .iter()
            .filter(|(id, ..)| *id == m.id)
            .map(|(_, s, e)| e.unwrap_or(now).min(to) - (*s).max(from))
            .collect();
        let downtime: i64 = mine.iter().sum();
        incident_total += mine.len();
        downtime_total += downtime;
        if let Some((_, since)) = open.iter().find(|(id, _)| *id == m.id) {
            down_now.push(DownNow { monitor: label(m), since: *since });
        }
        if total == 0 {
            not_checked.push(label(m));
            continue;
        }
        let uptime = (judged > 0).then(|| up as f64 * 100.0 / judged as f64);
        if !mine.is_empty() || uptime.is_some_and(|u| u < 100.0) {
            lines.push(MonitorLine {
                monitor: label(m),
                uptime,
                incidents: mine.len(),
                downtime_ms: downtime,
                longest_ms: mine.iter().copied().max().unwrap_or(0),
            });
        }
    }
    lines.sort_by(|a, b| a.uptime.unwrap_or(100.0).total_cmp(&b.uptime.unwrap_or(100.0)).then(b.incidents.cmp(&a.incidents)));
    let rows = selfcheck::runtime_rows(db, from, to).await?;
    let (coverage, gaps) = selfcheck::coverage(&rows, from, to);
    Ok(ReportData {
        frequency,
        from,
        to,
        site: site.to_string(),
        monitors: monitors.len(),
        healthy: monitors.len() - lines.len() - not_checked.len(),
        not_checked,
        checks,
        uptime: (judged_sum > 0).then(|| up_sum as f64 * 100.0 / judged_sum as f64),
        incidents: incident_total,
        downtime_ms: downtime_total,
        down_now,
        problems: lines,
        coverage,
        gaps,
        tz_offset_min,
    })
}

fn thousands(n: i64) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(' ');
        }
        out.push(c);
    }
    out
}

fn plural(n: usize, word: &str) -> String {
    format!("{n} {word}{}", if n == 1 { "" } else { "s" })
}

impl ReportData {
    fn period_label(&self) -> String {
        let tz = self.tz_offset_min;
        let end = self.to - 1;
        let same_month = format_local(self.from, tz, "[month]") == format_local(end, tz, "[month]");
        let start = if same_month { format_local(self.from, tz, "[day padding:none]") } else { format_local(self.from, tz, "[day padding:none] [month repr:short]") };
        let end = format_local(end, tz, "[day padding:none] [month repr:short]");
        if start == end.split(' ').next().unwrap_or_default() && same_month { end } else { format!("{start}–{end}") }
    }

    pub fn title(&self) -> String {
        format!("📊 {} – {} report, {}", self.site, self.frequency.as_str(), self.period_label())
    }

    pub fn body(&self) -> String {
        let mut out = Vec::new();
        for d in &self.down_now {
            out.push(format!("🔴 Down now: {} (for {})", d.monitor, format_duration_ms(self.to.max(d.since) - d.since)));
        }
        if self.monitors == 0 {
            out.push("No active monitors.".into());
        } else {
            let checked = self.monitors - self.not_checked.len();
            let who = if self.not_checked.is_empty() { format!("All {} checked", plural(self.monitors, "monitor")) } else { format!("{checked} of {} monitors checked", self.monitors) };
            out.push(format!("✅ {who} · {} checks · overall uptime {}", thousands(self.checks), format_pct(self.uptime)));
            if !self.not_checked.is_empty() {
                out.push(format!("⚠️ Not checked: {}", self.not_checked.join(", ")));
            }
            if self.incidents == 0 {
                out.push("🟢 No incidents".into());
            } else {
                out.push(format!("🔴 {}, {} of downtime total", plural(self.incidents, "incident"), format_duration_ms(self.downtime_ms)));
            }
            for l in self.problems.iter().take(MAX_LISTED) {
                let mut line = format!("• {} · {}", l.monitor, format_pct(l.uptime));
                if l.incidents > 0 {
                    line.push_str(&format!(" · {} · longest {}", plural(l.incidents, "incident"), format_duration_ms(l.longest_ms)));
                }
                out.push(line);
            }
            if self.problems.len() > MAX_LISTED {
                out.push(format!("… and {} more", self.problems.len() - MAX_LISTED));
            }
            if !self.problems.is_empty() && self.healthy > 0 {
                out.push(format!("🟢 {} at 100%", plural(self.healthy, "other monitor")));
            }
        }
        out.push(self.coverage_line());
        out.join("\n")
    }

    fn coverage_line(&self) -> String {
        let span = if self.frequency == Frequency::Weekly { "week" } else { "day" };
        if self.gaps.is_empty() {
            return format!("⏱ Monitoring coverage {} (anpi was running the whole {span})", format_pct(Some(self.coverage)));
        }
        let missing: i64 = self.gaps.iter().map(|(a, b)| b - a).sum();
        let mut when: Vec<String> = self
            .gaps
            .iter()
            .take(3)
            .map(|(a, b)| format!("{}–{}", format_local(*a, self.tz_offset_min, "[weekday repr:short] [hour]:[minute]"), format_local(*b, self.tz_offset_min, "[hour]:[minute]")))
            .collect();
        if self.gaps.len() > 3 {
            when.push(format!("{} more", self.gaps.len() - 3));
        }
        format!("⏱ Monitoring coverage {} · anpi was not running for {}: {}", format_pct(Some(self.coverage)), format_duration_ms(missing), when.join(", "))
    }
}

/// Sends a report to the chosen channels (or the defaults) and returns each channel's result.
pub async fn send(db: &Db, data: ReportData, channel_ids: &[i64]) -> sqlx::Result<Vec<(String, Result<(), String>)>> {
    let ids = if channel_ids.is_empty() { store::notifications::default_ids(db).await? } else { channel_ids.to_vec() };
    let channels: Vec<_> = store::notifications::list(db).await?.into_iter().filter(|c| c.active && ids.contains(&c.id)).collect();
    let ev = NotifyEvent {
        kind: EventKind::Report(Box::new(data)),
        monitor_name: String::new(),
        parent_name: None,
        group_name: None,
        target: String::new(),
        message: String::new(),
        at: now_ms(),
    };
    let sends = channels.iter().map(|c| async { (c.name.clone(), notify::send_channel(c, &ev).await) });
    Ok(futures_util::future::join_all(sends).await)
}

/// Sends the report that became due, if any; returns whether one was sent.
pub async fn tick(ctx: &Ctx, now: i64) -> anyhow::Result<bool> {
    let mut s = ReportSettings::load(&ctx.db).await?;
    let Some(due) = s.due(now) else { return Ok(false) };
    if s.last_sent >= due {
        return Ok(false);
    }
    // Enabled without a baseline: start with the next slot instead of an old one.
    if s.last_sent == 0 {
        s.last_sent = due;
        s.save(&ctx.db).await?;
        return Ok(false);
    }
    s.last_sent = due;
    s.save(&ctx.db).await?;
    let data = build(&ctx.db, &ctx.branding().site_name, s.frequency, due - s.frequency.period_ms(), due, s.tz_offset_min).await?;
    for (channel, result) in send(&ctx.db, data, &s.channels).await? {
        match result {
            Ok(()) => tracing::info!(%channel, "report sent"),
            Err(e) => tracing::warn!(%channel, error = %e, "report failed"),
        }
    }
    Ok(true)
}

pub fn spawn(ctx: Arc<Ctx>) {
    tokio::spawn(async move {
        let mut every = tokio::time::interval(selfcheck::TICK);
        loop {
            every.tick().await;
            if let Err(e) = tick(&ctx, now_ms()).await {
                tracing::error!(error = %e, "report job failed");
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(s: &str) -> i64 {
        time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).unwrap().unix_timestamp() * 1000
    }

    #[test]
    fn daily_and_weekly_slots_follow_the_local_time_zone() {
        // Warsaw in summer: UTC+2, so the browser reports -120.
        let daily = ReportSettings { frequency: Frequency::Daily, hour: 8, tz_offset_min: -120, ..Default::default() };
        assert_eq!(daily.due(at("2026-10-09T07:00:00Z")), Some(at("2026-10-09T06:00:00Z")), "08:00 local is 06:00 UTC");
        assert_eq!(daily.due(at("2026-10-09T05:59:00Z")), Some(at("2026-10-08T06:00:00Z")), "before today's slot, yesterday's");
        assert_eq!(daily.next(at("2026-10-09T07:00:00Z")), Some(at("2026-10-10T06:00:00Z")));

        // 2026-10-09 is a Friday; a Monday 08:00 report.
        let weekly = ReportSettings { frequency: Frequency::Weekly, weekday: 0, hour: 8, tz_offset_min: -120, ..Default::default() };
        assert_eq!(weekly.due(at("2026-10-09T12:00:00Z")), Some(at("2026-10-05T06:00:00Z")));
        assert_eq!(weekly.due(at("2026-10-12T06:00:00Z")), Some(at("2026-10-12T06:00:00Z")), "exactly on the slot");
        assert_eq!(weekly.due(at("2026-10-12T05:59:00Z")), Some(at("2026-10-05T06:00:00Z")));
        assert_eq!(ReportSettings::default().due(0), None, "off");
    }

    fn data() -> ReportData {
        ReportData {
            frequency: Frequency::Weekly,
            from: at("2026-10-02T06:00:00Z"),
            to: at("2026-10-09T06:00:00Z"),
            site: "anpi".into(),
            monitors: 12,
            not_checked: Vec::new(),
            checks: 120_960,
            uptime: Some(99.94),
            incidents: 3,
            downtime_ms: 47 * 60_000,
            down_now: Vec::new(),
            problems: vec![
                MonitorLine { monitor: "Product › API › Search".into(), uptime: Some(99.2), incidents: 2, downtime_ms: 38 * 60_000, longest_ms: 31 * 60_000 },
                MonitorLine { monitor: "Infra › Database".into(), uptime: Some(99.9), incidents: 1, downtime_ms: 9 * 60_000, longest_ms: 9 * 60_000 },
            ],
            healthy: 10,
            coverage: 100.0,
            gaps: Vec::new(),
            tz_offset_min: -120,
        }
    }

    #[test]
    fn report_text_reads_like_the_summary() {
        let d = data();
        assert_eq!(d.title(), "📊 anpi – weekly report, 2–9 Oct");
        let body = d.body();
        assert!(body.contains("✅ All 12 monitors checked · 120 960 checks · overall uptime 99.94%"), "{body}");
        assert!(body.contains("🔴 3 incidents, 47m 0s of downtime total"));
        assert!(body.contains("• Product › API › Search · 99.20% · 2 incidents · longest 31m 0s"));
        assert!(body.contains("🟢 10 other monitors at 100%"));
        assert!(body.ends_with("⏱ Monitoring coverage 100% (anpi was running the whole week)"));
    }

    #[test]
    fn report_shows_outages_of_anpi_and_long_lists_are_cut() {
        let mut d = data();
        d.gaps = vec![(at("2026-10-06T12:00:00Z"), at("2026-10-06T14:10:00Z"))];
        d.coverage = 98.7;
        d.problems = (0..14).map(|i| MonitorLine { monitor: format!("m{i}"), uptime: Some(99.0), incidents: 1, downtime_ms: 1, longest_ms: 1 }).collect();
        d.down_now = vec![DownNow { monitor: "Shop".into(), since: d.to - 12 * 60_000 }];
        d.not_checked = vec!["Nightly backup".into()];
        let body = d.body();
        assert!(body.starts_with("🔴 Down now: Shop (for 12m 0s)"), "{body}");
        assert!(body.contains("11 of 12 monitors checked") && body.contains("⚠️ Not checked: Nightly backup"));
        assert_eq!(body.matches("\n• ").count(), 10);
        assert!(body.contains("… and 4 more"));
        assert!(body.contains("anpi was not running for 2h 10m: Tue 14:00–16:10"), "local time, not UTC: {body}");
    }

    #[test]
    fn daily_label_spans_two_days_and_months_are_named() {
        let mut d = data();
        d.frequency = Frequency::Daily;
        d.from = at("2026-10-08T06:00:00Z");
        d.to = at("2026-10-09T06:00:00Z");
        assert_eq!(d.title(), "📊 anpi – daily report, 8–9 Oct");
        d.from = at("2026-09-28T06:00:00Z");
        d.to = at("2026-10-05T06:00:00Z");
        assert_eq!(d.period_label(), "28 Sep–5 Oct");
        assert_eq!(thousands(1_234_567), "1 234 567");
        assert_eq!(thousands(999), "999");
    }
}
