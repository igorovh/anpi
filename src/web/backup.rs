//! Export and import of the whole configuration as one JSON file (no history, no accounts).

use std::collections::HashMap;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};

use super::admin::MonitorForm;
use super::branding::{sniff_image, validate_site_name, MAX_LOGO_BYTES};
use crate::app::LOGO_KEY;
use crate::auth::sso::PanelSso;
use crate::db::Db;
use crate::models::{Monitor, MonitorKind};
use crate::notify::ChannelConfig;
use crate::store::{self, settings::AppSettings};
use crate::util::now_ms;

pub const FORMAT: u32 = 1;

#[derive(Debug, Default, PartialEq)]
pub struct ImportReport {
    pub monitors_created: usize,
    pub groups_created: usize,
    pub channels_created: usize,
    pub skipped: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Backup {
    pub anpi_export: u32,
    pub exported_at: String,
    pub version: String,
    pub settings: Option<BackupSettings>,
    pub logo: Option<BackupLogo>,
    pub sso: Option<BackupSso>,
    pub groups: Vec<BackupGroup>,
    pub channels: Vec<BackupChannel>,
    pub monitors: Vec<BackupMonitor>,
    pub maintenance: Vec<BackupMaintenance>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct BackupSettings {
    pub site_name: String,
    pub status_title: String,
    pub status_description: String,
    pub raw_retention_hours: i64,
    pub hourly_retention_days: i64,
    pub incident_retention_days: i64,
    pub incidents_shown: i64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct BackupLogo {
    pub content_type: String,
    pub data: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct BackupSso {
    pub enabled: bool,
    pub base_url: String,
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    pub required_role: String,
    pub scopes: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct BackupGroup {
    pub key: String,
    pub name: String,
    pub sort_order: i64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct BackupChannel {
    pub key: String,
    pub name: String,
    pub kind: String,
    pub config: ChannelConfig,
    pub active: bool,
    pub is_default: bool,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct BackupMonitor {
    pub key: String,
    pub name: String,
    pub kind: String,
    pub target: String,
    pub port: Option<i64>,
    pub method: String,
    pub headers: String,
    pub body: String,
    pub interval_s: Option<i64>,
    pub retry_interval_s: Option<i64>,
    pub timeout_s: Option<i64>,
    pub failure_threshold: Option<i64>,
    pub expected_status: String,
    pub ip_family: String,
    pub follow_redirects: Option<bool>,
    pub ignore_tls: bool,
    pub content_kind: String,
    pub content_value: String,
    pub content_expected: String,
    pub ssl_warn_days: Option<i64>,
    pub dns_record_type: String,
    pub dns_server: String,
    pub active: Option<bool>,
    pub public: bool,
    pub public_name: String,
    pub group: Option<String>,
    pub parent: Option<String>,
    pub channels: Vec<String>,
    pub push_token: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct BackupMaintenance {
    pub title: String,
    pub starts_at: i64,
    pub ends_at: i64,
    pub all_monitors: bool,
    pub monitors: Vec<String>,
}

fn monitor_key(id: i64) -> String {
    format!("m{id}")
}

fn to_backup_monitor(m: &Monitor, channels: Vec<String>) -> BackupMonitor {
    BackupMonitor {
        key: monitor_key(m.id),
        name: m.name.clone(),
        kind: m.kind.clone(),
        target: m.target.clone(),
        port: m.port,
        method: m.method.clone(),
        headers: m.headers.clone(),
        body: m.body.clone(),
        interval_s: Some(m.interval_s),
        retry_interval_s: Some(m.retry_interval_s),
        timeout_s: Some(m.timeout_s),
        failure_threshold: Some(m.failure_threshold),
        expected_status: m.expected_status.clone(),
        ip_family: m.ip_family.clone(),
        follow_redirects: Some(m.follow_redirects),
        ignore_tls: m.ignore_tls,
        content_kind: m.content_kind.clone(),
        content_value: m.content_value.clone(),
        content_expected: m.content_expected.clone(),
        ssl_warn_days: Some(m.ssl_warn_days),
        dns_record_type: m.dns_record_type.clone(),
        dns_server: m.dns_server.clone(),
        active: Some(m.active),
        public: m.public,
        public_name: m.public_name.clone(),
        group: m.group_id.map(|g| format!("g{g}")),
        parent: m.parent_id.map(monitor_key),
        channels,
        push_token: m.push_token.clone(),
    }
}

pub async fn export(db: &Db) -> anyhow::Result<Backup> {
    let s = AppSettings::load(db).await?;
    let site_name = crate::app::Branding::load(db).await?.site_name;
    let logo = store::assets::get(db, LOGO_KEY).await?.map(|a| BackupLogo { content_type: a.content_type, data: STANDARD.encode(a.data) });
    let sso = PanelSso::load(db).await?;
    let groups = store::groups::list(db).await?.into_iter().map(|g| BackupGroup { key: format!("g{}", g.id), name: g.name, sort_order: g.sort_order }).collect();
    let channels = store::notifications::list(db)
        .await?
        .into_iter()
        .map(|c| BackupChannel {
            key: format!("c{}", c.id),
            config: ChannelConfig::from_json(&c.config),
            name: c.name,
            kind: c.kind,
            active: c.active,
            is_default: c.is_default,
        })
        .collect();
    let mut monitors = Vec::new();
    for m in store::monitors::list(db).await? {
        let ch = store::monitors::channel_ids(db, m.id).await?.into_iter().map(|c| format!("c{c}")).collect();
        monitors.push(to_backup_monitor(&m, ch));
    }
    let mut maintenance = Vec::new();
    for w in store::maintenance::list(db).await? {
        let ids = store::maintenance::monitor_ids(db, w.id).await?;
        maintenance.push(BackupMaintenance {
            title: w.title,
            starts_at: w.starts_at,
            ends_at: w.ends_at,
            all_monitors: w.all_monitors,
            monitors: ids.into_iter().map(monitor_key).collect(),
        });
    }
    Ok(Backup {
        anpi_export: FORMAT,
        exported_at: crate::util::format_ts(now_ms()),
        version: env!("CARGO_PKG_VERSION").into(),
        settings: Some(BackupSettings {
            site_name,
            status_title: s.status_title,
            status_description: s.status_description,
            raw_retention_hours: s.raw_retention_hours,
            hourly_retention_days: s.hourly_retention_days,
            incident_retention_days: s.incident_retention_days,
            incidents_shown: s.incidents_shown,
        }),
        logo,
        sso: Some(BackupSso {
            enabled: sso.enabled,
            base_url: sso.base_url,
            issuer: sso.issuer,
            client_id: sso.client_id,
            client_secret: sso.client_secret,
            required_role: sso.required_role,
            scopes: sso.scopes,
        }),
        groups,
        channels,
        monitors,
        maintenance,
    })
}

pub fn is_backup(json: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(json).is_ok_and(|v| v.get("anpi_export").is_some())
}

fn to_form(m: &BackupMonitor) -> MonitorForm {
    let kind = MonitorKind::parse(&m.kind);
    let uses_url = matches!(kind, Some(MonitorKind::Http | MonitorKind::WebSocket));
    let is_dns = kind == Some(MonitorKind::Dns);
    let num = |v: Option<i64>| v.map(|n| n.to_string()).unwrap_or_default();
    let flag = |b: bool| b.then(|| "on".to_string());
    let or = |v: &str, d: &str| if v.trim().is_empty() { d.to_string() } else { v.to_string() };
    MonitorForm {
        name: m.name.clone(),
        kind: m.kind.clone(),
        url: if uses_url { m.target.clone() } else { String::new() },
        host: if uses_url { String::new() } else { m.target.clone() },
        port: num(m.port),
        method: or(&m.method, "GET"),
        headers: m.headers.clone(),
        body: m.body.clone(),
        interval_s: num(m.interval_s),
        retry_interval_s: num(m.retry_interval_s),
        timeout_s: num(m.timeout_s),
        failure_threshold: num(m.failure_threshold),
        expected_status: or(&m.expected_status, "200-299"),
        ip_family: or(&m.ip_family, "auto"),
        follow_redirects: flag(m.follow_redirects.unwrap_or(true)),
        ignore_tls: flag(m.ignore_tls),
        content_kind: or(&m.content_kind, "none"),
        content_value: m.content_value.clone(),
        content_expected: if is_dns { String::new() } else { m.content_expected.clone() },
        dns_expected: if is_dns { m.content_expected.clone() } else { String::new() },
        ssl_warn_days: num(m.ssl_warn_days),
        dns_record_type: or(&m.dns_record_type, "A"),
        dns_server: m.dns_server.clone(),
        active: flag(m.active.unwrap_or(true)),
        public: flag(m.public),
        public_name: m.public_name.clone(),
        ..MonitorForm::default()
    }
}

/// Wipes monitors (with their history), groups, channels and maintenance windows before a replace import.
async fn clear(db: &Db) -> sqlx::Result<()> {
    let mut tx = db.begin().await?;
    for sql in ["DELETE FROM maintenances", "DELETE FROM monitors", "DELETE FROM notification_channels", "DELETE FROM monitor_groups"] {
        sqlx::query(sql).execute(&mut *tx).await?;
    }
    tx.commit().await
}

pub async fn import(db: &Db, json: &str, replace: bool) -> Result<ImportReport, String> {
    if !is_backup(json) {
        return Err("This is not an anpi configuration export.".into());
    }
    let b: Backup = serde_json::from_str(json).map_err(|e| format!("not a valid anpi backup: {e}"))?;
    if b.anpi_export != FORMAT {
        return Err(format!("unsupported backup format {} (this version reads {FORMAT})", b.anpi_export));
    }
    let err = |e: sqlx::Error| e.to_string();
    let mut report = ImportReport::default();
    if replace {
        clear(db).await.map_err(err)?;
    }

    if let Some(s) = &b.settings {
        let d = AppSettings::default();
        let clamp = |v: i64, lo: i64, hi: i64, def: i64| if v == 0 { def } else { v.clamp(lo, hi) };
        let settings = AppSettings {
            status_title: if s.status_title.trim().is_empty() { d.status_title.clone() } else { s.status_title.chars().take(100).collect() },
            status_description: s.status_description.chars().take(1000).collect(),
            raw_retention_hours: clamp(s.raw_retention_hours, 1, 24 * 90, d.raw_retention_hours),
            hourly_retention_days: clamp(s.hourly_retention_days, 1, 3650, d.hourly_retention_days),
            incident_retention_days: clamp(s.incident_retention_days, 1, 3650, d.incident_retention_days),
            incidents_shown: s.incidents_shown.clamp(0, 50),
        };
        settings.save(db).await.map_err(err)?;
        if let Ok(name) = validate_site_name(&s.site_name) {
            store::settings::set(db, "site_name", &name).await.map_err(err)?;
        }
    }

    if let Some(logo) = &b.logo {
        match STANDARD.decode(logo.data.trim()) {
            Ok(data) if data.len() <= MAX_LOGO_BYTES => match sniff_image(&data) {
                Some(ct) => {
                    store::assets::put(db, LOGO_KEY, ct, &data).await.map_err(err)?;
                }
                None => report.warnings.push("logo skipped: not a supported image".into()),
            },
            _ => report.warnings.push("logo skipped: invalid or larger than 512 KB".into()),
        }
    }

    if let Some(s) = &b.sso {
        // Never switch password sign-in off from a file; the admin turns SSO on after testing it.
        let panel = PanelSso {
            enabled: false,
            base_url: s.base_url.clone(),
            issuer: s.issuer.clone(),
            client_id: s.client_id.clone(),
            client_secret: s.client_secret.clone(),
            required_role: s.required_role.clone(),
            scopes: s.scopes.clone(),
        };
        panel.save(db).await.map_err(err)?;
        if s.enabled {
            report.warnings.push("SSO settings were imported but left off; enable them under Settings after testing the connection".into());
        }
    }

    let existing_groups = store::groups::list(db).await.map_err(err)?;
    let mut groups: HashMap<String, i64> = HashMap::new();
    for g in &b.groups {
        let name = g.name.trim();
        if name.is_empty() {
            continue;
        }
        let id = match existing_groups.iter().find(|x| x.name.eq_ignore_ascii_case(name)) {
            Some(x) => x.id,
            None => {
                report.groups_created += 1;
                store::groups::create(db, &name.chars().take(60).collect::<String>(), g.sort_order).await.map_err(err)?
            }
        };
        groups.insert(g.key.clone(), id);
    }

    let existing_channels = store::notifications::list(db).await.map_err(err)?;
    let mut channels: HashMap<String, i64> = HashMap::new();
    for c in &b.channels {
        if let Err(e) = c.config.validate(&c.kind) {
            report.skipped.push(format!("notification \"{}\": {e}", c.name));
            continue;
        }
        let id = match existing_channels.iter().find(|x| x.name == c.name && x.kind == c.kind) {
            Some(x) => x.id,
            None => {
                report.channels_created += 1;
                store::notifications::create(db, c.name.trim(), &c.kind, &c.config.to_json(), c.active, c.is_default).await.map_err(err)?
            }
        };
        channels.insert(c.key.clone(), id);
    }

    let mut monitors: HashMap<String, i64> = HashMap::new();
    for m in &b.monitors {
        let mut input = match to_form(m).validate() {
            Ok(i) => i,
            Err(e) => {
                report.skipped.push(format!("monitor \"{}\": {e}", m.name));
                continue;
            }
        };
        input.group_id = m.group.as_ref().and_then(|g| groups.get(g).copied());
        let id = store::monitors::create(db, &input).await.map_err(err)?;
        if let Some(token) = m.push_token.as_ref().filter(|t| !t.is_empty() && input.kind == "push") {
            let taken = store::monitors::get_by_push_token(db, token).await.map_err(err)?.is_some();
            if taken {
                report.warnings.push(format!("\"{}\": push token already in use, a new one was generated", m.name));
            } else {
                sqlx::query("UPDATE monitors SET push_token = ? WHERE id = ?").bind(token).bind(id).execute(db).await.map_err(err)?;
            }
        }
        let ids: Vec<i64> = m.channels.iter().filter_map(|c| channels.get(c).copied()).collect();
        store::monitors::set_channels(db, id, &ids).await.map_err(err)?;
        monitors.insert(m.key.clone(), id);
        report.monitors_created += 1;
    }

    // Nest only after every monitor exists, keeping the one-level rule.
    let parents_in_file: HashMap<&str, bool> = b.monitors.iter().map(|m| (m.key.as_str(), m.parent.is_some())).collect();
    for m in &b.monitors {
        let (Some(id), Some(parent_key)) = (monitors.get(&m.key), &m.parent) else { continue };
        let Some(parent) = monitors.get(parent_key) else {
            report.warnings.push(format!("\"{}\": its parent was not imported, so it stays at the top level", m.name));
            continue;
        };
        if parents_in_file.get(parent_key.as_str()).copied().unwrap_or(false) {
            report.warnings.push(format!("\"{}\": nested more than one level deep, kept at the top level", m.name));
            continue;
        }
        let parent_group = store::monitors::get(db, *parent).await.map_err(err)?.and_then(|p| p.group_id);
        store::monitors::move_to(db, *id, parent_group, Some(*parent)).await.map_err(err)?;
    }

    for w in &b.maintenance {
        let ids: Vec<i64> = w.monitors.iter().filter_map(|k| monitors.get(k).copied()).collect();
        if w.ends_at <= w.starts_at || w.title.trim().is_empty() || (!w.all_monitors && ids.is_empty()) {
            report.skipped.push(format!("maintenance \"{}\": no matching monitors or invalid times", w.title));
            continue;
        }
        store::maintenance::create(db, w.title.trim(), w.starts_at, w.ends_at, w.all_monitors, &ids).await.map_err(err)?;
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn seeded() -> Db {
        let db = crate::db::open_memory().await.unwrap();
        crate::demo::seed(&db).await.unwrap();
        let cfg = ChannelConfig { webhook_url: "https://discord.com/api/webhooks/1/x".into(), ..Default::default() };
        let ch = store::notifications::create(&db, "Discord", "discord", &cfg.to_json(), true, false).await.unwrap();
        let web = store::monitors::list(&db).await.unwrap().into_iter().find(|m| m.name == "Website").unwrap();
        store::monitors::set_channels(&db, web.id, &[ch]).await.unwrap();
        store::maintenance::create(&db, "Upgrade", now_ms(), now_ms() + 3_600_000, false, &[web.id]).await.unwrap();
        db
    }

    #[tokio::test]
    async fn export_then_import_reproduces_the_configuration() {
        let src = seeded().await;
        let json = serde_json::to_string(&export(&src).await.unwrap()).unwrap();
        assert!(is_backup(&json));
        assert!(!json.contains("heartbeat"), "history is not exported");

        let dst = crate::db::open_memory().await.unwrap();
        let r = import(&dst, &json, false).await.unwrap();
        assert_eq!((r.monitors_created, r.groups_created, r.channels_created), (9, 2, 1), "{r:?}");
        assert!(r.skipped.is_empty(), "{:?}", r.skipped);

        let a = store::monitors::list(&src).await.unwrap();
        let b = store::monitors::list(&dst).await.unwrap();
        let shape = |ms: &[Monitor]| {
            let mut v: Vec<_> = ms
                .iter()
                .map(|m| {
                    let parent = m.parent_id.and_then(|p| ms.iter().find(|x| x.id == p)).map(|p| p.name.clone());
                    (m.name.clone(), m.kind.clone(), m.target.clone(), m.content_kind.clone(), m.public, parent, m.interval_s)
                })
                .collect();
            v.sort();
            v
        };
        assert_eq!(shape(&a), shape(&b), "monitors, sub-monitors and settings survive the round trip");
        let push_a = a.iter().find(|m| m.kind == "push").unwrap().push_token.clone();
        let push_b = b.iter().find(|m| m.kind == "push").unwrap().push_token.clone();
        assert_eq!(push_a, push_b, "cron jobs keep working after a move");
        let web = b.iter().find(|m| m.name == "Website").unwrap();
        assert_eq!(store::monitors::channel_ids(&dst, web.id).await.unwrap().len(), 1);
        assert_eq!(store::maintenance::list(&dst).await.unwrap().len(), 1);
        assert_eq!(AppSettings::load(&dst).await.unwrap().status_title, "Example status");
    }

    #[tokio::test]
    async fn merge_reuses_groups_and_replace_starts_over() {
        let db = seeded().await;
        let json = serde_json::to_string(&export(&db).await.unwrap()).unwrap();
        let r = import(&db, &json, false).await.unwrap();
        assert_eq!(r.groups_created, 0, "groups with the same name are reused");
        assert_eq!(store::monitors::list(&db).await.unwrap().len(), 18);
        assert!(r.warnings.iter().any(|w| w.contains("push token already in use")));

        let r = import(&db, &json, true).await.unwrap();
        assert_eq!(r.monitors_created, 9);
        assert_eq!(store::monitors::list(&db).await.unwrap().len(), 9, "replace removes what was there");
        assert_eq!(store::groups::list(&db).await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn bad_entries_are_reported_and_sso_is_never_switched_on() {
        let db = crate::db::open_memory().await.unwrap();
        let mut b = Backup { anpi_export: FORMAT, ..Default::default() };
        b.monitors.push(BackupMonitor { key: "m1".into(), name: "ok".into(), kind: "http".into(), target: "https://example.com".into(), ..Default::default() });
        b.monitors.push(BackupMonitor { key: "m2".into(), name: "broken".into(), kind: "http".into(), target: "not a url".into(), ..Default::default() });
        b.monitors.push(BackupMonitor { key: "m3".into(), name: "orphan".into(), kind: "tcp".into(), target: "h".into(), port: Some(1), parent: Some("m9".into()), ..Default::default() });
        b.channels.push(BackupChannel { key: "c1".into(), name: "empty".into(), kind: "discord".into(), ..Default::default() });
        b.sso = Some(BackupSso { enabled: true, base_url: "https://s".into(), issuer: "https://kc/realms/r".into(), client_id: "anpi".into(), ..Default::default() });
        let r = import(&db, &serde_json::to_string(&b).unwrap(), false).await.unwrap();
        assert_eq!(r.monitors_created, 2);
        assert!(r.skipped.iter().any(|s| s.contains("broken") && s.contains("URL")));
        assert!(r.skipped.iter().any(|s| s.contains("empty")));
        assert!(r.warnings.iter().any(|w| w.contains("orphan")));
        assert!(!PanelSso::load(&db).await.unwrap().enabled, "imported SSO stays off");

        assert!(import(&db, r#"{"anpi_export": 99}"#, false).await.unwrap_err().contains("unsupported"));
        assert!(import(&db, "nope", false).await.is_err());
    }
}
