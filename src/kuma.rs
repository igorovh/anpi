//! Import from an Uptime Kuma backup JSON (Settings → Backup → Export).

use std::collections::HashMap;

use serde_json::Value;

use crate::db::Db;
use crate::models::MonitorInput;
use crate::notify::ChannelConfig;
use crate::store;

#[derive(Debug, Default, PartialEq)]
pub struct ImportReport {
    pub monitors_created: usize,
    pub groups_created: usize,
    pub channels_created: usize,
    pub skipped: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, PartialEq)]
pub struct ParsedChannel {
    pub kuma_id: i64,
    pub name: String,
    pub kind: &'static str,
    pub config: ChannelConfig,
    pub active: bool,
    pub is_default: bool,
}

#[derive(Debug)]
pub struct ParsedMonitor {
    pub input: MonitorInput,
    pub push_token: Option<String>,
    pub kuma_channel_ids: Vec<i64>,
    pub kuma_parent: Option<i64>,
}

#[derive(Debug, Default)]
pub struct Parsed {
    pub groups: Vec<(i64, String)>,
    pub channels: Vec<ParsedChannel>,
    pub monitors: Vec<ParsedMonitor>,
    pub skipped: Vec<String>,
    pub warnings: Vec<String>,
}

fn s(v: &Value, k: &str) -> String {
    match v.get(k) {
        Some(Value::String(x)) => x.clone(),
        Some(Value::Number(n)) => n.to_string(),
        _ => String::new(),
    }
}

fn i(v: &Value, k: &str) -> Option<i64> {
    match v.get(k)? {
        Value::Number(n) => n.as_i64().or_else(|| n.as_f64().map(|f| f as i64)),
        Value::String(x) => x.parse().ok(),
        _ => None,
    }
}

fn b(v: &Value, k: &str, default: bool) -> bool {
    match v.get(k) {
        Some(Value::Bool(x)) => *x,
        Some(Value::Number(n)) => n.as_i64() != Some(0),
        Some(Value::String(x)) => x == "1" || x == "true",
        _ => default,
    }
}

pub fn parse(json: &str) -> Result<Parsed, String> {
    let root: Value = serde_json::from_str(json).map_err(|e| format!("not valid JSON: {e}"))?;
    let monitors = root.get("monitorList").and_then(Value::as_array).ok_or("missing monitorList: is this an Uptime Kuma backup?")?;
    let mut out = Parsed::default();

    for n in root.get("notificationList").and_then(Value::as_array).into_iter().flatten() {
        // Kuma stores each channel's settings as a JSON string inside `config`.
        let cfg: Value = match n.get("config") {
            Some(Value::String(raw)) => serde_json::from_str(raw).unwrap_or(Value::Null),
            Some(v) => v.clone(),
            None => Value::Null,
        };
        let name = s(n, "name");
        let ty = s(&cfg, "type");
        let mut c = ChannelConfig::default();
        let kind = match ty.as_str() {
            "discord" => {
                c.webhook_url = s(&cfg, "discordWebhookUrl");
                c.username = s(&cfg, "discordUsername");
                "discord"
            }
            "telegram" => {
                c.bot_token = s(&cfg, "telegramBotToken");
                c.chat_id = s(&cfg, "telegramChatID");
                "telegram"
            }
            "ntfy" => {
                c.server = s(&cfg, "ntfyserverurl");
                c.topic = s(&cfg, "ntfytopic");
                c.priority = s(&cfg, "ntfyPriority");
                c.token = s(&cfg, "ntfyaccesstoken");
                "ntfy"
            }
            "smtp" => {
                c.smtp_host = s(&cfg, "smtpHost");
                c.smtp_port = s(&cfg, "smtpPort");
                c.smtp_security = if b(&cfg, "smtpSecure", false) { "tls".into() } else { "starttls".into() };
                c.smtp_username = s(&cfg, "smtpUsername");
                c.smtp_password = s(&cfg, "smtpPassword");
                c.email_from = s(&cfg, "smtpFrom");
                c.email_to = s(&cfg, "smtpTo");
                "email"
            }
            "webhook" => {
                c.url = s(&cfg, "webhookURL");
                "webhook"
            }
            other => {
                out.skipped.push(format!("notification \"{name}\": unsupported type {other:?}"));
                continue;
            }
        };
        out.channels.push(ParsedChannel {
            kuma_id: i(n, "id").unwrap_or(-1),
            name,
            kind,
            config: c,
            active: b(n, "active", true),
            is_default: b(n, "isDefault", false),
        });
    }

    for m in monitors {
        let name = s(m, "name");
        let ty = s(m, "type");
        let interval = i(m, "interval").unwrap_or(60).max(1);
        let mut input = MonitorInput::http(&name, "");
        input.interval_s = interval;
        input.retry_interval_s = i(m, "retryInterval").filter(|v| *v > 0).unwrap_or(interval);
        input.failure_threshold = i(m, "maxretries").unwrap_or(0).max(0) + 1;
        input.timeout_s = i(m, "timeout").filter(|v| *v > 0).unwrap_or(((interval as f64) * 0.8) as i64).clamp(1, 300);
        input.active = b(m, "active", true);
        input.ip_family = "auto".into();
        input.ssl_warn_days = if b(m, "expiryNotification", false) { 14 } else { 0 };
        let mut push_token = None;

        match ty.as_str() {
            "http" | "keyword" | "json-query" => {
                input.kind = "http".into();
                input.target = s(m, "url");
                let method = s(m, "method").to_ascii_uppercase();
                input.method = if method.is_empty() { "GET".into() } else { method };
                input.body = s(m, "body");
                input.headers = headers_to_lines(&s(m, "headers"));
                input.ignore_tls = b(m, "ignoreTls", false);
                input.follow_redirects = i(m, "maxredirects").unwrap_or(10) > 0;
                let codes: Vec<String> = m
                    .get("accepted_statuscodes")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().filter_map(|c| c.as_str().map(str::to_string)).collect())
                    .unwrap_or_default();
                if !codes.is_empty() {
                    input.expected_status = codes.join(",");
                }
                if ty == "keyword" {
                    input.content_kind = if b(m, "invertKeyword", false) { "not_contains" } else { "contains" }.into();
                    input.content_value = s(m, "keyword");
                } else if ty == "json-query" {
                    let expr = s(m, "jsonPath");
                    input.content_kind = "json_path".into();
                    input.content_value = if expr.starts_with('$') { expr.clone() } else { format!("$.{expr}") };
                    input.content_expected = s(m, "expectedValue");
                    out.warnings.push(format!(
                        "\"{name}\": Kuma JSON query {expr:?} was converted to JSONPath {:?}; verify it",
                        input.content_value
                    ));
                }
            }
            "port" => {
                input.kind = "tcp".into();
                input.target = s(m, "hostname");
                input.port = i(m, "port");
            }
            "ping" => {
                input.kind = "ping".into();
                input.target = s(m, "hostname");
            }
            "dns" => {
                input.kind = "dns".into();
                input.target = s(m, "hostname");
                let rt = s(m, "dns_resolve_type");
                input.dns_record_type = if rt.is_empty() { "A".into() } else { rt };
                input.dns_server = s(m, "dns_resolve_server");
            }
            "push" => {
                input.kind = "push".into();
                push_token = Some(s(m, "pushToken")).filter(|t| !t.is_empty());
            }
            "group" => {
                out.groups.push((i(m, "id").unwrap_or(-1), name));
                continue;
            }
            other => {
                out.skipped.push(format!("monitor \"{name}\": unsupported type {other:?}"));
                continue;
            }
        }

        let kuma_channel_ids = match m.get("notificationIDList") {
            Some(Value::Object(map)) => {
                map.iter().filter(|(_, v)| v.as_bool().unwrap_or(true)).filter_map(|(k, _)| k.parse().ok()).collect()
            }
            Some(Value::Array(a)) => a.iter().filter_map(Value::as_i64).collect(),
            _ => vec![],
        };
        out.monitors.push(ParsedMonitor { input, push_token, kuma_channel_ids, kuma_parent: i(m, "parent") });
    }
    Ok(out)
}

fn headers_to_lines(raw: &str) -> String {
    match serde_json::from_str::<Value>(raw) {
        Ok(Value::Object(map)) => map
            .iter()
            .map(|(k, v)| format!("{k}: {}", v.as_str().map(str::to_string).unwrap_or_else(|| v.to_string())))
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    }
}

pub async fn import(db: &Db, json: &str) -> Result<ImportReport, String> {
    let parsed = parse(json)?;
    let mut report = ImportReport { skipped: parsed.skipped, warnings: parsed.warnings, ..Default::default() };
    let mut group_map: HashMap<i64, i64> = HashMap::new();
    for (kuma_id, name) in parsed.groups {
        let order = store::groups::next_sort_order(db).await.map_err(|e| e.to_string())?;
        let id = store::groups::create(db, &name, order).await.map_err(|e| e.to_string())?;
        group_map.insert(kuma_id, id);
        report.groups_created += 1;
    }
    let mut channel_map: HashMap<i64, i64> = HashMap::new();
    for c in parsed.channels {
        let id = store::notifications::create(db, &c.name, c.kind, &c.config.to_json(), c.active, c.is_default)
            .await
            .map_err(|e| e.to_string())?;
        channel_map.insert(c.kuma_id, id);
        report.channels_created += 1;
    }
    for mut m in parsed.monitors {
        m.input.group_id = m.kuma_parent.and_then(|p| group_map.get(&p).copied());
        let id = store::monitors::create(db, &m.input).await.map_err(|e| e.to_string())?;
        if let Some(token) = m.push_token {
            // Keep Kuma's token so existing cron jobs keep working after switching the host.
            let r = sqlx::query("UPDATE monitors SET push_token = ? WHERE id = ?").bind(&token).bind(id).execute(db).await;
            if r.is_err() {
                report.warnings.push(format!("\"{}\": push token already in use, a new one was generated", m.input.name));
            }
        }
        let ids: Vec<i64> = m.kuma_channel_ids.iter().filter_map(|k| channel_map.get(k).copied()).collect();
        store::monitors::set_channels(db, id, &ids).await.map_err(|e| e.to_string())?;
        report.monitors_created += 1;
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    pub const SAMPLE: &str = r#"{
      "version": "1.23.16",
      "notificationList": [
        {"id": 1, "name": "Discord alerts", "active": 1, "isDefault": true,
         "config": "{\"name\":\"Discord alerts\",\"type\":\"discord\",\"discordWebhookUrl\":\"https://discord.com/api/webhooks/1/x\"}"},
        {"id": 2, "name": "Pager", "active": 1, "config": "{\"type\":\"pagerduty\"}"}
      ],
      "monitorList": [
        {"id": 9, "name": "Production", "type": "group", "interval": 60},
        {"id": 10, "name": "Website", "type": "http", "parent": 9, "url": "https://example.com", "method": "GET", "interval": 60,
         "retryInterval": 20, "maxretries": 2, "timeout": 48, "active": 1, "ignoreTls": false, "maxredirects": 10,
         "accepted_statuscodes": ["200-299", "301"], "expiryNotification": true,
         "headers": "{\"Authorization\": \"Bearer t\"}", "notificationIDList": {"1": true}},
        {"id": 11, "name": "Keyword", "type": "keyword", "url": "https://example.com/health", "interval": 30,
         "keyword": "healthy", "invertKeyword": true, "maxretries": 0, "active": 0},
        {"id": 12, "name": "API json", "type": "json-query", "url": "https://api.example.com", "interval": 60,
         "jsonPath": "status", "expectedValue": "ok"},
        {"id": 13, "name": "SSH", "type": "port", "hostname": "10.0.0.1", "port": 22, "interval": 120},
        {"id": 14, "name": "Backup cron", "type": "push", "pushToken": "abc123", "interval": 86400},
        {"id": 15, "name": "Docker", "type": "docker", "interval": 60},
        {"id": 16, "name": "Resolver", "type": "dns", "hostname": "example.com", "dns_resolve_type": "AAAA",
         "dns_resolve_server": "1.1.1.1", "interval": 300}
      ]
    }"#;

    #[test]
    fn maps_kuma_monitors_to_anpi_semantics() {
        let p = parse(SAMPLE).unwrap();
        assert_eq!(p.monitors.len(), 6);
        let web = &p.monitors[0].input;
        assert_eq!((web.kind.as_str(), web.target.as_str()), ("http", "https://example.com"));
        assert_eq!(web.failure_threshold, 3, "Kuma maxretries=2 means down on the 3rd failure");
        assert_eq!(web.retry_interval_s, 20);
        assert_eq!(web.timeout_s, 48);
        assert_eq!(web.expected_status, "200-299,301");
        assert_eq!(web.headers, "Authorization: Bearer t");
        assert_eq!(web.ssl_warn_days, 14);
        assert_eq!(p.monitors[0].kuma_channel_ids, vec![1]);

        let kw = &p.monitors[1].input;
        assert_eq!((kw.content_kind.as_str(), kw.content_value.as_str()), ("not_contains", "healthy"));
        assert_eq!(kw.failure_threshold, 1);
        assert!(!kw.active);
        assert_eq!(kw.timeout_s, 24, "missing timeout defaults to 80% of the interval");

        let json = &p.monitors[2].input;
        assert_eq!((json.content_value.as_str(), json.content_expected.as_str()), ("$.status", "ok"));
        assert!(p.warnings.iter().any(|w| w.contains("API json")));

        assert_eq!(p.monitors[3].input.port, Some(22));
        assert_eq!(p.monitors[4].push_token.as_deref(), Some("abc123"));
        assert_eq!(p.monitors[5].input.dns_record_type, "AAAA");
    }

    #[test]
    fn unsupported_items_are_reported_not_fatal() {
        let p = parse(SAMPLE).unwrap();
        assert_eq!(p.channels.len(), 1);
        assert!(p.channels[0].is_default);
        assert!(p.skipped.iter().any(|s| s.contains("Docker")));
        assert!(p.skipped.iter().any(|s| s.contains("Pager")));
    }

    #[test]
    fn rejects_non_kuma_input() {
        assert!(parse("not json").is_err());
        assert!(parse("{}").unwrap_err().contains("monitorList"));
    }

    #[tokio::test]
    async fn import_links_channels_and_keeps_push_token() {
        let db = crate::db::open_memory().await.unwrap();
        let r = import(&db, SAMPLE).await.unwrap();
        assert_eq!((r.monitors_created, r.channels_created, r.groups_created), (6, 1, 1));
        let monitors = store::monitors::list(&db).await.unwrap();
        let web = monitors.iter().find(|m| m.name == "Website").unwrap();
        let groups = store::groups::list(&db).await.unwrap();
        assert_eq!(web.group_id, Some(groups[0].id), "Kuma parent becomes the anpi group");
        assert_eq!(groups[0].name, "Production");
        assert!(monitors.iter().filter(|m| m.name != "Website").all(|m| m.group_id.is_none()));
        assert_eq!(store::monitors::channel_ids(&db, web.id).await.unwrap().len(), 1);
        assert!(store::monitors::get_by_push_token(&db, "abc123").await.unwrap().is_some());
    }
}
