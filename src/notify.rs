use std::time::Duration;

use http::Method;
use http::header::CONTENT_TYPE;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::checks::http::{RequestSpec, send};
use crate::db::Db;
use crate::models::NotificationChannel;
use crate::store;
use crate::util::{format_duration_ms, format_ts};

#[derive(Clone, Debug, PartialEq)]
pub enum EventKind {
    Down,
    Up { downtime_ms: Option<i64> },
    SslExpiring { days_left: i64, expires_at: i64 },
    Test,
    Report(Box<crate::report::ReportData>),
}

#[derive(Clone, Debug)]
pub struct NotifyEvent {
    pub kind: EventKind,
    pub monitor_name: String,
    pub parent_name: Option<String>,
    pub group_name: Option<String>,
    pub target: String,
    pub message: String,
    pub at: i64,
}

impl NotifyEvent {
    pub fn code(&self) -> &'static str {
        match self.kind {
            EventKind::Down => "down",
            EventKind::Up { .. } => "up",
            EventKind::SslExpiring { .. } => "ssl_expiring",
            EventKind::Test => "test",
            EventKind::Report(_) => "report",
        }
    }

    /// "Group › Parent › Monitor", leaving out the parts a monitor does not have.
    pub fn label(&self) -> String {
        [self.group_name.as_deref(), self.parent_name.as_deref(), Some(self.monitor_name.as_str())]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join(" › ")
    }

    pub fn title(&self) -> String {
        let n = &self.label();
        match &self.kind {
            EventKind::Down => format!("🔴 {n} is down"),
            EventKind::Up { .. } => format!("🟢 {n} is back up"),
            EventKind::SslExpiring { days_left, .. } if *days_left < 0 => format!("⚠️ {n}: certificate expired"),
            EventKind::SslExpiring { days_left, .. } => format!("⚠️ {n}: certificate expires in {days_left} days"),
            EventKind::Test => "anpi test notification".to_string(),
            EventKind::Report(r) => r.title(),
        }
    }

    pub fn body(&self) -> String {
        if let EventKind::Report(r) = &self.kind {
            return r.body();
        }
        let mut lines = Vec::new();
        if !self.message.is_empty() {
            lines.push(self.message.clone());
        }
        match &self.kind {
            EventKind::Up { downtime_ms: Some(d) } => lines.push(format!("Downtime: {}", format_duration_ms(*d))),
            EventKind::SslExpiring { expires_at, .. } => lines.push(format!("Expires: {}", format_ts(*expires_at))),
            _ => {}
        }
        if !self.target.is_empty() {
            lines.push(format!("Target: {}", self.target));
        }
        lines.push(format!("Time: {}", format_ts(self.at)));
        lines.join("\n")
    }

    fn color(&self) -> u32 {
        match self.kind {
            EventKind::Down => 0xc4635a,
            EventKind::Up { .. } => 0x7fa37a,
            EventKind::SslExpiring { .. } => 0xc9a45c,
            EventKind::Test => 0x6f8fb0,
            EventKind::Report(ref r) if r.incidents == 0 && r.down_now.is_empty() => 0x7fa37a,
            EventKind::Report(_) => 0xc9a45c,
        }
    }
}

pub const KINDS: [(&str, &str); 5] =
    [("discord", "Discord"), ("telegram", "Telegram"), ("ntfy", "ntfy"), ("email", "E-mail (SMTP)"), ("webhook", "Webhook (JSON)")];

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct ChannelConfig {
    pub webhook_url: String,
    pub username: String,
    pub bot_token: String,
    pub chat_id: String,
    pub api_base: String,
    pub server: String,
    pub topic: String,
    pub token: String,
    pub priority: String,
    pub smtp_host: String,
    pub smtp_port: String,
    pub smtp_security: String,
    pub smtp_username: String,
    pub smtp_password: String,
    pub email_from: String,
    pub email_to: String,
    pub url: String,
}

impl ChannelConfig {
    pub fn from_json(s: &str) -> Self {
        serde_json::from_str(s).unwrap_or_default()
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("config serializes")
    }

    pub fn validate(&self, kind: &str) -> Result<(), String> {
        let need_url = |v: &str, field: &str| -> Result<(), String> {
            let u = url::Url::parse(v).map_err(|_| format!("{field} must be a full http(s) URL"))?;
            if matches!(u.scheme(), "http" | "https") { Ok(()) } else { Err(format!("{field} must use http or https")) }
        };
        let need = |v: &str, field: &str| if v.trim().is_empty() { Err(format!("{field} is required")) } else { Ok(()) };
        match kind {
            "discord" => need_url(&self.webhook_url, "Webhook URL"),
            "telegram" => need(&self.bot_token, "Bot token").and(need(&self.chat_id, "Chat ID")),
            "ntfy" => {
                need(&self.topic, "Topic")?;
                if !self.server.is_empty() {
                    need_url(&self.server, "Server")?;
                }
                Ok(())
            }
            "email" => {
                need(&self.smtp_host, "SMTP host")?;
                self.smtp_port.parse::<u16>().map_err(|_| "SMTP port must be a number".to_string())?;
                need(&self.email_from, "From")?;
                need(&self.email_to, "To")
            }
            "webhook" => need_url(&self.url, "URL"),
            other => Err(format!("unknown channel type {other}")),
        }
    }
}

async fn post_json(url: &str, body: serde_json::Value, extra: &[(&str, String)]) -> Result<(), String> {
    let url = url::Url::parse(url).map_err(|e| format!("invalid URL: {e}"))?;
    let mut spec = RequestSpec::new(Method::POST, url).header(CONTENT_TYPE, "application/json").body(body.to_string());
    for (k, v) in extra {
        if let Ok(name) = http::HeaderName::from_bytes(k.as_bytes()) {
            spec = spec.header(name, v);
        }
    }
    spec.timeout = Duration::from_secs(15);
    spec.max_redirects = 3;
    let resp = send(&spec).await.map_err(|e| e.to_string())?;
    if (200..300).contains(&resp.status) {
        Ok(())
    } else {
        let snippet: String = resp.text().chars().take(200).collect();
        Err(format!("HTTP {}: {snippet}", resp.status))
    }
}

/// Error messages can quote monitored responses, so Discord must not render them as markdown links or formatting.
fn discord_escape(s: &str, limit: usize) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars().take(limit) {
        if matches!(c, '\\' | '*' | '_' | '~' | '`' | '|' | '>' | '[' | ']' | '(' | ')' | '#' | '-' | '@' | '<') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

pub async fn send_one(kind: &str, cfg: &ChannelConfig, ev: &NotifyEvent) -> Result<(), String> {
    match kind {
        "discord" => {
            let ts = time::OffsetDateTime::from_unix_timestamp(ev.at / 1000)
                .ok()
                .and_then(|t| t.format(&time::format_description::well_known::Rfc3339).ok());
            let payload = json!({
                "username": if cfg.username.is_empty() { "anpi" } else { cfg.username.as_str() },
                "embeds": [{
                    "title": discord_escape(&ev.title(), 250),
                    // Reports are long but built by anpi; alerts can quote untrusted responses.
                    "description": discord_escape(&ev.body(), if matches!(ev.kind, EventKind::Report(_)) { 3800 } else { 1500 }),
                    "color": ev.color(),
                    "timestamp": ts,
                }],
                "allowed_mentions": { "parse": [] },
            });
            post_json(&cfg.webhook_url, payload, &[]).await
        }
        "telegram" => {
            let base = if cfg.api_base.is_empty() { "https://api.telegram.org" } else { cfg.api_base.trim_end_matches('/') };
            let text = format!("<b>{}</b>\n{}", html_escape(&ev.title()), html_escape(&ev.body()));
            let payload = json!({ "chat_id": cfg.chat_id, "text": text, "parse_mode": "HTML", "disable_web_page_preview": true });
            post_json(&format!("{base}/bot{}/sendMessage", cfg.bot_token), payload, &[]).await
        }
        "ntfy" => {
            let server = if cfg.server.is_empty() { "https://ntfy.sh" } else { cfg.server.trim_end_matches('/') };
            let priority: u8 = match ev.kind {
                _ if !cfg.priority.is_empty() => cfg.priority.parse().unwrap_or(3),
                EventKind::Down => 5,
                EventKind::SslExpiring { .. } => 4,
                _ => 3,
            };
            let tag = match ev.kind {
                EventKind::Down => "red_circle",
                EventKind::Up { .. } => "green_circle",
                EventKind::SslExpiring { .. } => "warning",
                EventKind::Test => "test_tube",
                EventKind::Report(_) => "bar_chart",
            };
            let payload = json!({ "topic": cfg.topic, "title": ev.title(), "message": ev.body(), "priority": priority, "tags": [tag] });
            let auth: Vec<(&str, String)> =
                if cfg.token.is_empty() { vec![] } else { vec![("authorization", format!("Bearer {}", cfg.token))] };
            post_json(server, payload, &auth).await
        }
        "webhook" => {
            let payload = match &ev.kind {
                EventKind::Report(r) => json!({ "event": ev.code(), "title": ev.title(), "message": ev.body(), "report": r, "at": ev.at }),
                _ => json!({
                    "event": ev.code(),
                    "title": ev.title(),
                    "message": ev.message,
                    "monitor": { "name": ev.monitor_name, "parent": ev.parent_name, "group": ev.group_name, "target": ev.target },
                    "at": ev.at,
                }),
            };
            post_json(&cfg.url, payload, &[]).await
        }
        "email" => send_email(cfg, ev).await,
        other => Err(format!("unknown channel type {other}")),
    }
}

async fn send_email(cfg: &ChannelConfig, ev: &NotifyEvent) -> Result<(), String> {
    use lettre::message::header::ContentType;
    use lettre::transport::smtp::authentication::Credentials;
    use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

    let mut builder = Message::builder()
        .from(cfg.email_from.parse().map_err(|e| format!("invalid From address: {e}"))?)
        .subject(ev.title())
        .header(ContentType::TEXT_PLAIN);
    for to in cfg.email_to.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        builder = builder.to(to.parse().map_err(|e| format!("invalid To address {to}: {e}"))?);
    }
    let message = builder.body(ev.body()).map_err(|e| e.to_string())?;
    let port: u16 = cfg.smtp_port.parse().unwrap_or(587);
    let mut transport = match cfg.smtp_security.as_str() {
        "tls" => AsyncSmtpTransport::<Tokio1Executor>::relay(&cfg.smtp_host).map_err(|e| e.to_string())?,
        "none" => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&cfg.smtp_host),
        _ => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&cfg.smtp_host).map_err(|e| e.to_string())?,
    }
    .port(port)
    .timeout(Some(Duration::from_secs(20)));
    if !cfg.smtp_username.is_empty() {
        transport = transport.credentials(Credentials::new(cfg.smtp_username.clone(), cfg.smtp_password.clone()));
    }
    transport.build().send(message).await.map(|_| ()).map_err(|e| e.to_string())
}

pub async fn send_channel(ch: &NotificationChannel, ev: &NotifyEvent) -> Result<(), String> {
    send_one(&ch.kind, &ChannelConfig::from_json(&ch.config), ev).await
}

/// Sends to every active channel linked to the monitor; failures are logged, never propagated.
pub async fn notify_monitor(db: &Db, monitor_id: i64, ev: NotifyEvent) {
    let channels = match store::notifications::for_monitor(db, monitor_id).await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "loading notification channels");
            return;
        }
    };
    let sends = channels.iter().map(|ch| async {
        if let Err(e) = send_channel(ch, &ev).await {
            tracing::warn!(channel = %ch.name, error = %e, event = ev.code(), "notification failed");
        }
    });
    futures_util::future::join_all(sends).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(kind: EventKind) -> NotifyEvent {
        NotifyEvent { kind, monitor_name: "API".into(), parent_name: None, group_name: None, target: "https://api.example.com".into(), message: "HTTP 503".into(), at: 0 }
    }

    #[test]
    fn titles_and_bodies_describe_the_event() {
        assert_eq!(ev(EventKind::Down).title(), "🔴 API is down");
        let child = NotifyEvent { parent_name: Some("Shop".into()), ..ev(EventKind::Down) };
        assert_eq!(child.title(), "🔴 Shop › API is down", "sub-monitors name their parent");
        let grouped = NotifyEvent { group_name: Some("Product".into()), ..child };
        assert_eq!(grouped.title(), "🔴 Product › Shop › API is down", "the group comes first");
        let up = ev(EventKind::Up { downtime_ms: Some(125_000) });
        assert!(up.title().contains("back up"));
        assert!(up.body().contains("Downtime: 2m 5s"));
        assert!(up.body().contains("Target: https://api.example.com"));
        let ssl = ev(EventKind::SslExpiring { days_left: 6, expires_at: 0 });
        assert!(ssl.title().contains("expires in 6 days"));
        assert!(ev(EventKind::SslExpiring { days_left: -1, expires_at: 0 }).title().contains("expired"));
    }

    #[test]
    fn channel_validation_requires_essentials() {
        let mut c = ChannelConfig::default();
        assert!(c.validate("discord").is_err());
        c.webhook_url = "ftp://x".into();
        assert!(c.validate("discord").is_err());
        c.webhook_url = "https://discord.com/api/webhooks/1/abc".into();
        assert!(c.validate("discord").is_ok());

        let t = ChannelConfig { bot_token: "1:x".into(), ..Default::default() };
        assert!(t.validate("telegram").unwrap_err().contains("Chat ID"));

        let e = ChannelConfig { smtp_host: "smtp".into(), smtp_port: "x".into(), ..Default::default() };
        assert!(e.validate("email").unwrap_err().contains("port"));
        assert!(ChannelConfig::default().validate("carrier-pigeon").is_err());
    }

    #[test]
    fn config_roundtrips_through_json_and_tolerates_garbage() {
        let c = ChannelConfig { topic: "alerts".into(), server: "https://ntfy.example".into(), ..Default::default() };
        assert_eq!(ChannelConfig::from_json(&c.to_json()), c);
        assert_eq!(ChannelConfig::from_json("not json"), ChannelConfig::default());
    }

    #[test]
    fn discord_text_cannot_inject_links_or_mentions() {
        let e = discord_escape("JSONPath $.x = \"[click](https://evil.example)\" @everyone", 1500);
        assert!(!e.contains("[click](") && e.contains("\\[click\\]\\("), "{e}");
        assert!(e.contains("\\@everyone"));
        assert_eq!(discord_escape(&"x".repeat(5000), 1500).len(), 1500, "long remote text is truncated");
    }

    #[test]
    fn telegram_text_is_html_escaped() {
        assert_eq!(html_escape("<b>&"), "&lt;b&gt;&amp;");
    }
}
