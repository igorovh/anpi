use serde::Serialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Down = 0,
    Up = 1,
    Pending = 2,
    Maintenance = 3,
}

impl Status {
    /// Severity used when combining several statuses into one.
    pub fn severity(self) -> u8 {
        match self {
            Self::Up => 0,
            Self::Maintenance => 1,
            Self::Pending => 2,
            Self::Down => 3,
        }
    }

    pub fn worst(statuses: impl IntoIterator<Item = Status>) -> Option<Status> {
        statuses.into_iter().max_by_key(|s| s.severity())
    }

    pub fn from_i64(v: i64) -> Self {
        match v {
            1 => Self::Up,
            2 => Self::Pending,
            3 => Self::Maintenance,
            _ => Self::Down,
        }
    }

    pub fn as_i64(self) -> i64 {
        self as i64
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Down => "down",
            Self::Up => "up",
            Self::Pending => "pending",
            Self::Maintenance => "maintenance",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MonitorKind {
    Http,
    Tcp,
    Ping,
    Dns,
    Push,
    Aggregate,
    WebSocket,
}

impl MonitorKind {
    pub const ALL: [MonitorKind; 7] = [Self::Http, Self::WebSocket, Self::Tcp, Self::Ping, Self::Dns, Self::Push, Self::Aggregate];

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "http" => Self::Http,
            "tcp" => Self::Tcp,
            "ping" => Self::Ping,
            "dns" => Self::Dns,
            "push" => Self::Push,
            "aggregate" => Self::Aggregate,
            "websocket" => Self::WebSocket,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Tcp => "tcp",
            Self::Ping => "ping",
            Self::Dns => "dns",
            Self::Push => "push",
            Self::Aggregate => "aggregate",
            Self::WebSocket => "websocket",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Http => "HTTP(S)",
            Self::Tcp => "TCP port",
            Self::Ping => "Ping",
            Self::Dns => "DNS",
            Self::Push => "Push (cron heartbeat)",
            Self::Aggregate => "Aggregate (status of sub-monitors)",
            Self::WebSocket => "WebSocket",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpFamily {
    Auto,
    V4,
    V6,
}

impl IpFamily {
    pub fn parse(s: &str) -> Self {
        match s {
            "v4" => Self::V4,
            "v6" => Self::V6,
            _ => Self::Auto,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::V4 => "v4",
            Self::V6 => "v6",
        }
    }

    pub fn allows(self, ip: &std::net::IpAddr) -> bool {
        match self {
            Self::Auto => true,
            Self::V4 => ip.is_ipv4(),
            Self::V6 => ip.is_ipv6(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContentKind {
    None,
    Contains,
    NotContains,
    Regex,
    JsonPath,
}

impl ContentKind {
    pub fn parse(s: &str) -> Self {
        match s {
            "contains" => Self::Contains,
            "not_contains" => Self::NotContains,
            "regex" => Self::Regex,
            "json_path" => Self::JsonPath,
            _ => Self::None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Contains => "contains",
            Self::NotContains => "not_contains",
            Self::Regex => "regex",
            Self::JsonPath => "json_path",
        }
    }
}

#[derive(Clone, Debug, sqlx::FromRow)]
pub struct Monitor {
    pub id: i64,
    pub name: String,
    pub kind: String,
    pub target: String,
    pub port: Option<i64>,
    pub method: String,
    pub headers: String,
    pub body: String,
    pub interval_s: i64,
    pub retry_interval_s: i64,
    pub timeout_s: i64,
    pub failure_threshold: i64,
    pub expected_status: String,
    pub ip_family: String,
    pub follow_redirects: bool,
    pub ignore_tls: bool,
    pub content_kind: String,
    pub content_value: String,
    pub content_expected: String,
    pub ssl_warn_days: i64,
    pub dns_record_type: String,
    pub dns_server: String,
    pub push_token: Option<String>,
    pub active: bool,
    pub public: bool,
    pub ssl_notified_days: Option<i64>,
    pub ssl_notified_expiry: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
    pub group_id: Option<i64>,
    pub public_name: String,
    pub parent_id: Option<i64>,
}

impl Monitor {
    /// Name shown on the public status page.
    pub fn public_label(&self) -> &str {
        if self.public_name.trim().is_empty() { &self.name } else { self.public_name.trim() }
    }

    pub fn kind(&self) -> MonitorKind {
        MonitorKind::parse(&self.kind).unwrap_or(MonitorKind::Http)
    }

    pub fn ip_family(&self) -> IpFamily {
        IpFamily::parse(&self.ip_family)
    }

    pub fn content_kind(&self) -> ContentKind {
        ContentKind::parse(&self.content_kind)
    }

    pub fn display_target(&self) -> String {
        match self.kind() {
            MonitorKind::Tcp => format!("{}:{}", self.target, self.port.unwrap_or(0)),
            MonitorKind::Dns => format!("{} {}", self.dns_record_type, self.target),
            MonitorKind::Push => "push".into(),
            MonitorKind::Aggregate => "sub-monitors".into(),
            _ => self.target.clone(),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct MonitorInput {
    pub name: String,
    pub kind: String,
    pub target: String,
    pub port: Option<i64>,
    pub method: String,
    pub headers: String,
    pub body: String,
    pub interval_s: i64,
    pub retry_interval_s: i64,
    pub timeout_s: i64,
    pub failure_threshold: i64,
    pub expected_status: String,
    pub ip_family: String,
    pub follow_redirects: bool,
    pub ignore_tls: bool,
    pub content_kind: String,
    pub content_value: String,
    pub content_expected: String,
    pub ssl_warn_days: i64,
    pub dns_record_type: String,
    pub dns_server: String,
    pub active: bool,
    pub public: bool,
    pub group_id: Option<i64>,
    pub public_name: String,
    pub parent_id: Option<i64>,
}

impl Monitor {
    /// An unsaved monitor built from form input, used to run a check before saving.
    pub fn draft(m: &MonitorInput) -> Self {
        Self {
            id: 0,
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
            push_token: None,
            active: m.active,
            public: m.public,
            ssl_notified_days: None,
            ssl_notified_expiry: None,
            created_at: 0,
            updated_at: 0,
            group_id: m.group_id,
            public_name: m.public_name.clone(),
            parent_id: m.parent_id,
        }
    }
}

impl MonitorInput {
    pub fn http(name: &str, url: &str) -> Self {
        Self {
            name: name.into(),
            kind: "http".into(),
            target: url.into(),
            method: "GET".into(),
            interval_s: 60,
            retry_interval_s: 30,
            timeout_s: 30,
            failure_threshold: 3,
            expected_status: "200-299".into(),
            ip_family: "auto".into(),
            follow_redirects: true,
            content_kind: "none".into(),
            ssl_warn_days: 14,
            dns_record_type: "A".into(),
            active: true,
            ..Default::default()
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Timings {
    pub dns_ms: Option<f64>,
    pub connect_ms: Option<f64>,
    pub tls_ms: Option<f64>,
    pub ttfb_ms: Option<f64>,
    pub total_ms: Option<f64>,
}

#[derive(Clone, Debug, Default)]
pub struct CheckOutcome {
    pub ok: bool,
    /// Start of the response body or WebSocket reply, shown by "Run check now".
    pub preview: Option<String>,
    pub message: String,
    pub status_code: Option<u16>,
    pub timings: Timings,
    pub remote_ip: Option<String>,
    pub cert_expires_at: Option<i64>,
}

impl CheckOutcome {
    pub fn fail(message: impl Into<String>) -> Self {
        Self { ok: false, message: message.into(), ..Default::default() }
    }
}

#[derive(Clone, Debug)]
pub struct NewHeartbeat {
    pub monitor_id: i64,
    pub ts: i64,
    pub status: Status,
    pub status_code: Option<u16>,
    pub timings: Timings,
    pub remote_ip: Option<String>,
    pub message: String,
    pub cert_expires_at: Option<i64>,
}

#[derive(Clone, Debug, sqlx::FromRow)]
pub struct Heartbeat {
    pub id: i64,
    pub monitor_id: i64,
    pub ts: i64,
    pub status: i64,
    pub status_code: Option<i64>,
    pub dns_ms: Option<f64>,
    pub connect_ms: Option<f64>,
    pub tls_ms: Option<f64>,
    pub ttfb_ms: Option<f64>,
    pub total_ms: Option<f64>,
    pub remote_ip: Option<String>,
    pub message: String,
    pub cert_expires_at: Option<i64>,
}

impl Heartbeat {
    pub fn status(&self) -> Status {
        Status::from_i64(self.status)
    }
}

#[derive(Clone, Debug, sqlx::FromRow)]
pub struct Incident {
    pub id: i64,
    pub monitor_id: i64,
    pub started_at: i64,
    pub ended_at: Option<i64>,
    pub message: String,
}

#[derive(Clone, Debug, sqlx::FromRow)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub password_hash: Option<String>,
    pub oidc_issuer: Option<String>,
    pub oidc_subject: Option<String>,
    pub created_at: i64,
}

#[derive(Clone, Debug, sqlx::FromRow)]
pub struct NotificationChannel {
    pub id: i64,
    pub name: String,
    pub kind: String,
    pub config: String,
    pub active: bool,
    pub is_default: bool,
    pub created_at: i64,
}

#[derive(Clone, Debug, sqlx::FromRow)]
pub struct MonitorGroup {
    pub id: i64,
    pub name: String,
    pub sort_order: i64,
    pub created_at: i64,
}

#[derive(Clone, Debug, sqlx::FromRow)]
pub struct Maintenance {
    pub id: i64,
    pub title: String,
    pub starts_at: i64,
    pub ends_at: i64,
    pub all_monitors: bool,
    pub created_at: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worst_status_prefers_outages() {
        assert_eq!(Status::worst([Status::Up, Status::Pending, Status::Maintenance]), Some(Status::Pending));
        assert_eq!(Status::worst([Status::Up, Status::Down, Status::Pending]), Some(Status::Down));
        assert_eq!(Status::worst([Status::Up, Status::Maintenance]), Some(Status::Maintenance));
        assert_eq!(Status::worst([]), None);
    }
}
