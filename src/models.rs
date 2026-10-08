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
}

impl MonitorKind {
    pub const ALL: [MonitorKind; 5] = [Self::Http, Self::Tcp, Self::Ping, Self::Dns, Self::Push];

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "http" => Self::Http,
            "tcp" => Self::Tcp,
            "ping" => Self::Ping,
            "dns" => Self::Dns,
            "push" => Self::Push,
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
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Http => "HTTP(S)",
            Self::Tcp => "TCP port",
            Self::Ping => "Ping",
            Self::Dns => "DNS",
            Self::Push => "Push (cron heartbeat)",
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
}

impl Monitor {
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
pub struct Maintenance {
    pub id: i64,
    pub title: String,
    pub starts_at: i64,
    pub ends_at: i64,
    pub all_monitors: bool,
    pub created_at: i64,
}
