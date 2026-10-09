pub mod content;
pub mod dns;
pub mod http;
pub mod ping;
pub mod status_codes;
pub mod tcp;
pub mod ws;

use std::time::Duration;

use ::http::{HeaderName, HeaderValue, Method};

use crate::models::{CheckOutcome, Monitor, MonitorKind};
use status_codes::StatusMatcher;

pub fn parse_headers(raw: &str) -> Result<Vec<(HeaderName, HeaderValue)>, String> {
    let mut out = Vec::new();
    for line in raw.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let (k, v) = line.split_once(':').ok_or_else(|| format!("header line {line:?} must look like 'Name: value'"))?;
        let name = HeaderName::from_bytes(k.trim().as_bytes()).map_err(|_| format!("invalid header name {:?}", k.trim()))?;
        let value = HeaderValue::from_str(v.trim()).map_err(|_| format!("invalid value for header {name}"))?;
        out.push((name, value));
    }
    Ok(out)
}

pub async fn run(m: &Monitor) -> CheckOutcome {
    let timeout = Duration::from_secs(m.timeout_s.clamp(1, 300) as u64);
    match m.kind() {
        MonitorKind::Http => http_check(m, timeout).await,
        MonitorKind::Tcp => tcp::check(&m.target, m.port.unwrap_or(0) as u16, m.ip_family(), timeout).await,
        MonitorKind::Ping => ping::check(&m.target, m.ip_family(), timeout).await,
        MonitorKind::Dns => dns::check(&m.target, &m.dns_record_type, &m.dns_server, &m.content_expected, timeout).await,
        MonitorKind::Push => CheckOutcome::fail("push monitors are not actively checked"),
        MonitorKind::Aggregate => CheckOutcome::fail("aggregate monitors are not checked"),
        MonitorKind::WebSocket => {
            let headers = match parse_headers(&m.headers) {
                Ok(h) => h,
                Err(e) => return CheckOutcome::fail(e),
            };
            ws::check(ws::WsSpec {
                url: &m.target,
                headers,
                send: &m.body,
                content_kind: m.content_kind(),
                content_value: &m.content_value,
                content_expected: &m.content_expected,
                ip_family: m.ip_family(),
                ignore_tls: m.ignore_tls,
                timeout,
            })
            .await
        }
    }
}

async fn http_check(m: &Monitor, timeout: Duration) -> CheckOutcome {
    let url = match url::Url::parse(&m.target) {
        Ok(u) => u,
        Err(e) => return CheckOutcome::fail(format!("invalid URL: {e}")),
    };
    let method = Method::from_bytes(m.method.as_bytes()).unwrap_or(Method::GET);
    let headers = match parse_headers(&m.headers) {
        Ok(h) => h,
        Err(e) => return CheckOutcome::fail(e),
    };
    let matcher = match StatusMatcher::parse(&m.expected_status) {
        Ok(s) => s,
        Err(e) => return CheckOutcome::fail(e),
    };
    let mut spec = http::RequestSpec::new(method, url);
    spec.headers = headers;
    spec.body = m.body.clone().into();
    spec.timeout = timeout;
    spec.ip_family = m.ip_family();
    spec.max_redirects = if m.follow_redirects { 10 } else { 0 };
    spec.ignore_tls = m.ignore_tls;

    match http::send(&spec).await {
        Err(e) => CheckOutcome {
            ok: false,
            message: e.to_string(),
            timings: e.timings.clone(),
            remote_ip: e.remote_ip.map(|ip| ip.to_string()),
            ..Default::default()
        },
        Ok(r) => {
            let mut out = CheckOutcome {
                ok: true,
                preview: Some(r.text().chars().take(600).collect()),
                status_code: Some(r.status),
                timings: r.timings.clone(),
                remote_ip: Some(r.remote_ip.to_string()),
                cert_expires_at: r.cert_expires_at,
                ..Default::default()
            };
            let reason = ::http::StatusCode::from_u16(r.status).ok().and_then(|s| s.canonical_reason()).unwrap_or("");
            if !matcher.matches(r.status) {
                out.ok = false;
                out.message = format!("HTTP {} {reason} (expected {})", r.status, m.expected_status);
            } else if let Err(e) = content::evaluate(m.content_kind(), &m.content_value, &m.content_expected, &r.text()) {
                out.ok = false;
                out.message = e;
            } else {
                out.message = format!("{} {reason}", r.status).trim().to_string();
            }
            if !r.notes.is_empty() {
                out.message = format!("{} ({})", out.message, r.notes.join("; "));
            }
            out
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_lines_parse_and_validate() {
        let h = parse_headers("Authorization: Bearer x\n\n  X-Test :  1 ").unwrap();
        assert_eq!(h.len(), 2);
        assert_eq!(h[0].0.as_str(), "authorization");
        assert_eq!(h[1].1.to_str().unwrap(), "1");
        assert!(parse_headers("no colon here").is_err());
        assert!(parse_headers("bad name: x").is_err());
    }
}
