use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use http::{HeaderName, HeaderValue};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsConnector;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use url::{Host, Url};

use super::content;
use super::http::{TlsConfigs, cert_not_after, connect_any, resolve, tls_error_text};
use crate::models::{CheckOutcome, ContentKind, IpFamily};

pub struct WsSpec<'a> {
    pub url: &'a str,
    pub headers: Vec<(HeaderName, HeaderValue)>,
    pub send: &'a str,
    pub content_kind: ContentKind,
    pub content_value: &'a str,
    pub content_expected: &'a str,
    pub ip_family: IpFamily,
    pub ignore_tls: bool,
    pub timeout: Duration,
}

fn ms(t: Instant) -> f64 {
    t.elapsed().as_secs_f64() * 1000.0
}

/// Connects, completes the WebSocket handshake and, if configured, sends a message and checks the first reply.
pub async fn check(spec: WsSpec<'_>) -> CheckOutcome {
    let started = Instant::now();
    let mut out = CheckOutcome::default();
    let result = tokio::time::timeout(spec.timeout, run(&spec, started, &mut out)).await;
    out.timings.total_ms = Some(ms(started));
    match result {
        Ok(Ok(())) => out.ok = true,
        Ok(Err(msg)) => {
            out.ok = false;
            out.message = msg;
        }
        Err(_) => {
            out.ok = false;
            let phase = if out.timings.ttfb_ms.is_some() {
                "waiting for a message"
            } else if out.timings.tls_ms.is_some() || (out.timings.connect_ms.is_some() && spec.url.starts_with("ws:")) {
                "handshake"
            } else if out.timings.connect_ms.is_some() {
                "TLS"
            } else {
                "connect"
            };
            out.message = format!("{phase}: timed out after {:.1}s", spec.timeout.as_secs_f64());
        }
    }
    out
}

async fn run(spec: &WsSpec<'_>, started: Instant, out: &mut CheckOutcome) -> Result<(), String> {
    let url = Url::parse(spec.url).map_err(|e| format!("invalid URL: {e}"))?;
    let secure = match url.scheme() {
        "wss" => true,
        "ws" => false,
        s => return Err(format!("unsupported scheme {s}, use ws:// or wss://")),
    };
    let host = url.host().ok_or("URL has no host")?;
    let host_str = url.host_str().unwrap_or_default().to_string();
    let port = url.port_or_known_default().unwrap_or(if secure { 443 } else { 80 });

    let t = Instant::now();
    let addrs = resolve(&host_str, port, spec.ip_family).await.map_err(|e| format!("DNS: {e}"))?;
    out.timings.dns_ms = Some(if matches!(host, Host::Domain(_)) { ms(t) } else { 0.0 });

    let t = Instant::now();
    let mut notes = Vec::new();
    let (tcp, addr) = connect_any(&addrs, started + spec.timeout, &mut notes).await.map_err(|e| format!("connect: {e}"))?;
    out.timings.connect_ms = Some(ms(t));
    out.remote_ip = Some(addr.ip().to_string());

    let mut request = url.as_str().into_client_request().map_err(|e| format!("invalid request: {e}"))?;
    for (k, v) in &spec.headers {
        request.headers_mut().insert(k.clone(), v.clone());
    }

    let result = if secure {
        let t = Instant::now();
        let server_name = match host {
            Host::Domain(d) => ServerName::try_from(d.to_string()).map_err(|_| "invalid server name".to_string())?,
            Host::Ipv4(ip) => ServerName::IpAddress(std::net::IpAddr::V4(ip).into()),
            Host::Ipv6(ip) => ServerName::IpAddress(std::net::IpAddr::V6(ip).into()),
        };
        let tls = TlsConnector::from(TlsConfigs::shared().client(spec.ignore_tls))
            .connect(server_name, tcp)
            .await
            .map_err(|e| format!("TLS: {}", tls_error_text(&e)))?;
        out.timings.tls_ms = Some(ms(t));
        out.cert_expires_at = tls.get_ref().1.peer_certificates().and_then(|c| c.first()).and_then(|c| cert_not_after(c));
        exchange(tls, request, spec, out).await
    } else {
        exchange(tcp, request, spec, out).await
    };
    if !notes.is_empty() {
        out.message = format!("{} ({})", out.message, notes.join("; "));
    }
    result
}

async fn exchange<S>(stream: S, request: http::Request<()>, spec: &WsSpec<'_>, out: &mut CheckOutcome) -> Result<(), String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let t = Instant::now();
    let (mut ws, response) = tokio_tungstenite::client_async(request, stream).await.map_err(|e| format!("handshake: {e}"))?;
    out.timings.ttfb_ms = Some(ms(t));
    out.status_code = Some(response.status().as_u16());

    let wants_reply = !spec.send.is_empty() || spec.content_kind != ContentKind::None;
    if !spec.send.is_empty() {
        ws.send(Message::text(spec.send)).await.map_err(|e| format!("sending message: {e}"))?;
    }
    if !wants_reply {
        out.message = "101 Switching Protocols".into();
        let _ = ws.close(None).await;
        return Ok(());
    }
    let reply = loop {
        match ws.next().await {
            Some(Ok(Message::Text(t))) => break t.to_string(),
            Some(Ok(Message::Binary(b))) => break String::from_utf8_lossy(&b).into_owned(),
            Some(Ok(Message::Close(frame))) => {
                return Err(match frame {
                    Some(f) => format!("server closed the connection: {} {}", u16::from(f.code), f.reason),
                    None => "server closed the connection without a message".into(),
                });
            }
            Some(Ok(_)) => continue,
            Some(Err(e)) => return Err(format!("reading message: {e}")),
            None => return Err("connection ended without a message".into()),
        }
    };
    let _ = ws.close(None).await;
    out.preview = Some(reply.chars().take(600).collect());
    content::evaluate(spec.content_kind, spec.content_value, spec.content_expected, &reply)?;
    let shown: String = reply.chars().take(80).collect();
    out.message = format!("received: {shown}");
    Ok(())
}
