#![allow(clippy::result_large_err)]

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::header::{ACCEPT, ACCEPT_ENCODING, CONNECTION, CONTENT_LENGTH, HOST, LOCATION, USER_AGENT};
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use url::{Host, Url};

use crate::models::{IpFamily, Timings};

pub const USER_AGENT_VALUE: &str = concat!("anpi/", env!("CARGO_PKG_VERSION"), " (uptime monitor)");

pub struct TlsConfigs {
    verified: Arc<ClientConfig>,
    insecure: Arc<ClientConfig>,
}

impl TlsConfigs {
    pub fn shared() -> &'static TlsConfigs {
        static CONFIGS: OnceLock<TlsConfigs> = OnceLock::new();
        CONFIGS.get_or_init(|| TlsConfigs::with_roots(default_roots()))
    }

    pub fn with_roots(roots: RootCertStore) -> Self {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut verified = ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .expect("ring supports the default protocol versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
        verified.alpn_protocols = vec![b"http/1.1".to_vec()];

        let mut insecure = ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .expect("ring supports the default protocol versions")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify(provider)))
            .with_no_client_auth();
        insecure.alpn_protocols = vec![b"http/1.1".to_vec()];

        Self { verified: Arc::new(verified), insecure: Arc::new(insecure) }
    }
}

fn default_roots() -> RootCertStore {
    let mut roots = RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
    for cert in rustls_native_certs::load_native_certs().certs {
        let _ = roots.add(cert);
    }
    roots
}

#[derive(Debug)]
struct NoVerify(Arc<CryptoProvider>);

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[derive(Clone, Debug)]
pub struct RequestSpec {
    pub method: Method,
    pub url: Url,
    pub headers: Vec<(HeaderName, HeaderValue)>,
    pub body: Bytes,
    pub timeout: Duration,
    pub ip_family: IpFamily,
    pub max_redirects: usize,
    pub ignore_tls: bool,
    pub max_body_bytes: usize,
}

impl RequestSpec {
    pub fn new(method: Method, url: Url) -> Self {
        Self {
            method,
            url,
            headers: Vec::new(),
            body: Bytes::new(),
            timeout: Duration::from_secs(15),
            ip_family: IpFamily::Auto,
            max_redirects: 10,
            ignore_tls: false,
            max_body_bytes: 2 * 1024 * 1024,
        }
    }

    pub fn header(mut self, name: HeaderName, value: &str) -> Self {
        if let Ok(v) = HeaderValue::from_str(value) {
            self.headers.push((name, v));
        }
        self
    }

    pub fn body(mut self, body: impl Into<Bytes>) -> Self {
        self.body = body.into();
        self
    }
}

#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub headers: HeaderMap,
    pub body: Bytes,
    pub body_truncated: bool,
    pub timings: Timings,
    pub remote_ip: IpAddr,
    pub cert_expires_at: Option<i64>,
    pub url: Url,
    /// Non-fatal observations, e.g. an IPv6 address that failed before IPv4 succeeded.
    pub notes: Vec<String>,
}

impl Response {
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Dns,
    Connect,
    Tls,
    Request,
    Response,
}

impl fmt::Display for Phase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Phase::Dns => "DNS",
            Phase::Connect => "connect",
            Phase::Tls => "TLS",
            Phase::Request => "request",
            Phase::Response => "response",
        })
    }
}

#[derive(Debug)]
pub struct HttpError {
    pub phase: Phase,
    pub message: String,
    pub timings: Timings,
    pub remote_ip: Option<IpAddr>,
}

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.phase, self.message)
    }
}

impl std::error::Error for HttpError {}

struct Progress {
    phase: Phase,
    timings: Timings,
    remote_ip: Option<IpAddr>,
    notes: Vec<String>,
}

impl Progress {
    fn fail(&self, message: impl Into<String>) -> HttpError {
        HttpError { phase: self.phase, message: message.into(), timings: self.timings.clone(), remote_ip: self.remote_ip }
    }
}

fn ms(since: Instant) -> f64 {
    since.elapsed().as_secs_f64() * 1000.0
}

pub async fn send(spec: &RequestSpec) -> Result<Response, HttpError> {
    let started = Instant::now();
    let deadline = started + spec.timeout;
    let mut progress = Progress { phase: Phase::Dns, timings: Timings::default(), remote_ip: None, notes: Vec::new() };
    let result = tokio::time::timeout(spec.timeout, run(spec, deadline, &mut progress)).await;
    match result {
        Ok(Ok(mut r)) => {
            r.timings.total_ms = Some(ms(started));
            Ok(r)
        }
        Ok(Err(mut e)) => {
            e.timings.total_ms = Some(ms(started));
            Err(e)
        }
        Err(_) => {
            let mut e = progress.fail(format!("timed out after {:.1}s", spec.timeout.as_secs_f64()));
            e.timings.total_ms = Some(ms(started));
            if !progress.notes.is_empty() {
                e.message = format!("{} ({})", e.message, progress.notes.join("; "));
            }
            Err(e)
        }
    }
}

async fn run(spec: &RequestSpec, deadline: Instant, p: &mut Progress) -> Result<Response, HttpError> {
    let mut url = spec.url.clone();
    let mut method = spec.method.clone();
    let mut body = spec.body.clone();
    let mut hops = 0;
    loop {
        let mut resp = one_request(&url, &method, &body, spec, deadline, p).await?;
        let location = resp.headers.get(LOCATION).and_then(|v| v.to_str().ok()).map(str::to_owned);
        let is_redirect = matches!(resp.status, 301 | 302 | 303 | 307 | 308);
        match location {
            Some(loc) if is_redirect && spec.max_redirects > 0 => {
                hops += 1;
                if hops > spec.max_redirects {
                    return Err(p.fail(format!("too many redirects (> {})", spec.max_redirects)));
                }
                url = url.join(&loc).map_err(|e| p.fail(format!("invalid redirect location {loc:?}: {e}")))?;
                if resp.status == 303 || (matches!(resp.status, 301 | 302) && method != Method::HEAD) {
                    method = Method::GET;
                    body = Bytes::new();
                }
            }
            _ => {
                resp.notes = std::mem::take(&mut p.notes);
                return Ok(resp);
            }
        }
    }
}

/// Resolves `host` and keeps only addresses allowed by `family`, in system preference order.
pub async fn resolve(host: &str, port: u16, family: IpFamily) -> Result<Vec<SocketAddr>, String> {
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = bare.parse::<IpAddr>() {
        if !family.allows(&ip) {
            return Err(format!("{ip} is not an {} address", if family == IpFamily::V4 { "IPv4" } else { "IPv6" }));
        }
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let all: Vec<SocketAddr> = tokio::net::lookup_host((bare, port)).await.map_err(|e| format!("cannot resolve {bare}: {e}"))?.collect();
    let mut out: Vec<SocketAddr> = Vec::new();
    for a in all.into_iter().filter(|a| family.allows(&a.ip())) {
        if !out.contains(&a) {
            out.push(a);
        }
    }
    if out.is_empty() {
        return Err(match family {
            IpFamily::V4 => format!("{bare} has no IPv4 (A) address"),
            IpFamily::V6 => format!("{bare} has no IPv6 (AAAA) address"),
            IpFamily::Auto => format!("{bare} resolved to no addresses"),
        });
    }
    Ok(out)
}

fn family_label(ip: &IpAddr) -> &'static str {
    if ip.is_ipv6() { "IPv6" } else { "IPv4" }
}

/// Tries each address in order; earlier attempts get part of the budget so a dead IPv6 path
/// still leaves time for IPv4.
pub async fn connect_any(addrs: &[SocketAddr], deadline: Instant, notes: &mut Vec<String>) -> Result<(TcpStream, SocketAddr), String> {
    let mut last_err = String::from("no addresses to connect to");
    for (i, addr) in addrs.iter().enumerate() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        // The last attempt ends just before the overall deadline so its error names the address.
        let budget = if i + 1 == addrs.len() {
            remaining.saturating_sub(Duration::from_millis(50))
        } else {
            (remaining / 2).min(Duration::from_secs(5))
        };
        match tokio::time::timeout(budget, TcpStream::connect(addr)).await {
            Ok(Ok(s)) => {
                let _ = s.set_nodelay(true);
                return Ok((s, *addr));
            }
            Ok(Err(e)) => last_err = format!("{} {} failed: {}", family_label(&addr.ip()), addr.ip(), io_error_text(&e)),
            Err(_) => last_err = format!("{} {} timed out after {:.1}s", family_label(&addr.ip()), addr.ip(), budget.as_secs_f64()),
        }
        if i + 1 < addrs.len() {
            notes.push(last_err.clone());
        }
    }
    Err(last_err)
}

pub fn io_error_text(e: &std::io::Error) -> String {
    use std::io::ErrorKind::*;
    match e.kind() {
        ConnectionRefused => "connection refused".into(),
        ConnectionReset => "connection reset".into(),
        TimedOut => "timed out".into(),
        HostUnreachable => "host unreachable".into(),
        NetworkUnreachable => "network unreachable".into(),
        _ => e.to_string(),
    }
}

struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn one_request(
    url: &Url,
    method: &Method,
    body: &Bytes,
    spec: &RequestSpec,
    deadline: Instant,
    p: &mut Progress,
) -> Result<Response, HttpError> {
    p.phase = Phase::Dns;
    let https = match url.scheme() {
        "https" => true,
        "http" => false,
        s => return Err(p.fail(format!("unsupported scheme {s}"))),
    };
    let host = url.host().ok_or_else(|| p.fail("URL has no host"))?;
    let port = url.port_or_known_default().unwrap_or(if https { 443 } else { 80 });
    let host_str = url.host_str().unwrap_or_default().to_string();

    let t = Instant::now();
    let addrs = resolve(&host_str, port, spec.ip_family).await.map_err(|e| p.fail(e))?;
    p.timings.dns_ms = Some(if matches!(host, Host::Domain(_)) { ms(t) } else { 0.0 });

    p.phase = Phase::Connect;
    let t = Instant::now();
    let (tcp, addr) = connect_any(&addrs, deadline, &mut p.notes).await.map_err(|e| p.fail(e))?;
    p.timings.connect_ms = Some(ms(t));
    p.remote_ip = Some(addr.ip());

    let mut headers = HeaderMap::new();
    let host_header = match url.port() {
        Some(port) => format!("{host_str}:{port}"),
        None => host_str.clone(),
    };
    headers.insert(HOST, HeaderValue::from_str(&host_header).map_err(|_| p.fail("invalid host"))?);
    headers.insert(USER_AGENT, HeaderValue::from_static(USER_AGENT_VALUE));
    headers.insert(ACCEPT, HeaderValue::from_static("*/*"));
    headers.insert(ACCEPT_ENCODING, HeaderValue::from_static("identity"));
    headers.insert(CONNECTION, HeaderValue::from_static("close"));
    if !body.is_empty() {
        headers.insert(CONTENT_LENGTH, HeaderValue::from(body.len()));
    }
    for (k, v) in &spec.headers {
        headers.insert(k.clone(), v.clone());
    }
    let path = match url.query() {
        Some(q) => format!("{}?{q}", url.path()),
        None => url.path().to_string(),
    };
    let mut req = Request::builder()
        .method(method.clone())
        .uri(path)
        .body(Full::new(body.clone()))
        .map_err(|e| p.fail(format!("invalid request: {e}")))?;
    *req.headers_mut() = headers;

    if https {
        p.phase = Phase::Tls;
        let t = Instant::now();
        let cfg = if spec.ignore_tls { &TlsConfigs::shared().insecure } else { &TlsConfigs::shared().verified };
        let server_name = match host {
            Host::Domain(d) => ServerName::try_from(d.to_string()).map_err(|_| p.fail("invalid server name"))?,
            Host::Ipv4(ip) => ServerName::IpAddress(IpAddr::V4(ip).into()),
            Host::Ipv6(ip) => ServerName::IpAddress(IpAddr::V6(ip).into()),
        };
        let tls = TlsConnector::from(cfg.clone()).connect(server_name, tcp).await.map_err(|e| p.fail(tls_error_text(&e)))?;
        p.timings.tls_ms = Some(ms(t));
        let cert_expires_at = tls.get_ref().1.peer_certificates().and_then(|c| c.first()).and_then(|c| cert_not_after(c));
        let mut r = exchange(TokioIo::new(tls), req, spec, p).await?;
        r.cert_expires_at = cert_expires_at;
        r.url = url.clone();
        Ok(r)
    } else {
        let mut r = exchange(TokioIo::new(tcp), req, spec, p).await?;
        r.url = url.clone();
        Ok(r)
    }
}

async fn exchange<T>(io: TokioIo<T>, req: Request<Full<Bytes>>, spec: &RequestSpec, p: &mut Progress) -> Result<Response, HttpError>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    p.phase = Phase::Request;
    let t = Instant::now();
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.map_err(|e| p.fail(e.to_string()))?;
    let _conn = AbortOnDrop(tokio::spawn(async move {
        let _ = conn.await;
    }));
    let resp = sender.send_request(req).await.map_err(|e| p.fail(hyper_error_text(&e)))?;
    p.timings.ttfb_ms = Some(ms(t));

    p.phase = Phase::Response;
    let status = resp.status().as_u16();
    let headers = resp.headers().clone();
    let mut incoming = resp.into_body();
    let mut buf: Vec<u8> = Vec::new();
    let mut truncated = false;
    while let Some(frame) = incoming.frame().await {
        let frame = frame.map_err(|e| p.fail(format!("reading body: {e}")))?;
        if let Ok(data) = frame.into_data() {
            let room = spec.max_body_bytes.saturating_sub(buf.len());
            buf.extend_from_slice(&data[..data.len().min(room)]);
            if data.len() > room {
                truncated = true;
                break;
            }
        }
    }
    Ok(Response {
        status,
        headers,
        body: Bytes::from(buf),
        body_truncated: truncated,
        timings: p.timings.clone(),
        remote_ip: p.remote_ip.expect("set after connect"),
        cert_expires_at: None,
        url: Url::parse("http://placeholder").expect("static url"),
        notes: Vec::new(),
    })
}

pub fn cert_not_after(der: &CertificateDer<'_>) -> Option<i64> {
    let (_, cert) = x509_parser::parse_x509_certificate(der.as_ref()).ok()?;
    Some(cert.validity().not_after.timestamp() * 1000)
}

fn tls_error_text(e: &std::io::Error) -> String {
    match e.get_ref().and_then(|inner| inner.downcast_ref::<rustls::Error>()) {
        Some(rustls::Error::InvalidCertificate(c)) => format!("invalid certificate: {c:?}"),
        Some(other) => other.to_string(),
        None => io_error_text(e),
    }
}

fn hyper_error_text(e: &hyper::Error) -> String {
    let mut msg = e.to_string();
    let mut src = std::error::Error::source(e);
    while let Some(s) = src {
        msg = format!("{msg}: {s}");
        src = s.source();
    }
    msg
}
