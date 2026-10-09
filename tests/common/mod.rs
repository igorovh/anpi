#![allow(dead_code)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anpi::config::Config;
use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, Request, StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::{any, post};
use http_body_util::BodyExt;
use tower::ServiceExt;

pub fn config(pairs: &[(&str, &str)]) -> Config {
    Config::from_map(&pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()).unwrap()
}

pub async fn app(cfg: Config) -> anpi::App {
    let db = anpi::db::open_memory().await.unwrap();
    anpi::build(cfg, db).await.unwrap()
}

pub async fn serve(router: Router) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    addr
}

pub async fn wait_for<F, Fut>(what: &str, timeout: Duration, mut cond: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        if cond().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out waiting for: {what}");
}

type TargetState = (Arc<AtomicU16>, Arc<AtomicU64>, Arc<Mutex<String>>);

/// A target whose response can be changed while a test runs.
#[derive(Clone)]
pub struct Target {
    pub addr: SocketAddr,
    pub status: Arc<AtomicU16>,
    pub delay_ms: Arc<AtomicU64>,
    pub body: Arc<Mutex<String>>,
}

impl Target {
    pub async fn start() -> Self {
        let status = Arc::new(AtomicU16::new(200));
        let delay_ms = Arc::new(AtomicU64::new(0));
        let body = Arc::new(Mutex::new(r#"{"status":"ok"}"#.to_string()));
        let state = (status.clone(), delay_ms.clone(), body.clone());
        let router = Router::new()
            .route("/redirect", any(|| async { (StatusCode::FOUND, [(header::LOCATION, "/")]).into_response() }))
            .route("/loop", any(|| async { (StatusCode::FOUND, [(header::LOCATION, "/loop")]).into_response() }))
            .fallback(any(|State((s, d, b)): State<TargetState>| async move {
                let delay = d.load(Ordering::SeqCst);
                if delay > 0 {
                    tokio::time::sleep(Duration::from_millis(delay)).await;
                }
                let code = StatusCode::from_u16(s.load(Ordering::SeqCst)).unwrap();
                (code, [(header::CONTENT_TYPE, "application/json")], b.lock().unwrap().clone()).into_response()
            }))
            .with_state(state);
        let addr = serve(router).await;
        Self { addr, status, delay_ms, body }
    }

    pub fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }

    pub fn set_status(&self, code: u16) {
        self.status.store(code, Ordering::SeqCst);
    }
}

/// Minimal HTTPS server with a self-signed certificate; returns its address and the cert expiry (ms).
pub async fn tls_server(valid_days: i64) -> (SocketAddr, i64) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()]).unwrap();
    let not_after = time::OffsetDateTime::now_utc() + time::Duration::days(valid_days);
    let not_after = not_after.replace_nanosecond(0).unwrap();
    params.not_after = not_after;
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into()),
        )
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else { return };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else { return };
                let mut buf = vec![0u8; 4096];
                let mut seen = Vec::new();
                while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
                    match tls.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => seen.extend_from_slice(&buf[..n]),
                    }
                }
                let _ = tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").await;
                let _ = tls.shutdown().await;
            });
        }
    });
    (addr, not_after.unix_timestamp() * 1000)
}

/// Collects JSON posted by the generic webhook notifier.
#[derive(Clone)]
pub struct Webhook {
    pub addr: SocketAddr,
    pub received: Arc<Mutex<Vec<serde_json::Value>>>,
}

impl Webhook {
    pub async fn start() -> Self {
        let received: Arc<Mutex<Vec<serde_json::Value>>> = Arc::default();
        let r = received.clone();
        let router = Router::new().route(
            "/hook",
            post(move |body: axum::body::Bytes| {
                let r = r.clone();
                async move {
                    r.lock().unwrap().push(serde_json::from_slice(&body).unwrap_or_default());
                    StatusCode::NO_CONTENT
                }
            }),
        );
        let addr = serve(router).await;
        Self { addr, received }
    }

    pub fn url(&self) -> String {
        format!("http://{}/hook", self.addr)
    }

    pub fn events(&self) -> Vec<String> {
        self.received.lock().unwrap().iter().map(|v| v["event"].as_str().unwrap_or("").to_string()).collect()
    }

    pub fn count(&self, event: &str) -> usize {
        self.events().iter().filter(|e| *e == event).count()
    }
}

pub async fn add_webhook_channel(db: &anpi::db::Db, url: &str) -> i64 {
    let cfg = anpi::notify::ChannelConfig { url: url.into(), ..Default::default() };
    anpi::store::notifications::create(db, "hook", "webhook", &cfg.to_json(), true, false).await.unwrap()
}

pub struct Resp {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: String,
}

impl Resp {
    pub fn location(&self) -> String {
        self.headers.get(header::LOCATION).map(|v| v.to_str().unwrap().to_string()).unwrap_or_default()
    }
}

/// Drives the router in-process and keeps cookies like a browser would.
pub struct Client {
    pub router: Router,
    pub cookies: HashMap<String, String>,
}

impl Client {
    pub fn new(router: Router) -> Self {
        Self { router, cookies: HashMap::new() }
    }

    fn cookie_header(&self) -> String {
        self.cookies.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("; ")
    }

    pub async fn send(&mut self, req: Request<Body>) -> Resp {
        let resp = self.router.clone().oneshot(req).await.unwrap();
        for sc in resp.headers().get_all(header::SET_COOKIE) {
            let raw = sc.to_str().unwrap();
            let (pair, attrs) = raw.split_once(';').unwrap_or((raw, ""));
            let (name, value) = pair.split_once('=').unwrap();
            if attrs.contains("Max-Age=0") || value.is_empty() {
                self.cookies.remove(name);
            } else {
                self.cookies.insert(name.to_string(), value.to_string());
            }
        }
        let status = resp.status();
        let headers = resp.headers().clone();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        Resp { status, headers, body: String::from_utf8_lossy(&bytes).into_owned() }
    }

    pub async fn get(&mut self, path: &str) -> Resp {
        let req = Request::get(path).header(header::HOST, "localhost").header(header::COOKIE, self.cookie_header()).body(Body::empty()).unwrap();
        self.send(req).await
    }

    pub async fn post(&mut self, path: &str, form: &[(&str, &str)]) -> Resp {
        self.post_with(path, form, None).await
    }

    pub async fn post_with(&mut self, path: &str, form: &[(&str, &str)], origin: Option<&str>) -> Resp {
        let body = url::form_urlencoded::Serializer::new(String::new()).extend_pairs(form).finish();
        let mut req = Request::post(path)
            .header(header::HOST, "localhost")
            .header(header::COOKIE, self.cookie_header())
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        if let Some(o) = origin {
            req = req.header(header::ORIGIN, o);
        }
        self.send(req.body(Body::from(body)).unwrap()).await
    }

    pub async fn post_multipart(&mut self, path: &str, fields: &[(&str, &str)], file: (&str, &str, &[u8])) -> Resp {
        let boundary = "anpi-test-boundary";
        let mut body = Vec::new();
        for (k, v) in fields {
            let part = format!("--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n");
            body.extend_from_slice(part.as_bytes());
        }
        let (name, filename, data) = file;
        let head = format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"; filename=\"{filename}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
        );
        body.extend_from_slice(head.as_bytes());
        body.extend_from_slice(data);
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let req = Request::post(path)
            .header(header::HOST, "localhost")
            .header(header::COOKIE, self.cookie_header())
            .header(header::CONTENT_TYPE, format!("multipart/form-data; boundary={boundary}"))
            .body(Body::from(body))
            .unwrap();
        self.send(req).await
    }

    /// Reads the CSRF token embedded in any admin page.
    pub async fn csrf(&mut self) -> String {
        let page = self.get("/admin/settings").await;
        let marker = r#"name="csrf" value=""#;
        let start = page.body.find(marker).expect("csrf field on page") + marker.len();
        page.body[start..].split('"').next().unwrap().to_string()
    }
}

/// Creates the first account through the real setup flow and returns a signed-in client.
pub async fn signed_in(app: &anpi::App) -> Client {
    let mut c = Client::new(anpi::web::router(app.state.clone()));
    let code = app.state.setup_code.lock().unwrap().clone().expect("setup code");
    let r = c
        .post("/setup", &[("setup_code", &code), ("username", "admin"), ("password", "a-long-password"), ("password2", "a-long-password")])
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
    c
}

/// WebSocket server that echoes text messages, prefixed with "echo: ".
pub async fn ws_echo_server() -> SocketAddr {
    use futures_util::{SinkExt, StreamExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else { return };
            tokio::spawn(async move {
                let Ok(mut ws) = tokio_tungstenite::accept_async(tcp).await else { return };
                while let Some(Ok(msg)) = ws.next().await {
                    if let tokio_tungstenite::tungstenite::Message::Text(t) = msg {
                        let _ = ws.send(tokio_tungstenite::tungstenite::Message::text(format!("echo: {t}"))).await;
                    }
                }
            });
        }
    });
    addr
}
