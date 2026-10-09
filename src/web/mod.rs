mod admin;
mod auth_routes;
pub mod backup;
mod branding;
mod channels;
mod charts;
mod public;
mod settings;
mod views;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use askama::Template;
use axum::extract::{ConnectInfo, FromRequestParts, Request, State};
use axum::http::request::Parts;
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::Router;
use axum_extra::extract::CookieJar;
use axum_extra::extract::cookie::{Cookie, SameSite};
use rust_embed::RustEmbed;
use tower_http::compression::CompressionLayer;
use tower_http::set_header::SetResponseHeaderLayer;

use crate::app::Ctx;
use crate::auth::oidc::Oidc;
use crate::auth::ratelimit::LoginLimiter;
use crate::monitor::scheduler::Scheduler;
use crate::store;

pub const SESSION_COOKIE: &str = "anpi_session";
/// Changes whenever a bundled asset changes, so browsers never keep stale CSS or JS.
pub fn asset_version() -> &'static str {
    static VERSION: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    VERSION.get_or_init(|| {
        let mut joined = String::new();
        for name in ["app.css", "app.js", "theme.js"] {
            if let Some(f) = Assets::get(name) {
                joined.push_str(&hex::encode(f.metadata.sha256_hash()));
            }
        }
        crate::util::sha256_hex(&joined)[..12].to_string()
    })
}

#[derive(Clone)]
pub struct AppState {
    pub ctx: Arc<Ctx>,
    pub scheduler: Arc<Scheduler>,
    pub limiter: Arc<LoginLimiter>,
    /// One-time code printed to the log; required to create the first account.
    pub setup_code: Arc<Mutex<Option<String>>>,
}

impl AppState {
    pub fn new(ctx: Arc<Ctx>, scheduler: Arc<Scheduler>) -> Self {
        Self {
            ctx,
            scheduler,
            limiter: Arc::new(LoginLimiter::new(10, Duration::from_secs(15 * 60))),
            setup_code: Arc::new(Mutex::new(None)),
        }
    }

    pub fn oidc(&self) -> Option<Arc<Oidc>> {
        self.ctx.auth().oidc
    }

    pub fn db(&self) -> &crate::db::Db {
        &self.ctx.db
    }

    pub fn session_cookie(&self, token: String) -> Cookie<'static> {
        Cookie::build((SESSION_COOKIE, token))
            .path("/")
            .http_only(true)
            .same_site(SameSite::Lax)
            .secure(self.ctx.secure_cookies())
            .max_age(time::Duration::milliseconds(store::users::SESSION_TTL_MS))
            .build()
    }
}

#[derive(Debug)]
pub struct AppError(pub StatusCode, pub String);

impl AppError {
    pub fn not_found() -> Self {
        Self(StatusCode::NOT_FOUND, "Not found".into())
    }

    pub fn bad_request(msg: impl Into<String>) -> Self {
        Self(StatusCode::BAD_REQUEST, msg.into())
    }

    pub fn forbidden(msg: impl Into<String>) -> Self {
        Self(StatusCode::FORBIDDEN, msg.into())
    }
}

impl<E: std::fmt::Display> From<E> for AppError {
    fn from(e: E) -> Self {
        tracing::error!(error = %e, "request failed");
        Self(StatusCode::INTERNAL_SERVER_ERROR, "Internal error".into())
    }
}

#[derive(Template)]
#[template(path = "error.html")]
struct ErrorPage {
    layout: views::Layout,
    code: u16,
    message: String,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let page = ErrorPage { layout: views::Layout::bare(&crate::app::Branding::default(), "Error"), code: self.0.as_u16(), message: self.1.clone() };
        match page.render() {
            Ok(html) => (self.0, Html(html)).into_response(),
            Err(_) => (self.0, self.1).into_response(),
        }
    }
}

pub type AppResult<T> = Result<T, AppError>;

pub fn render<T: Template>(t: &T) -> AppResult<Html<String>> {
    Ok(Html(t.render()?))
}

pub struct CurrentUser {
    pub id: i64,
    pub username: String,
    pub csrf: String,
    pub id_token: Option<String>,
    pub token: String,
    pub brand: crate::app::Branding,
}

impl CurrentUser {
    pub fn check_csrf(&self, token: &str) -> AppResult<()> {
        let a = self.csrf.as_bytes();
        let b = token.as_bytes();
        let same = a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0;
        if same { Ok(()) } else { Err(AppError::forbidden("Invalid or expired form token. Reload the page and try again.")) }
    }
}

impl FromRequestParts<AppState> for CurrentUser {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let jar = CookieJar::from_headers(&parts.headers);
        if let Some(c) = jar.get(SESSION_COOKIE)
            && let Ok(Some(s)) = store::users::session(state.db(), c.value()).await
        {
            return Ok(Self {
                id: s.user_id,
                username: s.username,
                csrf: s.csrf,
                id_token: s.id_token,
                token: c.value().to_string(),
                brand: state.ctx.branding(),
            });
        }
        let next = parts.uri.path_and_query().map(|p| p.as_str()).unwrap_or("/admin");
        Err(Redirect::to(&format!("/login?next={}", urlencoding::encode(next))).into_response())
    }
}

pub struct ClientIp(pub IpAddr);

impl FromRequestParts<AppState> for ClientIp {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let peer = parts.extensions.get::<ConnectInfo<SocketAddr>>().map(|c| c.0.ip()).unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        let forwarded = parts.headers.get_all("x-forwarded-for").iter().filter_map(|v| v.to_str().ok()).collect::<Vec<_>>().join(",");
        Ok(Self(client_ip(peer, state.ctx.config.trust_proxy.then_some(forwarded.as_str()))))
    }
}

/// The trusted proxy appends the real client address last; earlier entries come from the client and are ignored.
pub fn client_ip(peer: IpAddr, forwarded_for: Option<&str>) -> IpAddr {
    forwarded_for
        .and_then(|v| v.rsplit(',').map(str::trim).find(|s| !s.is_empty()))
        .and_then(|v| v.parse().ok())
        .unwrap_or(peer)
}

/// Returns a same-site path for `next`. Browsers drop tabs and newlines and treat `\\` as `/`,
/// so the value is resolved the way a browser would before its host is compared.
pub fn safe_next(next: Option<&str>) -> String {
    const FALLBACK: &str = "/admin";
    let Some(n) = next else { return FALLBACK.into() };
    if !n.starts_with('/') || n.chars().any(|c| c.is_control() || c == '\\') {
        return FALLBACK.into();
    }
    let base = url::Url::parse("http://anpi.invalid/").expect("static base URL");
    match base.join(n) {
        Ok(u) if u.origin() == base.origin() => match u.query() {
            Some(q) => format!("{}?{q}", u.path()),
            None => u.path().to_string(),
        },
        _ => FALLBACK.into(),
    }
}

#[derive(RustEmbed)]
#[folder = "static/"]
struct Assets;

// Debug builds read assets from disk on every request, so edits show up on reload.
const ASSET_CACHE: &str = if cfg!(debug_assertions) { "no-cache" } else { "public, max-age=604800" };

async fn static_asset(axum::extract::Path(path): axum::extract::Path<String>) -> Response {
    match Assets::get(&path) {
        Some(file) => {
            let mime = mime_guess::from_path(&path).first_or_octet_stream();
            (
                [
                    (header::CONTENT_TYPE, HeaderValue::from_str(mime.as_ref()).unwrap_or(HeaderValue::from_static("application/octet-stream"))),
                    (header::CACHE_CONTROL, HeaderValue::from_static(ASSET_CACHE)),
                ],
                file.data,
            )
                .into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// Rejects cross-site form posts; push endpoints are exempt because cron jobs call them.
async fn origin_guard(req: Request, next: Next) -> Response {
    if req.method() == Method::POST && !req.uri().path().starts_with("/api/push/") {
        let host = req.headers().get(header::HOST).and_then(|h| h.to_str().ok()).unwrap_or_default();
        if let Some(origin) = req.headers().get(header::ORIGIN).and_then(|o| o.to_str().ok()) {
            let origin_host = url::Url::parse(origin).ok().and_then(|u| {
                u.host_str().map(|h| match u.port() {
                    Some(p) => format!("{h}:{p}"),
                    None => h.to_string(),
                })
            });
            if origin_host.as_deref() != Some(host) {
                return (StatusCode::FORBIDDEN, "cross-origin request blocked").into_response();
            }
        }
    }
    next.run(req).await
}

async fn healthz(State(st): State<AppState>) -> impl IntoResponse {
    match sqlx::query("SELECT 1").execute(st.db()).await {
        Ok(_) => (StatusCode::OK, "ok"),
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, "database unavailable"),
    }
}

pub fn router(state: AppState) -> Router {
    let csp = "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; \
               frame-ancestors 'none'; base-uri 'none'; object-src 'none'";
    Router::new()
        .route("/", get(public::status_page))
        .route("/api/status.json", get(public::status_json))
        .route("/api/push/{token}", get(public::push).post(public::push))
        .route("/events/public", get(public::public_events))
        .route("/healthz", get(healthz))
        .route("/static/{*path}", get(static_asset))
        .route("/login", get(auth_routes::login_page).post(auth_routes::login))
        .route("/setup", get(auth_routes::setup_page).post(auth_routes::setup))
        .route("/logout", post(auth_routes::logout))
        .route("/auth/oidc/login", get(auth_routes::oidc_login))
        .route("/auth/oidc/callback", get(auth_routes::oidc_callback))
        .route("/admin", get(admin::dashboard))
        .route("/admin/events", get(admin::events))
        .route("/admin/incidents", get(admin::incidents))
        .route("/admin/monitors/new", get(admin::new_monitor))
        .route("/admin/monitors", post(admin::create_monitor))
        .route("/admin/monitors/test", post(admin::test_monitor))
        .route("/admin/monitors/bulk", post(admin::bulk_monitors))
        .route("/admin/monitors/{id}", get(admin::monitor_detail).post(admin::update_monitor))
        .route("/admin/monitors/{id}/edit", get(admin::edit_monitor))
        .route("/admin/monitors/{id}/toggle", post(admin::toggle_monitor))
        .route("/admin/monitors/{id}/delete", post(admin::delete_monitor))
        .route("/admin/monitors/{id}/move", post(admin::move_monitor))
        .route("/admin/notifications", get(channels::list).post(channels::create))
        .route("/admin/notifications/new", get(channels::new_form))
        .route("/admin/notifications/{id}", get(channels::edit_form).post(channels::update))
        .route("/admin/notifications/{id}/delete", post(channels::delete))
        .route("/admin/notifications/{id}/test", post(channels::test))
        .route("/admin/maintenance", get(settings::maintenance_page).post(settings::create_maintenance))
        .route("/admin/maintenance/{id}/delete", post(settings::delete_maintenance))
        .route("/admin/settings", get(settings::settings_page).post(settings::save_settings))
        .route("/admin/users", post(settings::create_user))
        .route("/admin/export", get(settings::export))
        .route("/admin/branding", post(branding::save_site_name))
        .route("/admin/sso", post(settings::save_sso))
        .route("/admin/sso/test", post(settings::test_sso))
        .route(
            "/admin/branding/logo",
            post(branding::upload_logo).layer(axum::extract::DefaultBodyLimit::max(branding::MAX_LOGO_BYTES + 64 * 1024)),
        )
        .route("/admin/branding/logo/delete", post(branding::delete_logo))
        .route("/admin/groups", post(branding::create_group))
        .route("/admin/groups/{id}", post(branding::update_group))
        .route("/admin/groups/{id}/delete", post(branding::delete_group))
        .route("/brand/logo", get(branding::logo))
        .route("/admin/users/{id}/delete", post(settings::delete_user))
        .route("/admin/account/password", post(settings::change_password))
        .route(
            "/admin/import",
            get(settings::import_page).post(settings::import).layer(axum::extract::DefaultBodyLimit::max(20 * 1024 * 1024)),
        )
        .fallback(|| async { AppError::not_found() })
        .layer(middleware::from_fn(origin_guard))
        .layer(CompressionLayer::new())
        .layer(SetResponseHeaderLayer::if_not_present(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static(csp)))
        .layer(SetResponseHeaderLayer::if_not_present(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff")))
        .layer(SetResponseHeaderLayer::if_not_present(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY")))
        .layer(SetResponseHeaderLayer::if_not_present(header::REFERRER_POLICY, HeaderValue::from_static("same-origin")))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_parameter_cannot_leave_the_site() {
        assert_eq!(safe_next(Some("/admin/monitors/3")), "/admin/monitors/3");
        assert_eq!(safe_next(Some("/admin/monitors/3?range=7d")), "/admin/monitors/3?range=7d");
        for evil in ["//evil.com", "/\\evil.com", "https://evil.com", "/\t/evil.com", "/\t\\evil.com", "/\n/evil.com", "/\r\n//evil.com", "evil.com", ""] {
            assert_eq!(safe_next(Some(evil)), "/admin", "{evil:?} must not leave the site");
        }
        assert_eq!(safe_next(Some("/%09/evil.com")), "/%09/evil.com", "percent-encoded tabs stay a path on this site");
        assert_eq!(safe_next(None), "/admin");
    }

    #[test]
    fn client_ip_uses_the_address_added_by_the_proxy() {
        let peer: IpAddr = "10.0.0.2".parse().unwrap();
        assert_eq!(client_ip(peer, None), peer, "headers are ignored unless the proxy is trusted");
        assert_eq!(client_ip(peer, Some("1.2.3.4, 198.51.100.7")), "198.51.100.7".parse::<IpAddr>().unwrap());
        assert_eq!(client_ip(peer, Some("198.51.100.7")), "198.51.100.7".parse::<IpAddr>().unwrap());
        assert_eq!(client_ip(peer, Some("1.2.3.4, garbage")), peer, "an unparsable proxy entry falls back to the peer");
        assert_eq!(client_ip(peer, Some("")), peer);
    }
}
