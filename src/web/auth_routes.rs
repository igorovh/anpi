use std::time::Instant;

use askama::Template;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::Form;
use axum_extra::extract::CookieJar;
use axum_extra::extract::cookie::{Cookie, SameSite};
use serde::Deserialize;

use super::views::Layout;
use super::{AppError, AppResult, AppState, ClientIp, CurrentUser, SESSION_COOKIE, render, safe_next};
use crate::auth::password;
use crate::store;

const OIDC_STATE_COOKIE: &str = "anpi_oidc_state";

#[derive(Template)]
#[template(path = "login.html")]
struct LoginPage {
    layout: Layout,
    sso: bool,
    next: String,
    username: String,
    error: Option<String>,
}

#[derive(Template)]
#[template(path = "setup.html")]
struct SetupPage {
    layout: Layout,
    username: String,
    error: Option<String>,
}

#[derive(Deserialize)]
pub struct NextQuery {
    next: Option<String>,
    error: Option<String>,
}

fn login_page_response(st: &AppState, status: StatusCode, next: &str, username: &str, error: Option<String>) -> AppResult<Response> {
    let page = LoginPage { layout: Layout::bare("Sign in"), sso: st.oidc.is_some(), next: next.into(), username: username.into(), error };
    Ok((status, render(&page)?).into_response())
}

pub async fn login_page(State(st): State<AppState>, Query(q): Query<NextQuery>) -> AppResult<Response> {
    if st.oidc.is_none() && store::users::count(st.db()).await? == 0 {
        return Ok(Redirect::to("/setup").into_response());
    }
    let error = q.error.map(|_| "Sign-in failed. Please try again.".to_string());
    login_page_response(&st, StatusCode::OK, &safe_next(q.next.as_deref()), "", error)
}

#[derive(Deserialize)]
pub struct LoginForm {
    username: String,
    password: String,
    next: Option<String>,
}

pub async fn login(State(st): State<AppState>, ClientIp(ip): ClientIp, jar: CookieJar, Form(f): Form<LoginForm>) -> AppResult<Response> {
    if st.oidc.is_some() {
        return Err(AppError::not_found());
    }
    let next = safe_next(f.next.as_deref());
    if st.limiter.is_blocked(ip, Instant::now()) {
        let msg = "Too many failed attempts. Try again in a few minutes.".to_string();
        return login_page_response(&st, StatusCode::TOO_MANY_REQUESTS, &next, &f.username, Some(msg));
    }
    let user = store::users::by_username(st.db(), f.username.trim()).await?;
    let valid = match &user {
        Some(u) => u.password_hash.as_deref().is_some_and(|h| password::verify(&f.password, h)),
        None => {
            password::dummy_verify(&f.password);
            false
        }
    };
    match user.filter(|_| valid) {
        Some(u) => {
            st.limiter.reset(ip);
            let token = store::users::create_session(st.db(), u.id, None).await?;
            tracing::info!(user = %u.username, %ip, "signed in");
            Ok((jar.add(st.session_cookie(token)), Redirect::to(&next)).into_response())
        }
        None => {
            st.limiter.record_failure(ip, Instant::now());
            tracing::warn!(username = %f.username, %ip, "failed sign-in");
            login_page_response(&st, StatusCode::UNAUTHORIZED, &next, &f.username, Some("Invalid username or password.".into()))
        }
    }
}

async fn setup_allowed(st: &AppState) -> AppResult<bool> {
    Ok(st.oidc.is_none() && store::users::count(st.db()).await? == 0)
}

pub async fn setup_page(State(st): State<AppState>) -> AppResult<Response> {
    if !setup_allowed(&st).await? {
        return Ok(Redirect::to("/login").into_response());
    }
    Ok(render(&SetupPage { layout: Layout::bare("Set up anpi"), username: String::new(), error: None })?.into_response())
}

#[derive(Deserialize)]
pub struct SetupForm {
    setup_code: String,
    username: String,
    password: String,
    password2: String,
}

pub async fn setup(State(st): State<AppState>, jar: CookieJar, Form(f): Form<SetupForm>) -> AppResult<Response> {
    if !setup_allowed(&st).await? {
        return Ok(Redirect::to("/login").into_response());
    }
    let fail = |msg: &str| -> AppResult<Response> {
        let page = SetupPage { layout: Layout::bare("Set up anpi"), username: f.username.clone(), error: Some(msg.into()) };
        Ok((StatusCode::BAD_REQUEST, render(&page)?).into_response())
    };
    let expected = st.setup_code.lock().expect("setup lock").clone();
    if expected.as_deref() != Some(f.setup_code.trim()) {
        return fail("Wrong setup code. It is printed in the server log.");
    }
    let username = f.username.trim();
    if username.is_empty() || username.len() > 64 {
        return fail("Choose a username (up to 64 characters).");
    }
    if f.password != f.password2 {
        return fail("Passwords do not match.");
    }
    if let Err(e) = password::check_strength(&f.password) {
        return fail(&e);
    }
    let id = store::users::create_local(st.db(), username, &password::hash(&f.password)?).await?;
    *st.setup_code.lock().expect("setup lock") = None;
    let token = store::users::create_session(st.db(), id, None).await?;
    tracing::info!(user = %username, "initial account created");
    Ok((jar.add(st.session_cookie(token)), Redirect::to("/admin")).into_response())
}

#[derive(Deserialize)]
pub struct CsrfForm {
    pub csrf: String,
}

pub async fn logout(State(st): State<AppState>, user: CurrentUser, jar: CookieJar, Form(f): Form<CsrfForm>) -> AppResult<Response> {
    user.check_csrf(&f.csrf)?;
    store::users::delete_session(st.db(), &user.token).await?;
    let jar = jar.remove(Cookie::build(SESSION_COOKIE).path("/"));
    if let Some(oidc) = &st.oidc {
        let home = format!("{}/", st.ctx.config.base_url.clone().unwrap_or_default());
        if let Some(url) = oidc.logout_url(user.id_token.as_deref(), &home).await {
            return Ok((jar, Redirect::to(&url)).into_response());
        }
    }
    Ok((jar, Redirect::to("/")).into_response())
}

pub async fn oidc_login(State(st): State<AppState>, jar: CookieJar, Query(q): Query<NextQuery>) -> AppResult<Response> {
    let oidc = st.oidc.clone().ok_or_else(AppError::not_found)?;
    let (url, state) = oidc.begin(&safe_next(q.next.as_deref())).await.map_err(|e| {
        tracing::error!(error = %e, "OIDC discovery failed");
        AppError(StatusCode::BAD_GATEWAY, "The identity provider is unreachable.".into())
    })?;
    let cookie = Cookie::build((OIDC_STATE_COOKIE, state))
        .path("/auth/oidc")
        .http_only(true)
        .same_site(SameSite::Lax)
        .secure(st.ctx.config.secure_cookies())
        .max_age(time::Duration::minutes(10))
        .build();
    Ok((jar.add(cookie), Redirect::to(&url)).into_response())
}

#[derive(Deserialize)]
pub struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

pub async fn oidc_callback(State(st): State<AppState>, jar: CookieJar, Query(q): Query<CallbackQuery>) -> AppResult<Response> {
    let oidc = st.oidc.clone().ok_or_else(AppError::not_found)?;
    let fail = |msg: String| login_page_response(&st, StatusCode::UNAUTHORIZED, "/admin", "", Some(msg));
    if let Some(err) = q.error {
        return fail(format!("Identity provider returned an error: {}", q.error_description.unwrap_or(err)));
    }
    let (Some(code), Some(state)) = (q.code, q.state) else {
        return fail("Missing code or state in the callback.".into());
    };
    // The state must match the cookie set on this browser, which blocks login CSRF.
    if jar.get(OIDC_STATE_COOKIE).map(|c| c.value()) != Some(state.as_str()) {
        return fail("Sign-in session mismatch. Please start again.".into());
    }
    let jar = jar.remove(Cookie::build(OIDC_STATE_COOKIE).path("/auth/oidc"));
    let login = match oidc.complete(&code, &state).await {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!(error = %e, "OIDC sign-in rejected");
            return fail(e);
        }
    };
    let user = store::users::upsert_oidc(st.db(), &login.issuer, &login.subject, &login.username).await?;
    let token = store::users::create_session(st.db(), user.id, Some(&login.id_token)).await?;
    tracing::info!(user = %user.username, "signed in via OIDC");
    Ok((jar.add(st.session_cookie(token)), Redirect::to(&safe_next(Some(&login.next)))).into_response())
}
