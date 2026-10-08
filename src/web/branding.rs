use axum::extract::{Multipart, Path, State};
use axum::http::{HeaderValue, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::Form;
use serde::Deserialize;

use super::auth_routes::CsrfForm;
use super::{AppError, AppResult, AppState, CurrentUser};
use crate::app::LOGO_KEY;
use crate::store;

pub const MAX_LOGO_BYTES: usize = 512 * 1024;

/// Detects the image type from its bytes; the browser-supplied type is not trusted.
pub fn sniff_image(data: &[u8]) -> Option<&'static str> {
    if data.starts_with(b"\x89PNG\r\n\x1a\n") {
        return Some("image/png");
    }
    if data.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return Some("image/jpeg");
    }
    if data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a") {
        return Some("image/gif");
    }
    if data.len() > 12 && &data[..4] == b"RIFF" && &data[8..12] == b"WEBP" {
        return Some("image/webp");
    }
    if data.starts_with(&[0, 0, 1, 0]) {
        return Some("image/x-icon");
    }
    let head = String::from_utf8_lossy(&data[..data.len().min(1024)]).to_ascii_lowercase();
    let trimmed = head.trim_start_matches('\u{feff}').trim_start();
    if (trimmed.starts_with("<svg") || trimmed.starts_with("<?xml")) && head.contains("<svg") {
        return Some("image/svg+xml");
    }
    None
}

pub async fn logo(State(st): State<AppState>) -> AppResult<Response> {
    let asset = store::assets::get(st.db(), LOGO_KEY).await?.ok_or_else(AppError::not_found)?;
    let content_type = HeaderValue::from_str(&asset.content_type).unwrap_or(HeaderValue::from_static("application/octet-stream"));
    Ok((
        [
            (header::CONTENT_TYPE, content_type),
            (header::CACHE_CONTROL, HeaderValue::from_static("public, max-age=31536000, immutable")),
            // Uploaded SVG must never run scripts, even when opened directly.
            (header::CONTENT_SECURITY_POLICY, HeaderValue::from_static("default-src 'none'; style-src 'unsafe-inline'; sandbox")),
        ],
        asset.data,
    )
        .into_response())
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub struct SiteNameForm {
    csrf: String,
    site_name: String,
}

pub fn validate_site_name(name: &str) -> Result<String, String> {
    let n = name.trim();
    if n.is_empty() || n.chars().count() > 40 {
        return Err("Site name is required (up to 40 characters)".into());
    }
    Ok(n.to_string())
}

pub async fn save_site_name(State(st): State<AppState>, user: CurrentUser, Form(f): Form<SiteNameForm>) -> AppResult<Response> {
    user.check_csrf(&f.csrf)?;
    let name = validate_site_name(&f.site_name).map_err(AppError::bad_request)?;
    store::settings::set(st.db(), "site_name", &name).await?;
    st.ctx.reload_branding().await?;
    Ok(Redirect::to("/admin/settings?notice=saved").into_response())
}

pub async fn upload_logo(State(st): State<AppState>, user: CurrentUser, mut form: Multipart) -> AppResult<Response> {
    let mut csrf = String::new();
    let mut data: Option<Vec<u8>> = None;
    while let Some(field) = form.next_field().await.map_err(|e| AppError::bad_request(e.to_string()))? {
        match field.name() {
            Some("csrf") => csrf = field.text().await.map_err(|e| AppError::bad_request(e.to_string()))?,
            Some("logo") => data = Some(field.bytes().await.map_err(|_| AppError::bad_request("Logo is too large (max 512 KB)"))?.to_vec()),
            _ => {}
        }
    }
    user.check_csrf(&csrf)?;
    let data = data.filter(|d| !d.is_empty()).ok_or_else(|| AppError::bad_request("Choose an image file"))?;
    if data.len() > MAX_LOGO_BYTES {
        return Err(AppError::bad_request("Logo is too large (max 512 KB)"));
    }
    let content_type = sniff_image(&data).ok_or_else(|| AppError::bad_request("Use a PNG, JPEG, WebP, GIF, ICO or SVG image"))?;
    store::assets::put(st.db(), LOGO_KEY, content_type, &data).await?;
    st.ctx.reload_branding().await?;
    Ok(Redirect::to("/admin/settings?notice=saved").into_response())
}

pub async fn delete_logo(State(st): State<AppState>, user: CurrentUser, Form(f): Form<CsrfForm>) -> AppResult<Response> {
    user.check_csrf(&f.csrf)?;
    store::assets::delete(st.db(), LOGO_KEY).await?;
    st.ctx.reload_branding().await?;
    Ok(Redirect::to("/admin/settings?notice=deleted").into_response())
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub struct GroupForm {
    csrf: String,
    name: String,
    sort_order: String,
}

fn validate_group(f: &GroupForm, default_order: i64) -> AppResult<(String, i64)> {
    let name = f.name.trim();
    if name.is_empty() || name.chars().count() > 60 {
        return Err(AppError::bad_request("Group name is required (up to 60 characters)"));
    }
    let order = match f.sort_order.trim() {
        "" => default_order,
        o => o.parse().map_err(|_| AppError::bad_request("Order must be a number"))?,
    };
    Ok((name.to_string(), order))
}

pub async fn create_group(State(st): State<AppState>, user: CurrentUser, Form(f): Form<GroupForm>) -> AppResult<Response> {
    user.check_csrf(&f.csrf)?;
    let (name, order) = validate_group(&f, store::groups::next_sort_order(st.db()).await?)?;
    store::groups::create(st.db(), &name, order).await?;
    Ok(Redirect::to("/admin/settings?notice=created#groups").into_response())
}

pub async fn update_group(State(st): State<AppState>, user: CurrentUser, Path(id): Path<i64>, Form(f): Form<GroupForm>) -> AppResult<Response> {
    user.check_csrf(&f.csrf)?;
    let (name, order) = validate_group(&f, 0)?;
    store::groups::update(st.db(), id, &name, order).await?;
    Ok(Redirect::to("/admin/settings?notice=saved#groups").into_response())
}

pub async fn delete_group(State(st): State<AppState>, user: CurrentUser, Path(id): Path<i64>, Form(f): Form<CsrfForm>) -> AppResult<Response> {
    user.check_csrf(&f.csrf)?;
    store::groups::delete(st.db(), id).await?;
    Ok(Redirect::to("/admin/settings?notice=deleted#groups").into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_types_are_detected_from_content() {
        assert_eq!(sniff_image(b"\x89PNG\r\n\x1a\nrest"), Some("image/png"));
        assert_eq!(sniff_image(&[0xFF, 0xD8, 0xFF, 0xE0]), Some("image/jpeg"));
        assert_eq!(sniff_image(b"RIFF\x00\x00\x00\x00WEBPVP8 "), Some("image/webp"));
        assert_eq!(sniff_image(b"  <svg xmlns='http://www.w3.org/2000/svg'/>"), Some("image/svg+xml"));
        assert_eq!(sniff_image(b"<?xml version='1.0'?><svg/>"), Some("image/svg+xml"));
        assert_eq!(sniff_image(b"<html><script>alert(1)</script>"), None);
        assert_eq!(sniff_image(b"<?xml version='1.0'?><html/>"), None);
        assert_eq!(sniff_image(b"MZ\x90\x00"), None, "executables are rejected");
    }

    #[test]
    fn site_name_is_trimmed_and_bounded() {
        assert_eq!(validate_site_name("  igorovh status ").unwrap(), "igorovh status");
        assert!(validate_site_name("   ").is_err());
        assert!(validate_site_name(&"x".repeat(41)).is_err());
    }
}
