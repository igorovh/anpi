use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};

pub const HOUR_MS: i64 = 3_600_000;
pub const DAY_MS: i64 = 24 * HOUR_MS;

pub fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

pub fn floor_hour(ms: i64) -> i64 {
    ms.div_euclid(HOUR_MS) * HOUR_MS
}

pub fn floor_day(ms: i64) -> i64 {
    ms.div_euclid(DAY_MS) * DAY_MS
}

pub fn random_token(bytes: usize) -> String {
    let buf: Vec<u8> = (0..bytes).map(|_| rand::random::<u8>()).collect();
    URL_SAFE_NO_PAD.encode(buf)
}

pub fn sha256_hex(input: &str) -> String {
    hex::encode(Sha256::digest(input.as_bytes()))
}

pub fn sha256_b64url(input: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(input.as_bytes()))
}

pub fn format_ts(ms: i64) -> String {
    let Ok(dt) = time::OffsetDateTime::from_unix_timestamp_nanos(ms as i128 * 1_000_000) else {
        return String::new();
    };
    let fmt = time::macros::format_description!("[year]-[month]-[day] [hour]:[minute]:[second] UTC");
    dt.format(&fmt).unwrap_or_default()
}

pub fn format_ts_short(ms: i64) -> String {
    let Ok(dt) = time::OffsetDateTime::from_unix_timestamp_nanos(ms as i128 * 1_000_000) else {
        return String::new();
    };
    let fmt = time::macros::format_description!("[month]-[day] [hour]:[minute]");
    dt.format(&fmt).unwrap_or_default()
}

pub fn format_duration_ms(ms: i64) -> String {
    let s = ms.max(0) / 1000;
    match s {
        0..60 => format!("{s}s"),
        60..3600 => format!("{}m {}s", s / 60, s % 60),
        3600..86400 => format!("{}h {}m", s / 3600, (s % 3600) / 60),
        _ => format!("{}d {}h", s / 86400, (s % 86400) / 3600),
    }
}

pub fn format_ms(v: Option<f64>) -> String {
    match v {
        Some(v) if v >= 1000.0 => format!("{:.2} s", v / 1000.0),
        Some(v) => format!("{v:.0} ms"),
        None => "–".into(),
    }
}

pub fn format_pct(v: Option<f64>) -> String {
    match v {
        Some(v) if v >= 100.0 => "100%".into(),
        Some(v) => format!("{:.2}%", (v * 100.0).floor() / 100.0),
        None => "–".into(),
    }
}

/// Parses an `<input type="datetime-local">` value shifted by the browser's UTC offset in minutes.
pub fn parse_local_datetime(value: &str, tz_offset_min: i64) -> Option<i64> {
    let fmt = time::macros::format_description!("[year]-[month]-[day]T[hour]:[minute]");
    let dt = time::PrimitiveDateTime::parse(value.get(..16)?, &fmt).ok()?;
    let utc = dt.assume_utc().unix_timestamp() * 1000;
    Some(utc + tz_offset_min * 60_000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hour_and_day_flooring() {
        assert_eq!(floor_hour(HOUR_MS * 5 + 1234), HOUR_MS * 5);
        assert_eq!(floor_hour(HOUR_MS * 5), HOUR_MS * 5);
        assert_eq!(floor_day(DAY_MS * 3 + HOUR_MS * 7), DAY_MS * 3);
    }

    #[test]
    fn tokens_are_random_and_url_safe() {
        let a = random_token(32);
        let b = random_token(32);
        assert_ne!(a, b);
        assert_eq!(a.len(), 43);
        assert!(a.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn pkce_challenge_matches_rfc7636_example() {
        assert_eq!(
            sha256_b64url("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn percentages_never_round_up_to_100() {
        assert_eq!(format_pct(Some(99.999)), "99.99%");
        assert_eq!(format_pct(Some(100.0)), "100%");
        assert_eq!(format_pct(None), "–");
    }

    #[test]
    fn local_datetime_respects_browser_offset() {
        // Browser in UTC+2 reports getTimezoneOffset() = -120.
        let ms = parse_local_datetime("2026-01-01T12:00", -120).unwrap();
        assert_eq!(format_ts(ms), "2026-01-01 10:00:00 UTC");
        assert!(parse_local_datetime("garbage", 0).is_none());
    }

    #[test]
    fn durations_are_human_readable() {
        assert_eq!(format_duration_ms(5_000), "5s");
        assert_eq!(format_duration_ms(125_000), "2m 5s");
        assert_eq!(format_duration_ms(2 * HOUR_MS + 60_000), "2h 1m");
        assert_eq!(format_duration_ms(DAY_MS + HOUR_MS), "1d 1h");
    }
}
