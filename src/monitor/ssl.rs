use crate::util::DAY_MS;

pub fn days_left(expires_at: i64, now: i64) -> i64 {
    (expires_at - now).div_euclid(DAY_MS)
}

/// Alert steps: the configured window, then 7, 3 and 1 days before expiry.
pub fn thresholds(warn_days: i64) -> Vec<i64> {
    let mut t: Vec<i64> = [warn_days, 7, 3, 1].into_iter().filter(|d| *d >= 1 && *d <= warn_days).collect();
    t.sort_unstable_by(|a, b| b.cmp(a));
    t.dedup();
    t
}

/// Returns the threshold to alert for, if a new one was crossed since the last alert.
/// A renewed certificate (different expiry) starts the sequence again.
pub fn warning_due(
    warn_days: i64,
    expires_at: i64,
    now: i64,
    last_notified_days: Option<i64>,
    last_notified_expiry: Option<i64>,
) -> Option<i64> {
    if warn_days <= 0 {
        return None;
    }
    let left = days_left(expires_at, now);
    let crossed = thresholds(warn_days).into_iter().filter(|t| left < *t).min()?;
    let last = if last_notified_expiry == Some(expires_at) { last_notified_days } else { None };
    match last {
        Some(l) if l <= crossed => None,
        _ => Some(crossed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_800_000_000_000;

    fn exp(days: f64) -> i64 {
        NOW + (days * DAY_MS as f64) as i64
    }

    #[test]
    fn thresholds_are_bounded_by_window() {
        assert_eq!(thresholds(14), vec![14, 7, 3, 1]);
        assert_eq!(thresholds(5), vec![5, 3, 1]);
        assert_eq!(thresholds(7), vec![7, 3, 1]);
        assert!(thresholds(0).is_empty());
    }

    #[test]
    fn no_warning_outside_window_or_when_disabled() {
        assert_eq!(warning_due(14, exp(30.0), NOW, None, None), None);
        assert_eq!(warning_due(0, exp(1.0), NOW, None, None), None);
    }

    #[test]
    fn each_threshold_alerts_once() {
        let e = exp(13.5);
        assert_eq!(warning_due(14, e, NOW, None, None), Some(14));
        assert_eq!(warning_due(14, e, NOW, Some(14), Some(e)), None, "same step must not repeat");
        let later = NOW + 7 * DAY_MS;
        assert_eq!(warning_due(14, e, later, Some(14), Some(e)), Some(7));
        assert_eq!(warning_due(14, e, later + 4 * DAY_MS, Some(7), Some(e)), Some(3));
    }

    #[test]
    fn jumping_past_several_steps_alerts_for_the_most_urgent() {
        assert_eq!(warning_due(14, exp(2.5), NOW, None, None), Some(3));
        assert_eq!(warning_due(14, exp(0.5), NOW, Some(14), Some(exp(0.5))), Some(1));
    }

    #[test]
    fn renewed_certificate_resets_sequence() {
        let old = exp(1.5);
        let renewed = exp(13.0);
        assert_eq!(warning_due(14, renewed, NOW, Some(1), Some(old)), Some(14));
    }

    #[test]
    fn expired_certificate_still_warns() {
        assert_eq!(warning_due(14, exp(-2.0), NOW, Some(3), Some(exp(-2.0))), Some(1));
    }
}
