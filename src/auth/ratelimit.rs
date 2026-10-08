use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub struct LoginLimiter {
    max_attempts: u32,
    window: Duration,
    entries: Mutex<HashMap<IpAddr, (u32, Instant)>>,
}

impl LoginLimiter {
    pub fn new(max_attempts: u32, window: Duration) -> Self {
        Self { max_attempts, window, entries: Mutex::new(HashMap::new()) }
    }

    pub fn is_blocked(&self, ip: IpAddr, now: Instant) -> bool {
        let entries = self.entries.lock().expect("limiter lock");
        matches!(entries.get(&ip), Some((n, start)) if *n >= self.max_attempts && now.duration_since(*start) < self.window)
    }

    pub fn record_failure(&self, ip: IpAddr, now: Instant) {
        let mut entries = self.entries.lock().expect("limiter lock");
        if entries.len() > 10_000 {
            entries.retain(|_, (_, start)| now.duration_since(*start) < self.window);
        }
        let e = entries.entry(ip).or_insert((0, now));
        if now.duration_since(e.1) >= self.window {
            *e = (0, now);
        }
        e.0 += 1;
    }

    pub fn reset(&self, ip: IpAddr) {
        self.entries.lock().expect("limiter lock").remove(&ip);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_after_max_failures_until_window_passes() {
        let l = LoginLimiter::new(3, Duration::from_secs(60));
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        let other: IpAddr = "203.0.113.8".parse().unwrap();
        let t0 = Instant::now();
        for _ in 0..3 {
            assert!(!l.is_blocked(ip, t0));
            l.record_failure(ip, t0);
        }
        assert!(l.is_blocked(ip, t0));
        assert!(!l.is_blocked(other, t0), "limits are per IP");
        assert!(!l.is_blocked(ip, t0 + Duration::from_secs(61)));
        l.record_failure(ip, t0 + Duration::from_secs(61));
        assert!(!l.is_blocked(ip, t0 + Duration::from_secs(61)), "counter restarts after the window");
    }

    #[test]
    fn successful_login_resets_counter() {
        let l = LoginLimiter::new(2, Duration::from_secs(60));
        let ip: IpAddr = "::1".parse().unwrap();
        let t0 = Instant::now();
        l.record_failure(ip, t0);
        l.reset(ip);
        l.record_failure(ip, t0);
        assert!(!l.is_blocked(ip, t0));
    }
}
