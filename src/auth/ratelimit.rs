use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub struct LoginLimiter {
    max_attempts: u32,
    window: Duration,
    max_entries: usize,
    entries: Mutex<HashMap<IpAddr, (u32, Instant)>>,
}

impl LoginLimiter {
    pub fn new(max_attempts: u32, window: Duration) -> Self {
        Self::with_capacity(max_attempts, window, 50_000)
    }

    pub fn with_capacity(max_attempts: u32, window: Duration, max_entries: usize) -> Self {
        Self { max_attempts, window, max_entries: max_entries.max(1), entries: Mutex::new(HashMap::new()) }
    }

    pub fn tracked(&self) -> usize {
        self.entries.lock().expect("limiter lock").len()
    }

    pub fn is_blocked(&self, ip: IpAddr, now: Instant) -> bool {
        let entries = self.entries.lock().expect("limiter lock");
        matches!(entries.get(&ip), Some((n, start)) if *n >= self.max_attempts && now.duration_since(*start) < self.window)
    }

    pub fn record_failure(&self, ip: IpAddr, now: Instant) {
        let mut entries = self.entries.lock().expect("limiter lock");
        if !entries.contains_key(&ip) && entries.len() >= self.max_entries {
            entries.retain(|_, (_, start)| now.duration_since(*start) < self.window);
            // Still full: forget the oldest window so memory stays bounded.
            if entries.len() >= self.max_entries
                && let Some(oldest) = entries.iter().min_by_key(|(_, (_, start))| *start).map(|(k, _)| *k)
            {
                entries.remove(&oldest);
            }
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
    fn memory_stays_bounded_and_recent_blocks_survive() {
        let l = LoginLimiter::with_capacity(1, Duration::from_secs(60), 100);
        let t0 = Instant::now();
        let target: IpAddr = "203.0.113.200".parse().unwrap();
        for i in 0..1_000u32 {
            let ip = IpAddr::V6(std::net::Ipv6Addr::from(u128::from(i)));
            l.record_failure(ip, t0);
        }
        assert!(l.tracked() <= 100, "tracked {}", l.tracked());
        l.record_failure(target, t0 + Duration::from_secs(1));
        assert!(l.is_blocked(target, t0 + Duration::from_secs(1)), "the newest offender is kept");
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
