use std::time::{Duration, Instant};

use super::http::{connect_any, resolve};
use crate::models::{CheckOutcome, IpFamily, Timings};

pub async fn check(host: &str, port: u16, family: IpFamily, timeout: Duration) -> CheckOutcome {
    let started = Instant::now();
    let deadline = started + timeout;
    let fut = async {
        let mut timings = Timings::default();
        let t = Instant::now();
        let addrs = resolve(host, port, family).await.map_err(|e| (format!("DNS: {e}"), timings.clone()))?;
        timings.dns_ms = Some(t.elapsed().as_secs_f64() * 1000.0);
        let t = Instant::now();
        let mut notes = Vec::new();
        let (_stream, addr) = connect_any(&addrs, deadline, &mut notes).await.map_err(|e| (format!("connect: {e}"), timings.clone()))?;
        timings.connect_ms = Some(t.elapsed().as_secs_f64() * 1000.0);
        Ok::<_, (String, Timings)>((addr, timings, notes))
    };
    let total = || Some(started.elapsed().as_secs_f64() * 1000.0);
    match tokio::time::timeout(timeout, fut).await {
        Ok(Ok((addr, mut timings, notes))) => {
            timings.total_ms = total();
            let mut message = format!("port {port} open");
            if !notes.is_empty() {
                message = format!("{message} ({})", notes.join("; "));
            }
            CheckOutcome { ok: true, message, timings, remote_ip: Some(addr.ip().to_string()), ..Default::default() }
        }
        Ok(Err((message, mut timings))) => {
            timings.total_ms = total();
            CheckOutcome { ok: false, message, timings, ..Default::default() }
        }
        Err(_) => CheckOutcome {
            ok: false,
            message: format!("timed out after {:.1}s", timeout.as_secs_f64()),
            timings: Timings { total_ms: total(), ..Default::default() },
            ..Default::default()
        },
    }
}
