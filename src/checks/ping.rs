use std::net::IpAddr;
use std::time::{Duration, Instant};

use surge_ping::{Client, Config, ICMP, PingIdentifier, PingSequence};

use super::http::resolve;
use crate::models::{CheckOutcome, IpFamily, Timings};

pub async fn check(host: &str, family: IpFamily, timeout: Duration) -> CheckOutcome {
    let t = Instant::now();
    let ip = match resolve(host, 0, family).await {
        Ok(addrs) => addrs[0].ip(),
        Err(e) => return CheckOutcome::fail(format!("DNS: {e}")),
    };
    let dns_ms = t.elapsed().as_secs_f64() * 1000.0;
    let config = match ip {
        IpAddr::V4(_) => Config::default(),
        IpAddr::V6(_) => Config::builder().kind(ICMP::V6).build(),
    };
    let client = match Client::new(&config) {
        Ok(c) => c,
        Err(e) => return CheckOutcome::fail(format!("cannot open ICMP socket (needs CAP_NET_RAW or ping_group_range): {e}")),
    };
    let mut pinger = client.pinger(ip, PingIdentifier(rand::random())).await;
    pinger.timeout(timeout);
    let base = CheckOutcome { remote_ip: Some(ip.to_string()), ..Default::default() };
    match pinger.ping(PingSequence(0), &[0u8; 56]).await {
        Ok((_, rtt)) => {
            let rtt_ms = rtt.as_secs_f64() * 1000.0;
            CheckOutcome {
                ok: true,
                message: format!("reply from {ip} in {rtt_ms:.1} ms"),
                timings: Timings { dns_ms: Some(dns_ms), total_ms: Some(rtt_ms), ..Default::default() },
                ..base
            }
        }
        Err(e) => CheckOutcome { ok: false, message: format!("ping {ip}: {e}"), ..base },
    }
}
