use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::time::{Duration, Instant};

use hickory_resolver::TokioResolver;
use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::RecordType;

use crate::models::{CheckOutcome, Timings};

pub const RECORD_TYPES: [&str; 8] = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA"];

pub fn parse_server(s: &str) -> Result<Option<SocketAddr>, String> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(None);
    }
    if let Ok(addr) = SocketAddr::from_str(s) {
        return Ok(Some(addr));
    }
    IpAddr::from_str(s.trim_start_matches('[').trim_end_matches(']'))
        .map(|ip| Some(SocketAddr::new(ip, 53)))
        .map_err(|_| format!("DNS server {s:?} must be an IP address, optionally with :port"))
}

fn build_resolver(server: Option<SocketAddr>, timeout: Duration) -> Result<TokioResolver, String> {
    let mut builder = match server {
        None => TokioResolver::builder_tokio().map_err(|e| format!("reading system DNS config: {e}"))?,
        Some(addr) => {
            let mut udp = ConnectionConfig::udp();
            udp.port = addr.port();
            let mut tcp = ConnectionConfig::tcp();
            tcp.port = addr.port();
            let ns = NameServerConfig::new(addr.ip(), true, vec![udp, tcp]);
            TokioResolver::builder_with_config(ResolverConfig::from_name_servers(vec![ns]), TokioRuntimeProvider::default())
        }
    };
    let opts = builder.options_mut();
    opts.timeout = timeout;
    opts.attempts = 1;
    opts.cache_size = 0;
    builder.build().map_err(|e| e.to_string())
}

pub async fn check(name: &str, record_type: &str, server: &str, expected: &str, timeout: Duration) -> CheckOutcome {
    let rtype = match RecordType::from_str(&record_type.to_ascii_uppercase()) {
        Ok(t) => t,
        Err(_) => return CheckOutcome::fail(format!("unsupported record type {record_type}")),
    };
    let server = match parse_server(server) {
        Ok(s) => s,
        Err(e) => return CheckOutcome::fail(e),
    };
    let resolver = match build_resolver(server, timeout) {
        Ok(r) => r,
        Err(e) => return CheckOutcome::fail(e),
    };
    let t = Instant::now();
    let result = tokio::time::timeout(timeout, resolver.lookup(name, rtype)).await;
    let elapsed = t.elapsed().as_secs_f64() * 1000.0;
    let timings = Timings { dns_ms: Some(elapsed), total_ms: Some(elapsed), ..Default::default() };
    let lookup = match result {
        Err(_) => return CheckOutcome { message: format!("timed out after {:.1}s", timeout.as_secs_f64()), timings, ..Default::default() },
        Ok(Err(e)) => return CheckOutcome { message: format!("{rtype} {name}: {e}"), timings, ..Default::default() },
        Ok(Ok(l)) => l,
    };
    let records: Vec<String> =
        lookup.answers().iter().filter(|r| r.record_type() == rtype).map(|r| r.data.to_string()).collect();
    evaluate(&records, rtype, name, expected, timings)
}

fn evaluate(records: &[String], rtype: RecordType, name: &str, expected: &str, timings: Timings) -> CheckOutcome {
    if records.is_empty() {
        return CheckOutcome { message: format!("no {rtype} records for {name}"), timings, ..Default::default() };
    }
    let joined = records.join(", ");
    let expected = expected.trim();
    if !expected.is_empty() && !records.iter().any(|r| r.trim_end_matches('.').contains(expected.trim_end_matches('.'))) {
        return CheckOutcome { message: format!("{rtype}: {joined} (expected {expected})"), timings, ..Default::default() };
    }
    CheckOutcome { ok: true, message: format!("{rtype}: {joined}"), timings, ..Default::default() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_parsing() {
        assert_eq!(parse_server("").unwrap(), None);
        assert_eq!(parse_server("1.1.1.1").unwrap(), Some("1.1.1.1:53".parse().unwrap()));
        assert_eq!(parse_server("9.9.9.9:5353").unwrap(), Some("9.9.9.9:5353".parse().unwrap()));
        assert_eq!(parse_server("2606:4700::1111").unwrap(), Some("[2606:4700::1111]:53".parse().unwrap()));
        assert_eq!(parse_server("[::1]:5300").unwrap(), Some("[::1]:5300".parse().unwrap()));
        assert!(parse_server("dns.google").is_err());
    }

    #[test]
    fn expected_value_must_appear_in_some_record() {
        let recs = vec!["93.184.215.14".to_string(), "93.184.215.15".to_string()];
        assert!(evaluate(&recs, RecordType::A, "x", "", Timings::default()).ok);
        assert!(evaluate(&recs, RecordType::A, "x", "93.184.215.15", Timings::default()).ok);
        let bad = evaluate(&recs, RecordType::A, "x", "10.0.0.1", Timings::default());
        assert!(!bad.ok && bad.message.contains("expected 10.0.0.1"));
        assert!(!evaluate(&[], RecordType::A, "x", "", Timings::default()).ok);
        let cname = vec!["target.example.com.".to_string()];
        assert!(evaluate(&cname, RecordType::CNAME, "x", "target.example.com", Timings::default()).ok);
    }
}
