use std::collections::HashMap;
use std::time::Duration;

use anpi::checks::http::{RequestSpec, send};
use anpi::config::Config;
use http::Method;

fn self_signed(dir: &std::path::Path) -> (String, String) {
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".into(), "127.0.0.1".into()]).unwrap().self_signed(&key).unwrap();
    let (cert_path, key_path) = (dir.join("cert.pem"), dir.join("key.pem"));
    std::fs::write(&cert_path, cert.pem()).unwrap();
    std::fs::write(&key_path, key.serialize_pem()).unwrap();
    (cert_path.display().to_string(), key_path.display().to_string())
}

fn config(dir: &std::path::Path, port: u16, cert: &str, key: &str) -> Config {
    let env: HashMap<String, String> = [
        ("ANPI_BIND", format!("127.0.0.1:{port}")),
        ("ANPI_DATABASE", dir.join("anpi.db").display().to_string()),
        ("ANPI_TLS_CERT", cert.to_string()),
        ("ANPI_TLS_KEY", key.to_string()),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v))
    .collect();
    Config::from_map(&env).unwrap()
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

async fn get(url: &str) -> Result<anpi::checks::http::Response, String> {
    let mut spec = RequestSpec::new(Method::GET, url::Url::parse(url).unwrap());
    spec.ignore_tls = true;
    spec.timeout = Duration::from_secs(3);
    send(&spec).await.map_err(|e| e.to_string())
}

#[tokio::test]
async fn serves_https_with_its_own_certificate() {
    let dir = tempfile::tempdir().unwrap();
    let (cert, key) = self_signed(dir.path());
    let port = free_port();
    let server = tokio::spawn(anpi::run(config(dir.path(), port, &cert, &key)));

    let mut healthy = None;
    for _ in 0..50 {
        if let Ok(r) = get(&format!("https://127.0.0.1:{port}/healthz")).await {
            healthy = Some(r);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let r = healthy.expect("the HTTPS server answers");
    assert_eq!((r.status, r.text().as_str()), (200, "ok"));
    assert!(r.cert_expires_at.is_some(), "the configured certificate is presented");

    let page = get(&format!("https://127.0.0.1:{port}/")).await.unwrap();
    assert_eq!(page.status, 200);
    assert!(page.text().contains("powered by"));
    assert!(!get(&format!("http://127.0.0.1:{port}/healthz")).await.is_ok_and(|r| r.status == 200), "plain HTTP is not served");
    server.abort();
}

#[tokio::test]
async fn refuses_to_start_with_a_broken_certificate() {
    let dir = tempfile::tempdir().unwrap();
    let (cert, _) = self_signed(dir.path());
    let other = tempfile::tempdir().unwrap();
    let (_, wrong_key) = self_signed(other.path());
    let err = anpi::run(config(dir.path(), free_port(), &cert, &wrong_key)).await.unwrap_err();
    assert!(format!("{err:#}").contains("do not match"), "{err:#}");

    let missing = dir.path().join("missing.pem").display().to_string();
    let err = anpi::run(config(dir.path(), free_port(), &missing, &wrong_key)).await.unwrap_err();
    assert!(format!("{err:#}").contains("reading certificate"), "{err:#}");
}
