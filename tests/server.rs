//! The real server loop: shutdown must not hang on open live-update streams.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn shutdown_does_not_wait_for_live_updates() {
    let dir = tempfile::tempdir().unwrap();
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let env: HashMap<String, String> = [("ANPI_BIND", format!("127.0.0.1:{port}")), ("ANPI_DATABASE", dir.path().join("anpi.db").display().to_string())]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(anpi::run_until(anpi::config::Config::from_map(&env).unwrap(), async {
        let _ = stop_rx.await;
    }));

    let mut stream = None;
    for _ in 0..50 {
        if let Ok(s) = tokio::net::TcpStream::connect(("127.0.0.1", port)).await {
            stream = Some(s);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let mut stream = stream.expect("server is listening");
    stream.write_all(b"GET /events/public HTTP/1.1\r\nHost: localhost\r\n\r\n").await.unwrap();
    let mut head = vec![0u8; 512];
    let n = stream.read(&mut head).await.unwrap();
    assert!(String::from_utf8_lossy(&head[..n]).contains("text/event-stream"), "the live stream is open");

    let started = Instant::now();
    stop_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(4), server).await.expect("stops without waiting for the stream").unwrap().unwrap();
    assert!(started.elapsed() < Duration::from_secs(3), "took {:?}", started.elapsed());

    let mut rest = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(1), stream.read_to_end(&mut rest)).await;
}
