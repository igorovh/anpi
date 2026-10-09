//! Built-in HTTPS for running without a reverse proxy, e.g. behind Cloudflare with an origin certificate.

use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, ensure};
use rustls::ServerConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

pub fn load(cert: &Path, key: &Path) -> anyhow::Result<TlsAcceptor> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert)
        .with_context(|| format!("reading certificate {}", cert.display()))?
        .collect::<Result<_, _>>()
        .with_context(|| format!("parsing certificate {}", cert.display()))?;
    ensure!(!certs.is_empty(), "{} contains no certificate", cert.display());
    let key = PrivateKeyDer::from_pem_file(key).with_context(|| format!("reading private key {}", key.display()))?;
    let mut config = ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("the certificate and private key do not match")?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// Accepts TCP connections and hands out finished TLS sessions; handshakes run in their own tasks.
pub struct TlsListener {
    rx: mpsc::Receiver<(TlsStream<TcpStream>, SocketAddr)>,
    local: SocketAddr,
}

impl TlsListener {
    pub fn new(tcp: TcpListener, acceptor: TlsAcceptor) -> io::Result<Self> {
        let local = tcp.local_addr()?;
        let (tx, rx) = mpsc::channel(64);
        tokio::spawn(async move {
            while !tx.is_closed() {
                let (socket, addr) = match tcp.accept().await {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::debug!(error = %e, "accept failed");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                };
                let (acceptor, tx) = (acceptor.clone(), tx.clone());
                tokio::spawn(async move {
                    match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(socket)).await {
                        Ok(Ok(stream)) => {
                            let _ = tx.send((stream, addr)).await;
                        }
                        Ok(Err(e)) => tracing::debug!(%addr, error = %e, "TLS handshake failed"),
                        Err(_) => tracing::debug!(%addr, "TLS handshake timed out"),
                    }
                });
            }
        });
        Ok(Self { rx, local })
    }
}

impl axum::serve::Listener for TlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.rx.recv().await {
            Some(conn) => conn,
            None => std::future::pending().await,
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        Ok(self.local)
    }
}
