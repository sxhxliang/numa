use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::extract::{Request, State};
use axum::response::IntoResponse;
use axum::routing::any;
use axum::Router;
use hyper::StatusCode;
use log::{debug, error, info, warn};
use tokio_rustls::TlsAcceptor;

use crate::ctx::ServerCtx;
use crate::mitm::MitmStores;

/// Per-connection state shared with the axum handler.
#[derive(Clone)]
struct MitmProxyState {
    ctx: Arc<ServerCtx>,
    mitm: Arc<MitmStores>,
    client_ip: IpAddr,
    scheme: &'static str, // "https" or "http"
}

/// Start the HTTPS MitM listener. Binds `bind_addr:port`, performs TLS
/// termination using `mitm.cert_resolver` (per-SNI dynamic certs), parses
/// the inner HTTP request, and dispatches to the forwarder.
pub async fn start_mitm_https(ctx: Arc<ServerCtx>, mitm: Arc<MitmStores>) {
    let addr = match parse_bind_addr(&mitm.config.bind_addr, mitm.config.https_port) {
        Ok(a) => a,
        Err(e) => {
            warn!(
                "MitM HTTPS: bad bind_addr '{}:{}' — {}",
                mitm.config.bind_addr, mitm.config.https_port, e
            );
            return;
        }
    };

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            warn!(
                "MitM HTTPS: could not bind {} ({}) — MitM HTTPS disabled",
                addr, e
            );
            return;
        }
    };
    info!("MitM HTTPS listening on {}", addr);

    let server_config = crate::tls::build_mitm_tls_config(mitm.cert_resolver.clone());

    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                error!("MitM accept error: {}", e);
                continue;
            }
        };

        let acceptor = TlsAcceptor::from(server_config.clone());
        let ctx2 = Arc::clone(&ctx);
        let mitm2 = Arc::clone(&mitm);

        tokio::spawn(async move {
            let tls_stream = match acceptor.accept(tcp).await {
                Ok(s) => s,
                Err(e) => {
                    debug!("MitM TLS handshake failed from {}: {}", peer, e);
                    return;
                }
            };

            let state = MitmProxyState {
                ctx: ctx2,
                mitm: mitm2,
                client_ip: peer.ip(),
                scheme: "https",
            };

            let app = Router::new()
                .fallback(any(handle_request))
                .with_state(state);

            let io = hyper_util::rt::TokioIo::new(tls_stream);
            let svc = hyper_util::service::TowerToHyperService::new(app.into_service());
            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .preserve_header_case(true)
                .serve_connection(io, svc)
                .await
            {
                debug!("MitM connection error from {}: {}", peer, e);
            }
        });
    }
}

/// Start the plain HTTP MitM listener. Same routing as HTTPS but without
/// TLS termination — Host header drives the upstream lookup.
pub async fn start_mitm_http(ctx: Arc<ServerCtx>, mitm: Arc<MitmStores>) {
    let addr = match parse_bind_addr(&mitm.config.bind_addr, mitm.config.http_port) {
        Ok(a) => a,
        Err(e) => {
            warn!(
                "MitM HTTP: bad bind_addr '{}:{}' — {}",
                mitm.config.bind_addr, mitm.config.http_port, e
            );
            return;
        }
    };

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            warn!(
                "MitM HTTP: could not bind {} ({}) — MitM HTTP disabled",
                addr, e
            );
            return;
        }
    };
    info!("MitM HTTP listening on {}", addr);

    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                error!("MitM HTTP accept error: {}", e);
                continue;
            }
        };

        let ctx2 = Arc::clone(&ctx);
        let mitm2 = Arc::clone(&mitm);

        tokio::spawn(async move {
            let state = MitmProxyState {
                ctx: ctx2,
                mitm: mitm2,
                client_ip: peer.ip(),
                scheme: "http",
            };

            let app = Router::new()
                .fallback(any(handle_request))
                .with_state(state);

            let io = hyper_util::rt::TokioIo::new(tcp);
            let svc = hyper_util::service::TowerToHyperService::new(app.into_service());
            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .preserve_header_case(true)
                .serve_connection(io, svc)
                .await
            {
                debug!("MitM HTTP connection error from {}: {}", peer, e);
            }
        });
    }
}

fn parse_bind_addr(bind: &str, port: u16) -> Result<SocketAddr, String> {
    let ip: IpAddr = bind
        .parse()
        .map_err(|e: std::net::AddrParseError| e.to_string())?;
    Ok(SocketAddr::new(ip, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_bind_addr_accepts_ipv4() {
        let a = parse_bind_addr("127.0.0.1", 8443).unwrap();
        assert_eq!(a.to_string(), "127.0.0.1:8443");
    }

    #[test]
    fn parse_bind_addr_rejects_garbage() {
        assert!(parse_bind_addr("not-an-ip", 8443).is_err());
    }

    /// End-to-end: spin up the MitM HTTPS listener on an ephemeral port,
    /// connect with a rustls client that trusts the numa CA, send a real
    /// HTTP/1.1 request. With no `upstream_cache` entry the forwarder
    /// returns 502, and the failure is recorded as a CaptureEntry with
    /// the error string set — proving the TLS path, the rule gate, the
    /// listener, and the failure-capture path all wire up correctly.
    #[tokio::test]
    async fn mitm_https_listener_serves_intercepted_request() {
        use rustls::pki_types::ServerName;
        use std::sync::Arc;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let dir = std::env::temp_dir().join(format!(
            "numa-test-mitm-e2e-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        let config = crate::config::MitmConfig {
            enabled: true,
            https_port: 0,
            ..Default::default()
        };
        let mitm = Arc::new(crate::mitm::MitmStores::new(config, &dir).unwrap());
        mitm.rules
            .write()
            .unwrap()
            .insert("api.example.com", true);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_cfg = crate::tls::build_mitm_tls_config(mitm.cert_resolver.clone());

        let ctx = Arc::new(crate::testutil::test_ctx().await);

        let mitm_for_server = Arc::clone(&mitm);
        let ctx_for_server = Arc::clone(&ctx);
        tokio::spawn(async move {
            let (tcp, peer) = listener.accept().await.unwrap();
            let acceptor = TlsAcceptor::from(server_cfg);
            let tls_stream = acceptor.accept(tcp).await.unwrap();
            let state = MitmProxyState {
                ctx: ctx_for_server,
                mitm: mitm_for_server,
                client_ip: peer.ip(),
                scheme: "https",
            };
            let app = Router::new()
                .fallback(any(handle_request))
                .with_state(state);
            let io = hyper_util::rt::TokioIo::new(tls_stream);
            let svc = hyper_util::service::TowerToHyperService::new(app.into_service());
            let _ = hyper::server::conn::http1::Builder::new()
                .preserve_header_case(true)
                .serve_connection(io, svc)
                .await;
        });

        let ca_pem = std::fs::read_to_string(dir.join("ca.pem")).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut ca_pem.as_bytes()) {
            roots.add(cert.unwrap()).unwrap();
        }
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client_cfg = Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let connector = tokio_rustls::TlsConnector::from(client_cfg);

        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let sni = ServerName::try_from("api.example.com").unwrap();
        let mut tls = connector.connect(sni, tcp).await.expect("TLS handshake");

        tls.write_all(b"GET /foo HTTP/1.1\r\nHost: api.example.com\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        tls.flush().await.unwrap();

        let mut resp = Vec::new();
        tls.read_to_end(&mut resp).await.unwrap();
        let resp_str = String::from_utf8_lossy(&resp);
        assert!(
            resp_str.starts_with("HTTP/1.1 502 "),
            "expected 502 Bad Gateway (cache miss), got: {}",
            &resp_str[..resp_str.len().min(200)]
        );

        // Failure must be captured with an error string so the dashboard
        // can show "couldn't reach upstream" rather than silently swallowing.
        let captures = mitm.captures.lock().unwrap();
        assert_eq!(captures.len(), 1, "exactly one capture expected");
        let only = captures.list(&crate::mitm::capture::CaptureFilter {
            domain: None,
            since_id: None,
            limit: Some(1),
        });
        let entry = only[0];
        assert_eq!(entry.status, 502);
        assert!(
            entry.error.as_ref().is_some_and(|e| e.contains("upstream IP not cached")),
            "expected cache-miss error, got: {:?}",
            entry.error
        );

        assert_eq!(
            mitm.rules.read().unwrap().get("api.example.com").unwrap().hits,
            1,
            "rule.hits must be incremented even on upstream failure"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A connection whose Host header isn't on the rule list must be
    /// refused with 403 Forbidden. Defense-in-depth against direct
    /// connections that bypass DNS hijacking.
    #[tokio::test]
    async fn mitm_https_listener_rejects_non_whitelisted_host() {
        use rustls::pki_types::ServerName;
        use std::sync::Arc;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let dir = std::env::temp_dir().join(format!(
            "numa-test-mitm-rej-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let config = crate::config::MitmConfig {
            enabled: true,
            ..Default::default()
        };
        let mitm = Arc::new(crate::mitm::MitmStores::new(config, &dir).unwrap());
        // No rule for the host we're about to request — expect 403.

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_cfg = crate::tls::build_mitm_tls_config(mitm.cert_resolver.clone());

        let ctx = Arc::new(crate::testutil::test_ctx().await);
        let mitm_for_server = Arc::clone(&mitm);
        let ctx_for_server = Arc::clone(&ctx);
        tokio::spawn(async move {
            let (tcp, peer) = listener.accept().await.unwrap();
            let acceptor = TlsAcceptor::from(server_cfg);
            let tls_stream = acceptor.accept(tcp).await.unwrap();
            let state = MitmProxyState {
                ctx: ctx_for_server,
                mitm: mitm_for_server,
                client_ip: peer.ip(),
                scheme: "https",
            };
            let app = Router::new()
                .fallback(any(handle_request))
                .with_state(state);
            let io = hyper_util::rt::TokioIo::new(tls_stream);
            let svc = hyper_util::service::TowerToHyperService::new(app.into_service());
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, svc)
                .await;
        });

        let ca_pem = std::fs::read_to_string(dir.join("ca.pem")).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut ca_pem.as_bytes()) {
            roots.add(cert.unwrap()).unwrap();
        }
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client_cfg = Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let connector = tokio_rustls::TlsConnector::from(client_cfg);
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let sni = ServerName::try_from("api.example.com").unwrap();
        let mut tls = connector.connect(sni, tcp).await.unwrap();
        tls.write_all(b"GET / HTTP/1.1\r\nHost: api.example.com\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        tls.flush().await.unwrap();

        let mut resp = Vec::new();
        tls.read_to_end(&mut resp).await.unwrap();
        let s = String::from_utf8_lossy(&resp);
        assert!(
            s.starts_with("HTTP/1.1 403 "),
            "expected 403 for non-whitelisted host, got: {}",
            &s[..s.len().min(200)]
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// HTTP listener (no TLS) — Host-based routing must work the same as
    /// HTTPS: rule gate, forwarder call, capture record. Cache-miss → 502.
    #[tokio::test]
    async fn mitm_http_listener_serves_intercepted_request() {
        use std::sync::Arc;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let dir = std::env::temp_dir().join(format!(
            "numa-test-mitm-http-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let config = crate::config::MitmConfig {
            enabled: true,
            ..Default::default()
        };
        let mitm = Arc::new(crate::mitm::MitmStores::new(config, &dir).unwrap());
        mitm.rules.write().unwrap().insert("api.example.com", true);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let ctx = Arc::new(crate::testutil::test_ctx().await);
        let mitm_for_server = Arc::clone(&mitm);
        let ctx_for_server = Arc::clone(&ctx);

        tokio::spawn(async move {
            let (tcp, peer) = listener.accept().await.unwrap();
            let state = MitmProxyState {
                ctx: ctx_for_server,
                mitm: mitm_for_server,
                client_ip: peer.ip(),
                scheme: "http",
            };
            let app = Router::new()
                .fallback(any(handle_request))
                .with_state(state);
            let io = hyper_util::rt::TokioIo::new(tcp);
            let svc = hyper_util::service::TowerToHyperService::new(app.into_service());
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, svc)
                .await;
        });

        let mut tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        tcp.write_all(b"GET /foo HTTP/1.1\r\nHost: api.example.com\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        tcp.flush().await.unwrap();

        let mut resp = Vec::new();
        tcp.read_to_end(&mut resp).await.unwrap();
        let s = String::from_utf8_lossy(&resp);
        assert!(
            s.starts_with("HTTP/1.1 502 "),
            "expected 502 (cache miss), got: {}",
            &s[..s.len().min(200)]
        );

        let captures = mitm.captures.lock().unwrap();
        let only = captures.list(&crate::mitm::capture::CaptureFilter {
            domain: None,
            since_id: None,
            limit: Some(1),
        });
        assert_eq!(only.len(), 1);
        assert_eq!(only[0].scheme, "http");
        assert_eq!(only[0].host, "api.example.com");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// HTTP listener must reject non-whitelisted Host headers with 403,
    /// same as the HTTPS listener.
    #[tokio::test]
    async fn mitm_http_listener_rejects_non_whitelisted_host() {
        use std::sync::Arc;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let dir = std::env::temp_dir().join(format!(
            "numa-test-mitm-http-rej-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let config = crate::config::MitmConfig {
            enabled: true,
            ..Default::default()
        };
        let mitm = Arc::new(crate::mitm::MitmStores::new(config, &dir).unwrap());
        // No rule for the Host — must 403.

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let ctx = Arc::new(crate::testutil::test_ctx().await);
        let mitm_for_server = Arc::clone(&mitm);
        let ctx_for_server = Arc::clone(&ctx);
        tokio::spawn(async move {
            let (tcp, peer) = listener.accept().await.unwrap();
            let state = MitmProxyState {
                ctx: ctx_for_server,
                mitm: mitm_for_server,
                client_ip: peer.ip(),
                scheme: "http",
            };
            let app = Router::new()
                .fallback(any(handle_request))
                .with_state(state);
            let io = hyper_util::rt::TokioIo::new(tcp);
            let svc = hyper_util::service::TowerToHyperService::new(app.into_service());
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, svc)
                .await;
        });

        let mut tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        tcp.write_all(b"GET / HTTP/1.1\r\nHost: api.example.com\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        tcp.flush().await.unwrap();
        let mut resp = Vec::new();
        tcp.read_to_end(&mut resp).await.unwrap();
        let s = String::from_utf8_lossy(&resp);
        assert!(
            s.starts_with("HTTP/1.1 403 "),
            "expected 403 for non-whitelisted Host, got: {}",
            &s[..s.len().min(200)]
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}

async fn handle_request(
    State(state): State<MitmProxyState>,
    req: Request,
) -> axum::response::Response {
    // Extract host (drop port suffix) from Host header.
    let host = req
        .headers()
        .get(hyper::header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(|h| h.split(':').next().unwrap_or(h).to_lowercase());
    let Some(host) = host else {
        return (StatusCode::BAD_REQUEST, "missing Host header").into_response();
    };

    // Gate by rule list: if the Host isn't whitelisted, refuse. This is
    // the defense-in-depth check — DNS hijack should mean only listed
    // hosts arrive here, but a direct connection to the proxy port
    // bypasses DNS.
    if !state.mitm.rules.read().unwrap().is_listed(&host) {
        return (StatusCode::FORBIDDEN, "host not on MitM rule list").into_response();
    }
    state.mitm.rules.write().unwrap().record_hit(&host);

    crate::mitm::forwarder::forward(state.scheme, state.client_ip, &state.ctx, &state.mitm, host, req)
        .await
}
