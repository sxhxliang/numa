//! MitM upstream forwarder. Decrypts the inner HTTP request, dials the
//! **real** upstream IP (recorded by the DNS hijack hook in `ctx.rs`),
//! re-encrypts with the system root store (NOT numa's CA), then records
//! the round-trip into `MitmStores::captures`.
//!
//! Critical invariant: the dial target is `(cached_real_ip, port)` but
//! TLS SNI + Host header stay equal to the original hostname. This is
//! what keeps cert validation honest (we verify against `host`'s real
//! cert) while avoiding a DNS loop back through numa.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::Request;
use axum::response::IntoResponse;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::StatusCode;
use hyper_util::rt::TokioIo;
use log::{debug, warn};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::ctx::ServerCtx;
use crate::mitm::capture::{skip_body_for_content_type, truncate_body, CaptureEntry};
use crate::mitm::MitmStores;

const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const UPSTREAM_TLS_TIMEOUT: Duration = Duration::from_secs(10);

/// Build a client config that trusts the Mozilla root bundle (`webpki-roots`).
/// We deliberately do NOT use numa's CA here — we're impersonating the
/// origin to the client, but to the *real* origin we're a normal client
/// and want full chain validation against the world's CAs.
fn upstream_tls_config() -> Arc<ClientConfig> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

pub async fn forward(
    scheme: &'static str,
    client_ip: IpAddr,
    _ctx: &Arc<ServerCtx>,
    mitm: &Arc<MitmStores>,
    host: String,
    req: Request,
) -> axum::response::Response {
    let start = Instant::now();
    let method = req.method().clone();
    let path = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str().to_owned())
        .unwrap_or_else(|| "/".to_owned());

    // Collect request headers + body (decrypted plaintext at this point).
    let request_headers: Vec<(String, String)> = req
        .headers()
        .iter()
        .map(|(k, v)| (k.as_str().to_owned(), v.to_str().unwrap_or("").to_owned()))
        .collect();
    let request_content_type = req
        .headers()
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    let (parts, body) = req.into_parts();
    let req_body_bytes = match body.collect().await {
        Ok(b) => b.to_bytes(),
        Err(e) => {
            return record_failure(
                mitm,
                start,
                scheme,
                client_ip,
                method.to_string(),
                host,
                path,
                request_headers,
                Vec::new(),
                false,
                StatusCode::BAD_REQUEST,
                format!("error reading client body: {e}"),
            );
        }
    };

    // Look up the real upstream IP cached at DNS hijack time.
    let real_ip = mitm
        .upstream_cache
        .lock()
        .unwrap()
        .lookup(&host)
        .and_then(|r| r.first_ip());

    let Some(real_ip) = real_ip else {
        return record_failure(
            mitm,
            start,
            scheme,
            client_ip,
            method.to_string(),
            host,
            path,
            request_headers,
            req_body_bytes.to_vec(),
            false,
            StatusCode::BAD_GATEWAY,
            "MitM: upstream IP not cached — first connection may race the prefetch; client should retry"
                .to_string(),
        );
    };

    let port: u16 = if scheme == "https" { 443 } else { 80 };
    let upstream_addr = SocketAddr::new(real_ip, port);

    // Dial the pinned upstream IP. If https, wrap in TLS using SNI=host
    // so the cert validates against the real origin's CN/SAN.
    let upstream_result = dial_upstream(scheme, upstream_addr, &host).await;
    let upstream_io = match upstream_result {
        Ok(io) => io,
        Err(e) => {
            return record_failure(
                mitm,
                start,
                scheme,
                client_ip,
                method.to_string(),
                host,
                path,
                request_headers,
                req_body_bytes.to_vec(),
                false,
                StatusCode::BAD_GATEWAY,
                format!("upstream dial failed: {e}"),
            );
        }
    };

    // hyper 1.x: handshake on raw IO, send a single request, drop sender.
    let (mut sender, conn) =
        match hyper::client::conn::http1::handshake::<_, Full<Bytes>>(TokioIo::new(upstream_io))
            .await
        {
            Ok(p) => p,
            Err(e) => {
                return record_failure(
                    mitm,
                    start,
                    scheme,
                    client_ip,
                    method.to_string(),
                    host,
                    path,
                    request_headers,
                    req_body_bytes.to_vec(),
                    false,
                    StatusCode::BAD_GATEWAY,
                    format!("upstream HTTP handshake failed: {e}"),
                );
            }
        };
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            debug!("MitM upstream conn ended: {e}");
        }
    });

    // Rebuild the upstream request: same method/path/headers, body inline.
    // Strip hop-by-hop headers that should not be forwarded over a brand
    // new connection — `Connection`, `Proxy-*`, etc. Keep `Host` set to
    // the original hostname (NOT the IP) so virtual-hosted servers route
    // correctly and TLS SNI matches.
    let mut upstream_req_builder = hyper::Request::builder().method(parts.method.clone()).uri(&path);
    for (name, value) in parts.headers.iter() {
        if is_hop_by_hop(name.as_str()) {
            continue;
        }
        upstream_req_builder = upstream_req_builder.header(name, value);
    }
    upstream_req_builder = upstream_req_builder
        .header(hyper::header::HOST, host.clone())
        .header(hyper::header::CONNECTION, "close");

    let upstream_req = match upstream_req_builder.body(Full::new(req_body_bytes.clone())) {
        Ok(r) => r,
        Err(e) => {
            return record_failure(
                mitm,
                start,
                scheme,
                client_ip,
                method.to_string(),
                host,
                path,
                request_headers,
                req_body_bytes.to_vec(),
                false,
                StatusCode::BAD_GATEWAY,
                format!("could not build upstream request: {e}"),
            );
        }
    };

    let upstream_resp = match sender.send_request(upstream_req).await {
        Ok(r) => r,
        Err(e) => {
            return record_failure(
                mitm,
                start,
                scheme,
                client_ip,
                method.to_string(),
                host,
                path,
                request_headers,
                req_body_bytes.to_vec(),
                false,
                StatusCode::BAD_GATEWAY,
                format!("upstream send failed: {e}"),
            );
        }
    };

    let status = upstream_resp.status();
    let resp_headers: Vec<(String, String)> = upstream_resp
        .headers()
        .iter()
        .map(|(k, v)| (k.as_str().to_owned(), v.to_str().unwrap_or("").to_owned()))
        .collect();
    let resp_content_type = upstream_resp
        .headers()
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    let resp_body_bytes = match upstream_resp.into_body().collect().await {
        Ok(b) => b.to_bytes(),
        Err(e) => {
            return record_failure(
                mitm,
                start,
                scheme,
                client_ip,
                method.to_string(),
                host,
                path,
                request_headers,
                req_body_bytes.to_vec(),
                false,
                StatusCode::BAD_GATEWAY,
                format!("upstream read body failed: {e}"),
            );
        }
    };

    let duration_ms = start.elapsed().as_millis() as u64;

    // Record capture. Bodies are truncated and binary types stored as
    // metadata-only (size + flag) so memory footprint stays bounded.
    let max_body = mitm.config.max_body_bytes;
    let (req_body_stored, req_truncated) =
        if skip_body_for_content_type(request_content_type.as_deref()) {
            (Vec::new(), req_body_bytes.len() > 0)
        } else {
            truncate_body(req_body_bytes.to_vec(), max_body)
        };
    let (resp_body_stored, resp_truncated) =
        if skip_body_for_content_type(resp_content_type.as_deref()) {
            (Vec::new(), resp_body_bytes.len() > 0)
        } else {
            truncate_body(resp_body_bytes.to_vec(), max_body)
        };

    let id = mitm.captures.lock().unwrap().next_id();
    let entry = CaptureEntry {
        id,
        timestamp: std::time::SystemTime::now(),
        client_ip,
        scheme,
        method: method.to_string(),
        host: host.clone(),
        path: path.clone(),
        request_headers,
        request_body: req_body_stored,
        request_body_truncated: req_truncated,
        status: status.as_u16(),
        response_headers: resp_headers.clone(),
        response_body: resp_body_stored,
        response_body_truncated: resp_truncated,
        duration_ms,
        error: None,
    };
    mitm.captures.lock().unwrap().push(entry);

    // Stream the (untruncated) original bytes back to the client. We only
    // truncate for storage; the wire response is full-fidelity.
    let mut out = hyper::Response::builder().status(status);
    for (name, value) in resp_headers.iter() {
        if is_hop_by_hop(name) {
            continue;
        }
        out = out.header(name, value);
    }
    match out.body(Body::from(resp_body_bytes)) {
        Ok(r) => r.into_response(),
        Err(e) => {
            warn!("MitM could not rebuild downstream response: {e}");
            (StatusCode::BAD_GATEWAY, "MitM response rebuild failed").into_response()
        }
    }
}

async fn dial_upstream(
    scheme: &str,
    addr: SocketAddr,
    sni_host: &str,
) -> Result<Box<dyn UpstreamIo>, String> {
    let tcp = tokio::time::timeout(UPSTREAM_CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .map_err(|_| format!("timeout connecting to {addr}"))?
        .map_err(|e| format!("tcp connect {addr}: {e}"))?;
    tcp.set_nodelay(true).ok();

    if scheme == "https" {
        let cfg = upstream_tls_config();
        let connector = TlsConnector::from(cfg);
        let server_name = ServerName::try_from(sni_host.to_owned())
            .map_err(|e| format!("invalid SNI '{sni_host}': {e}"))?;
        let tls = tokio::time::timeout(UPSTREAM_TLS_TIMEOUT, connector.connect(server_name, tcp))
            .await
            .map_err(|_| format!("timeout in TLS handshake to {addr}"))?
            .map_err(|e| format!("TLS handshake to {addr} for SNI={sni_host}: {e}"))?;
        Ok(Box::new(tls))
    } else {
        Ok(Box::new(tcp))
    }
}

/// Type-erased AsyncRead + AsyncWrite for the upstream connection.
/// hyper's `client::conn::http1::handshake` works over any `Tokio`-shaped
/// IO; the box keeps the call sites uniform between http and https.
trait UpstreamIo: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + ?Sized> UpstreamIo for T {}

/// RFC 7230 §6.1: hop-by-hop headers must not be forwarded across a
/// proxy boundary. We additionally drop `Content-Length` and let hyper
/// re-derive it from the body it receives, to avoid mismatches when the
/// upstream uses chunked transfer encoding.
fn is_hop_by_hop(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "content-length"
    )
}

#[allow(clippy::too_many_arguments)]
fn record_failure(
    mitm: &Arc<MitmStores>,
    start: Instant,
    scheme: &'static str,
    client_ip: IpAddr,
    method: String,
    host: String,
    path: String,
    request_headers: Vec<(String, String)>,
    request_body: Vec<u8>,
    request_body_truncated: bool,
    downstream_status: StatusCode,
    error: String,
) -> axum::response::Response {
    let duration_ms = start.elapsed().as_millis() as u64;
    let id = mitm.captures.lock().unwrap().next_id();
    let entry = CaptureEntry {
        id,
        timestamp: std::time::SystemTime::now(),
        client_ip,
        scheme,
        method,
        host,
        path,
        request_headers,
        request_body,
        request_body_truncated,
        status: downstream_status.as_u16(),
        response_headers: Vec::new(),
        response_body: Vec::new(),
        response_body_truncated: false,
        duration_ms,
        error: Some(error.clone()),
    };
    mitm.captures.lock().unwrap().push(entry);
    (downstream_status, error).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hop_by_hop_filter() {
        assert!(is_hop_by_hop("Connection"));
        assert!(is_hop_by_hop("transfer-encoding"));
        assert!(is_hop_by_hop("Content-Length"));
        assert!(!is_hop_by_hop("Authorization"));
        assert!(!is_hop_by_hop("X-Custom-Header"));
    }
}
