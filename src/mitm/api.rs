use std::sync::Arc;
use std::time::UNIX_EPOCH;

use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::ctx::ServerCtx;

use super::capture::CaptureFilter;

/// Build the `/mitm/*` sub-router. Mounted into the main API router by
/// `crate::api::router()`. Returns an empty router (no routes) when MitM
/// is disabled, so the rest of the API is unaffected.
pub fn router(ctx: Arc<ServerCtx>) -> Router {
    if ctx.mitm.is_none() {
        return Router::new();
    }
    Router::new()
        .route("/mitm/status", get(status))
        .route("/mitm/ca.pem", get(ca_pem))
        .route("/mitm/rules", get(list_rules))
        .route("/mitm/rules", post(create_rule))
        .route("/mitm/rules", delete(clear_rules))
        .route("/mitm/rules/{domain}", delete(remove_rule))
        .route("/mitm/captures", get(list_captures))
        .route("/mitm/captures", delete(clear_captures))
        .route("/mitm/captures/{id}", get(get_capture))
        .with_state(ctx)
}

#[derive(Serialize)]
struct StatusResponse {
    enabled: bool,
    https_port: u16,
    http_port: u16,
    bind_addr: String,
    rules_count: usize,
    captures_count: usize,
    upstream_cache_count: usize,
    capture_buffer_capacity: usize,
}

async fn status(State(ctx): State<Arc<ServerCtx>>) -> impl IntoResponse {
    let mitm = ctx.mitm.as_ref().expect("router gated on mitm.is_some()");
    // Take each lock once; std::sync::Mutex is NOT reentrant, so
    // calling .lock() twice on the same Mutex in one statement deadlocks.
    let (captures_count, capture_buffer_capacity) = {
        let captures = mitm.captures.lock().unwrap();
        (captures.len(), captures.capacity())
    };
    Json(StatusResponse {
        enabled: mitm.config.enabled,
        https_port: mitm.config.https_port,
        http_port: mitm.config.http_port,
        bind_addr: mitm.config.bind_addr.clone(),
        rules_count: mitm.rules.read().unwrap().len(),
        captures_count,
        upstream_cache_count: mitm.upstream_cache.lock().unwrap().len(),
        capture_buffer_capacity,
    })
}

/// Alias of the existing `/ca.pem` for clients that conceptually associate
/// the cert with MitM rather than with the .numa proxy.
async fn ca_pem(State(ctx): State<Arc<ServerCtx>>) -> impl IntoResponse {
    match &ctx.ca_pem {
        Some(pem) => (
            [
                (header::CONTENT_TYPE, "application/x-pem-file"),
                (
                    header::CONTENT_DISPOSITION,
                    "attachment; filename=\"numa-ca.pem\"",
                ),
            ],
            pem.clone(),
        )
            .into_response(),
        None => (StatusCode::SERVICE_UNAVAILABLE, "CA not generated").into_response(),
    }
}

#[derive(Deserialize)]
struct CreateRuleRequest {
    domain: String,
    #[serde(default = "default_enabled")]
    enabled: bool,
}

fn default_enabled() -> bool {
    true
}

#[derive(Serialize)]
struct RuleResponse {
    domain: String,
    enabled: bool,
    created_at_epoch: f64,
    hits: u64,
}

impl From<&super::rules::MitmRule> for RuleResponse {
    fn from(r: &super::rules::MitmRule) -> Self {
        let created = r
            .created_at
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);
        RuleResponse {
            domain: r.domain.clone(),
            enabled: r.enabled,
            created_at_epoch: created,
            hits: r.hits,
        }
    }
}

async fn list_rules(State(ctx): State<Arc<ServerCtx>>) -> impl IntoResponse {
    let mitm = ctx.mitm.as_ref().expect("router gated on mitm.is_some()");
    let rules = mitm.rules.read().unwrap();
    let out: Vec<RuleResponse> = rules.list().into_iter().map(RuleResponse::from).collect();
    Json(out)
}

async fn create_rule(
    State(ctx): State<Arc<ServerCtx>>,
    Json(req): Json<CreateRuleRequest>,
) -> impl IntoResponse {
    if req.domain.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, "domain must not be empty").into_response();
    }
    let mitm = ctx.mitm.as_ref().expect("router gated on mitm.is_some()");
    let mut rules = mitm.rules.write().unwrap();
    let r: RuleResponse = (&*rules.insert(&req.domain, req.enabled)).into();
    (StatusCode::CREATED, Json(r)).into_response()
}

async fn remove_rule(
    State(ctx): State<Arc<ServerCtx>>,
    Path(domain): Path<String>,
) -> impl IntoResponse {
    let mitm = ctx.mitm.as_ref().expect("router gated on mitm.is_some()");
    let removed = mitm.rules.write().unwrap().remove(&domain);
    if removed {
        // Drop the cached real-IP so a re-added rule re-resolves fresh.
        mitm.upstream_cache.lock().unwrap().remove(&domain);
        StatusCode::NO_CONTENT.into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

async fn clear_rules(State(ctx): State<Arc<ServerCtx>>) -> impl IntoResponse {
    let mitm = ctx.mitm.as_ref().expect("router gated on mitm.is_some()");
    mitm.rules.write().unwrap().clear();
    mitm.upstream_cache.lock().unwrap().clear();
    StatusCode::NO_CONTENT
}

#[derive(Deserialize)]
struct CapturesQuery {
    domain: Option<String>,
    since: Option<u64>,
    limit: Option<usize>,
    #[serde(default)]
    with_body: bool,
}

#[derive(Serialize)]
struct CaptureSummary {
    id: u64,
    timestamp_epoch: f64,
    client_ip: String,
    scheme: &'static str,
    method: String,
    host: String,
    path: String,
    status: u16,
    duration_ms: u64,
    request_body_size: usize,
    response_body_size: usize,
    request_body_truncated: bool,
    response_body_truncated: bool,
    error: Option<String>,
}

#[derive(Serialize)]
struct CaptureDetail {
    #[serde(flatten)]
    summary: CaptureSummary,
    request_headers: Vec<(String, String)>,
    response_headers: Vec<(String, String)>,
    request_body_b64: String,
    response_body_b64: String,
}

fn summary(e: &super::capture::CaptureEntry) -> CaptureSummary {
    let ts = e
        .timestamp
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);
    CaptureSummary {
        id: e.id,
        timestamp_epoch: ts,
        client_ip: e.client_ip.to_string(),
        scheme: e.scheme,
        method: e.method.clone(),
        host: e.host.clone(),
        path: e.path.clone(),
        status: e.status,
        duration_ms: e.duration_ms,
        request_body_size: e.request_body.len(),
        response_body_size: e.response_body.len(),
        request_body_truncated: e.request_body_truncated,
        response_body_truncated: e.response_body_truncated,
        error: e.error.clone(),
    }
}

async fn list_captures(
    State(ctx): State<Arc<ServerCtx>>,
    axum::extract::Query(q): axum::extract::Query<CapturesQuery>,
) -> impl IntoResponse {
    let mitm = ctx.mitm.as_ref().expect("router gated on mitm.is_some()");
    let captures = mitm.captures.lock().unwrap();
    let filter = CaptureFilter {
        domain: q.domain,
        since_id: q.since,
        limit: q.limit,
    };
    let out: Vec<serde_json::Value> = captures
        .list(&filter)
        .into_iter()
        .map(|e| {
            if q.with_body {
                serde_json::to_value(detail(e)).unwrap_or_default()
            } else {
                serde_json::to_value(summary(e)).unwrap_or_default()
            }
        })
        .collect();
    Json(out)
}

async fn get_capture(
    State(ctx): State<Arc<ServerCtx>>,
    Path(id): Path<u64>,
) -> impl IntoResponse {
    let mitm = ctx.mitm.as_ref().expect("router gated on mitm.is_some()");
    let captures = mitm.captures.lock().unwrap();
    match captures.get(id) {
        Some(e) => Json(detail(e)).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

fn detail(e: &super::capture::CaptureEntry) -> CaptureDetail {
    CaptureDetail {
        summary: summary(e),
        request_headers: e.request_headers.clone(),
        response_headers: e.response_headers.clone(),
        request_body_b64: base64_encode(&e.request_body),
        response_body_b64: base64_encode(&e.response_body),
    }
}

async fn clear_captures(State(ctx): State<Arc<ServerCtx>>) -> impl IntoResponse {
    let mitm = ctx.mitm.as_ref().expect("router gated on mitm.is_some()");
    mitm.captures.lock().unwrap().clear();
    StatusCode::NO_CONTENT
}

/// Minimal base64 encoder so we don't pull a new dep just for the API.
/// Standard alphabet, with `=` padding.
fn base64_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    let mut chunks = input.chunks_exact(3);
    for chunk in &mut chunks {
        let n = (u32::from(chunk[0]) << 16) | (u32::from(chunk[1]) << 8) | u32::from(chunk[2]);
        out.push(ALPHABET[((n >> 18) & 0x3f) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 0x3f) as usize] as char);
        out.push(ALPHABET[((n >> 6) & 0x3f) as usize] as char);
        out.push(ALPHABET[(n & 0x3f) as usize] as char);
    }
    let rem = chunks.remainder();
    if !rem.is_empty() {
        let b0 = u32::from(rem[0]);
        let b1 = rem.get(1).copied().map(u32::from).unwrap_or(0);
        let n = (b0 << 16) | (b1 << 8);
        out.push(ALPHABET[((n >> 18) & 0x3f) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 0x3f) as usize] as char);
        if rem.len() == 2 {
            out.push(ALPHABET[((n >> 6) & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
        out.push('=');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use http::Request as HttpRequest;
    use tower::ServiceExt;

    async fn ctx_with_mitm() -> Arc<ServerCtx> {
        let dir = std::env::temp_dir().join(format!(
            "numa-test-mitm-api-{}-{}",
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
        let mut ctx = crate::testutil::test_ctx().await;
        ctx.mitm = Some(Arc::new(
            crate::mitm::MitmStores::new(config, &dir).unwrap(),
        ));
        // Stash the dir on ca_pem so the test can read it (unused in code path).
        ctx.ca_pem = Some(std::fs::read_to_string(dir.join("ca.pem")).unwrap());
        Arc::new(ctx)
    }

    #[test]
    fn base64_known_vectors() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[tokio::test]
    async fn router_is_empty_when_mitm_disabled() {
        // No mitm field set → router() returns an empty Router and /mitm/status 404s.
        let ctx = Arc::new(crate::testutil::test_ctx().await);
        let app = router(ctx);
        let resp = app
            .oneshot(HttpRequest::get("/mitm/status").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), 404);
    }

    #[tokio::test]
    async fn status_reports_enabled_when_mitm_present() {
        let ctx = ctx_with_mitm().await;
        let app = router(ctx);
        let resp = app
            .oneshot(HttpRequest::get("/mitm/status").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body = axum::body::to_bytes(resp.into_body(), 10000).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["enabled"], true);
        assert_eq!(v["https_port"], 8443);
        assert_eq!(v["http_port"], 8080);
        assert_eq!(v["rules_count"], 0);
        assert_eq!(v["captures_count"], 0);
    }

    #[tokio::test]
    async fn rules_crud_roundtrip() {
        let ctx = ctx_with_mitm().await;
        let app = router(ctx.clone());

        // Add
        let resp = app
            .clone()
            .oneshot(
                HttpRequest::post("/mitm/rules")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"domain":"api.example.com"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 201);

        // List sees it
        let resp = app
            .clone()
            .oneshot(HttpRequest::get("/mitm/rules").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body = axum::body::to_bytes(resp.into_body(), 10000).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v[0]["domain"], "api.example.com");
        assert_eq!(v[0]["enabled"], true);

        // Status reflects updated count
        let resp = app
            .clone()
            .oneshot(HttpRequest::get("/mitm/status").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let body = axum::body::to_bytes(resp.into_body(), 10000).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["rules_count"], 1);

        // Delete
        let resp = app
            .clone()
            .oneshot(
                HttpRequest::delete("/mitm/rules/api.example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 204);

        // List is empty again
        let resp = app
            .oneshot(HttpRequest::get("/mitm/rules").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let body = axum::body::to_bytes(resp.into_body(), 10000).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(v.as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn rules_post_rejects_empty_domain() {
        let ctx = ctx_with_mitm().await;
        let app = router(ctx);
        let resp = app
            .oneshot(
                HttpRequest::post("/mitm/rules")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"domain":""}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 400);
    }

    #[tokio::test]
    async fn captures_list_and_get_and_clear() {
        let ctx = ctx_with_mitm().await;
        // Seed a capture directly so we don't need to spin up the proxy.
        {
            let mitm = ctx.mitm.as_ref().unwrap();
            let mut captures = mitm.captures.lock().unwrap();
            let id = captures.next_id();
            captures.push(crate::mitm::capture::CaptureEntry {
                id,
                timestamp: std::time::SystemTime::now(),
                client_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                scheme: "https",
                method: "GET".into(),
                host: "api.example.com".into(),
                path: "/foo".into(),
                request_headers: vec![("host".into(), "api.example.com".into())],
                request_body: b"hello".to_vec(),
                request_body_truncated: false,
                status: 200,
                response_headers: vec![("content-type".into(), "application/json".into())],
                response_body: br#"{"ok":true}"#.to_vec(),
                response_body_truncated: false,
                duration_ms: 42,
                error: None,
            });
        }

        let app = router(ctx.clone());

        // List default (no bodies) — summaries only.
        let resp = app
            .clone()
            .oneshot(
                HttpRequest::get("/mitm/captures")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body = axum::body::to_bytes(resp.into_body(), 10000).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v[0]["host"], "api.example.com");
        assert_eq!(v[0]["status"], 200);
        assert_eq!(v[0]["request_body_size"], 5);
        assert!(
            v[0].get("request_body_b64").is_none(),
            "list w/o with_body must not include base64 bodies"
        );

        // GET detail returns full bodies as base64.
        let resp = app
            .clone()
            .oneshot(
                HttpRequest::get("/mitm/captures/1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body = axum::body::to_bytes(resp.into_body(), 10000).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["host"], "api.example.com");
        // "hello" → base64("hello") = "aGVsbG8="
        assert_eq!(v["request_body_b64"], "aGVsbG8=");
        // {"ok":true} → base64 = "eyJvayI6dHJ1ZX0="
        assert_eq!(v["response_body_b64"], "eyJvayI6dHJ1ZX0=");

        // Missing id → 404.
        let resp = app
            .clone()
            .oneshot(
                HttpRequest::get("/mitm/captures/999")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 404);

        // Filter by domain — match.
        let resp = app
            .clone()
            .oneshot(
                HttpRequest::get("/mitm/captures?domain=example")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(resp.into_body(), 10000).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v.as_array().unwrap().len(), 1);

        // Filter by domain — non-match.
        let resp = app
            .clone()
            .oneshot(
                HttpRequest::get("/mitm/captures?domain=nomatch")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(resp.into_body(), 10000).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(v.as_array().unwrap().is_empty());

        // Clear.
        let resp = app
            .clone()
            .oneshot(
                HttpRequest::delete("/mitm/captures")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 204);
        assert_eq!(ctx.mitm.as_ref().unwrap().captures.lock().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn ca_pem_endpoint_returns_pem() {
        let ctx = ctx_with_mitm().await;
        let app = router(ctx);
        let resp = app
            .oneshot(HttpRequest::get("/mitm/ca.pem").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body = axum::body::to_bytes(resp.into_body(), 100_000).await.unwrap();
        let s = String::from_utf8_lossy(&body);
        assert!(s.contains("BEGIN CERTIFICATE"), "expected PEM, got: {}", &s[..s.len().min(200)]);
    }
}
