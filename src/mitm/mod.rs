//! MitM HTTPS interception built on top of numa's DNS hijacking +
//! self-signed CA. See `plans/dns-ssl-mitm-peaceful-backus.md` for the
//! design rationale.
//!
//! Module layout:
//!
//! - [`rules`]          — domain whitelist (only listed domains are intercepted)
//! - [`upstream_cache`] — caches the *real* upstream IP per intercepted domain
//! - [`capture`]        — bounded ring buffer of decrypted req/resp pairs
//! - [`cert_resolver`]  — per-SNI dynamic leaf certs signed by numa's CA
//! - [`proxy`]          — HTTPS/HTTP MitM listeners
//! - [`api`]            — REST endpoints under `/mitm/*`

use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};

pub mod api;
pub mod capture;
pub mod cert_resolver;
pub mod forwarder;
pub mod proxy;
pub mod rules;
pub mod upstream_cache;

use crate::config::MitmConfig;

/// Aggregated state shared between the DNS hijack hook (in `ctx.rs`), the
/// MitM proxy listeners (in `mitm/proxy.rs`), and the REST API. Held by
/// `ServerCtx` as `Option<Arc<MitmStores>>` — `None` when MitM is disabled
/// or when the CA could not be loaded (e.g. read-only data_dir).
pub struct MitmStores {
    pub config: MitmConfig,
    pub rules: RwLock<rules::MitmRules>,
    pub upstream_cache: Mutex<upstream_cache::UpstreamCache>,
    pub captures: Mutex<capture::CaptureStore>,
    pub cert_resolver: Arc<cert_resolver::MitmCertResolver>,
}

impl MitmStores {
    /// `data_dir` is the same directory the regular TLS stack uses for
    /// `ca.pem`. Errors propagate from CA load — caller should disable
    /// MitM if construction fails.
    pub fn new(config: MitmConfig, data_dir: &Path) -> crate::Result<Self> {
        let cap = config.capture_buffer;
        let cert_resolver = Arc::new(cert_resolver::MitmCertResolver::new(data_dir)?);
        Ok(MitmStores {
            config,
            rules: RwLock::new(rules::MitmRules::new()),
            upstream_cache: Mutex::new(upstream_cache::UpstreamCache::new()),
            captures: Mutex::new(capture::CaptureStore::new(cap)),
            cert_resolver,
        })
    }
}
