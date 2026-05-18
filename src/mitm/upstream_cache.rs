use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// One real upstream record. Stores the IPs the *real* DNS pipeline returned
/// for an intercepted domain, plus an absolute expiry derived from the TTL
/// at the time of insertion.
pub struct UpstreamRecord {
    pub ips: Vec<IpAddr>,
    pub expires_at: Instant,
}

impl UpstreamRecord {
    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }

    /// Prefer IPv4 first to avoid Happy-Eyeballs flake during testing —
    /// the proxy can dial v4 deterministically and only fall back to v6
    /// on failure.
    pub fn first_ip(&self) -> Option<IpAddr> {
        self.ips
            .iter()
            .find(|ip| matches!(ip, IpAddr::V4(_)))
            .or_else(|| self.ips.first())
            .copied()
    }
}

/// Cache of `(intercepted_domain → real_upstream_ips)`. Populated by the DNS
/// hijack hook in `ctx.rs::resolve_local`, read by the MitM forwarder when it
/// needs to dial the genuine origin server.
pub struct UpstreamCache {
    entries: HashMap<String, UpstreamRecord>,
}

impl Default for UpstreamCache {
    fn default() -> Self {
        Self::new()
    }
}

impl UpstreamCache {
    pub fn new() -> Self {
        UpstreamCache {
            entries: HashMap::new(),
        }
    }

    pub fn put(&mut self, domain: &str, ips: Vec<IpAddr>, ttl_secs: u32) {
        if ips.is_empty() {
            return;
        }
        // TTL floor of 30s — the real upstream's TTL might be 0 (e.g.
        // CDN-load-balanced hostnames), and we don't want to re-resolve
        // on every TLS handshake.
        let secs = ttl_secs.max(30) as u64;
        self.entries.insert(
            domain.to_lowercase(),
            UpstreamRecord {
                ips,
                expires_at: Instant::now() + Duration::from_secs(secs),
            },
        );
    }

    pub fn lookup(&self, domain: &str) -> Option<&UpstreamRecord> {
        let r = self.entries.get(domain)?;
        if r.is_expired() {
            return None;
        }
        Some(r)
    }

    pub fn remove(&mut self, domain: &str) -> bool {
        self.entries.remove(&domain.to_lowercase()).is_some()
    }

    pub fn prune(&mut self) {
        self.entries.retain(|_, r| !r.is_expired());
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn put_and_lookup() {
        let mut c = UpstreamCache::new();
        c.put(
            "api.example.com",
            vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))],
            300,
        );
        let r = c.lookup("api.example.com").unwrap();
        assert_eq!(r.ips.len(), 1);
        assert_eq!(r.first_ip(), Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
    }

    #[test]
    fn empty_ips_not_stored() {
        let mut c = UpstreamCache::new();
        c.put("api.example.com", vec![], 300);
        assert!(c.lookup("api.example.com").is_none());
    }

    #[test]
    fn prefers_ipv4_over_ipv6() {
        use std::net::Ipv6Addr;
        let mut c = UpstreamCache::new();
        c.put(
            "api.example.com",
            vec![
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            ],
            300,
        );
        let r = c.lookup("api.example.com").unwrap();
        assert_eq!(r.first_ip(), Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
    }

    #[test]
    fn lookup_uses_lowercase_key() {
        let mut c = UpstreamCache::new();
        c.put(
            "API.Example.COM",
            vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))],
            300,
        );
        // Hot-path lookup expects pre-lowercased input (matches override_store).
        assert!(c.lookup("api.example.com").is_some());
    }

    #[test]
    fn ttl_floor_applies() {
        // ttl_secs=0 should not produce immediately-expired records.
        let mut c = UpstreamCache::new();
        c.put(
            "api.example.com",
            vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))],
            0,
        );
        assert!(c.lookup("api.example.com").is_some());
    }
}
