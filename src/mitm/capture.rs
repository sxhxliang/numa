use std::collections::VecDeque;
use std::net::IpAddr;
use std::time::SystemTime;

/// One captured request/response pair from the MitM proxy. Headers are kept
/// in full; bodies are truncated to the configured limit and flagged.
pub struct CaptureEntry {
    pub id: u64,
    pub timestamp: SystemTime,
    pub client_ip: IpAddr,
    pub scheme: &'static str, // "https" or "http"
    pub method: String,
    pub host: String,
    pub path: String,
    pub request_headers: Vec<(String, String)>,
    pub request_body: Vec<u8>,
    pub request_body_truncated: bool,
    pub status: u16,
    pub response_headers: Vec<(String, String)>,
    pub response_body: Vec<u8>,
    pub response_body_truncated: bool,
    pub duration_ms: u64,
    pub error: Option<String>,
}

pub struct CaptureStore {
    entries: VecDeque<CaptureEntry>,
    capacity: usize,
    next_id: u64,
}

impl CaptureStore {
    pub fn new(capacity: usize) -> Self {
        // Cap of zero would silently drop everything; clamp to 1.
        let capacity = capacity.max(1);
        CaptureStore {
            entries: VecDeque::with_capacity(capacity.min(1024)),
            capacity,
            next_id: 1,
        }
    }

    /// Reserve the next id without yet committing the entry. Used by the
    /// forwarder to tag a row at request time and finish it later when the
    /// upstream response arrives.
    pub fn next_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    pub fn push(&mut self, entry: CaptureEntry) {
        if self.entries.len() >= self.capacity {
            self.entries.pop_front();
        }
        self.entries.push_back(entry);
    }

    pub fn list(&self, filter: &CaptureFilter) -> Vec<&CaptureEntry> {
        let limit = filter.limit.unwrap_or(50);
        self.entries
            .iter()
            .rev()
            .filter(|e| {
                if let Some(d) = &filter.domain {
                    if !e.host.contains(d.as_str()) {
                        return false;
                    }
                }
                if let Some(s) = filter.since_id {
                    if e.id <= s {
                        return false;
                    }
                }
                true
            })
            .take(limit)
            .collect()
    }

    pub fn get(&self, id: u64) -> Option<&CaptureEntry> {
        // Linear scan — capture buffer is bounded (default 1000), so this
        // is fast enough and avoids a parallel index.
        self.entries.iter().find(|e| e.id == id)
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

    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

pub struct CaptureFilter {
    pub domain: Option<String>,
    pub since_id: Option<u64>,
    pub limit: Option<usize>,
}

/// Returns true if the body should be skipped entirely (only metadata stored)
/// based on Content-Type. Used by the forwarder to avoid spending memory on
/// large binary payloads (images, video) where the content isn't useful for
/// debugging anyway.
pub fn skip_body_for_content_type(content_type: Option<&str>) -> bool {
    let Some(ct) = content_type else {
        return false;
    };
    let ct = ct.to_ascii_lowercase();
    ct.starts_with("image/")
        || ct.starts_with("video/")
        || ct.starts_with("audio/")
        || ct == "application/octet-stream"
}

/// Truncate `body` to `max_bytes` and return whether truncation happened.
pub fn truncate_body(body: Vec<u8>, max_bytes: usize) -> (Vec<u8>, bool) {
    if body.len() <= max_bytes {
        (body, false)
    } else {
        let mut truncated = body;
        truncated.truncate(max_bytes);
        (truncated, true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn entry(id: u64, host: &str) -> CaptureEntry {
        CaptureEntry {
            id,
            timestamp: SystemTime::now(),
            client_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            scheme: "https",
            method: "GET".into(),
            host: host.into(),
            path: "/".into(),
            request_headers: vec![],
            request_body: vec![],
            request_body_truncated: false,
            status: 200,
            response_headers: vec![],
            response_body: vec![],
            response_body_truncated: false,
            duration_ms: 1,
            error: None,
        }
    }

    #[test]
    fn ring_buffer_wraps() {
        let mut s = CaptureStore::new(3);
        for i in 1..=5 {
            s.push(entry(i, "example.com"));
        }
        assert_eq!(s.len(), 3);
        // First two should have been dropped — ids 3,4,5 remain.
        assert!(s.get(1).is_none());
        assert!(s.get(2).is_none());
        assert!(s.get(3).is_some());
        assert!(s.get(5).is_some());
    }

    #[test]
    fn filter_by_domain() {
        let mut s = CaptureStore::new(10);
        s.push(entry(1, "api.example.com"));
        s.push(entry(2, "cdn.other.com"));
        s.push(entry(3, "api.example.com"));
        let out = s.list(&CaptureFilter {
            domain: Some("example".into()),
            since_id: None,
            limit: None,
        });
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn filter_since_id() {
        let mut s = CaptureStore::new(10);
        for i in 1..=5 {
            s.push(entry(i, "example.com"));
        }
        let out = s.list(&CaptureFilter {
            domain: None,
            since_id: Some(2),
            limit: None,
        });
        assert_eq!(out.len(), 3);
        assert!(out.iter().all(|e| e.id > 2));
    }

    #[test]
    fn next_id_monotonic() {
        let mut s = CaptureStore::new(10);
        let a = s.next_id();
        let b = s.next_id();
        assert!(b > a);
    }

    #[test]
    fn capacity_zero_clamped_to_one() {
        let mut s = CaptureStore::new(0);
        s.push(entry(1, "example.com"));
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn truncate_body_respects_limit() {
        let body = vec![0u8; 1000];
        let (out, truncated) = truncate_body(body.clone(), 100);
        assert_eq!(out.len(), 100);
        assert!(truncated);
        let (out, truncated) = truncate_body(body, 10000);
        assert_eq!(out.len(), 1000);
        assert!(!truncated);
    }

    #[test]
    fn skip_body_recognizes_binary_types() {
        assert!(skip_body_for_content_type(Some("image/png")));
        assert!(skip_body_for_content_type(Some("VIDEO/MP4")));
        assert!(skip_body_for_content_type(Some("application/octet-stream")));
        assert!(!skip_body_for_content_type(Some("application/json")));
        assert!(!skip_body_for_content_type(None));
    }
}
