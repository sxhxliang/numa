use std::collections::HashMap;
use std::time::{Instant, SystemTime};

/// One MitM whitelist entry. The presence of an enabled entry tells the
/// resolver to hijack `domain` to the local MitM proxy IP, and tells the
/// proxy to terminate TLS for that SNI.
pub struct MitmRule {
    pub domain: String,
    pub enabled: bool,
    pub created_at: SystemTime,
    /// Counter incremented each time the proxy serves an intercepted
    /// connection for this rule. Read-only outside MitmRules.
    pub hits: u64,
    /// Last time we served a connection for this rule (for dashboard ordering).
    pub last_hit: Option<Instant>,
}

pub struct MitmRules {
    entries: HashMap<String, MitmRule>,
}

impl Default for MitmRules {
    fn default() -> Self {
        Self::new()
    }
}

impl MitmRules {
    pub fn new() -> Self {
        MitmRules {
            entries: HashMap::new(),
        }
    }

    pub fn insert(&mut self, domain: &str, enabled: bool) -> &MitmRule {
        let key = domain.to_lowercase();
        self.entries.insert(
            key.clone(),
            MitmRule {
                domain: key.clone(),
                enabled,
                created_at: SystemTime::now(),
                hits: 0,
                last_hit: None,
            },
        );
        self.entries.get(&key).unwrap()
    }

    /// Hot path: assumes `domain` is already lowercased.
    pub fn is_listed(&self, domain: &str) -> bool {
        self.entries.get(domain).is_some_and(|r| r.enabled)
    }

    pub fn record_hit(&mut self, domain: &str) {
        if let Some(r) = self.entries.get_mut(domain) {
            r.hits += 1;
            r.last_hit = Some(Instant::now());
        }
    }

    pub fn get(&self, domain: &str) -> Option<&MitmRule> {
        self.entries.get(&domain.to_lowercase())
    }

    pub fn remove(&mut self, domain: &str) -> bool {
        self.entries.remove(&domain.to_lowercase()).is_some()
    }

    pub fn list(&self) -> Vec<&MitmRule> {
        self.entries.values().collect()
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

    #[test]
    fn insert_lookup_remove() {
        let mut r = MitmRules::new();
        r.insert("Api.Example.COM", true);
        assert!(r.is_listed("api.example.com"), "lookup must be lowercased");
        assert!(!r.is_listed("other.example.com"));
        assert_eq!(r.len(), 1);
        assert!(r.remove("API.example.com"));
        assert!(r.is_empty());
    }

    #[test]
    fn disabled_rule_is_not_listed() {
        let mut r = MitmRules::new();
        r.insert("api.example.com", false);
        assert!(!r.is_listed("api.example.com"));
        assert_eq!(r.len(), 1, "disabled rules still count toward len()");
    }

    #[test]
    fn record_hit_increments_counter() {
        let mut r = MitmRules::new();
        r.insert("api.example.com", true);
        r.record_hit("api.example.com");
        r.record_hit("api.example.com");
        assert_eq!(r.get("api.example.com").unwrap().hits, 2);
    }

    #[test]
    fn record_hit_on_missing_is_noop() {
        let mut r = MitmRules::new();
        r.record_hit("missing.example.com");
        assert!(r.is_empty());
    }
}
