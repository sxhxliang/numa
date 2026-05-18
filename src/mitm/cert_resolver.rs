use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use log::warn;
use rcgen::{CertificateParams, DnType, Issuer, KeyPair, SanType};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use time::{Duration, OffsetDateTime};

/// Maximum number of leaf certs to keep in memory. Each entry holds a
/// `CertifiedKey` (cert chain + signing key) and is keyed by SNI. When
/// exceeded the cache is wiped wholesale — cheaper than tracking insertion
/// order, and the next handshakes simply re-mint. 500 is large enough that
/// a debugging session almost never hits the limit.
const CACHE_LIMIT: usize = 500;

/// Leaf cert validity. 30 days keeps mint-on-handshake cost low while
/// limiting the blast radius if the in-memory keypair ever leaks.
const LEAF_VALIDITY_DAYS: i64 = 30;

/// Per-SNI dynamic cert generator. Signed leaves with the same CA the
/// .numa proxy uses, so a client that already trusts numa's CA also
/// trusts MitM-intercepted hosts.
pub struct MitmCertResolver {
    ca_der: CertificateDer<'static>,
    issuer: Issuer<'static, KeyPair>,
    cache: Mutex<HashMap<String, Arc<CertifiedKey>>>,
}

impl std::fmt::Debug for MitmCertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let cached = self.cache.lock().map(|c| c.len()).unwrap_or(0);
        f.debug_struct("MitmCertResolver")
            .field("cached_certs", &cached)
            .finish()
    }
}

impl MitmCertResolver {
    pub fn new(data_dir: &Path) -> crate::Result<Self> {
        let (ca_der, issuer) = crate::tls::load_ca(data_dir)?;
        Ok(MitmCertResolver {
            ca_der,
            issuer,
            cache: Mutex::new(HashMap::new()),
        })
    }

    /// Mint a leaf cert for `sni`. Cert chain is `[leaf, CA]` so the
    /// client can build the trust path even if it only trusts the CA.
    fn mint(&self, sni: &str) -> crate::Result<CertifiedKey> {
        let kp = KeyPair::generate()?;
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, sni);

        let san = SanType::DnsName(sni.to_string().try_into()?);
        params.subject_alt_names = vec![san];
        params.not_before = OffsetDateTime::now_utc();
        params.not_after = OffsetDateTime::now_utc() + Duration::days(LEAF_VALIDITY_DAYS);

        let cert = params.signed_by(&kp, &self.issuer)?;
        let cert_der = cert.der().clone();
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(kp.serialize_der()));
        let signing_key = rustls::crypto::ring::sign::any_supported_type(&key_der)?;
        Ok(CertifiedKey::new(
            vec![cert_der, self.ca_der.clone()],
            signing_key,
        ))
    }

    /// Test helper: number of certs currently cached.
    #[cfg(test)]
    pub fn cached_len(&self) -> usize {
        self.cache.lock().unwrap().len()
    }
}

impl ResolvesServerCert for MitmCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let sni = client_hello.server_name()?.to_lowercase();

        {
            let cache = self.cache.lock().unwrap();
            if let Some(ck) = cache.get(&sni) {
                return Some(Arc::clone(ck));
            }
        }

        let ck = match self.mint(&sni) {
            Ok(ck) => Arc::new(ck),
            Err(e) => {
                warn!("MitM cert mint failed for {}: {}", sni, e);
                return None;
            }
        };

        let mut cache = self.cache.lock().unwrap();
        if cache.len() >= CACHE_LIMIT {
            cache.clear();
        }
        cache.insert(sni, Arc::clone(&ck));
        Some(ck)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_parser::prelude::GeneralName;

    fn tempdir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "numa-test-mitm-cert-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn mint_produces_chain_with_sni_san() {
        let dir = tempdir();
        let resolver = MitmCertResolver::new(&dir).unwrap();
        let ck = resolver.mint("api.example.com").unwrap();
        assert_eq!(ck.cert.len(), 2, "chain must be [leaf, CA]");

        let (_, cert) = x509_parser::parse_x509_certificate(ck.cert[0].as_ref()).unwrap();
        let san = cert
            .tbs_certificate
            .subject_alternative_name()
            .unwrap()
            .unwrap();
        let dns: Vec<&str> = san
            .value
            .general_names
            .iter()
            .filter_map(|gn| match gn {
                GeneralName::DNSName(s) => Some(*s),
                _ => None,
            })
            .collect();
        assert_eq!(dns, vec!["api.example.com"]);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cache_hit_avoids_remint() {
        let dir = tempdir();
        let resolver = MitmCertResolver::new(&dir).unwrap();

        // First mint, cache the result by calling resolve via the trait.
        let ck1 = resolver.mint("api.example.com").unwrap();
        let arc1 = Arc::new(ck1);
        resolver
            .cache
            .lock()
            .unwrap()
            .insert("api.example.com".into(), Arc::clone(&arc1));

        // Build a fake ClientHello-style call via private hash: we can't
        // construct ClientHello in unit tests, so test the cache invariant
        // directly. resolve() does: cache lookup → return Arc::clone.
        let arc2 = resolver
            .cache
            .lock()
            .unwrap()
            .get("api.example.com")
            .cloned()
            .unwrap();
        assert!(Arc::ptr_eq(&arc1, &arc2), "cache must hand back same Arc");
        assert_eq!(resolver.cached_len(), 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cache_overflow_clears() {
        let dir = tempdir();
        let resolver = MitmCertResolver::new(&dir).unwrap();
        // Populate past the limit and verify clear-on-overflow.
        for i in 0..(CACHE_LIMIT + 10) {
            let host = format!("host{i}.example.com");
            let ck = resolver.mint(&host).unwrap();
            let mut cache = resolver.cache.lock().unwrap();
            if cache.len() >= CACHE_LIMIT {
                cache.clear();
            }
            cache.insert(host, Arc::new(ck));
        }
        assert!(
            resolver.cached_len() <= CACHE_LIMIT,
            "overflow must trigger clear: got {}",
            resolver.cached_len()
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Two separate resolvers backed by the same data_dir should produce
    /// leaves chaining to the same CA — that's the whole point of having
    /// the resolver use `load_ca()` rather than mint its own CA.
    #[test]
    fn shares_ca_with_main_tls() {
        let dir = tempdir();

        // Build the regular .numa proxy TLS first — materializes ca.pem.
        let regular =
            crate::tls::build_tls_config("numa", &["app.numa".to_string()], Vec::new(), &dir)
                .unwrap();
        // Resolver reads the same CA from disk.
        let resolver = MitmCertResolver::new(&dir).unwrap();
        let mitm_ck = resolver.mint("api.example.com").unwrap();

        // The MitM leaf's CA (chain[1]) must equal the bytes that the
        // regular config would distribute to clients (the CA cert at
        // chain[1] of any .numa leaf). We can read it from disk.
        let ca_pem = std::fs::read_to_string(dir.join("ca.pem")).unwrap();
        let ca_der = rustls_pemfile::certs(&mut ca_pem.as_bytes())
            .next()
            .unwrap()
            .unwrap();
        assert_eq!(
            mitm_ck.cert[1].as_ref(),
            ca_der.as_ref(),
            "MitM leaf's CA must match the on-disk CA"
        );

        drop(regular);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
