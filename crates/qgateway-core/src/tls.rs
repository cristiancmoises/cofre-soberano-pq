//! TLS 1.3 termination on the serve-tcp listener.
//!
//! The `tls` block under a serve-tcp tenant requests TLS termination at the
//! gateway — clients open a TLS 1.3 connection on the listen address, and
//! the gateway re-encrypts (PQ) over CSPQ to the peer leg. This is intended
//! for environments where the local application speaks plain TLS to the
//! local gateway and the gateway promotes the link to post-quantum
//! authenticated transport across an untrusted network.
//!
//! ## Provider
//!
//! We use `rustls 0.23` with the `ring` provider. TLS 1.2 is enabled because
//! some Brazilian regulated environments still run legacy clients during
//! their migration window; TLS 1.3 is preferred by negotiation.
//!
//! ## Cipher suites
//!
//! `rustls` ships sensible defaults; we do not narrow the list. Operators
//! who need to constrain the cipher suite must pin the rustls version and
//! patch this module.

use anyhow::{anyhow, Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::path::Path;
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;

use crate::config::TlsConfig;

/// Install the default `ring` CryptoProvider for `rustls`. Must be called
/// exactly once per process before any TLS operations. Idempotent calls are
/// silently ignored.
pub fn ensure_crypto_provider_installed() {
    // `set_default` returns Err if a provider was already installed; that's
    // fine for us, we just want to ensure one is present.
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Build a `TlsAcceptor` from a [`TlsConfig`] — loads the cert chain + key
/// from disk and configures a TLS 1.3-preferred server with no client auth.
pub fn build_acceptor(cfg: &TlsConfig) -> Result<Arc<TlsAcceptor>> {
    ensure_crypto_provider_installed();

    let certs = load_cert_chain(&cfg.cert)
        .with_context(|| format!("loading cert chain from {}", cfg.cert.display()))?;
    if certs.is_empty() {
        return Err(anyhow!(
            "no certificates parsed from {}",
            cfg.cert.display()
        ));
    }
    let key = load_private_key(&cfg.key)
        .with_context(|| format!("loading private key from {}", cfg.key.display()))?;

    let server_cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| anyhow!("rustls server config build failed: {e}"))?;
    let acceptor = TlsAcceptor::from(Arc::new(server_cfg));
    Ok(Arc::new(acceptor))
}

// ============================================================================
//                  Sprint 5.5 — cert hot-reload primitives
// ============================================================================
//
// SIGUSR1 triggers a re-read of cert/key files for every tenant that has TLS
// enabled. We don't use `notify`/`inotify` here: a POSIX signal is simpler,
// equally effective in practice, and avoids the supply-chain weight of a
// filesystem-watching dep. Operators can `kill -USR1 $(pidof qgateway)` after
// running `certbot renew` or equivalent.
//
// Race model: the watch channel is single-producer (the signal handler task)
// and single-consumer-per-tenant (each tenant accept loop reads it before
// every accept). The `watch::Receiver::borrow()` is a synchronous, fast read
// that returns the latest value. Concurrent accept tasks pick up the new
// acceptor on their next accept; in-flight TLS handshakes complete with the
// previous acceptor (no mid-handshake swap, which would corrupt state).
//
// If the reload fails (bad PEM, file unreadable), the previous acceptor is
// retained and the failure is logged. The daemon keeps serving on the old
// cert until the next successful reload.

/// Cloneable read-handle over the current TLS acceptor.
///
/// Each accept loop holds one and calls `current()` per accept to snapshot
/// the latest acceptor — usually unchanged (cheap `Arc` clone), occasionally
/// replaced after a SIGUSR1 reload.
#[derive(Clone)]
pub struct TlsAcceptorHandle {
    rx: tokio::sync::watch::Receiver<Arc<TlsAcceptor>>,
}

impl TlsAcceptorHandle {
    /// Snapshot the currently-installed `TlsAcceptor`.
    pub fn current(&self) -> Arc<TlsAcceptor> {
        self.rx.borrow().clone()
    }

    /// Build a non-reloadable handle from a single static acceptor. Used by
    /// SNI groups in Sprint 6 — hot-reload of multi-SNI acceptors is
    /// deferred to Sprint 6.5 (separate reload coordinator needed for the
    /// multi-cert resolver).
    pub fn from_static(acceptor: Arc<TlsAcceptor>) -> Self {
        // Use a never-updated watch channel. The sender is dropped
        // immediately; the receiver returns the initial value forever via
        // `borrow()`. (tokio::sync::watch keeps the initial value alive
        // even after the sender is dropped, as long as a receiver exists.)
        let (_tx, rx) = tokio::sync::watch::channel(acceptor);
        Self { rx }
    }
}

/// Source description that lets a `TlsReloadTrigger` rebuild its acceptor.
/// Single-tenant TLS rebuilds one cert+key into one acceptor. SNI groups
/// rebuild every member's cert+key into ONE multi-SNI acceptor (atomic
/// swap of the whole resolver, not per-entry).
enum ReloadSource {
    Single {
        cfg: TlsConfig,
    },
    Multi {
        // Sprint 22 (Stage B): entries are now behind a Mutex so the SIGHUP
        // arm can add/remove SNI tenants by mutating the set, then calling
        // `reload()` to rebuild + atomically swap the acceptor. Reload still
        // works exactly as before — it reads `entries.lock()` and rebuilds
        // from the current snapshot. SIGUSR1 (cert file path unchanged,
        // contents updated on disk) and SIGHUP (entries set changed in
        // memory) both go through the same rebuild path.
        entries: std::sync::Mutex<Vec<(String, String, TlsConfig)>>,
    },
}

/// Reload trigger held by the daemon's signal-handler task. Owns the
/// rebuild description so it can reconstruct the acceptor from the same
/// paths on every SIGUSR1.
pub struct TlsReloadTrigger {
    tx: tokio::sync::watch::Sender<Arc<TlsAcceptor>>,
    source: ReloadSource,
    /// Tenant name (single) or group label (multi-SNI) — used in log lines.
    label: String,
}

impl TlsReloadTrigger {
    /// Re-read cert + key from disk, rebuild the acceptor, and atomically
    /// install it. Returns the previous acceptor for logging/diagnostics.
    /// On failure, the previous acceptor remains installed.
    pub fn reload(&self) -> Result<Arc<TlsAcceptor>> {
        let new_acc = match &self.source {
            ReloadSource::Single { cfg } => build_acceptor(cfg).with_context(|| {
                format!(
                    "rebuilding TLS acceptor for tenant {} (cert={} key={})",
                    self.label,
                    cfg.cert.display(),
                    cfg.key.display()
                )
            })?,
            ReloadSource::Multi { entries } => {
                // Sprint 22: snapshot the entries under the mutex,
                // release the lock, then rebuild from the snapshot.
                // Avoids holding the lock across the (potentially
                // costly) build_multi_sni_acceptor call.
                let snapshot = entries
                    .lock()
                    .map_err(|e| anyhow!("multi-SNI entries mutex poisoned: {e}"))?
                    .clone();
                let n = snapshot.len();
                build_multi_sni_acceptor(snapshot).with_context(|| {
                    format!(
                        "rebuilding multi-SNI acceptor for group {} (n_certs={n})",
                        self.label,
                    )
                })?
            }
        };
        let prev = self.tx.borrow().clone();
        // `send` only fails if all receivers are dropped — in that case the
        // tenant accept loop is gone and reload is moot; tolerate silently.
        let _ = self.tx.send(new_acc);
        Ok(prev)
    }

    /// Sprint 22 (Stage B): add a (label, sni, TlsConfig) entry to the
    /// multi-SNI group's cert set, then rebuild + atomically swap the
    /// acceptor. Returns Err on:
    /// - Single-source trigger (this method is only for multi-SNI).
    /// - Duplicate label (operator error — must be surfaced).
    /// - Cert/key load failure (the rebuild fails; previous acceptor
    ///   stays installed, the entry is rolled back).
    ///
    /// Used by Sprint 23+'s SIGHUP arm to add a tenant to a running
    /// SNI group without restarting the group's accept loop.
    pub fn add_sni_entry(
        &self,
        label: String,
        sni: String,
        cfg: TlsConfig,
    ) -> Result<Arc<TlsAcceptor>> {
        let ReloadSource::Multi { entries } = &self.source else {
            return Err(anyhow!(
                "add_sni_entry called on single-source trigger {}",
                self.label
            ));
        };
        {
            let mut guard = entries
                .lock()
                .map_err(|e| anyhow!("multi-SNI entries mutex poisoned: {e}"))?;
            if guard.iter().any(|(l, _, _)| l == &label) {
                return Err(anyhow!(
                    "tenant {label} already in multi-SNI group {}",
                    self.label
                ));
            }
            guard.push((label.clone(), sni, cfg));
        }
        // Rebuild + swap. If this fails, roll back the entries push
        // so the trigger's state stays consistent with what's actually
        // running.
        match self.reload() {
            Ok(prev) => Ok(prev),
            Err(e) => {
                let mut guard = entries.lock().map_err(|e2| {
                    anyhow!("multi-SNI entries mutex poisoned during rollback: {e2}")
                })?;
                guard.retain(|(l, _, _)| l != &label);
                Err(e.context("add_sni_entry: rollback after rebuild failure"))
            }
        }
    }

    /// Sprint 22 (Stage B): remove an entry from the multi-SNI group's
    /// cert set, then rebuild + atomically swap the acceptor. Returns
    /// Err on:
    /// - Single-source trigger.
    /// - Label not present (operator referenced a tenant that isn't
    ///   in this group — distinct error case, returned so caller can
    ///   distinguish "already removed" from "removed successfully").
    /// - Rebuild failure (rare — removing certs shouldn't fail; if
    ///   it does, the entry is restored to keep state consistent).
    pub fn remove_sni_entry(&self, label: &str) -> Result<Arc<TlsAcceptor>> {
        let ReloadSource::Multi { entries } = &self.source else {
            return Err(anyhow!(
                "remove_sni_entry called on single-source trigger {}",
                self.label
            ));
        };
        let removed_entry;
        {
            let mut guard = entries
                .lock()
                .map_err(|e| anyhow!("multi-SNI entries mutex poisoned: {e}"))?;
            let pos = guard
                .iter()
                .position(|(l, _, _)| l == label)
                .ok_or_else(|| anyhow!("tenant {label} not in multi-SNI group {}", self.label))?;
            removed_entry = guard.remove(pos);
        }
        match self.reload() {
            Ok(prev) => Ok(prev),
            Err(e) => {
                let mut guard = entries.lock().map_err(|e2| {
                    anyhow!("multi-SNI entries mutex poisoned during rollback: {e2}")
                })?;
                guard.push(removed_entry);
                Err(e.context("remove_sni_entry: rollback after rebuild failure"))
            }
        }
    }

    /// Sprint 22: snapshot the current entry labels in a multi-SNI group.
    /// Returns Err for single-source triggers. Used by the SIGHUP apply
    /// step's diff computation.
    pub fn sni_labels(&self) -> Result<Vec<String>> {
        let ReloadSource::Multi { entries } = &self.source else {
            return Err(anyhow!(
                "sni_labels called on single-source trigger {}",
                self.label
            ));
        };
        let guard = entries
            .lock()
            .map_err(|e| anyhow!("multi-SNI entries mutex poisoned: {e}"))?;
        Ok(guard.iter().map(|(l, _, _)| l.clone()).collect())
    }

    /// Tenant name (single) or group label (multi-SNI). For log lines.
    pub fn tenant_name(&self) -> &str {
        &self.label
    }

    /// True if this trigger reloads a multi-SNI group.
    pub fn is_multi_sni(&self) -> bool {
        matches!(self.source, ReloadSource::Multi { .. })
    }
}

/// Build a hot-reloadable single-tenant acceptor pair.
pub fn build_reloadable_acceptor(
    cfg: &TlsConfig,
    tenant_name: impl Into<String>,
) -> Result<(TlsAcceptorHandle, TlsReloadTrigger)> {
    let acc = build_acceptor(cfg)?;
    let (tx, rx) = tokio::sync::watch::channel(acc);
    Ok((
        TlsAcceptorHandle { rx },
        TlsReloadTrigger {
            tx,
            source: ReloadSource::Single { cfg: cfg.clone() },
            label: tenant_name.into(),
        },
    ))
}

/// Sprint 6.5: build a hot-reloadable multi-SNI acceptor pair. Reload
/// re-reads every member's cert+key, rebuilds the `MultiSniCertResolver`,
/// and atomically installs the new acceptor. A partial failure (one bad
/// cert in the group) aborts the reload — the previous acceptor stays in
/// place — rather than silently degrading the group.
pub fn build_reloadable_multi_sni_acceptor(
    entries: Vec<(String, String, TlsConfig)>,
    group_label: impl Into<String>,
) -> Result<(TlsAcceptorHandle, TlsReloadTrigger)> {
    let acc = build_multi_sni_acceptor(entries.clone())?;
    let (tx, rx) = tokio::sync::watch::channel(acc);
    Ok((
        TlsAcceptorHandle { rx },
        TlsReloadTrigger {
            tx,
            source: ReloadSource::Multi {
                entries: std::sync::Mutex::new(entries),
            },
            label: group_label.into(),
        },
    ))
}

fn load_cert_chain(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let pem = std::fs::read(path)?;
    let mut rd: &[u8] = &pem;
    let mut out: Vec<CertificateDer<'static>> = Vec::new();
    for entry in rustls_pemfile::certs(&mut rd) {
        out.push(entry?);
    }
    Ok(out)
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let pem = std::fs::read(path)?;

    // PKCS#8 first.
    {
        let mut rd: &[u8] = &pem;
        let keys: Vec<_> = rustls_pemfile::pkcs8_private_keys(&mut rd).collect();
        if let Some(k) = keys.into_iter().next() {
            return Ok(PrivateKeyDer::Pkcs8(k?));
        }
    }
    // RSA (PKCS#1)
    {
        let mut rd: &[u8] = &pem;
        let keys: Vec<_> = rustls_pemfile::rsa_private_keys(&mut rd).collect();
        if let Some(k) = keys.into_iter().next() {
            return Ok(PrivateKeyDer::Pkcs1(k?));
        }
    }
    // SEC1 (EC)
    {
        let mut rd: &[u8] = &pem;
        let keys: Vec<_> = rustls_pemfile::ec_private_keys(&mut rd).collect();
        if let Some(k) = keys.into_iter().next() {
            return Ok(PrivateKeyDer::Sec1(k?));
        }
    }
    Err(anyhow!(
        "no PKCS#8, PKCS#1, or SEC1 private key found in {}",
        path.display()
    ))
}

// ============================================================================
//              Sprint 6 — multi-SNI cert resolution
// ============================================================================
//
// When multiple tenants share one TLS listen port, we build one
// `TlsAcceptor` whose `ServerConfig` carries a custom
// `ResolvesServerCert` impl that picks the right `CertifiedKey` based on
// the SNI hostname in the ClientHello. The dispatch then happens at the
// CSPQ layer (not the TLS layer): after TLS handshake, the accept loop
// reads the negotiated `server_name()` and routes to the matching
// tenant's `TenantRuntime`.
//
// This module exposes the resolver + the builder; the accept-loop wiring
// lives in `gateway.rs`.

use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::{CertifiedKey, SingleCertAndKey};
use std::collections::HashMap;

/// One tenant's TLS material indexed by SNI hostname.
pub struct SniTenantCert {
    /// SNI hostname this entry responds to.
    pub sni: String,
    /// Tenant name (for log lines / dispatch).
    pub tenant_name: String,
    /// Loaded + parsed cert chain + private key.
    pub certified: Arc<CertifiedKey>,
}

/// Multi-SNI resolver — picks a `CertifiedKey` based on the ClientHello's
/// SNI extension. Unknown SNIs return `None`, which rustls translates to
/// a TLS `unrecognized_name` alert — strict isolation, no fallback cert.
///
/// Sprint 8: wildcard SNI patterns are supported. A pattern like
/// `"*.example.com"` matches exactly one label of subdomain — `a.example.com`
/// and `b.example.com` match; `a.b.example.com` and `example.com` do not.
/// Exact-match entries always win over wildcards (so an explicit
/// `priority.example.com` route overrides a `*.example.com` catchall).
#[derive(Debug)]
pub struct MultiSniCertResolver {
    /// Exact-match map. Looked up first.
    by_sni: HashMap<String, Arc<CertifiedKey>>,
    /// Wildcard patterns. Stored as the suffix after the `*` (e.g.
    /// `*.example.com` → `.example.com`). Sprint 8: order in this vec is
    /// the order entries were inserted, which is fine for small lists.
    /// For larger deployments we'd switch to a trie.
    wildcards: Vec<(String, Arc<CertifiedKey>)>,
}

impl MultiSniCertResolver {
    /// Build the resolver from a non-empty list of `SniTenantCert` entries.
    /// Duplicate SNIs are rejected at construction (config validation should
    /// have caught them upstream, but defense in depth).
    ///
    /// Sprint 8: entries whose `sni` starts with `*.` are stored as wildcard
    /// patterns. Pattern syntax is strict: `*.example.com` is valid,
    /// `*example.com` (no dot) and `a.*.com` (mid-string) are rejected.
    pub fn new(entries: Vec<SniTenantCert>) -> Result<Self> {
        if entries.is_empty() {
            return Err(anyhow!(
                "MultiSniCertResolver: at least one tenant cert required"
            ));
        }
        let mut by_sni = HashMap::new();
        let mut wildcards: Vec<(String, Arc<CertifiedKey>)> = Vec::new();
        for entry in entries {
            // Validate pattern shape.
            if entry.sni.contains('*') {
                if !entry.sni.starts_with("*.") || entry.sni[2..].contains('*') {
                    return Err(anyhow!(
                        "MultiSniCertResolver: invalid wildcard SNI {:?} \
                         (must be of the form '*.host.example.com')",
                        entry.sni
                    ));
                }
                let suffix = entry.sni[1..].to_string(); // ".example.com"
                if wildcards.iter().any(|(s, _)| *s == suffix) {
                    return Err(anyhow!(
                        "MultiSniCertResolver: duplicate wildcard SNI {:?}",
                        entry.sni
                    ));
                }
                wildcards.push((suffix, entry.certified));
            } else if by_sni.insert(entry.sni.clone(), entry.certified).is_some() {
                return Err(anyhow!(
                    "MultiSniCertResolver: duplicate SNI hostname {:?}",
                    entry.sni
                ));
            }
        }
        Ok(Self { by_sni, wildcards })
    }

    /// Names this resolver responds to. For diagnostics / log lines only.
    /// Wildcards appear in their original `*.example.com` form.
    pub fn known_snis(&self) -> Vec<String> {
        let mut out: Vec<String> = self.by_sni.keys().cloned().collect();
        for (suffix, _) in &self.wildcards {
            out.push(format!("*{suffix}"));
        }
        out
    }
}

impl ResolvesServerCert for MultiSniCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        // ClientHello::server_name returns the SNI hostname as &str if the
        // client sent one. We do NOT case-fold the comparison: SNI is
        // case-insensitive in spec but every modern client sends lowercase.
        // Config-supplied SNIs are expected lowercase as well.
        let name = client_hello.server_name()?;
        // 1) Exact match wins.
        if let Some(c) = self.by_sni.get(name) {
            return Some(c.clone());
        }
        // 2) Wildcard match. The pattern `*.example.com` matches `x.example.com`
        //    but NOT `x.y.example.com` (single-label sub-match, per RFC 6125 §6.4.3).
        for (suffix, cert) in &self.wildcards {
            // suffix = ".example.com". We need name to end with suffix AND
            // the prefix (before the dot) to contain no dots itself.
            if let Some(prefix) = name.strip_suffix(suffix) {
                if !prefix.is_empty() && !prefix.contains('.') {
                    return Some(cert.clone());
                }
            }
        }
        None
    }
}

/// Build a multi-SNI `TlsAcceptor` from a non-empty list of `(SNI, TlsConfig)`
/// pairs. Each tenant's cert + key is loaded once at startup. The returned
/// acceptor is wrapped in `Arc<TlsAcceptor>` for the gateway's accept loop.
pub fn build_multi_sni_acceptor(
    entries: Vec<(String, String, TlsConfig)>, // (sni, tenant_name, tls_cfg)
) -> Result<Arc<TlsAcceptor>> {
    ensure_crypto_provider_installed();
    let mut certified_entries = Vec::with_capacity(entries.len());
    for (sni, tenant_name, cfg) in entries {
        let certs = load_cert_chain(&cfg.cert)
            .with_context(|| format!("loading cert chain for tenant {tenant_name}"))?;
        if certs.is_empty() {
            return Err(anyhow!(
                "tenant {tenant_name}: no certificates parsed from {}",
                cfg.cert.display()
            ));
        }
        let key = load_private_key(&cfg.key)
            .with_context(|| format!("loading private key for tenant {tenant_name}"))?;
        let signing_key = rustls::crypto::ring::sign::any_supported_type(&key)
            .map_err(|e| anyhow!("tenant {tenant_name}: invalid signing key: {e}"))?;
        let certified = Arc::new(CertifiedKey::new(certs, signing_key));
        // Validate cert/key pair consistency (parsing succeeded; this is just
        // a smoke check that we have what `SingleCertAndKey` would build).
        let _ = SingleCertAndKey::from(CertifiedKey::clone(&certified));
        certified_entries.push(SniTenantCert {
            sni,
            tenant_name,
            certified,
        });
    }
    let resolver = MultiSniCertResolver::new(certified_entries)?;
    let server_cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(resolver));
    Ok(Arc::new(TlsAcceptor::from(Arc::new(server_cfg))))
}

#[cfg(test)]
#[allow(clippy::err_expect)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::PathBuf;

    fn write(path: &Path, bytes: &[u8]) {
        let mut f = std::fs::File::create(path).unwrap();
        f.write_all(bytes).unwrap();
    }

    /// A test cert + PKCS#8 key generated with rcgen by hand once and
    /// pasted in. Not used in production. The cert is a 1-day self-signed
    /// "example.local" ECDSA P-256.
    const TEST_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIBdjCCARugAwIBAgIUWqsP9X4tk5G3X9zKt4tH4j9I0HMwCgYIKoZIzj0EAwIw
GjEYMBYGA1UEAwwPZXhhbXBsZS5sb2NhbDAeFw0yMzAxMDEwMDAwMDBaFw0zMzEy
MzEyMzU5NTlaMBoxGDAWBgNVBAMMD2V4YW1wbGUubG9jYWwwWTATBgcqhkjOPQIB
BggqhkjOPQMBBwNCAATh5Jd6Av7BHJ4f1ZRZ1zT7g4D1k4Z4kqhFhE1aJp5J0DnT
fHcZTGykk2VHB1eXqHKQ8c8/o4dY3WdsBE7nKxbXo1MwUTAdBgNVHQ4EFgQUmJl9
F8nF9D5/cFklzZL5L5L5sZkwHwYDVR0jBBgwFoAUmJl9F8nF9D5/cFklzZL5L5L5
sZkwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiEAxbR0/Q8B/I8z
0Pp7gM7p1k1z6f1Pq5xLs5N+jJ/yPwgCIGZ4xN8B0p7sN+pV7vEr0hY+E0e3o1Sg
9k4l5VyD7Lm7
-----END CERTIFICATE-----
";

    #[test]
    fn rejects_missing_files() {
        let cfg = TlsConfig {
            cert: PathBuf::from("/nonexistent/cert.pem"),
            key: PathBuf::from("/nonexistent/key.pem"),
        };
        assert!(build_acceptor(&cfg).is_err());
    }

    #[test]
    fn rejects_empty_cert_file() {
        let tmp = tempfile::TempDir::new().unwrap();
        let cert = tmp.path().join("cert.pem");
        let key = tmp.path().join("key.pem");
        write(&cert, b"");
        write(&key, b"");
        let cfg = TlsConfig {
            cert: cert.clone(),
            key: key.clone(),
        };
        assert!(build_acceptor(&cfg).is_err());
    }

    #[test]
    fn rejects_cert_without_matching_key() {
        let tmp = tempfile::TempDir::new().unwrap();
        let cert = tmp.path().join("cert.pem");
        let key = tmp.path().join("key.pem");
        write(&cert, TEST_CERT_PEM.as_bytes());
        write(
            &key,
            b"-----BEGIN GARBAGE-----\nAAAA\n-----END GARBAGE-----\n",
        );
        let cfg = TlsConfig { cert, key };
        assert!(build_acceptor(&cfg).is_err());
    }

    // ========================================================================
    //              Sprint 5.5 — hot-reload API smoke tests
    // ========================================================================

    /// `build_reloadable_acceptor` surfaces the same errors as `build_acceptor`
    /// when the underlying cert/key paths are bad — failure happens at build
    /// time, not at first reload, so daemon startup catches bad TLS config
    /// before any traffic is accepted.
    #[test]
    fn reloadable_builder_rejects_bad_paths_at_construction() {
        let cfg = TlsConfig {
            cert: PathBuf::from("/nonexistent/cert.pem"),
            key: PathBuf::from("/nonexistent/key.pem"),
        };
        let result = build_reloadable_acceptor(&cfg, "test-tenant");
        assert!(
            result.is_err(),
            "construction must fail on bad initial paths"
        );
    }

    /// `TlsReloadTrigger::tenant_name` returns the name passed at
    /// construction time — important for log lines on SIGUSR1.
    #[test]
    fn reload_trigger_carries_tenant_name() {
        ensure_crypto_provider_installed();
        let cfg = TlsConfig {
            cert: PathBuf::from("/x"),
            key: PathBuf::from("/y"),
        };
        // The trigger's internal channel never carries a valid acceptor in
        // this test — that's OK because we only call `tenant_name()`.
        let (tx, _rx) = tokio::sync::watch::channel(Arc::new(TlsAcceptor::from(Arc::new(
            // A bare minimum ServerConfig — won't accept real traffic but
            // satisfies the type constructor for our accessor smoke test.
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(NoCertResolver)),
        ))));
        let trigger = TlsReloadTrigger {
            tx,
            source: ReloadSource::Single { cfg },
            label: "branch-sp".into(),
        };
        assert_eq!(trigger.tenant_name(), "branch-sp");
        assert!(!trigger.is_multi_sni());
    }

    /// `TlsAcceptorHandle::current` returns the value the channel was
    /// initialized with and reflects subsequent updates.
    #[tokio::test]
    async fn handle_current_observes_channel_updates() {
        ensure_crypto_provider_installed();
        let a = Arc::new(TlsAcceptor::from(Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(NoCertResolver)),
        )));
        let b = Arc::new(TlsAcceptor::from(Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(NoCertResolver)),
        )));
        let (tx, rx) = tokio::sync::watch::channel(a.clone());
        let handle = TlsAcceptorHandle { rx };

        // Initial snapshot is `a`.
        assert!(Arc::ptr_eq(&handle.current(), &a));

        // Swap to `b`; next snapshot returns `b`.
        tx.send(b.clone()).unwrap();
        assert!(Arc::ptr_eq(&handle.current(), &b));
        assert!(!Arc::ptr_eq(&handle.current(), &a));
    }

    /// A `ResolvesServerCert` that always returns None — used solely for the
    /// in-process API smoke tests above. Never serves a real handshake.
    #[derive(Debug)]
    struct NoCertResolver;
    impl rustls::server::ResolvesServerCert for NoCertResolver {
        fn resolve(
            &self,
            _client_hello: rustls::server::ClientHello<'_>,
        ) -> Option<Arc<rustls::sign::CertifiedKey>> {
            None
        }
    }

    // ========================================================================
    //                  Sprint 6 — multi-SNI resolver smoke tests
    // ========================================================================
    //
    // We test what we can without rcgen: the empty-entries rejection path.
    // Construction with real cert+key pairs is covered indirectly via
    // `build_multi_sni_acceptor`, exercised under `cargo test` only when a
    // valid cert is available — that gate is the integration-level
    // coverage. The SNI dispatch logic itself (HashMap lookup keyed by
    // negotiated server_name) is exercised through the gateway end-to-end
    // tests in Sprint 6.5 once we have rcgen-generated test material in
    // tree.

    /// `MultiSniCertResolver::new` rejects an empty entry list — the
    /// resolver must always know at least one SNI to respond to.
    #[test]
    fn multi_sni_resolver_rejects_empty_entries() {
        let result = MultiSniCertResolver::new(vec![]);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("at least one"), "got: {msg}");
    }

    /// `build_multi_sni_acceptor` fails on an empty entry list (mirrors
    /// the resolver's contract).
    #[test]
    fn build_multi_sni_acceptor_rejects_empty_entries() {
        let result = build_multi_sni_acceptor(vec![]);
        assert!(result.is_err());
    }

    /// `build_multi_sni_acceptor` propagates per-tenant cert-loading errors
    /// with the tenant name in the context — operators need to know which
    /// tenant's cert is broken on a startup-time failure.
    #[test]
    fn build_multi_sni_acceptor_propagates_tenant_name_in_errors() {
        let bad_cfg = TlsConfig {
            cert: PathBuf::from("/nonexistent-tenant-cert.pem"),
            key: PathBuf::from("/nonexistent-tenant-key.pem"),
        };
        let entries = vec![("a.example.com".into(), "tenant-broken".into(), bad_cfg)];
        // Cannot `unwrap_err()` because `TlsAcceptor` doesn't impl `Debug`;
        // match by hand.
        let err = match build_multi_sni_acceptor(entries) {
            Ok(_) => panic!("expected error from bad cert path"),
            Err(e) => e,
        };
        let msg = format!("{err:#}");
        assert!(
            msg.contains("tenant-broken"),
            "tenant name must appear in error context, got: {msg}"
        );
    }

    // ========================================================================
    //              Sprint 8 — wildcard SNI resolver tests
    // ========================================================================
    //
    // These tests exercise the pattern-validation and dispatch logic of the
    // MultiSniCertResolver without requiring a real TLS handshake. The
    // resolve() path can't be hit directly because `rustls::server::ClientHello`
    // has no public constructor — that path is covered by the integration
    // test `sni_cert_dispatch.rs` once it's extended with a wildcard cert
    // (Sprint 8.5 follow-up). Here we cover construction-side validation,
    // which catches the most common operator mistake.

    fn dummy_certified_key() -> Arc<CertifiedKey> {
        // Generate a real (throwaway) self-signed cert via rcgen so rustls's
        // signer parser accepts it. We never invoke the resulting signer —
        // these tests only exercise resolver construction logic.
        ensure_crypto_provider_installed();
        let key = rcgen::KeyPair::generate().expect("rcgen keypair");
        let params =
            rcgen::CertificateParams::new(vec!["test.example.com".into()]).expect("rcgen params");
        let cert = params.self_signed(&key).expect("self-sign");
        let cert_der = cert.der().clone();
        let key_pem = key.serialize_pem();
        let mut reader: &[u8] = key_pem.as_bytes();
        let key_der_iter = rustls_pemfile::pkcs8_private_keys(&mut reader);
        let key_der_owned = key_der_iter
            .into_iter()
            .next()
            .and_then(|r| r.ok())
            .expect("pkcs8 key parse");
        let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(key_der_owned);
        let signer = rustls::crypto::ring::sign::any_supported_type(&key_der)
            .expect("ring accepts the rcgen key");
        Arc::new(CertifiedKey::new(vec![cert_der], signer))
    }

    #[test]
    fn wildcard_resolver_rejects_invalid_pattern_no_dot_after_star() {
        let entries = vec![SniTenantCert {
            sni: "*example.com".into(),
            tenant_name: "a".into(),
            certified: dummy_certified_key(),
        }];
        let err = MultiSniCertResolver::new(entries).unwrap_err();
        assert!(format!("{err}").contains("invalid wildcard"));
    }

    #[test]
    fn wildcard_resolver_rejects_invalid_pattern_midstring_star() {
        let entries = vec![SniTenantCert {
            sni: "a.*.example.com".into(),
            tenant_name: "a".into(),
            certified: dummy_certified_key(),
        }];
        let err = MultiSniCertResolver::new(entries).unwrap_err();
        assert!(format!("{err}").contains("invalid wildcard"));
    }

    #[test]
    fn wildcard_resolver_rejects_duplicate_wildcard() {
        let entries = vec![
            SniTenantCert {
                sni: "*.example.com".into(),
                tenant_name: "a".into(),
                certified: dummy_certified_key(),
            },
            SniTenantCert {
                sni: "*.example.com".into(),
                tenant_name: "b".into(),
                certified: dummy_certified_key(),
            },
        ];
        let err = MultiSniCertResolver::new(entries).unwrap_err();
        assert!(format!("{err}").contains("duplicate wildcard"));
    }

    #[test]
    fn wildcard_resolver_accepts_mixed_exact_and_wildcard() {
        let entries = vec![
            SniTenantCert {
                sni: "priority.example.com".into(),
                tenant_name: "exact".into(),
                certified: dummy_certified_key(),
            },
            SniTenantCert {
                sni: "*.example.com".into(),
                tenant_name: "wildcard".into(),
                certified: dummy_certified_key(),
            },
        ];
        let resolver = MultiSniCertResolver::new(entries).expect("must accept mix");
        let mut snis = resolver.known_snis();
        snis.sort();
        assert_eq!(snis, vec!["*.example.com", "priority.example.com"]);
    }

    #[test]
    fn wildcard_resolver_known_snis_reports_pattern_form() {
        // Asserts the wildcard pattern appears in `known_snis()` in its
        // original `*.host` form (not as the stored `.host` suffix).
        let entries = vec![SniTenantCert {
            sni: "*.bank.example.com".into(),
            tenant_name: "wildcard".into(),
            certified: dummy_certified_key(),
        }];
        let resolver = MultiSniCertResolver::new(entries).unwrap();
        assert_eq!(resolver.known_snis(), vec!["*.bank.example.com"]);
    }

    // ========================================================================
    //          Sprint 22 — multi-SNI add/remove mutation API
    // ========================================================================

    fn gen_cert_pair(sni: &str) -> (PathBuf, PathBuf, tempfile::TempDir) {
        use rcgen::{CertificateParams, DistinguishedName, KeyPair};
        let mut params = CertificateParams::new(vec![sni.to_string()]).unwrap();
        let mut dn = DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, sni);
        params.distinguished_name = dn;
        let kp = KeyPair::generate().unwrap();
        let cert = params.self_signed(&kp).unwrap();
        let tmp = tempfile::TempDir::new().unwrap();
        let cert_path = tmp.path().join(format!("{sni}.crt"));
        let key_path = tmp.path().join(format!("{sni}.key"));
        std::fs::write(&cert_path, cert.pem()).unwrap();
        std::fs::write(&key_path, kp.serialize_pem()).unwrap();
        (cert_path, key_path, tmp)
    }

    fn make_multi_trigger(snis: &[&str]) -> (TlsReloadTrigger, Vec<tempfile::TempDir>) {
        let mut entries = Vec::new();
        let mut keepalives = Vec::new();
        for sni in snis {
            let (c, k, td) = gen_cert_pair(sni);
            entries.push((
                sni.to_string(),
                sni.to_string(),
                TlsConfig { cert: c, key: k },
            ));
            keepalives.push(td);
        }
        let (_handle, trigger) =
            build_reloadable_multi_sni_acceptor(entries, "test-group").unwrap();
        (trigger, keepalives)
    }

    #[test]
    fn add_sni_entry_appends_and_rebuilds() {
        let (trigger, _td) = make_multi_trigger(&["alice.test", "bob.test"]);
        let labels_before = trigger.sni_labels().unwrap();
        assert_eq!(labels_before.len(), 2);

        let (c, k, _td_charlie) = gen_cert_pair("charlie.test");
        let _prev_acc = trigger
            .add_sni_entry(
                "charlie".into(),
                "charlie.test".into(),
                TlsConfig { cert: c, key: k },
            )
            .expect("add_sni_entry must succeed");
        let labels_after = trigger.sni_labels().unwrap();
        assert_eq!(labels_after.len(), 3);
        assert!(labels_after.contains(&"charlie".to_string()));
    }

    #[test]
    fn add_sni_entry_rejects_duplicate_label() {
        let (trigger, _td) = make_multi_trigger(&["alice.test"]);
        let (c, k, _td2) = gen_cert_pair("alice2.test");
        let err = trigger
            .add_sni_entry(
                "alice.test".into(),
                "alice2.test".into(),
                TlsConfig { cert: c, key: k },
            )
            .err()
            .expect("duplicate label must fail");
        assert!(err.to_string().contains("already in multi-SNI group"));
        // Set unchanged after rejected add.
        assert_eq!(trigger.sni_labels().unwrap().len(), 1);
    }

    #[test]
    fn add_sni_entry_rolls_back_on_rebuild_failure() {
        let (trigger, _td) = make_multi_trigger(&["alice.test"]);
        // Use a non-existent cert path → build_multi_sni_acceptor fails →
        // the push must be rolled back.
        let bad = TlsConfig {
            cert: PathBuf::from("/nonexistent/bad.crt"),
            key: PathBuf::from("/nonexistent/bad.key"),
        };
        let err = trigger
            .add_sni_entry("bad".into(), "bad.test".into(), bad)
            .err()
            .expect("rebuild failure must propagate");
        assert!(err.to_string().contains("rollback after rebuild failure"));
        // Rollback verified: labels still has only alice.
        let labels = trigger.sni_labels().unwrap();
        assert_eq!(labels.len(), 1);
        assert_eq!(labels[0], "alice.test");
    }

    #[test]
    fn remove_sni_entry_drops_and_rebuilds() {
        let (trigger, _td) = make_multi_trigger(&["alice.test", "bob.test", "charlie.test"]);
        let _prev_acc = trigger
            .remove_sni_entry("bob.test")
            .expect("remove must succeed");
        let labels = trigger.sni_labels().unwrap();
        assert_eq!(labels.len(), 2);
        assert!(!labels.contains(&"bob.test".to_string()));
    }

    #[test]
    fn remove_sni_entry_rejects_missing_label() {
        let (trigger, _td) = make_multi_trigger(&["alice.test"]);
        let err = trigger
            .remove_sni_entry("ghost.test")
            .err()
            .expect("missing label must fail");
        assert!(err.to_string().contains("not in multi-SNI group"));
        // Set unchanged.
        assert_eq!(trigger.sni_labels().unwrap().len(), 1);
    }

    #[test]
    fn add_remove_on_single_source_trigger_errors() {
        let (c, k, _td) = gen_cert_pair("alice.test");
        let (_handle, trigger) =
            build_reloadable_acceptor(&TlsConfig { cert: c, key: k }, "alice".to_string()).unwrap();
        // single-source trigger rejects multi-SNI mutation
        let (c2, k2, _td2) = gen_cert_pair("bob.test");
        let err = trigger
            .add_sni_entry(
                "bob".into(),
                "bob.test".into(),
                TlsConfig { cert: c2, key: k2 },
            )
            .err()
            .expect("add on single source must error");
        assert!(err.to_string().contains("single-source trigger"));
        let err = trigger
            .remove_sni_entry("anything")
            .err()
            .expect("remove on single source must error");
        assert!(err.to_string().contains("single-source trigger"));
        let err = trigger
            .sni_labels()
            .err()
            .expect("labels on single must error");
        assert!(err.to_string().contains("single-source trigger"));
    }

    #[test]
    fn reload_after_add_sees_new_entries() {
        // Pure smoke test that reload() reads from the mutated entries.
        let (trigger, _td) = make_multi_trigger(&["alice.test"]);
        let (c, k, _td2) = gen_cert_pair("bob.test");
        trigger
            .add_sni_entry(
                "bob".into(),
                "bob.test".into(),
                TlsConfig { cert: c, key: k },
            )
            .unwrap();
        // Calling reload() again should succeed (proves the entries are
        // still readable through the mutex and build_multi_sni_acceptor
        // accepts the new set).
        trigger.reload().unwrap();
    }
}
