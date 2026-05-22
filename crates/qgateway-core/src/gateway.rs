//! Accept loops for QGateway tenants (Sprint 4 — multi-tenant + TLS).
//!
//! Each function runs ONE tenant; the daemon spawns N of these per config.

use crate::audit::AuditHandle;
use crate::config::{ServePqTenant, ServeTcpTenant};
use crate::metrics::MetricsRegistry;
use crate::proxy::{run_session, Direction};
use crate::tls::TlsAcceptorHandle;
use anyhow::{anyhow, Context, Result};
use qtransport_cspq::{accept, connect, IdentityKey, PeerPolicy};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};

/// serve-tcp tenant accept loop: accept local TCP, optionally terminate TLS,
/// dial peer over CSPQ, proxy.
#[allow(clippy::too_many_arguments)]
pub async fn run_serve_tcp_tenant(
    tenant: ServeTcpTenant,
    identity: Arc<IdentityKey>,
    peer_policy: Arc<PeerPolicy>,
    audit: AuditHandle,
    metrics: MetricsRegistry,
    shutdown: Arc<Notify>,
    tls: Option<TlsAcceptorHandle>,
    // Sprint 16 (Stage B): optional shared admission controller. When
    // `None`, the loop builds one internally from `tenant.limits` (the
    // existing Sprint-9.5 path). When `Some`, the caller passes a shared
    // `Arc<HotAdmissionController>` whose `swap()` method can be called
    // from the SIGHUP arm to hot-apply `[tenants.limits]` changes
    // without restarting the accept loop. Both shapes use the same
    // `check(peer)` call inside the loop, so the hot path is unchanged.
    admission_override: Option<Arc<crate::HotAdmissionController>>,
) -> Result<()> {
    let listener = TcpListener::bind(&tenant.listen)
        .await
        .with_context(|| format!("binding {} for tenant {}", tenant.listen, tenant.id.name))?;
    info!(
        tenant = %tenant.id.name,
        listen  = %tenant.listen,
        peer_pq = %tenant.peer_pq,
        tls = tls.is_some(),
        admission_shared = admission_override.is_some(),
        "serve-tcp tenant active"
    );

    // Sprint 9.5 / 16: build admission controller from tenant config OR
    // accept a shared one from the caller for hot-reconfigure.
    let admission = admission_override.unwrap_or_else(|| build_admission(&tenant.limits));

    loop {
        tokio::select! {
            biased;
            _ = shutdown.notified() => {
                info!(tenant = %tenant.id.name, "serve-tcp shutdown requested");
                return Ok(());
            }
            accept_res = listener.accept() => {
                let (tcp, who) = match accept_res {
                    Ok(x) => x,
                    Err(e) => {
                        warn!(tenant = %tenant.id.name, "accept failed: {e}");
                        continue;
                    }
                };
                // Sprint 9.5: admission check BEFORE spawning anything.
                // Rejected connections are dropped immediately (TCP RST on
                // the kernel side when `tcp` is dropped) and counted in
                // tenant metrics.
                let permit = match admission.check(who.ip()) {
                    crate::admission::Admit::Ok(p) => p,
                    crate::admission::Admit::Reject(reason) => {
                        record_admission_reject(&metrics, reason);
                        drop(tcp);
                        continue;
                    }
                };
                let tenant = tenant.clone();
                let identity = identity.clone();
                let peer_policy = peer_policy.clone();
                let audit = audit.clone();
                let metrics = metrics.clone();
                // Snapshot the current acceptor for this connection. Hot-
                // reload after this point won't affect this handshake; the
                // next accept picks up the new one.
                let tls_acceptor = tls.as_ref().map(|h| h.current());
                tokio::spawn(async move {
                    // Sprint 9.5: hold the permit for the session lifetime.
                    // Dropping it releases the quota slot.
                    let _permit = permit;
                    if let Err(e) = handle_serve_tcp_session(
                        tcp, who.to_string(), tenant, identity, peer_policy, audit, metrics, tls_acceptor,
                    ).await {
                        warn!("serve-tcp session error from {who}: {e:#}");
                    }
                });
            }
        }
    }
}

/// Sprint 9.5: build an `AdmissionController` from optional tenant limits.
/// Sprint 15: returns `HotAdmissionController` so the SIGHUP apply step
/// can swap the inner controller without restarting the tenant task.
fn build_admission(
    limits: &Option<crate::config::TenantLimits>,
) -> Arc<crate::HotAdmissionController> {
    let (mc, rl) = match limits {
        Some(l) => (
            l.max_concurrent,
            l.rate_limit_per_source
                .as_ref()
                .map(crate::RateLimitConfig::from),
        ),
        None => (None, None),
    };
    Arc::new(crate::HotAdmissionController::new(mc, rl))
}

/// Sprint 9.5: bump the right rejection counter on the tenant's metrics.
fn record_admission_reject(metrics: &MetricsRegistry, reason: crate::admission::RejectReason) {
    use crate::admission::RejectReason;
    use std::sync::atomic::Ordering;
    match reason {
        RejectReason::Quota => {
            metrics
                .inner()
                .admission_rejected_quota
                .fetch_add(1, Ordering::Relaxed);
        }
        RejectReason::Rate => {
            metrics
                .inner()
                .admission_rejected_rate
                .fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_serve_tcp_session(
    tcp: TcpStream,
    who: String,
    tenant: ServeTcpTenant,
    identity: Arc<IdentityKey>,
    peer_policy: Arc<PeerPolicy>,
    audit: AuditHandle,
    metrics: MetricsRegistry,
    tls_acceptor: Option<Arc<TlsAcceptor>>,
) -> Result<()> {
    let _ = tcp.set_nodelay(true);
    let hs_started = Instant::now();
    let peer_tcp = TcpStream::connect(&tenant.peer_pq)
        .await
        .with_context(|| format!("dialing peer {}", tenant.peer_pq))?;
    let _ = peer_tcp.set_nodelay(true);

    let cspq = match connect(peer_tcp, &identity, &peer_policy).await {
        Ok(s) => s,
        Err(e) => {
            metrics
                .inner()
                .sessions_failed
                .fetch_add(1, Ordering::Relaxed);
            return Err(anyhow!("CSPQ handshake to peer failed: {e}"));
        }
    };
    let handshake_elapsed = hs_started.elapsed();
    info!(
        tenant = %tenant.id.name,
        from = %who,
        to = %tenant.peer_pq,
        handshake_ms = handshake_elapsed.as_millis() as u64,
        "serve-tcp session established"
    );

    // Either pass the plain TCP stream, or the TLS-wrapped one. Both impl
    // AsyncRead+AsyncWrite, and run_session is generic over the local type.
    match tls_acceptor {
        Some(acc) => {
            let tls_stream = acc.accept(tcp).await.context("TLS handshake failed")?;
            run_session(
                tls_stream,
                cspq,
                Direction::AppToPeer,
                &tenant.id.name,
                who,
                &audit,
                &metrics,
                handshake_elapsed,
            )
            .await;
        }
        None => {
            run_session(
                tcp,
                cspq,
                Direction::AppToPeer,
                &tenant.id.name,
                who,
                &audit,
                &metrics,
                handshake_elapsed,
            )
            .await;
        }
    }
    Ok(())
}

/// serve-pq tenant accept loop: accept inbound peer CSPQ, dial backend TCP, proxy.
#[allow(clippy::too_many_arguments)]
pub async fn run_serve_pq_tenant(
    tenant: ServePqTenant,
    identity: Arc<IdentityKey>,
    peer_policy: Arc<PeerPolicy>,
    audit: AuditHandle,
    metrics: MetricsRegistry,
    shutdown: Arc<Notify>,
    // Sprint 16 (Stage B): same opt-in shared admission controller as
    // `run_serve_tcp_tenant`. See that function's doc comment for the
    // shape and rationale.
    admission_override: Option<Arc<crate::HotAdmissionController>>,
) -> Result<()> {
    let listener = TcpListener::bind(&tenant.listen)
        .await
        .with_context(|| format!("binding {} for tenant {}", tenant.listen, tenant.id.name))?;
    info!(
        tenant = %tenant.id.name,
        listen = %tenant.listen,
        backend = %tenant.backend,
        admission_shared = admission_override.is_some(),
        "serve-pq tenant active"
    );

    // Sprint 9.5 / 16: same admission control as serve-tcp.
    let admission = admission_override.unwrap_or_else(|| build_admission(&tenant.limits));

    loop {
        tokio::select! {
            biased;
            _ = shutdown.notified() => {
                info!(tenant = %tenant.id.name, "serve-pq shutdown requested");
                return Ok(());
            }
            accept_res = listener.accept() => {
                let (tcp, who) = match accept_res {
                    Ok(x) => x,
                    Err(e) => {
                        warn!(tenant = %tenant.id.name, "accept failed: {e}");
                        continue;
                    }
                };
                let permit = match admission.check(who.ip()) {
                    crate::admission::Admit::Ok(p) => p,
                    crate::admission::Admit::Reject(reason) => {
                        record_admission_reject(&metrics, reason);
                        drop(tcp);
                        continue;
                    }
                };
                let tenant = tenant.clone();
                let identity = identity.clone();
                let peer_policy = peer_policy.clone();
                let audit = audit.clone();
                let metrics = metrics.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(e) = handle_serve_pq_session(
                        tcp, who.to_string(), tenant, identity, peer_policy, audit, metrics
                    ).await {
                        warn!("serve-pq session error from {who}: {e:#}");
                    }
                });
            }
        }
    }
}

async fn handle_serve_pq_session(
    peer_tcp: TcpStream,
    who: String,
    tenant: ServePqTenant,
    identity: Arc<IdentityKey>,
    peer_policy: Arc<PeerPolicy>,
    audit: AuditHandle,
    metrics: MetricsRegistry,
) -> Result<()> {
    let _ = peer_tcp.set_nodelay(true);
    let hs_started = Instant::now();
    let cspq = match accept(peer_tcp, &identity, &peer_policy).await {
        Ok(s) => s,
        Err(e) => {
            metrics
                .inner()
                .sessions_failed
                .fetch_add(1, Ordering::Relaxed);
            error!(
                tenant = %tenant.id.name,
                "CSPQ handshake from peer {who} failed: {e}"
            );
            return Err(anyhow!("CSPQ handshake from peer failed: {e}"));
        }
    };
    let handshake_elapsed = hs_started.elapsed();

    let backend_tcp = TcpStream::connect(&tenant.backend)
        .await
        .with_context(|| format!("dialing backend {}", tenant.backend))?;
    let _ = backend_tcp.set_nodelay(true);
    info!(
        tenant = %tenant.id.name,
        from = %who,
        backend = %tenant.backend,
        handshake_ms = handshake_elapsed.as_millis() as u64,
        "serve-pq session established"
    );

    run_session(
        backend_tcp,
        cspq,
        Direction::PeerToBackend,
        &tenant.id.name,
        who,
        &audit,
        &metrics,
        handshake_elapsed,
    )
    .await;
    Ok(())
}

// ============================================================================
//                  Sprint 6 — SNI tenant dispatch
// ============================================================================
//
// Multiple tenants sharing a listen address are served by ONE accept loop
// that owns a multi-SNI `TlsAcceptor`. Per-tenant context (peer policy,
// metrics, audit handle, ServeTcpTenant) lives in a `SniDispatchTable`
// keyed by SNI hostname. After TLS handshake completes, the loop reads the
// negotiated server_name and looks up the corresponding tenant context.

use std::collections::HashMap;

/// Per-tenant runtime context for SNI dispatch. One of these lives in the
/// dispatch table for every tenant in a multi-SNI group.
#[derive(Clone)]
pub struct SniTenantContext {
    /// Resolved tenant — peer_pq dial address, audit log path, etc.
    pub tenant: ServeTcpTenant,
    /// Trust scope for inbound CSPQ.
    pub peer_policy: Arc<PeerPolicy>,
    /// Audit channel handle.
    pub audit: AuditHandle,
    /// Metrics registry (per-tenant `tenant=` label).
    pub metrics: MetricsRegistry,
    /// Sprint 9.5: per-tenant admission controller. Shared across all
    /// concurrent SNI dispatches into this tenant. Built once when the
    /// context is constructed in main.rs.
    pub admission: Arc<crate::HotAdmissionController>,
}

/// Dispatch table — maps SNI hostname to the tenant context that handles it.
/// Built once at startup; immutable during the lifetime of the listener.
///
/// Sprint 8: wildcard tenants (with `sni = "*.example.com"`) live in a
/// parallel suffix list, looked up only when exact-match misses. Exact
/// matches always win over wildcards.
#[derive(Clone)]
pub struct SniDispatchTable {
    by_sni: Arc<HashMap<String, SniTenantContext>>,
    wildcards: Arc<Vec<(String, SniTenantContext)>>,
}

impl SniDispatchTable {
    /// Build from a slice of per-tenant contexts. Duplicate SNIs are caught
    /// by upstream config validation; we double-check here for defense in
    /// depth.
    pub fn new(contexts: Vec<SniTenantContext>) -> Result<Self> {
        let mut by_sni: HashMap<String, SniTenantContext> = HashMap::new();
        let mut wildcards: Vec<(String, SniTenantContext)> = Vec::new();
        for ctx in contexts {
            let sni = ctx
                .tenant
                .sni
                .as_ref()
                .ok_or_else(|| anyhow!("tenant {} has no sni", ctx.tenant.id.name))?
                .clone();
            if sni.starts_with("*.") {
                let suffix = sni[1..].to_string();
                if wildcards.iter().any(|(s, _)| *s == suffix) {
                    return Err(anyhow!("duplicate wildcard SNI in dispatch table: {sni}"));
                }
                wildcards.push((suffix, ctx));
            } else {
                if by_sni.insert(sni.clone(), ctx).is_some() {
                    return Err(anyhow!("duplicate SNI in dispatch table: {sni}"));
                }
            }
        }
        Ok(Self {
            by_sni: Arc::new(by_sni),
            wildcards: Arc::new(wildcards),
        })
    }

    /// Look up the tenant responsible for a negotiated SNI. Returns `None`
    /// if no tenant claims this hostname. Exact matches take priority over
    /// wildcards.
    pub fn lookup(&self, sni: &str) -> Option<&SniTenantContext> {
        if let Some(c) = self.by_sni.get(sni) {
            return Some(c);
        }
        for (suffix, ctx) in self.wildcards.iter() {
            if let Some(prefix) = sni.strip_suffix(suffix) {
                if !prefix.is_empty() && !prefix.contains('.') {
                    return Some(ctx);
                }
            }
        }
        None
    }

    /// Sprint 21: build a new table with one additional tenant context.
    /// Used by the SIGHUP apply step to compute a successor table before
    /// swapping it into the hot wrapper. Returns Err on duplicate SNI
    /// (exact or wildcard).
    pub fn with_tenant_added(&self, ctx: SniTenantContext) -> Result<Self> {
        let sni = ctx
            .tenant
            .sni
            .as_ref()
            .ok_or_else(|| anyhow!("tenant {} has no sni", ctx.tenant.id.name))?
            .clone();
        let mut by_sni: HashMap<String, SniTenantContext> = (*self.by_sni).clone();
        let mut wildcards: Vec<(String, SniTenantContext)> = (*self.wildcards).clone();
        if sni.starts_with("*.") {
            let suffix = sni[1..].to_string();
            if wildcards.iter().any(|(s, _)| *s == suffix) {
                return Err(anyhow!("duplicate wildcard SNI: {sni}"));
            }
            wildcards.push((suffix, ctx));
        } else if by_sni.insert(sni.clone(), ctx).is_some() {
            return Err(anyhow!("duplicate SNI: {sni}"));
        }
        Ok(Self {
            by_sni: Arc::new(by_sni),
            wildcards: Arc::new(wildcards),
        })
    }

    /// Sprint 21: build a new table without the named tenant. Returns
    /// `None` if the tenant wasn't in the table — caller can distinguish
    /// "already absent" from "successfully removed". Walks both the
    /// exact-match map and the wildcard list (only one will contain
    /// the tenant — the SNI string determines which).
    pub fn with_tenant_removed(&self, tenant_name: &str) -> Option<Self> {
        let mut by_sni: HashMap<String, SniTenantContext> = (*self.by_sni).clone();
        let mut wildcards: Vec<(String, SniTenantContext)> = (*self.wildcards).clone();
        let initial_by_sni_len = by_sni.len();
        let initial_wildcards_len = wildcards.len();
        by_sni.retain(|_, ctx| ctx.tenant.id.name != tenant_name);
        wildcards.retain(|(_, ctx)| ctx.tenant.id.name != tenant_name);
        if by_sni.len() == initial_by_sni_len && wildcards.len() == initial_wildcards_len {
            return None;
        }
        Some(Self {
            by_sni: Arc::new(by_sni),
            wildcards: Arc::new(wildcards),
        })
    }

    /// Sprint 21: enumerate the tenant names currently in the table.
    /// Useful for the SIGHUP apply step's diff computation when an SNI
    /// group is the affected target. Order is not stable across calls
    /// (HashMap iteration); callers needing stable order should sort.
    pub fn tenant_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .by_sni
            .values()
            .map(|c| c.tenant.id.name.clone())
            .collect();
        names.extend(self.wildcards.iter().map(|(_, c)| c.tenant.id.name.clone()));
        names
    }
}

/// Sprint 21: hot-swappable wrapper around `SniDispatchTable`. The SNI
/// accept loop reads via `arc_swap::ArcSwap::load()` — single atomic
/// pointer load on x86_64, no contention with writers. The SIGHUP apply
/// step calls `swap()` to install a new table after computing it via
/// `SniDispatchTable::with_tenant_added` / `with_tenant_removed`.
///
/// Swap semantics:
/// - In-flight handshakes that already resolved their SNI via the OLD
///   table continue with the old context. The dispatch only happens
///   ONCE per connection (immediately after TLS negotiation completes),
///   so an in-flight session running with an old tenant context is
///   normal and expected — that session's audit log, peer policy, and
///   admission permits are all tied to the OLD tenant's identity.
/// - New TLS handshakes after `swap()` see the new table.
/// - Removing a tenant from the table does NOT drain its in-flight
///   sessions — those continue under the OLD context until they end
///   naturally. To drain, the operator must remove the tenant fully
///   (which still requires per-tenant shutdown notify — Sprint 22+).
///
/// Sprint 21 ships the type and its tests; wiring into `run_sni_group`
/// + the SIGHUP arm is Sprint 22 work.
pub struct HotSniDispatchTable {
    inner: arc_swap::ArcSwap<SniDispatchTable>,
}

impl HotSniDispatchTable {
    /// Build a hot-swappable wrapper from an initial dispatch table.
    pub fn new(initial: SniDispatchTable) -> Self {
        Self {
            inner: arc_swap::ArcSwap::from_pointee(initial),
        }
    }

    /// Hot-path: load the currently-installed table. Callers use
    /// `.lookup()` on the returned guard. The Arc clone inside ArcSwap
    /// keeps the table alive even if a concurrent swap drops the
    /// previous one.
    pub fn load(&self) -> arc_swap::Guard<Arc<SniDispatchTable>> {
        self.inner.load()
    }

    /// Sprint 21: atomically replace the inner table. Returns the old
    /// table as Arc for caller inspection or drop. New table must be
    /// pre-built via `SniDispatchTable::with_tenant_added` /
    /// `with_tenant_removed` so this call is infallible.
    pub fn swap(&self, new_table: SniDispatchTable) -> Arc<SniDispatchTable> {
        self.inner.swap(Arc::new(new_table))
    }
}

/// Run one SNI-dispatching accept loop. Binds once on `listen`, runs every
/// inbound TLS handshake through `tls_handle.current()`, then dispatches
/// to the per-tenant context based on the negotiated SNI.
///
/// Hot-reload (Sprint 5.5) still works: the `tls_handle` is shared with
/// the SIGUSR1 path, so SIGUSR1 swaps the multi-SNI acceptor atomically.
pub async fn run_sni_group(
    listen: String,
    tls_handle: TlsAcceptorHandle,
    // Sprint 22 (Stage B): the dispatch table is now hot-swappable.
    // The accept loop reads via `dispatch.load().lookup(&sni)` per
    // handshake — single atomic pointer load + map lookup. The SIGHUP
    // arm can call `dispatch.swap(new_table)` to add/remove tenants
    // without restarting this loop.
    dispatch: Arc<crate::HotSniDispatchTable>,
    identity: Arc<IdentityKey>,
    shutdown: Arc<Notify>,
) -> Result<()> {
    let listener = TcpListener::bind(&listen)
        .await
        .with_context(|| format!("binding SNI listener {listen}"))?;
    {
        let snapshot = dispatch.load();
        info!(
            listen = %listen,
            n_tenants = snapshot.by_sni.len() + snapshot.wildcards.len(),
            "SNI multi-tenant listener active (hot-swappable dispatch)"
        );
    }

    loop {
        tokio::select! {
            biased;
            _ = shutdown.notified() => {
                info!(listen = %listen, "SNI listener shutdown requested");
                return Ok(());
            }
            accept_res = listener.accept() => {
                let (tcp, who) = match accept_res {
                    Ok(x) => x,
                    Err(e) => {
                        warn!(listen = %listen, "accept failed: {e}");
                        continue;
                    }
                };
                let acceptor = tls_handle.current();
                // Sprint 22: clone the Arc to the hot wrapper, NOT the
                // inner table. The session task loads the current
                // table once and uses its guard for dispatch — any
                // concurrent swap is invisible to this in-flight
                // session.
                let dispatch = dispatch.clone();
                let identity = identity.clone();
                let peer_ip = who.ip();
                tokio::spawn(async move {
                    if let Err(e) = handle_sni_session(
                        tcp, who.to_string(), peer_ip, acceptor, dispatch, identity
                    ).await {
                        warn!("SNI session from {who}: {e:#}");
                    }
                });
            }
        }
    }
}

async fn handle_sni_session(
    tcp: TcpStream,
    who: String,
    peer_ip: std::net::IpAddr,
    acceptor: Arc<TlsAcceptor>,
    dispatch: Arc<crate::HotSniDispatchTable>,
    identity: Arc<IdentityKey>,
) -> Result<()> {
    let _ = tcp.set_nodelay(true);
    let hs_started = Instant::now();
    // TLS handshake first — this reads ClientHello, the multi-SNI resolver
    // picks the right cert, and we negotiate.
    let tls_stream = acceptor.accept(tcp).await.context("TLS handshake failed")?;
    // Extract the server_name the client requested. With our multi-SNI
    // resolver, a handshake that completes means SOME hostname matched —
    // but we re-check defensively (the resolver could in principle accept
    // a connection without SNI by returning Some on a None lookup, which
    // ours does not).
    let chosen_sni = tls_stream
        .get_ref()
        .1
        .server_name()
        .ok_or_else(|| anyhow!("client did not send SNI; cannot dispatch"))?
        .to_string();
    // Sprint 22 (Stage B): load the current dispatch table once, lookup,
    // clone the resolved context. Concurrent swap is invisible — the
    // ArcSwap guard holds the table version we read; the session runs
    // with that tenant's identity even if it was removed mid-session.
    // Matches Sprint 15 HotAdmissionController in-flight permit policy.
    let ctx = {
        let snapshot = dispatch.load();
        snapshot
            .lookup(&chosen_sni)
            .ok_or_else(|| anyhow!("no tenant claims SNI {chosen_sni:?}"))?
            .clone()
    };

    // Sprint 9.5: per-tenant admission check POST-dispatch. SNI groups
    // share a TCP accept loop, so the pre-handshake check that single-
    // tenant listeners can do isn't possible here — we have to pay the
    // TLS handshake cost before knowing which tenant's limits apply.
    // This is documented in SPEC §13.15.4 as a known trade-off.
    let _permit = match ctx.admission.check(peer_ip) {
        crate::admission::Admit::Ok(p) => p,
        crate::admission::Admit::Reject(reason) => {
            record_admission_reject(&ctx.metrics, reason);
            // Drop the TLS stream cleanly; client sees the connection close.
            drop(tls_stream);
            return Ok(());
        }
    };

    info!(
        sni = %chosen_sni,
        tenant = %ctx.tenant.id.name,
        from = %who,
        "SNI dispatched"
    );

    // From here on, identical to handle_serve_tcp_session post-TLS: dial
    // the peer over CSPQ, then run the proxied session.
    let peer_tcp = TcpStream::connect(&ctx.tenant.peer_pq)
        .await
        .with_context(|| format!("dialing peer {}", ctx.tenant.peer_pq))?;
    let _ = peer_tcp.set_nodelay(true);
    let cspq = match connect(peer_tcp, &identity, &ctx.peer_policy).await {
        Ok(s) => s,
        Err(e) => {
            ctx.metrics
                .inner()
                .sessions_failed
                .fetch_add(1, Ordering::Relaxed);
            return Err(anyhow!("CSPQ handshake to peer failed: {e}"));
        }
    };
    let handshake_elapsed = hs_started.elapsed();
    info!(
        tenant = %ctx.tenant.id.name,
        sni    = %chosen_sni,
        from   = %who,
        to     = %ctx.tenant.peer_pq,
        handshake_ms = handshake_elapsed.as_millis() as u64,
        "serve-tcp SNI session established"
    );
    run_session(
        tls_stream,
        cspq,
        Direction::AppToPeer,
        &ctx.tenant.id.name,
        who,
        &ctx.audit,
        &ctx.metrics,
        handshake_elapsed,
    )
    .await;
    Ok(())
}

// ============================================================================
//                  Sprint 21 — SniDispatchTable mutation + hot swap
// ============================================================================

#[cfg(test)]
mod sni_dispatch_tests {
    use super::*;

    // Minimal SniTenantContext factory for unit tests. Sufficient for
    // testing the dispatch lookup logic; doesn't exercise the audit /
    // metrics / admission paths.
    fn ctx(name: &str, sni: &str) -> SniTenantContext {
        use crate::config::{AuditSignerConfig, TenantId};
        let tenant = ServeTcpTenant {
            id: TenantId {
                name: name.to_string(),
            },
            listen: "127.0.0.1:0".to_string(),
            peer_pq: "peer.test:0".to_string(),
            peer_pub_dir: std::path::PathBuf::from("/tmp/test/peers"),
            audit_log: std::path::PathBuf::from("/tmp/test/audit.qa"),
            tls: None,
            audit_signer: AuditSignerConfig::Softkey {
                secret_key: std::path::PathBuf::from("/tmp/test/sk"),
                public_key: std::path::PathBuf::from("/tmp/test/pk"),
            },
            sni: Some(sni.to_string()),
            limits: None,
        };
        SniTenantContext {
            tenant,
            peer_policy: Arc::new(PeerPolicy::from_keys(std::iter::empty())),
            audit: AuditHandle::test_noop(),
            metrics: MetricsRegistry::new(name),
            admission: Arc::new(crate::HotAdmissionController::new(None, None)),
        }
    }

    #[test]
    fn with_tenant_added_appends_exact_match() {
        let initial = SniDispatchTable::new(vec![ctx("alice", "alice.example.com")]).unwrap();
        let updated = initial
            .with_tenant_added(ctx("bob", "bob.example.com"))
            .unwrap();
        // Initial table unchanged (immutable builder pattern).
        assert!(initial.lookup("bob.example.com").is_none());
        // Updated table has both.
        assert!(updated.lookup("alice.example.com").is_some());
        assert!(updated.lookup("bob.example.com").is_some());
    }

    #[test]
    fn with_tenant_added_appends_wildcard() {
        let initial = SniDispatchTable::new(vec![ctx("alice", "alice.example.com")]).unwrap();
        let updated = initial
            .with_tenant_added(ctx("catchall", "*.svc.internal"))
            .unwrap();
        // Exact match still works.
        assert_eq!(
            updated.lookup("alice.example.com").unwrap().tenant.id.name,
            "alice"
        );
        // Wildcard matches a one-label prefix.
        assert_eq!(
            updated.lookup("api.svc.internal").unwrap().tenant.id.name,
            "catchall"
        );
        // Wildcard rejects multi-label prefix.
        assert!(updated.lookup("a.b.svc.internal").is_none());
    }

    #[test]
    fn with_tenant_added_rejects_duplicate_exact_sni() {
        let initial = SniDispatchTable::new(vec![ctx("alice", "alice.example.com")]).unwrap();
        let err = initial
            .with_tenant_added(ctx("alice2", "alice.example.com"))
            .err()
            .expect("duplicate exact SNI must fail");
        assert!(err.to_string().contains("duplicate SNI"));
    }

    #[test]
    fn with_tenant_added_rejects_duplicate_wildcard() {
        let initial = SniDispatchTable::new(vec![ctx("a", "*.svc.internal")]).unwrap();
        let err = initial
            .with_tenant_added(ctx("b", "*.svc.internal"))
            .err()
            .expect("duplicate wildcard SNI must fail");
        assert!(err.to_string().contains("duplicate wildcard SNI"));
    }

    #[test]
    fn with_tenant_removed_drops_exact_match() {
        let initial = SniDispatchTable::new(vec![
            ctx("alice", "alice.example.com"),
            ctx("bob", "bob.example.com"),
        ])
        .unwrap();
        let updated = initial.with_tenant_removed("alice").unwrap();
        assert!(updated.lookup("alice.example.com").is_none());
        assert!(updated.lookup("bob.example.com").is_some());
        // Initial unchanged.
        assert!(initial.lookup("alice.example.com").is_some());
    }

    #[test]
    fn with_tenant_removed_drops_wildcard() {
        let initial = SniDispatchTable::new(vec![
            ctx("alice", "alice.example.com"),
            ctx("catchall", "*.svc.internal"),
        ])
        .unwrap();
        let updated = initial.with_tenant_removed("catchall").unwrap();
        assert!(updated.lookup("api.svc.internal").is_none());
        assert!(updated.lookup("alice.example.com").is_some());
    }

    #[test]
    fn with_tenant_removed_returns_none_if_absent() {
        let initial = SniDispatchTable::new(vec![ctx("alice", "alice.example.com")]).unwrap();
        // Nothing to remove → None signal.
        assert!(initial.with_tenant_removed("ghost").is_none());
    }

    #[test]
    fn tenant_names_enumerates_exact_and_wildcard() {
        let initial = SniDispatchTable::new(vec![
            ctx("a", "a.example.com"),
            ctx("b", "*.svc.internal"),
            ctx("c", "c.example.com"),
        ])
        .unwrap();
        let mut names = initial.tenant_names();
        names.sort();
        assert_eq!(names, vec!["a", "b", "c"]);
    }

    #[test]
    fn hot_dispatch_table_initial_lookup() {
        let initial = SniDispatchTable::new(vec![ctx("alice", "alice.example.com")]).unwrap();
        let hot = HotSniDispatchTable::new(initial);
        let guard = hot.load();
        assert_eq!(
            guard.lookup("alice.example.com").unwrap().tenant.id.name,
            "alice"
        );
    }

    #[test]
    fn hot_dispatch_table_swap_installs_new_table() {
        let initial = SniDispatchTable::new(vec![ctx("alice", "alice.example.com")]).unwrap();
        let hot = HotSniDispatchTable::new(initial);
        // Add bob via with_tenant_added, swap into hot.
        let next = hot
            .load()
            .with_tenant_added(ctx("bob", "bob.example.com"))
            .unwrap();
        let _old = hot.swap(next);
        // Subsequent loads see both tenants.
        let guard = hot.load();
        assert!(guard.lookup("alice.example.com").is_some());
        assert!(guard.lookup("bob.example.com").is_some());
    }

    #[test]
    fn hot_dispatch_table_swap_returns_old_table_arc() {
        let initial = SniDispatchTable::new(vec![ctx("alice", "alice.example.com")]).unwrap();
        let hot = HotSniDispatchTable::new(initial);
        let next = SniDispatchTable::new(vec![ctx("bob", "bob.example.com")]).unwrap();
        let old_arc = hot.swap(next);
        // The returned Arc points at the original table — confirm by lookup.
        assert_eq!(
            old_arc.lookup("alice.example.com").unwrap().tenant.id.name,
            "alice"
        );
        // The hot wrapper now serves the new table.
        assert!(hot.load().lookup("alice.example.com").is_none());
        assert!(hot.load().lookup("bob.example.com").is_some());
    }

    #[test]
    fn hot_dispatch_table_inflight_guard_survives_swap() {
        // Sprint 21 swap semantics: a guard loaded BEFORE the swap holds
        // an Arc to the OLD table. Even after swap installs a new table,
        // the old guard's lookups still work — this models an in-flight
        // SNI handshake that resolved its context just before the swap.
        let initial = SniDispatchTable::new(vec![ctx("alice", "alice.example.com")]).unwrap();
        let hot = HotSniDispatchTable::new(initial);
        let inflight_guard = hot.load();
        // Now swap — new table has only bob.
        let next = SniDispatchTable::new(vec![ctx("bob", "bob.example.com")]).unwrap();
        let _ = hot.swap(next);
        // In-flight guard still finds alice.
        assert!(inflight_guard.lookup("alice.example.com").is_some());
        // New loads see only bob.
        assert!(hot.load().lookup("alice.example.com").is_none());
        assert!(hot.load().lookup("bob.example.com").is_some());
    }
}
