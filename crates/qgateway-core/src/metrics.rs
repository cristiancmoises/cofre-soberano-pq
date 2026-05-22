//! In-memory metrics with tenant-labelled Prometheus exposition.
//!
//! Each tenant owns one [`MetricsRegistry`]. The daemon collects all
//! registries and renders them at `/metrics` via [`render_prometheus`],
//! producing series with a `tenant="<name>"` label.
//!
//! Sprint 17 also adds a [`DaemonMetrics`] surface for daemon-wide
//! counters that are not tenant-scoped — SIGHUP cycle counters and
//! hot-apply counters. These render alongside the tenant series under
//! distinct metric names with no `tenant=` label.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Histogram bucket bounds (microseconds) for handshake latency.
const HANDSHAKE_BUCKETS_US: &[u64] = &[
    500, 1_000, 2_000, 5_000, 10_000, 20_000, 50_000, 100_000, 250_000, 500_000, 1_000_000,
];

/// Sprint 17: daemon-wide metrics. Single instance shared across the
/// daemon — the SIGHUP arm bumps these counters, the metrics server
/// renders them at `/metrics` without any tenant label.
#[derive(Default)]
pub struct DaemonMetrics {
    /// Total successful SIGHUP cycles (validation passed). Increments
    /// regardless of whether the cycle resulted in any apply work.
    pub sighup_cycles_total: AtomicU64,
    /// Total SIGHUP cycles where `Config::load` failed validation. The
    /// daemon continued with the previously-loaded config; operators
    /// should grep the daemon log for the underlying parse/validation
    /// error.
    pub sighup_failed_total: AtomicU64,
    /// Total tenants successfully ADDED at runtime.
    pub tenants_added_total: AtomicU64,
    /// Total tenant ADD failures (build_tenant_runtime returned Err).
    pub tenants_add_failed_total: AtomicU64,
    /// Total tenants successfully REMOVED at runtime (Sprint 17+).
    pub tenants_removed_total: AtomicU64,
    /// Total tenant REMOVE failures (drain timed out, etc.).
    pub tenants_remove_failed_total: AtomicU64,
    /// Total successful hot-applies of `[tenants.limits]`. Operators
    /// alerting on this counter see at-a-glance how often live policy
    /// is being tuned.
    pub limits_hot_applied_total: AtomicU64,
    /// Total tenant-config diff entries classified as `Hot` (today: only
    /// `limits`). Reset to 0 means no operator has ever tuned limits.
    pub config_changed_hot_total: AtomicU64,
    /// Total tenant-config diff entries classified as `Cold` (everything
    /// else). High count without a corresponding restart suggests
    /// configuration drift — operators editing TOML without restarting.
    pub config_changed_cold_total: AtomicU64,
}

/// Per-tenant metrics registry.
#[derive(Clone)]
pub struct MetricsRegistry {
    inner: Arc<Metrics>,
    tenant: String,
}

impl MetricsRegistry {
    /// Construct a registry bound to a specific tenant name.
    pub fn new(tenant: impl Into<String>) -> Self {
        Self {
            inner: Arc::new(Metrics::default()),
            tenant: tenant.into(),
        }
    }

    /// Access the underlying atomic counters (proxy / gateway internals).
    pub fn inner(&self) -> &Metrics {
        &self.inner
    }

    /// Tenant label for this registry.
    pub fn tenant(&self) -> &str {
        &self.tenant
    }
}

/// Atomic counters and histogram for one tenant.
pub struct Metrics {
    /// Sessions opened (handshake completed successfully).
    pub sessions_opened: AtomicU64,
    /// Sessions closed cleanly.
    pub sessions_closed: AtomicU64,
    /// Sessions that failed before becoming established.
    pub sessions_failed: AtomicU64,
    /// Sessions currently open.
    pub sessions_active: AtomicU64,
    /// Plaintext bytes forwarded client → server.
    pub bytes_c2s: AtomicU64,
    /// Plaintext bytes forwarded server → client.
    pub bytes_s2c: AtomicU64,
    /// Total audit events emitted.
    pub audit_events: AtomicU64,
    /// Total audit-event append failures.
    pub audit_failures: AtomicU64,
    /// Sprint 8: total audit-log rotations completed successfully.
    pub audit_rotations: AtomicU64,
    /// Sprint 9.5: connections rejected by admission control due to
    /// per-tenant concurrency quota.
    pub admission_rejected_quota: AtomicU64,
    /// Sprint 9.5: connections rejected by admission control due to
    /// per-source-IP token-bucket exhaustion.
    pub admission_rejected_rate: AtomicU64,
    /// Sprint 10: PKCS#11 sessions successfully opened. Increments on
    /// startup signer creation AND on every rotation that mints a fresh
    /// HSM-backed signer. For deployments using a non-PKCS#11 signer
    /// (Softkey), this counter remains 0.
    pub hsm_sessions_opened: AtomicU64,
    /// Sprint 10: PKCS#11 session-open failures. Bumps on any error during
    /// `Pkcs11Signer::open` — load failures, slot-not-found, login-rejected,
    /// key-not-found. Operators alerting on this counter detect HSM
    /// outages and PIN expiration before they affect signing.
    pub hsm_sessions_failed: AtomicU64,
    /// Sprint 10: PKCS#11 `C_Sign` calls completed successfully. Bumps
    /// per-event for HSM-backed audit signers.
    pub hsm_sign_ops: AtomicU64,
    /// Sprint 10: PKCS#11 `C_Sign` failures. A persistent climb of this
    /// counter while `hsm_sessions_opened` stays flat indicates an HSM
    /// session that's still live but rejecting signs (token disconnected,
    /// mechanism unsupported, etc.).
    pub hsm_sign_failures: AtomicU64,
    /// Number of completed handshakes (histogram count).
    pub handshake_count: AtomicU64,
    /// Sum of handshake durations in microseconds.
    pub handshake_sum_us: AtomicU64,
    handshake_buckets: [AtomicU64; HANDSHAKE_BUCKETS_US.len() + 1],
}

impl Default for Metrics {
    fn default() -> Self {
        Self {
            sessions_opened: AtomicU64::new(0),
            sessions_closed: AtomicU64::new(0),
            sessions_failed: AtomicU64::new(0),
            sessions_active: AtomicU64::new(0),
            bytes_c2s: AtomicU64::new(0),
            bytes_s2c: AtomicU64::new(0),
            audit_events: AtomicU64::new(0),
            audit_failures: AtomicU64::new(0),
            audit_rotations: AtomicU64::new(0),
            admission_rejected_quota: AtomicU64::new(0),
            admission_rejected_rate: AtomicU64::new(0),
            hsm_sessions_opened: AtomicU64::new(0),
            hsm_sessions_failed: AtomicU64::new(0),
            hsm_sign_ops: AtomicU64::new(0),
            hsm_sign_failures: AtomicU64::new(0),
            handshake_count: AtomicU64::new(0),
            handshake_sum_us: AtomicU64::new(0),
            handshake_buckets: Default::default(),
        }
    }
}

impl Metrics {
    /// Observe a handshake duration.
    pub fn observe_handshake(&self, d: Duration) {
        let us = d.as_micros().min(u64::MAX as u128) as u64;
        self.handshake_count.fetch_add(1, Ordering::Relaxed);
        self.handshake_sum_us.fetch_add(us, Ordering::Relaxed);
        for (i, &bound) in HANDSHAKE_BUCKETS_US.iter().enumerate() {
            if us <= bound {
                self.handshake_buckets[i].fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
        self.handshake_buckets[HANDSHAKE_BUCKETS_US.len()].fetch_add(1, Ordering::Relaxed);
    }

    fn handshake_buckets_snapshot(&self) -> Vec<u64> {
        self.handshake_buckets
            .iter()
            .map(|a| a.load(Ordering::Relaxed))
            .collect()
    }
}

/// Render one or more per-tenant registries as Prometheus text format 0.0.4.
///
/// Each metric is emitted once per tenant with a `tenant="<name>"` label.
pub fn render_prometheus(registries: &[&MetricsRegistry]) -> String {
    let mut s = String::with_capacity(4096);

    emit_counter(
        &mut s,
        registries,
        "qgateway_sessions_opened_total",
        "Total CSPQ sessions successfully opened.",
        |m| m.sessions_opened.load(Ordering::Relaxed),
    );
    emit_counter(
        &mut s,
        registries,
        "qgateway_sessions_closed_total",
        "Total CSPQ sessions cleanly closed.",
        |m| m.sessions_closed.load(Ordering::Relaxed),
    );
    emit_counter(
        &mut s,
        registries,
        "qgateway_sessions_failed_total",
        "Total handshakes that failed.",
        |m| m.sessions_failed.load(Ordering::Relaxed),
    );
    emit_gauge(
        &mut s,
        registries,
        "qgateway_sessions_active",
        "Currently open CSPQ sessions.",
        |m| m.sessions_active.load(Ordering::Relaxed),
    );
    emit_counter(
        &mut s,
        registries,
        "qgateway_bytes_c2s_total",
        "Plaintext bytes forwarded client → server.",
        |m| m.bytes_c2s.load(Ordering::Relaxed),
    );
    emit_counter(
        &mut s,
        registries,
        "qgateway_bytes_s2c_total",
        "Plaintext bytes forwarded server → client.",
        |m| m.bytes_s2c.load(Ordering::Relaxed),
    );
    emit_counter(
        &mut s,
        registries,
        "qgateway_audit_events_total",
        "Audit events emitted to qaudit.",
        |m| m.audit_events.load(Ordering::Relaxed),
    );
    emit_counter(
        &mut s,
        registries,
        "qgateway_audit_failures_total",
        "Audit events that failed to be appended.",
        |m| m.audit_failures.load(Ordering::Relaxed),
    );
    emit_counter(
        &mut s,
        registries,
        "qgateway_audit_rotations_total",
        "Audit log rotations completed successfully.",
        |m| m.audit_rotations.load(Ordering::Relaxed),
    );
    emit_counter(
        &mut s,
        registries,
        "qgateway_admission_rejected_quota_total",
        "Inbound connections rejected by admission control due to per-tenant concurrency quota.",
        |m| m.admission_rejected_quota.load(Ordering::Relaxed),
    );
    emit_counter(
        &mut s,
        registries,
        "qgateway_admission_rejected_rate_total",
        "Inbound connections rejected by admission control due to per-source-IP rate limit.",
        |m| m.admission_rejected_rate.load(Ordering::Relaxed),
    );
    emit_counter(
        &mut s,
        registries,
        "qgateway_hsm_sessions_opened_total",
        "PKCS#11 sessions opened successfully (startup + per-rotation).",
        |m| m.hsm_sessions_opened.load(Ordering::Relaxed),
    );
    emit_counter(
        &mut s,
        registries,
        "qgateway_hsm_sessions_failed_total",
        "PKCS#11 session-open failures (load, slot, login, or key lookup errors).",
        |m| m.hsm_sessions_failed.load(Ordering::Relaxed),
    );
    emit_counter(
        &mut s,
        registries,
        "qgateway_hsm_sign_ops_total",
        "PKCS#11 C_Sign calls completed successfully (audit signatures).",
        |m| m.hsm_sign_ops.load(Ordering::Relaxed),
    );
    emit_counter(
        &mut s,
        registries,
        "qgateway_hsm_sign_failures_total",
        "PKCS#11 C_Sign failures (token disconnected, mechanism unsupported, etc.).",
        |m| m.hsm_sign_failures.load(Ordering::Relaxed),
    );

    // Handshake latency histogram, per tenant.
    s.push_str("# HELP qgateway_handshake_seconds Handshake duration (seconds).\n");
    s.push_str("# TYPE qgateway_handshake_seconds histogram\n");
    for r in registries {
        let tenant = escape_label(r.tenant());
        let m = r.inner();
        let buckets = m.handshake_buckets_snapshot();
        let mut cumulative: u64 = 0;
        for (i, &bound_us) in HANDSHAKE_BUCKETS_US.iter().enumerate() {
            cumulative = cumulative.saturating_add(buckets[i]);
            let bound_s = bound_us as f64 / 1_000_000.0;
            s.push_str(&format!(
                "qgateway_handshake_seconds_bucket{{tenant=\"{tenant}\",le=\"{bound_s}\"}} {cumulative}\n"
            ));
        }
        let plus_inf = cumulative.saturating_add(buckets[HANDSHAKE_BUCKETS_US.len()]);
        s.push_str(&format!(
            "qgateway_handshake_seconds_bucket{{tenant=\"{tenant}\",le=\"+Inf\"}} {plus_inf}\n"
        ));
        let sum_us = m.handshake_sum_us.load(Ordering::Relaxed) as f64 / 1_000_000.0;
        s.push_str(&format!(
            "qgateway_handshake_seconds_sum{{tenant=\"{tenant}\"}} {sum_us}\n"
        ));
        s.push_str(&format!(
            "qgateway_handshake_seconds_count{{tenant=\"{tenant}\"}} {}\n",
            m.handshake_count.load(Ordering::Relaxed)
        ));
    }

    s
}

fn emit_counter(
    s: &mut String,
    registries: &[&MetricsRegistry],
    name: &str,
    help: &str,
    f: impl Fn(&Metrics) -> u64,
) {
    s.push_str(&format!("# HELP {name} {help}\n# TYPE {name} counter\n"));
    for r in registries {
        s.push_str(&format!(
            "{name}{{tenant=\"{}\"}} {}\n",
            escape_label(r.tenant()),
            f(r.inner())
        ));
    }
}

/// Sprint 17: render daemon-wide counters (SIGHUP cycle counters, hot-apply
/// counters). Emit unlabeled — these are not tenant-scoped. Callers
/// typically concatenate the output with [`render_prometheus`]'s.
pub fn render_daemon_metrics(d: &DaemonMetrics) -> String {
    let mut s = String::with_capacity(2048);
    emit_daemon_counter(
        &mut s,
        "qgateway_sighup_cycles_total",
        "Total SIGHUP cycles that passed config validation.",
        d.sighup_cycles_total.load(Ordering::Relaxed),
    );
    emit_daemon_counter(
        &mut s,
        "qgateway_sighup_failed_total",
        "Total SIGHUP cycles where Config::load failed validation.",
        d.sighup_failed_total.load(Ordering::Relaxed),
    );
    emit_daemon_counter(
        &mut s,
        "qgateway_tenants_added_total",
        "Total tenants successfully added at runtime via SIGHUP.",
        d.tenants_added_total.load(Ordering::Relaxed),
    );
    emit_daemon_counter(
        &mut s,
        "qgateway_tenants_add_failed_total",
        "Total tenant ADD failures during SIGHUP apply.",
        d.tenants_add_failed_total.load(Ordering::Relaxed),
    );
    emit_daemon_counter(
        &mut s,
        "qgateway_tenants_removed_total",
        "Total tenants successfully removed at runtime via SIGHUP.",
        d.tenants_removed_total.load(Ordering::Relaxed),
    );
    emit_daemon_counter(
        &mut s,
        "qgateway_tenants_remove_failed_total",
        "Total tenant REMOVE failures during SIGHUP apply (drain timeout, etc.).",
        d.tenants_remove_failed_total.load(Ordering::Relaxed),
    );
    emit_daemon_counter(
        &mut s,
        "qgateway_limits_hot_applied_total",
        "Total successful hot-applies of [tenants.limits] via SIGHUP.",
        d.limits_hot_applied_total.load(Ordering::Relaxed),
    );
    emit_daemon_counter(
        &mut s,
        "qgateway_config_changed_hot_total",
        "Total tenant-config diff entries classified as Hot (limits-only today).",
        d.config_changed_hot_total.load(Ordering::Relaxed),
    );
    emit_daemon_counter(
        &mut s,
        "qgateway_config_changed_cold_total",
        "Total tenant-config diff entries classified as Cold (require restart).",
        d.config_changed_cold_total.load(Ordering::Relaxed),
    );
    s
}

fn emit_daemon_counter(s: &mut String, name: &str, help: &str, value: u64) {
    s.push_str(&format!(
        "# HELP {name} {help}\n# TYPE {name} counter\n{name} {value}\n"
    ));
}

fn emit_gauge(
    s: &mut String,
    registries: &[&MetricsRegistry],
    name: &str,
    help: &str,
    f: impl Fn(&Metrics) -> u64,
) {
    s.push_str(&format!("# HELP {name} {help}\n# TYPE {name} gauge\n"));
    for r in registries {
        s.push_str(&format!(
            "{name}{{tenant=\"{}\"}} {}\n",
            escape_label(r.tenant()),
            f(r.inner())
        ));
    }
}

fn escape_label(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_registry_renders_clean() {
        let r = MetricsRegistry::new("default");
        let s = render_prometheus(&[&r]);
        assert!(s.contains("# TYPE qgateway_sessions_opened_total counter"));
        assert!(s.contains("qgateway_sessions_opened_total{tenant=\"default\"} 0"));
        assert!(s.contains("qgateway_handshake_seconds_count{tenant=\"default\"} 0"));
    }

    #[test]
    fn multi_tenant_renders_per_label() {
        let a = MetricsRegistry::new("acme");
        let b = MetricsRegistry::new("globex");
        a.inner().sessions_opened.fetch_add(3, Ordering::Relaxed);
        b.inner().sessions_opened.fetch_add(7, Ordering::Relaxed);
        a.inner().bytes_c2s.fetch_add(1024, Ordering::Relaxed);
        let s = render_prometheus(&[&a, &b]);
        assert!(s.contains("qgateway_sessions_opened_total{tenant=\"acme\"} 3"));
        assert!(s.contains("qgateway_sessions_opened_total{tenant=\"globex\"} 7"));
        assert!(s.contains("qgateway_bytes_c2s_total{tenant=\"acme\"} 1024"));
    }

    #[test]
    fn handshake_histogram_per_tenant() {
        let r = MetricsRegistry::new("t1");
        r.inner().observe_handshake(Duration::from_millis(3));
        r.inner().observe_handshake(Duration::from_millis(15));
        r.inner().observe_handshake(Duration::from_millis(1500));
        let s = render_prometheus(&[&r]);
        assert!(s.contains("qgateway_handshake_seconds_count{tenant=\"t1\"} 3"));
        for line in s.lines() {
            if line.contains("qgateway_handshake_seconds_bucket{tenant=\"t1\",le=\"+Inf\"}") {
                let v: u64 = line.split(' ').next_back().unwrap().parse().unwrap();
                assert_eq!(v, 3);
            }
        }
    }

    #[test]
    fn label_escaping_works() {
        let r = MetricsRegistry::new("bad\"name\\here");
        let s = render_prometheus(&[&r]);
        assert!(s.contains("tenant=\"bad\\\"name\\\\here\""));
    }
}
