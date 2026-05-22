//! TOML config loader (Sprint 4 — multi-tenant + optional TLS termination).

use serde::Deserialize;
use std::path::{Path, PathBuf};

/// Top-level config.
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// Daemon role.
    pub role: Role,
    /// Path to the long-term transport identity secret key file (`.skid`).
    pub identity_key: PathBuf,
    /// Path to the long-term transport identity public key file (`.cspqid.pub`).
    pub identity_pub: PathBuf,
    /// Prometheus listener address.
    #[serde(default = "default_metrics_listen")]
    pub metrics_listen: String,
    /// Default audit signer configuration. Used by tenants that don't
    /// declare their own `[tenants.audit_signer]` block. May be omitted
    /// only if every tenant declares its own signer.
    #[serde(default)]
    pub audit_signer: Option<AuditSignerConfig>,
    /// Sprint 8: optional auto-rotation policy for tenant audit logs.
    /// When set, every tenant's audit channel observes the policy and
    /// rotates its `.qa` file when any trigger fires. SIGUSR2 triggers a
    /// rotation cycle on all tenants regardless of the configured
    /// policy. Defaults to "no auto-rotation" (signal-only).
    #[serde(default)]
    pub rotation: Option<RotationPolicy>,
    /// Sprint 19: drain timeout for SIGHUP REMOVE in seconds. When a
    /// tenant is removed, the daemon notifies the tenant's accept loop
    /// and awaits its completion up to this many seconds. Sessions that
    /// don't honor cancellation in time trigger a
    /// `tenants_remove_failed_total` counter bump and leave the entry
    /// in the shared maps (full cleanup requires daemon restart).
    /// Defaults to 30s — short enough that a bad SIGHUP doesn't block
    /// the daemon, long enough for healthy CSPQ sessions to complete
    /// under normal load.
    #[serde(default = "default_drain_timeout_secs")]
    pub tenant_drain_timeout_secs: u64,
    /// Per-tenant configuration. At least one required.
    pub tenants: Vec<TenantConfig>,
}

/// Sprint 8: audit-log auto-rotation policy. Triggers a `rotate_to` on
/// the tenant's audit log when any of the configured thresholds is
/// crossed. SIGUSR2 always triggers a rotation regardless of policy.
#[derive(Debug, Clone, Deserialize)]
pub struct RotationPolicy {
    /// Trigger rotation when the current log has at least this many entries.
    /// Unset = no entry-count trigger.
    #[serde(default)]
    pub max_entries: Option<u64>,
    /// Trigger rotation when the current log file on disk exceeds this many
    /// bytes. Unset = no byte trigger. Note: measured AFTER the most recent
    /// batched save, so the practical threshold is `max_bytes + batch_size *
    /// avg_entry_size`.
    #[serde(default)]
    pub max_bytes: Option<u64>,
    /// Trigger rotation when the current log has been open for at least this
    /// many seconds (since the gateway started or since the last rotation).
    /// Unset = no time trigger.
    #[serde(default)]
    pub max_age_secs: Option<u64>,
    /// Sprint 35: how often the auto-rotation monitor checks the
    /// thresholds, in milliseconds. Default: 5000 (5 seconds). Lower
    /// values are useful for tight-deadline compliance scenarios and
    /// for tests. Has no effect on SIGUSR2-driven manual rotation
    /// (which fires immediately).
    ///
    /// Floor: 10 ms. Lower values are clamped to 10 ms to avoid
    /// busy-spinning on accident; the lib does not validate the upper
    /// bound (an operator who wants daily polling can set 86_400_000).
    #[serde(default)]
    pub poll_interval_ms: Option<u64>,
    /// File-naming pattern for rotated logs. `{label}` is replaced with the
    /// current log's label; `{ts}` is replaced with a UTC timestamp
    /// (`YYYYMMDDTHHMMSSZ`); `{counter}` is replaced with a per-tenant
    /// monotonic rotation counter starting at 1. Default:
    /// `"{label}-{ts}.qa"`. The rotated file is written alongside the
    /// current `audit_log` path (same parent directory).
    #[serde(default = "default_archive_pattern")]
    pub archive_pattern: String,
}

fn default_archive_pattern() -> String {
    "{label}-{ts}.qa".to_string()
}

impl RotationPolicy {
    /// True if any trigger is set. A policy with no triggers is signal-only —
    /// equivalent to `rotation = {}` in TOML.
    pub fn has_auto_trigger(&self) -> bool {
        self.max_entries.is_some() || self.max_bytes.is_some() || self.max_age_secs.is_some()
    }

    /// Sprint 35: resolved poll interval for the auto-rotation monitor.
    /// Returns the configured `poll_interval_ms` if set (clamped to
    /// a 10 ms floor), otherwise the 5-second default.
    pub fn poll_interval(&self) -> std::time::Duration {
        match self.poll_interval_ms {
            Some(ms) => std::time::Duration::from_millis(ms.max(10)),
            None => std::time::Duration::from_secs(5),
        }
    }

    /// Render `archive_pattern` with the supplied substitutions. Used both
    /// at runtime (when a rotation fires) and in `validate` (to surface a
    /// malformed pattern at config load time).
    pub fn render_archive_name(
        &self,
        label: &str,
        counter: u64,
        now: chrono::DateTime<chrono::Utc>,
    ) -> String {
        let ts = now.format("%Y%m%dT%H%M%SZ").to_string();
        self.archive_pattern
            .replace("{label}", label)
            .replace("{ts}", &ts)
            .replace("{counter}", &counter.to_string())
    }
}

fn default_metrics_listen() -> String {
    "127.0.0.1:9099".to_string()
}

/// Sprint 19: default drain timeout in seconds. Used when the operator
/// doesn't set `tenant_drain_timeout_secs` in the TOML. 30s is short
/// enough that a bad SIGHUP doesn't block daemon shutdown, long enough
/// for healthy CSPQ sessions to complete under normal load.
fn default_drain_timeout_secs() -> u64 {
    30
}

/// Daemon role discriminant.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Role {
    /// Accept TCP from local app, dial peer over CSPQ.
    ServeTcp,
    /// Accept CSPQ from peer, dial backend TCP.
    ServePq,
}

/// Per-tenant configuration as deserialized from TOML.
#[derive(Debug, Clone, Deserialize)]
pub struct TenantConfig {
    /// Stable name (used in metrics labels and audit metadata).
    pub name: String,
    /// Local listen address.
    pub listen: String,
    /// serve-tcp: peer CSPQ address to dial.
    #[serde(default)]
    pub peer_pq: Option<String>,
    /// serve-pq: backend TCP address to dial.
    #[serde(default)]
    pub backend: Option<String>,
    /// Directory of trusted peer `.cspqid.pub` files for this tenant.
    pub peer_pub_dir: PathBuf,
    /// Per-tenant `.qa` audit log file.
    pub audit_log: PathBuf,
    /// Optional TLS 1.3 termination on the listen side (serve-tcp only).
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    /// Server Name Indication hostname this tenant responds to. Required
    /// when multiple tenants share the same `listen` address (SNI dispatch
    /// at TLS handshake time picks the right tenant). Forbidden when this
    /// tenant is the sole tenant on its listen address — single-tenant
    /// listeners don't need SNI.
    #[serde(default)]
    pub sni: Option<String>,
    /// Optional per-tenant audit-signer override. When set, completely
    /// replaces (does not merge with) the top-level `[audit_signer]` for
    /// this tenant. When unset, the tenant inherits the top-level signer.
    /// Cross-tenant audit-key isolation requires this override.
    #[serde(default)]
    pub audit_signer: Option<AuditSignerConfig>,
    /// Sprint 9.5: optional connection admission limits for this tenant.
    /// When unset, the tenant has no quota and no rate limit — every
    /// inbound connection proceeds to the handshake stage.
    #[serde(default)]
    pub limits: Option<TenantLimits>,
}

impl TenantConfig {
    /// Sprint 13: enumerate fields that differ between `self` and `other`
    /// at semantic equality (path strings, address strings, label sets).
    /// Returns an empty `Vec` when the two tenants are operationally
    /// identical. The order of fields in the returned vector is stable
    /// (declaration order in this method) for deterministic log output.
    ///
    /// Used by the SIGHUP apply step to surface "same name, different
    /// settings" as a separate operator-visible category — distinct from
    /// "tenant added" or "tenant removed". The current Sprint-13 apply
    /// path still treats material changes as "restart required" (no
    /// hot-reconfiguration of a live tenant), but operators see the
    /// specific field name in the daemon log so they know what to
    /// expect on restart.
    ///
    /// Sprint 14: each change is now classified as `Hot` (could be
    /// applied in-place if the apply path supported it; currently still
    /// not applied automatically) or `Cold` (requires tenant restart).
    /// The classification is intrinsic to the field — `limits` is hot
    /// because the AdmissionController could be rebuilt without
    /// rebinding the listener; `listen` is cold because changing the
    /// bind address requires a fresh listener; `audit_signer` is cold
    /// because changing the signing key mid-stream would split the
    /// audit chain.
    pub fn material_changes(&self, other: &Self) -> Vec<TenantChange> {
        let mut changes: Vec<TenantChange> = Vec::new();
        // `name` is the diff key — we never call this method with
        // mismatched names, so we don't check it.
        if self.listen != other.listen {
            changes.push(TenantChange::cold("listen"));
        }
        if self.peer_pq != other.peer_pq {
            changes.push(TenantChange::cold("peer_pq"));
        }
        if self.backend != other.backend {
            changes.push(TenantChange::cold("backend"));
        }
        if self.peer_pub_dir != other.peer_pub_dir {
            changes.push(TenantChange::cold("peer_pub_dir"));
        }
        if self.audit_log != other.audit_log {
            changes.push(TenantChange::cold("audit_log"));
        }
        if !tls_eq(&self.tls, &other.tls) {
            changes.push(TenantChange::cold("tls"));
        }
        if self.sni != other.sni {
            changes.push(TenantChange::cold("sni"));
        }
        if !audit_signer_eq(&self.audit_signer, &other.audit_signer) {
            changes.push(TenantChange::cold("audit_signer"));
        }
        if !limits_eq(&self.limits, &other.limits) {
            // Sprint 14: limits is hot-applicable. Even though Sprint 14's
            // apply path doesn't yet rebuild the AdmissionController, the
            // classification tells operators the change CAN be done
            // without restart in a future sprint, and makes the diff
            // log distinguish the "harmless tweak" case from the
            // "requires careful restart planning" case.
            changes.push(TenantChange::hot("limits"));
        }
        changes
    }

    /// Convenience: `true` iff `material_changes` would return a non-empty vec.
    pub fn differs_from(&self, other: &Self) -> bool {
        !self.material_changes(other).is_empty()
    }
}

/// Sprint 14: a single material change between two tenant configs.
/// Carries the field name and a classification of whether the change
/// is theoretically applicable without restarting the tenant.
///
/// "Hot" does NOT mean the daemon will automatically rebuild on that
/// change — it means the rebuild is mechanically possible (the state
/// the field controls can be swapped without invalidating other live
/// state). Whether the apply path actually does the rebuild is a
/// separate decision per sprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantChange {
    /// Static field name (e.g. "listen", "limits", "audit_signer").
    pub field: &'static str,
    /// Kind of change.
    pub kind: TenantChangeKind,
}

impl TenantChange {
    fn cold(field: &'static str) -> Self {
        Self {
            field,
            kind: TenantChangeKind::Cold,
        }
    }
    fn hot(field: &'static str) -> Self {
        Self {
            field,
            kind: TenantChangeKind::Hot,
        }
    }
}

/// Sprint 14: classification of a tenant config change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantChangeKind {
    /// Could be applied without restarting the tenant (state swap is
    /// mechanically safe). Whether the daemon actually does so depends
    /// on the current sprint's apply path.
    Hot,
    /// Requires tenant restart (or daemon restart). Changing the field
    /// in place would invalidate other live state.
    Cold,
}

fn tls_eq(a: &Option<TlsConfig>, b: &Option<TlsConfig>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(x), Some(y)) => x.cert == y.cert && x.key == y.key,
        _ => false,
    }
}

fn audit_signer_eq(a: &Option<AuditSignerConfig>, b: &Option<AuditSignerConfig>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(x), Some(y)) => audit_signer_inner_eq(x, y),
        _ => false,
    }
}

fn audit_signer_inner_eq(a: &AuditSignerConfig, b: &AuditSignerConfig) -> bool {
    match (a, b) {
        (
            AuditSignerConfig::Softkey {
                secret_key: ask,
                public_key: apk,
            },
            AuditSignerConfig::Softkey {
                secret_key: bsk,
                public_key: bpk,
            },
        ) => ask == bsk && apk == bpk,
        (
            AuditSignerConfig::Pkcs11 {
                module: am,
                slot: as_,
                pin_env: ap,
                key_label: akl,
                pub_label: apl,
                mechanism_id: ami,
            },
            AuditSignerConfig::Pkcs11 {
                module: bm,
                slot: bs,
                pin_env: bp,
                key_label: bkl,
                pub_label: bpl,
                mechanism_id: bmi,
            },
        ) => am == bm && as_ == bs && ap == bp && akl == bkl && apl == bpl && ami == bmi,
        // Different variants
        _ => false,
    }
}

fn limits_eq(a: &Option<TenantLimits>, b: &Option<TenantLimits>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(x), Some(y)) => {
            x.max_concurrent == y.max_concurrent
                && rate_eq(&x.rate_limit_per_source, &y.rate_limit_per_source)
        }
        _ => false,
    }
}

fn rate_eq(a: &Option<RateLimitTomlConfig>, b: &Option<RateLimitTomlConfig>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(x), Some(y)) => x.capacity == y.capacity && x.refill_per_sec == y.refill_per_sec,
        _ => false,
    }
}

/// Sprint 9.5: per-tenant connection admission limits. All fields are
/// optional and independently scoped — you can set just `max_concurrent`,
/// just `rate_limit_per_source`, or both. Empty `[tenants.limits]` block
/// is equivalent to no `limits` at all.
#[derive(Debug, Clone, Deserialize)]
pub struct TenantLimits {
    /// Cap on concurrent in-flight sessions for this tenant. Each accepted
    /// connection holds a semaphore permit for the lifetime of its session;
    /// the (N+1)th attempt while N permits are held is rejected with TCP RST
    /// and counted in `qgateway_admission_rejected_total{reason="quota"}`.
    #[serde(default)]
    pub max_concurrent: Option<u32>,
    /// Token-bucket rate limit per source IP. `capacity` = max burst,
    /// `refill_per_sec` = steady-state max-accept rate. Buckets are
    /// per-tenant-per-source-IP — different tenants don't share state.
    #[serde(default)]
    pub rate_limit_per_source: Option<RateLimitTomlConfig>,
}

/// Sprint 9.5: TOML mirror of [`crate::RateLimitConfig`]. Separate from the
/// library type so the TOML schema is decoupled from internal struct shape
/// (lets us evolve the library type without breaking config files).
#[derive(Debug, Clone, Deserialize)]
pub struct RateLimitTomlConfig {
    /// Bucket capacity in tokens (max burst size in connections).
    pub capacity: u32,
    /// Refill rate in tokens per second (steady-state max-accept rate per source IP).
    pub refill_per_sec: u32,
}

impl From<&RateLimitTomlConfig> for crate::RateLimitConfig {
    fn from(v: &RateLimitTomlConfig) -> Self {
        crate::RateLimitConfig {
            capacity: v.capacity,
            refill_per_sec: v.refill_per_sec,
        }
    }
}

/// TLS termination configuration for a serve-tcp tenant.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    /// Path to a PEM-encoded server certificate chain.
    pub cert: PathBuf,
    /// Path to a PEM-encoded PKCS#8 private key.
    pub key: PathBuf,
}

/// Resolved tenant identity used by the gateway runtime.
#[derive(Debug, Clone)]
pub struct TenantId {
    /// Display name.
    pub name: String,
}

/// Resolved serve-tcp tenant parameters.
#[derive(Debug, Clone)]
pub struct ServeTcpTenant {
    /// Tenant identity.
    pub id: TenantId,
    /// Local TCP listen address.
    pub listen: String,
    /// Peer CSPQ address to dial.
    pub peer_pq: String,
    /// Trust scope.
    pub peer_pub_dir: PathBuf,
    /// Per-tenant audit log.
    pub audit_log: PathBuf,
    /// Optional TLS 1.3 termination params for the listen side.
    pub tls: Option<TlsConfig>,
    /// Effective audit signer for this tenant — per-tenant override if set,
    /// otherwise the daemon-level default. Resolved at config-load time.
    pub audit_signer: AuditSignerConfig,
    /// SNI hostname this tenant claims. `Some(_)` iff this tenant shares
    /// its listen with sibling tenants (multi-SNI dispatch). `None` for
    /// single-tenant listeners.
    pub sni: Option<String>,
    /// Sprint 9.5: optional connection admission limits. `None` = unlimited
    /// (every accepted connection proceeds to handshake).
    pub limits: Option<TenantLimits>,
}

/// Resolved serve-pq tenant parameters.
#[derive(Debug, Clone)]
pub struct ServePqTenant {
    /// Tenant identity.
    pub id: TenantId,
    /// CSPQ listen address.
    pub listen: String,
    /// Backend TCP address to dial.
    pub backend: String,
    /// Trust scope.
    pub peer_pub_dir: PathBuf,
    /// Per-tenant audit log.
    pub audit_log: PathBuf,
    /// Effective audit signer for this tenant — per-tenant override if set,
    /// otherwise the daemon-level default. Resolved at config-load time.
    pub audit_signer: AuditSignerConfig,
    /// Sprint 9.5: optional connection admission limits.
    pub limits: Option<TenantLimits>,
}

/// Sprint 6: a TLS-terminating listener group. A group has either ONE
/// tenant (current single-tenant model, optionally with TLS) or MANY
/// tenants sharing one listen address and dispatched by SNI at handshake
/// time. The grouping is determined at `resolve_serve_tcp_groups()` time
/// from `[tenants.listen]` collisions in the parsed config.
#[derive(Debug, Clone)]
pub struct TlsListenerGroup {
    /// Bind address shared by all members of the group.
    pub listen: String,
    /// True iff this group has >1 tenant and must SNI-dispatch at TLS
    /// handshake time.
    pub sni_dispatch: bool,
    /// Members. Length >= 1. When `sni_dispatch`, every tenant has
    /// `tls.is_some()` and `sni.is_some()` (enforced at validate time).
    pub tenants: Vec<ServeTcpTenant>,
}

/// Audit-signer configuration. Shared across all tenants of a daemon.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum AuditSignerConfig {
    /// Software ML-DSA-87 key stored on disk.
    Softkey {
        /// Path to the audit `.audit.skid`.
        secret_key: PathBuf,
        /// Path to the audit `.audit.pub`.
        public_key: PathBuf,
    },
    /// PKCS#11-backed signer (requires `qaudit-hsm` with `pkcs11` feature).
    Pkcs11 {
        /// Path to the PKCS#11 module shared object.
        module: PathBuf,
        /// Slot number on the HSM.
        slot: usize,
        /// Env-var name from which the PIN will be read at startup.
        pin_env: String,
        /// CKA_LABEL of the keypair on the HSM.
        key_label: String,
        /// Optional separate label for the public key.
        #[serde(default)]
        pub_label: Option<String>,
        /// Vendor-defined PKCS#11 mechanism ID for ML-DSA-87.
        #[serde(default)]
        mechanism_id: Option<u64>,
    },
}

impl Config {
    /// Load and validate config from a TOML file.
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let p = path.as_ref();
        let text = std::fs::read_to_string(p)
            .map_err(|e| ConfigError::Read(p.display().to_string(), e.to_string()))?;
        let cfg: Self = toml::from_str(&text).map_err(|e| ConfigError::Parse(e.to_string()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Parse a config from a TOML string. Validates as well.
    pub fn from_toml_str(text: &str) -> Result<Self, ConfigError> {
        let cfg: Self = toml::from_str(text).map_err(|e| ConfigError::Parse(e.to_string()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.tenants.is_empty() {
            return Err(ConfigError::Missing(
                "config must declare at least one [[tenants]] entry".into(),
            ));
        }
        let mut seen = std::collections::HashSet::new();
        for t in &self.tenants {
            if !seen.insert(t.name.clone()) {
                return Err(ConfigError::Conflict(format!(
                    "duplicate tenant name: {}",
                    t.name
                )));
            }
            // Audit signer must be resolvable (per-tenant override OR daemon default).
            if t.audit_signer.is_none() && self.audit_signer.is_none() {
                return Err(ConfigError::Missing(format!(
                    "tenant {}: no audit_signer (declare [tenants.audit_signer] for \
                     this tenant or a top-level [audit_signer] as the default)",
                    t.name
                )));
            }
            match self.role {
                Role::ServeTcp => {
                    if t.peer_pq.is_none() {
                        return Err(ConfigError::Missing(format!(
                            "tenant {}: peer_pq required for role = serve-tcp",
                            t.name
                        )));
                    }
                    if t.backend.is_some() {
                        return Err(ConfigError::Conflict(format!(
                            "tenant {}: backend must not be set when role = serve-tcp",
                            t.name
                        )));
                    }
                }
                Role::ServePq => {
                    if t.backend.is_none() {
                        return Err(ConfigError::Missing(format!(
                            "tenant {}: backend required for role = serve-pq",
                            t.name
                        )));
                    }
                    if t.peer_pq.is_some() {
                        return Err(ConfigError::Conflict(format!(
                            "tenant {}: peer_pq must not be set when role = serve-pq",
                            t.name
                        )));
                    }
                    if t.tls.is_some() {
                        return Err(ConfigError::Conflict(format!(
                            "tenant {}: tls section only valid for role = serve-tcp",
                            t.name
                        )));
                    }
                }
            }
        }

        // Sprint 6: Validate SNI-listener grouping. Tenants that share a
        // `listen` address form a multi-SNI TLS group; the validation rules
        // are strict so that misconfiguration can't silently expose one
        // tenant's traffic to another tenant's TLS terminator.
        self.validate_sni_groups()?;
        Ok(())
    }

    /// Sprint 6: group serve-tcp tenants by `listen` address, then verify:
    /// - Multi-tenant groups: every member MUST have `[tenants.tls]` AND
    ///   `sni = "..."` set, AND all SNIs within the group MUST be distinct.
    /// - Single-tenant groups: SNI is optional and meaningless (one cert
    ///   serves all incoming connections); reject `sni` to avoid false
    ///   sense of routing.
    /// - Mixing TLS-on and TLS-off in the same group is rejected: a single
    ///   listen port is either fully TLS-terminated or not.
    fn validate_sni_groups(&self) -> Result<(), ConfigError> {
        if self.role != Role::ServeTcp {
            // SNI is irrelevant for serve-pq (no TLS termination on that side).
            for t in &self.tenants {
                if t.sni.is_some() {
                    return Err(ConfigError::Conflict(format!(
                        "tenant {}: sni only meaningful for role = serve-tcp",
                        t.name
                    )));
                }
            }
            return Ok(());
        }
        use std::collections::HashMap;
        let mut by_listen: HashMap<&str, Vec<&TenantConfig>> = HashMap::new();
        for t in &self.tenants {
            by_listen.entry(t.listen.as_str()).or_default().push(t);
        }
        for (listen, group) in &by_listen {
            if group.len() == 1 {
                // Single-tenant listener: SNI must NOT be set.
                let t = group[0];
                if t.sni.is_some() {
                    return Err(ConfigError::Conflict(format!(
                        "tenant {}: sni is set but listen {} has only one tenant —                          remove sni or add a sibling tenant on the same listen",
                        t.name, listen
                    )));
                }
                continue;
            }
            // Multi-tenant listener: TLS + SNI required on every member.
            let mut tls_state: Option<bool> = None;
            let mut seen_sni: std::collections::HashSet<&str> = std::collections::HashSet::new();
            for t in group {
                let has_tls = t.tls.is_some();
                if let Some(prev) = tls_state {
                    if prev != has_tls {
                        return Err(ConfigError::Conflict(format!(
                            "listen {}: cannot mix tenants with and without [tenants.tls]                              — a single listen port is either fully TLS-terminated or not                              (tenant {} disagrees)",
                            listen, t.name
                        )));
                    }
                } else {
                    tls_state = Some(has_tls);
                }
                if !has_tls {
                    return Err(ConfigError::Conflict(format!(
                        "listen {}: tenants sharing a listen must all have [tenants.tls]                          set (tenant {} does not) — SNI dispatch is only possible at TLS                          handshake time",
                        listen, t.name
                    )));
                }
                let sni = t.sni.as_deref().ok_or_else(|| {
                    ConfigError::Missing(format!(
                        "tenant {}: shares listen {} with {} other tenant(s) but has no                          sni — SNI is mandatory for multi-tenant listeners",
                        t.name,
                        listen,
                        group.len() - 1
                    ))
                })?;
                if sni.is_empty() {
                    return Err(ConfigError::Missing(format!(
                        "tenant {}: sni must be a non-empty hostname",
                        t.name
                    )));
                }
                // Sprint 8: validate wildcard pattern shape early.
                if sni.contains('*') && (!sni.starts_with("*.") || sni[2..].contains('*')) {
                    return Err(ConfigError::Conflict(format!(
                        "tenant {}: sni {:?} is an invalid wildcard \
                         (must be '*.host.example.com' with the asterisk \
                         only as the leftmost label)",
                        t.name, sni
                    )));
                }
                if !seen_sni.insert(sni) {
                    return Err(ConfigError::Conflict(format!(
                        "listen {}: duplicate sni {:?} (tenant {} collides with another)",
                        listen, sni, t.name
                    )));
                }
            }
        }
        // Sprint 9.5: validate per-tenant limits (zero values are operator
        // errors — a quota of 0 rejects every connection, a rate limit of 0
        // is meaningless).
        for t in &self.tenants {
            if let Some(limits) = &t.limits {
                if let Some(0) = limits.max_concurrent {
                    return Err(ConfigError::Conflict(format!(
                        "tenant {}: limits.max_concurrent = 0 rejects every \
                         connection; omit the field or set ≥ 1",
                        t.name
                    )));
                }
                if let Some(rl) = &limits.rate_limit_per_source {
                    if rl.capacity == 0 {
                        return Err(ConfigError::Conflict(format!(
                            "tenant {}: limits.rate_limit_per_source.capacity = 0 \
                             rejects every connection; omit the block or set ≥ 1",
                            t.name
                        )));
                    }
                    if rl.refill_per_sec == 0 {
                        return Err(ConfigError::Conflict(format!(
                            "tenant {}: limits.rate_limit_per_source.refill_per_sec = 0 \
                             means buckets never refill — sources exhaust permanently; \
                             omit the block or set ≥ 1",
                            t.name
                        )));
                    }
                }
            }
        }
        Ok(())
    }

    /// Effective audit signer for a tenant: tenant override OR daemon default.
    /// Returns `None` only in configs that didn't pass `validate()`.
    /// Effective audit signer for `t` — tenant override or daemon default.
    /// Returns `None` if neither is set (caller decides whether that's fatal).
    pub fn effective_signer(&self, t: &TenantConfig) -> Option<AuditSignerConfig> {
        t.audit_signer.clone().or_else(|| self.audit_signer.clone())
    }

    /// Resolve all tenants into typed `ServeTcpTenant` values.
    pub fn resolve_serve_tcp(&self) -> Result<Vec<ServeTcpTenant>, ConfigError> {
        if self.role != Role::ServeTcp {
            return Err(ConfigError::Conflict(
                "resolve_serve_tcp called on non-serve-tcp config".into(),
            ));
        }
        self.tenants
            .iter()
            .map(|t| self.resolve_one_serve_tcp(t))
            .collect()
    }

    /// Sprint 13: resolve a SINGLE tenant config into a `ServeTcpTenant`.
    /// Used by the SIGHUP apply step to spawn an accept loop for a
    /// newly-added serve-tcp tenant without restart.
    pub fn resolve_one_serve_tcp(&self, t: &TenantConfig) -> Result<ServeTcpTenant, ConfigError> {
        if self.role != Role::ServeTcp {
            return Err(ConfigError::Conflict(
                "resolve_one_serve_tcp called on non-serve-tcp config".into(),
            ));
        }
        let audit_signer = self
            .effective_signer(t)
            .ok_or_else(|| ConfigError::Missing(format!("tenant {}: no audit_signer", t.name)))?;
        let peer_pq = t.peer_pq.clone().ok_or_else(|| {
            ConfigError::Missing(format!(
                "tenant {}: serve-tcp tenant must declare a peer_pq",
                t.name
            ))
        })?;
        Ok(ServeTcpTenant {
            id: TenantId {
                name: t.name.clone(),
            },
            listen: t.listen.clone(),
            peer_pq,
            peer_pub_dir: t.peer_pub_dir.clone(),
            audit_log: t.audit_log.clone(),
            tls: t.tls.clone(),
            audit_signer,
            sni: t.sni.clone(),
            limits: t.limits.clone(),
        })
    }

    /// Resolve all tenants into typed `ServePqTenant` values.
    /// Sprint 6: group resolved serve-tcp tenants by `listen` address.
    /// Each group is either a single-tenant listener (current model) or a
    /// multi-tenant SNI-dispatched listener.
    pub fn resolve_serve_tcp_groups(&self) -> Result<Vec<TlsListenerGroup>, ConfigError> {
        let flat = self.resolve_serve_tcp()?;
        use std::collections::BTreeMap;
        // BTreeMap keeps the group order deterministic by listen string,
        // which matters for log lines and metrics endpoint ordering.
        let mut by_listen: BTreeMap<String, Vec<ServeTcpTenant>> = BTreeMap::new();
        for t in flat {
            by_listen.entry(t.listen.clone()).or_default().push(t);
        }
        let mut out = Vec::with_capacity(by_listen.len());
        for (listen, tenants) in by_listen {
            let sni_dispatch = tenants.len() > 1;
            out.push(TlsListenerGroup {
                listen,
                sni_dispatch,
                tenants,
            });
        }
        Ok(out)
    }

    /// Resolve serve-pq tenants. SNI grouping doesn't apply on this side —
    /// the serve-pq leg is purely CSPQ-over-TCP with no TLS termination.
    pub fn resolve_serve_pq(&self) -> Result<Vec<ServePqTenant>, ConfigError> {
        if self.role != Role::ServePq {
            return Err(ConfigError::Conflict(
                "resolve_serve_pq called on non-serve-pq config".into(),
            ));
        }
        self.tenants
            .iter()
            .map(|t| self.resolve_one_serve_pq(t))
            .collect()
    }

    /// Sprint 12: resolve a SINGLE tenant config into a `ServePqTenant`.
    /// Used by the SIGHUP apply step to spawn an accept loop for a
    /// newly-added tenant without re-resolving the full daemon config.
    /// Returns the same error variants as `resolve_serve_pq` would for
    /// that single entry.
    pub fn resolve_one_serve_pq(&self, t: &TenantConfig) -> Result<ServePqTenant, ConfigError> {
        if self.role != Role::ServePq {
            return Err(ConfigError::Conflict(
                "resolve_one_serve_pq called on non-serve-pq config".into(),
            ));
        }
        let audit_signer = self
            .effective_signer(t)
            .ok_or_else(|| ConfigError::Missing(format!("tenant {}: no audit_signer", t.name)))?;
        let backend = t.backend.clone().ok_or_else(|| {
            ConfigError::Missing(format!(
                "tenant {}: serve-pq tenant must declare a backend",
                t.name
            ))
        })?;
        Ok(ServePqTenant {
            id: TenantId {
                name: t.name.clone(),
            },
            listen: t.listen.clone(),
            backend,
            peer_pub_dir: t.peer_pub_dir.clone(),
            audit_log: t.audit_log.clone(),
            audit_signer,
            limits: t.limits.clone(),
        })
    }
}

/// Config validation / load errors.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// Filesystem read failed.
    #[error("cannot read {0}: {1}")]
    Read(String, String),
    /// TOML deserialization failed.
    #[error("TOML parse error: {0}")]
    Parse(String),
    /// Required field missing.
    #[error("config missing field: {0}")]
    Missing(String),
    /// Conflict between fields or duplicates.
    #[error("config conflict: {0}")]
    Conflict(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    const SERVE_TCP_TOML: &str = r#"
role = "serve-tcp"
identity_key   = "/etc/qg/qg.skid"
identity_pub   = "/etc/qg/qg.cspqid.pub"
metrics_listen = "127.0.0.1:9098"

[audit_signer]
kind       = "softkey"
secret_key = "/etc/qg/audit.skid"
public_key = "/etc/qg/audit.pub"

[[tenants]]
name         = "branch-sp"
listen       = "127.0.0.1:8443"
peer_pq      = "10.0.1.50:9999"
peer_pub_dir = "/etc/qg/peers-sp"
audit_log    = "/var/lib/qg/sp.qa"

[[tenants]]
name         = "branch-rj"
listen       = "127.0.0.1:8444"
peer_pq      = "10.0.2.50:9999"
peer_pub_dir = "/etc/qg/peers-rj"
audit_log    = "/var/lib/qg/rj.qa"
"#;

    const SERVE_PQ_TOML: &str = r#"
role = "serve-pq"
identity_key   = "/etc/qg/qg.skid"
identity_pub   = "/etc/qg/qg.cspqid.pub"

[audit_signer]
kind       = "softkey"
secret_key = "/etc/qg/audit.skid"
public_key = "/etc/qg/audit.pub"

[[tenants]]
name         = "branch-sp"
listen       = "0.0.0.0:9999"
backend      = "127.0.0.1:80"
peer_pub_dir = "/etc/qg/peers-sp"
audit_log    = "/var/lib/qg/sp.qa"
"#;

    const PKCS11_AUDIT_TOML: &str = r#"
role = "serve-tcp"
identity_key   = "/etc/qg/qg.skid"
identity_pub   = "/etc/qg/qg.cspqid.pub"

[audit_signer]
kind         = "pkcs11"
module       = "/opt/dinamo/lib/libdinamo.so"
slot         = 0
pin_env      = "QGATEWAY_HSM_PIN"
key_label    = "qgateway-audit"
mechanism_id = 0x80000001

[[tenants]]
name         = "branch-sp"
listen       = "127.0.0.1:8443"
peer_pq      = "10.0.1.50:9999"
peer_pub_dir = "/etc/qg/peers-sp"
audit_log    = "/var/lib/qg/sp.qa"
"#;

    const TLS_TENANT_TOML: &str = r#"
role = "serve-tcp"
identity_key   = "/etc/qg/qg.skid"
identity_pub   = "/etc/qg/qg.cspqid.pub"

[audit_signer]
kind       = "softkey"
secret_key = "/etc/qg/audit.skid"
public_key = "/etc/qg/audit.pub"

[[tenants]]
name         = "tls-tenant"
listen       = "127.0.0.1:8443"
peer_pq      = "10.0.1.50:9999"
peer_pub_dir = "/etc/qg/peers"
audit_log    = "/var/lib/qg/tls.qa"

[tenants.tls]
cert = "/etc/qg/tls/server.pem"
key  = "/etc/qg/tls/server.key"
"#;

    #[test]
    fn parse_serve_tcp_multi_tenant() {
        let cfg = Config::from_toml_str(SERVE_TCP_TOML).unwrap();
        assert_eq!(cfg.role, Role::ServeTcp);
        assert_eq!(cfg.tenants.len(), 2);
        let r = cfg.resolve_serve_tcp().unwrap();
        assert_eq!(r[0].id.name, "branch-sp");
        assert_eq!(r[0].peer_pq, "10.0.1.50:9999");
        assert_eq!(r[1].peer_pq, "10.0.2.50:9999");
        assert_eq!(cfg.metrics_listen, "127.0.0.1:9098");
        assert!(r[0].tls.is_none());
    }

    #[test]
    fn parse_serve_pq_single_tenant() {
        let cfg = Config::from_toml_str(SERVE_PQ_TOML).unwrap();
        assert_eq!(cfg.role, Role::ServePq);
        let r = cfg.resolve_serve_pq().unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].listen, "0.0.0.0:9999");
        assert_eq!(r[0].backend, "127.0.0.1:80");
    }

    #[test]
    fn parse_pkcs11_audit_signer() {
        let cfg = Config::from_toml_str(PKCS11_AUDIT_TOML).unwrap();
        match cfg.audit_signer {
            Some(AuditSignerConfig::Pkcs11 {
                ref module,
                slot,
                ref pin_env,
                ref key_label,
                ref pub_label,
                mechanism_id,
            }) => {
                assert_eq!(module.to_str().unwrap(), "/opt/dinamo/lib/libdinamo.so");
                assert_eq!(slot, 0);
                assert_eq!(pin_env, "QGATEWAY_HSM_PIN");
                assert_eq!(key_label, "qgateway-audit");
                assert!(pub_label.is_none());
                assert_eq!(mechanism_id, Some(0x80000001));
            }
            _ => panic!("expected pkcs11 audit signer"),
        }
    }

    #[test]
    fn parse_tls_tenant() {
        let cfg = Config::from_toml_str(TLS_TENANT_TOML).unwrap();
        let r = cfg.resolve_serve_tcp().unwrap();
        let tls = r[0].tls.as_ref().expect("tls present");
        assert_eq!(tls.cert.to_str().unwrap(), "/etc/qg/tls/server.pem");
        assert_eq!(tls.key.to_str().unwrap(), "/etc/qg/tls/server.key");
    }

    #[test]
    fn rejects_duplicate_tenant_names() {
        let bad = SERVE_TCP_TOML.replace("branch-rj", "branch-sp");
        let err = Config::from_toml_str(&bad).unwrap_err();
        assert!(matches!(err, ConfigError::Conflict(_)));
    }

    #[test]
    fn rejects_tls_on_serve_pq() {
        let bad = r#"
role = "serve-pq"
identity_key = "/x"
identity_pub = "/y"
[audit_signer]
kind = "softkey"
secret_key = "/z"
public_key = "/w"
[[tenants]]
name = "t1"
listen = "0.0.0.0:1"
backend = "127.0.0.1:80"
peer_pub_dir = "/p"
audit_log = "/a"
[tenants.tls]
cert = "/c"
key = "/k"
"#;
        let err = Config::from_toml_str(bad).unwrap_err();
        assert!(matches!(err, ConfigError::Conflict(_)));
    }

    #[test]
    fn rejects_role_field_mismatch() {
        let bad = r#"
role = "serve-tcp"
identity_key = "/x"
identity_pub = "/y"
[audit_signer]
kind = "softkey"
secret_key = "/z"
public_key = "/w"
[[tenants]]
name = "t1"
listen = "127.0.0.1:1"
peer_pq = "10.0.0.1:2"
backend = "10.0.0.1:3"
peer_pub_dir = "/p"
audit_log = "/a"
"#;
        let err = Config::from_toml_str(bad).unwrap_err();
        assert!(
            matches!(err, ConfigError::Conflict(_) | ConfigError::Missing(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_zero_tenants() {
        let bad = r#"
role = "serve-tcp"
identity_key = "/x"
identity_pub = "/y"
[audit_signer]
kind = "softkey"
secret_key = "/z"
public_key = "/w"
tenants = []
"#;
        let err = Config::from_toml_str(bad).unwrap_err();
        assert!(
            matches!(err, ConfigError::Missing(_) | ConfigError::Parse(_)),
            "got {err:?}"
        );
    }

    // ========================================================================
    //              Sprint 5 — per-tenant audit signer isolation
    // ========================================================================

    /// Per-tenant `[tenants.audit_signer]` override fully replaces the
    /// daemon-level default for that tenant, while other tenants keep the
    /// default. Resolved `ServeTcpTenant.audit_signer` must reflect this.
    #[test]
    fn per_tenant_audit_signer_override() {
        // Two tenants: `sp` uses an override audit key, `rj` falls back to
        // the daemon default. Resolving both must yield distinct signers.
        let toml = r#"
role = "serve-tcp"
identity_key  = "/etc/qg/qg.skid"
identity_pub  = "/etc/qg/qg.cspqid.pub"

[audit_signer]
kind       = "softkey"
secret_key = "/etc/qg/audit-default.skid"
public_key = "/etc/qg/audit-default.pub"

[[tenants]]
name         = "sp"
listen       = "127.0.0.1:8443"
peer_pq      = "10.0.1.50:9999"
peer_pub_dir = "/etc/qg/peers-sp"
audit_log    = "/var/lib/qg/sp.qa"

# This tenant uses its OWN audit key — it MUST NOT inherit the default.
[tenants.audit_signer]
kind       = "softkey"
secret_key = "/etc/qg/audit-sp.skid"
public_key = "/etc/qg/audit-sp.pub"

[[tenants]]
name         = "rj"
listen       = "127.0.0.1:8444"
peer_pq      = "10.0.2.50:9999"
peer_pub_dir = "/etc/qg/peers-rj"
audit_log    = "/var/lib/qg/rj.qa"
# (no per-tenant audit_signer — falls back to daemon default)
"#;

        let cfg = Config::from_toml_str(toml).unwrap();
        let tenants = cfg.resolve_serve_tcp().unwrap();
        assert_eq!(tenants.len(), 2);

        // Find each tenant by name and pull out its resolved signer.
        let sp = tenants.iter().find(|t| t.id.name == "sp").unwrap();
        let rj = tenants.iter().find(|t| t.id.name == "rj").unwrap();

        match (&sp.audit_signer, &rj.audit_signer) {
            (
                AuditSignerConfig::Softkey {
                    secret_key: sp_sk,
                    public_key: sp_pk,
                },
                AuditSignerConfig::Softkey {
                    secret_key: rj_sk,
                    public_key: rj_pk,
                },
            ) => {
                assert_eq!(sp_sk, std::path::Path::new("/etc/qg/audit-sp.skid"));
                assert_eq!(sp_pk, std::path::Path::new("/etc/qg/audit-sp.pub"));
                assert_eq!(rj_sk, std::path::Path::new("/etc/qg/audit-default.skid"));
                assert_eq!(rj_pk, std::path::Path::new("/etc/qg/audit-default.pub"));
                assert_ne!(sp_sk, rj_sk, "per-tenant signer must NOT inherit");
            }
            other => panic!("expected two softkey signers, got {other:?}"),
        }
    }

    /// A config with no daemon-level signer AND no per-tenant override must
    /// fail validation. (One or the other must be present for every tenant.)
    #[test]
    fn rejects_tenant_without_any_audit_signer() {
        let bad = r#"
role = "serve-tcp"
identity_key  = "/x"
identity_pub  = "/y"
# Note: no daemon-level [audit_signer] block.

[[tenants]]
name         = "lonely"
listen       = "127.0.0.1:8443"
peer_pq      = "10.0.1.50:9999"
peer_pub_dir = "/p"
audit_log    = "/l.qa"
# Note: no per-tenant audit_signer either.
"#;
        let err = Config::from_toml_str(bad).unwrap_err();
        match err {
            ConfigError::Missing(m) => {
                assert!(m.contains("audit_signer"), "got {m:?}");
                assert!(m.contains("lonely"), "got {m:?}");
            }
            other => panic!("expected Missing(audit_signer), got {other:?}"),
        }
    }

    /// A config with NO daemon-level signer but every tenant declaring its
    /// OWN signer must validate. This is the strict per-tenant isolation
    /// posture: no fallback, every tenant owns its audit key.
    #[test]
    fn accepts_strict_per_tenant_no_daemon_default() {
        let toml = r#"
role = "serve-tcp"
identity_key  = "/etc/qg/qg.skid"
identity_pub  = "/etc/qg/qg.cspqid.pub"

[[tenants]]
name         = "sp"
listen       = "127.0.0.1:8443"
peer_pq      = "10.0.1.50:9999"
peer_pub_dir = "/etc/qg/peers-sp"
audit_log    = "/var/lib/qg/sp.qa"
[tenants.audit_signer]
kind       = "softkey"
secret_key = "/etc/qg/audit-sp.skid"
public_key = "/etc/qg/audit-sp.pub"

[[tenants]]
name         = "rj"
listen       = "127.0.0.1:8444"
peer_pq      = "10.0.2.50:9999"
peer_pub_dir = "/etc/qg/peers-rj"
audit_log    = "/var/lib/qg/rj.qa"
[tenants.audit_signer]
kind       = "softkey"
secret_key = "/etc/qg/audit-rj.skid"
public_key = "/etc/qg/audit-rj.pub"
"#;
        let cfg = Config::from_toml_str(toml).unwrap();
        let tenants = cfg.resolve_serve_tcp().unwrap();
        assert_eq!(tenants.len(), 2);
        // Verify each tenant carries DIFFERENT signer paths.
        let signers: Vec<_> = tenants.iter().map(|t| &t.audit_signer).collect();
        match (&signers[0], &signers[1]) {
            (
                AuditSignerConfig::Softkey { secret_key: a, .. },
                AuditSignerConfig::Softkey { secret_key: b, .. },
            ) => assert_ne!(a, b, "two tenants must resolve to two different signers"),
            other => panic!("expected two softkey signers, got {other:?}"),
        }
    }

    /// Mixing signer kinds across tenants must work — e.g. SP on PKCS#11 HSM
    /// for regulatory reasons, RJ on softkey for cost. Resolved tenants must
    /// carry the right kind.
    #[test]
    fn accepts_mixed_signer_kinds_across_tenants() {
        let toml = r#"
role = "serve-tcp"
identity_key  = "/etc/qg/qg.skid"
identity_pub  = "/etc/qg/qg.cspqid.pub"

[[tenants]]
name         = "sp-regulated"
listen       = "127.0.0.1:8443"
peer_pq      = "10.0.1.50:9999"
peer_pub_dir = "/etc/qg/peers-sp"
audit_log    = "/var/lib/qg/sp.qa"
[tenants.audit_signer]
kind         = "pkcs11"
module       = "/opt/dinamo/lib/libdinamo.so"
slot         = 0
pin_env      = "QGATEWAY_HSM_PIN_SP"
key_label    = "audit-sp"
mechanism_id = 0x80000001

[[tenants]]
name         = "rj-dev"
listen       = "127.0.0.1:8444"
peer_pq      = "10.0.2.50:9999"
peer_pub_dir = "/etc/qg/peers-rj"
audit_log    = "/var/lib/qg/rj.qa"
[tenants.audit_signer]
kind       = "softkey"
secret_key = "/etc/qg/audit-rj.skid"
public_key = "/etc/qg/audit-rj.pub"
"#;
        let cfg = Config::from_toml_str(toml).unwrap();
        let tenants = cfg.resolve_serve_tcp().unwrap();
        assert_eq!(tenants.len(), 2);

        let sp = tenants
            .iter()
            .find(|t| t.id.name == "sp-regulated")
            .unwrap();
        let rj = tenants.iter().find(|t| t.id.name == "rj-dev").unwrap();

        assert!(
            matches!(sp.audit_signer, AuditSignerConfig::Pkcs11 { .. }),
            "sp-regulated must resolve to PKCS#11"
        );
        assert!(
            matches!(rj.audit_signer, AuditSignerConfig::Softkey { .. }),
            "rj-dev must resolve to Softkey"
        );
    }

    // ========================================================================
    //              Sprint 6 — SNI listener grouping validation
    // ========================================================================

    #[test]
    fn sni_multi_tenant_listener_groups_correctly() {
        let toml = r#"
role = "serve-tcp"
identity_key = "/etc/qg/qg.skid"
identity_pub = "/etc/qg/qg.cspqid.pub"

[audit_signer]
kind = "softkey"
secret_key = "/etc/qg/audit.skid"
public_key = "/etc/qg/audit.pub"

[[tenants]]
name = "sp"
listen = "0.0.0.0:8443"
sni = "sp.example.com"
peer_pq = "10.0.1.50:9999"
peer_pub_dir = "/etc/qg/peers-sp"
audit_log = "/var/lib/qg/sp.qa"
[tenants.tls]
cert = "/etc/qg/sp.pem"
key = "/etc/qg/sp.key"

[[tenants]]
name = "rj"
listen = "0.0.0.0:8443"
sni = "rj.example.com"
peer_pq = "10.0.2.50:9999"
peer_pub_dir = "/etc/qg/peers-rj"
audit_log = "/var/lib/qg/rj.qa"
[tenants.tls]
cert = "/etc/qg/rj.pem"
key = "/etc/qg/rj.key"
"#;
        let cfg = Config::from_toml_str(toml).expect("config must validate");
        let groups = cfg.resolve_serve_tcp_groups().unwrap();
        assert_eq!(groups.len(), 1, "single shared listener");
        let g = &groups[0];
        assert_eq!(g.listen, "0.0.0.0:8443");
        assert!(g.sni_dispatch, "must be SNI-dispatched");
        assert_eq!(g.tenants.len(), 2);
        let snis: Vec<&str> = g
            .tenants
            .iter()
            .map(|t| t.sni.as_deref().unwrap())
            .collect();
        assert!(snis.contains(&"sp.example.com"));
        assert!(snis.contains(&"rj.example.com"));
    }

    #[test]
    fn sni_single_tenant_listener_is_not_dispatched() {
        let toml = r#"
role = "serve-tcp"
identity_key = "/x"
identity_pub = "/y"

[audit_signer]
kind = "softkey"
secret_key = "/z"
public_key = "/w"

[[tenants]]
name = "solo"
listen = "0.0.0.0:8443"
peer_pq = "10.0.1.50:9999"
peer_pub_dir = "/peers"
audit_log = "/log.qa"
[tenants.tls]
cert = "/c"
key = "/k"
"#;
        let cfg = Config::from_toml_str(toml).unwrap();
        let groups = cfg.resolve_serve_tcp_groups().unwrap();
        assert_eq!(groups.len(), 1);
        assert!(!groups[0].sni_dispatch);
        assert_eq!(groups[0].tenants.len(), 1);
        assert!(groups[0].tenants[0].sni.is_none());
    }

    #[test]
    fn sni_multi_tenant_without_sni_field_rejected() {
        let bad = r#"
role = "serve-tcp"
identity_key = "/x"
identity_pub = "/y"

[audit_signer]
kind = "softkey"
secret_key = "/z"
public_key = "/w"

[[tenants]]
name = "sp"
listen = "0.0.0.0:8443"
peer_pq = "10.0.1.50:9999"
peer_pub_dir = "/peers"
audit_log = "/sp.qa"
[tenants.tls]
cert = "/c1"
key = "/k1"

[[tenants]]
name = "rj"
listen = "0.0.0.0:8443"
peer_pq = "10.0.2.50:9999"
peer_pub_dir = "/peers"
audit_log = "/rj.qa"
[tenants.tls]
cert = "/c2"
key = "/k2"
"#;
        let err = Config::from_toml_str(bad).unwrap_err();
        match err {
            ConfigError::Missing(m) => {
                assert!(m.contains("sni"), "expected sni-missing error, got: {m}");
            }
            other => panic!("expected Missing, got {other:?}"),
        }
    }

    #[test]
    fn sni_duplicate_within_same_listener_rejected() {
        let bad = r#"
role = "serve-tcp"
identity_key = "/x"
identity_pub = "/y"

[audit_signer]
kind = "softkey"
secret_key = "/z"
public_key = "/w"

[[tenants]]
name = "sp"
listen = "0.0.0.0:8443"
sni = "shared.example.com"
peer_pq = "10.0.1.50:9999"
peer_pub_dir = "/peers"
audit_log = "/sp.qa"
[tenants.tls]
cert = "/c1"
key = "/k1"

[[tenants]]
name = "rj"
listen = "0.0.0.0:8443"
sni = "shared.example.com"
peer_pq = "10.0.2.50:9999"
peer_pub_dir = "/peers"
audit_log = "/rj.qa"
[tenants.tls]
cert = "/c2"
key = "/k2"
"#;
        let err = Config::from_toml_str(bad).unwrap_err();
        match err {
            ConfigError::Conflict(m) => {
                assert!(
                    m.contains("duplicate sni") || m.contains("collides"),
                    "expected duplicate-sni error, got: {m}"
                );
            }
            other => panic!("expected Conflict, got {other:?}"),
        }
    }

    #[test]
    fn sni_set_on_single_tenant_listener_rejected() {
        // Belt-and-suspenders: SNI is meaningless for a single-tenant listener.
        // Allowing it would create a false sense of routing isolation.
        let bad = r#"
role = "serve-tcp"
identity_key = "/x"
identity_pub = "/y"

[audit_signer]
kind = "softkey"
secret_key = "/z"
public_key = "/w"

[[tenants]]
name = "lonely"
listen = "0.0.0.0:8443"
sni = "lonely.example.com"
peer_pq = "10.0.1.50:9999"
peer_pub_dir = "/peers"
audit_log = "/log.qa"
[tenants.tls]
cert = "/c"
key = "/k"
"#;
        let err = Config::from_toml_str(bad).unwrap_err();
        match err {
            ConfigError::Conflict(m) => {
                assert!(m.contains("sni"), "expected sni-conflict, got: {m}");
            }
            other => panic!("expected Conflict, got {other:?}"),
        }
    }

    #[test]
    fn sni_mixing_tls_on_and_off_rejected() {
        let bad = r#"
role = "serve-tcp"
identity_key = "/x"
identity_pub = "/y"

[audit_signer]
kind = "softkey"
secret_key = "/z"
public_key = "/w"

[[tenants]]
name = "sp"
listen = "0.0.0.0:8443"
sni = "sp.example.com"
peer_pq = "10.0.1.50:9999"
peer_pub_dir = "/peers"
audit_log = "/sp.qa"
[tenants.tls]
cert = "/c1"
key = "/k1"

[[tenants]]
name = "rj"
listen = "0.0.0.0:8443"
sni = "rj.example.com"
peer_pq = "10.0.2.50:9999"
peer_pub_dir = "/peers"
audit_log = "/rj.qa"
# (no [tenants.tls] block — must be rejected when sharing a listen)
"#;
        let err = Config::from_toml_str(bad).unwrap_err();
        match err {
            ConfigError::Conflict(m) => {
                assert!(
                    m.contains("tls") || m.contains("TLS"),
                    "expected tls-conflict, got: {m}"
                );
            }
            other => panic!("expected Conflict, got {other:?}"),
        }
    }

    #[test]
    fn sni_on_serve_pq_role_rejected() {
        // SNI only applies to serve-tcp (the TLS-terminating side).
        let bad = r#"
role = "serve-pq"
identity_key = "/x"
identity_pub = "/y"

[audit_signer]
kind = "softkey"
secret_key = "/z"
public_key = "/w"

[[tenants]]
name = "sp"
listen = "0.0.0.0:9999"
sni = "sp.example.com"
backend = "127.0.0.1:80"
peer_pub_dir = "/peers"
audit_log = "/sp.qa"
"#;
        let err = Config::from_toml_str(bad).unwrap_err();
        match err {
            ConfigError::Conflict(m) => {
                assert!(m.contains("sni"), "expected sni-on-pq conflict, got: {m}");
            }
            other => panic!("expected Conflict, got {other:?}"),
        }
    }

    // ================================================================
    //          Sprint 12 — resolve_one_serve_pq
    // ================================================================

    // ================================================================
    //          Sprint 12 — resolve_one_serve_pq
    // ================================================================

    #[test]
    fn resolve_one_serve_pq_returns_resolved_single_tenant() {
        let cfg = Config::from_toml_str(SERVE_PQ_TOML).unwrap();
        let t = &cfg.tenants[0];
        let resolved = cfg.resolve_one_serve_pq(t).expect("single-tenant resolve");
        assert_eq!(resolved.id.name, "branch-sp");
        assert_eq!(resolved.listen, "0.0.0.0:9999");
        assert_eq!(resolved.backend, "127.0.0.1:80");
        assert!(matches!(
            resolved.audit_signer,
            AuditSignerConfig::Softkey { .. }
        ));
        assert!(resolved.limits.is_none());
    }

    #[test]
    fn resolve_one_serve_pq_rejects_when_not_serve_pq_role() {
        // Build a serve-tcp config, then try to resolve one of its
        // tenants as serve-pq — must fail with Conflict.
        let cfg = Config::from_toml_str(SERVE_TCP_TOML).unwrap();
        let t = &cfg.tenants[0];
        let err = cfg.resolve_one_serve_pq(t).unwrap_err();
        match err {
            ConfigError::Conflict(m) => {
                assert!(
                    m.contains("non-serve-pq"),
                    "expected non-serve-pq conflict, got: {m}"
                );
            }
            other => panic!("expected Conflict, got {other:?}"),
        }
    }

    #[test]
    fn resolve_one_serve_pq_rejects_missing_backend() {
        // Synthesize a serve-pq tenant with no backend at TOML level
        // would already fail validation — so this test exercises the
        // post-validation path where someone hands us a hand-built
        // TenantConfig (e.g. from a future runtime add API).
        let cfg = Config::from_toml_str(SERVE_PQ_TOML).unwrap();
        // Hand-mutate a clone to strip the backend.
        let mut t = cfg.tenants[0].clone();
        t.backend = None;
        let err = cfg.resolve_one_serve_pq(&t).unwrap_err();
        match err {
            ConfigError::Missing(m) => {
                assert!(
                    m.contains("backend"),
                    "expected backend-required message, got: {m}"
                );
            }
            other => panic!("expected Missing, got {other:?}"),
        }
    }

    // ================================================================
    //          Sprint 13 — TenantConfig::material_changes
    // ================================================================

    fn base_tenant() -> TenantConfig {
        let cfg = Config::from_toml_str(SERVE_PQ_TOML).unwrap();
        cfg.tenants[0].clone()
    }

    #[test]
    fn material_changes_identical_returns_empty() {
        let a = base_tenant();
        let b = base_tenant();
        assert_eq!(a.material_changes(&b), Vec::<TenantChange>::new());
        assert!(!a.differs_from(&b));
    }

    #[test]
    fn material_changes_listen_detected() {
        let a = base_tenant();
        let mut b = base_tenant();
        b.listen = "127.0.0.1:9991".into();
        assert_eq!(
            a.material_changes(&b),
            vec![TenantChange {
                field: "listen",
                kind: TenantChangeKind::Cold
            }]
        );
        assert!(a.differs_from(&b));
    }

    #[test]
    fn material_changes_backend_detected() {
        let a = base_tenant();
        let mut b = base_tenant();
        b.backend = Some("10.0.0.99:80".into());
        assert_eq!(
            a.material_changes(&b),
            vec![TenantChange {
                field: "backend",
                kind: TenantChangeKind::Cold
            }]
        );
    }

    #[test]
    fn material_changes_limits_added() {
        let a = base_tenant();
        let mut b = base_tenant();
        b.limits = Some(TenantLimits {
            max_concurrent: Some(100),
            rate_limit_per_source: None,
        });
        assert_eq!(
            a.material_changes(&b),
            vec![TenantChange {
                field: "limits",
                kind: TenantChangeKind::Hot
            }]
        );
    }

    #[test]
    fn material_changes_limits_max_concurrent_modified() {
        let mut a = base_tenant();
        a.limits = Some(TenantLimits {
            max_concurrent: Some(100),
            rate_limit_per_source: None,
        });
        let mut b = a.clone();
        // Same structure, different value.
        if let Some(ref mut l) = b.limits {
            l.max_concurrent = Some(200);
        }
        assert_eq!(
            a.material_changes(&b),
            vec![TenantChange {
                field: "limits",
                kind: TenantChangeKind::Hot
            }]
        );
    }

    #[test]
    fn material_changes_limits_unchanged_with_same_values() {
        let mut a = base_tenant();
        a.limits = Some(TenantLimits {
            max_concurrent: Some(100),
            rate_limit_per_source: Some(RateLimitTomlConfig {
                capacity: 10,
                refill_per_sec: 2,
            }),
        });
        let b = a.clone();
        assert_eq!(a.material_changes(&b), Vec::<TenantChange>::new());
    }

    #[test]
    fn material_changes_audit_signer_softkey_paths() {
        let mut a = base_tenant();
        a.audit_signer = Some(AuditSignerConfig::Softkey {
            secret_key: "/x/sk".into(),
            public_key: "/x/pk".into(),
        });
        let mut b = a.clone();
        b.audit_signer = Some(AuditSignerConfig::Softkey {
            secret_key: "/y/sk".into(),
            public_key: "/x/pk".into(),
        });
        assert_eq!(
            a.material_changes(&b),
            vec![TenantChange {
                field: "audit_signer",
                kind: TenantChangeKind::Cold
            }]
        );
    }

    #[test]
    fn material_changes_audit_signer_softkey_to_pkcs11() {
        let mut a = base_tenant();
        a.audit_signer = Some(AuditSignerConfig::Softkey {
            secret_key: "/x/sk".into(),
            public_key: "/x/pk".into(),
        });
        let mut b = a.clone();
        b.audit_signer = Some(AuditSignerConfig::Pkcs11 {
            module: "/opt/hsm.so".into(),
            slot: 0,
            pin_env: "HSM_PIN".into(),
            key_label: "audit-key".into(),
            pub_label: None,
            mechanism_id: None,
        });
        assert_eq!(
            a.material_changes(&b),
            vec![TenantChange {
                field: "audit_signer",
                kind: TenantChangeKind::Cold
            }]
        );
    }

    #[test]
    fn material_changes_multiple_fields_reported_in_stable_order() {
        let a = base_tenant();
        let mut b = base_tenant();
        b.listen = "127.0.0.1:9991".into();
        b.audit_log = "/tmp/different.qa".into();
        b.limits = Some(TenantLimits {
            max_concurrent: Some(100),
            rate_limit_per_source: None,
        });
        // Order matches declaration order in material_changes:
        // listen, peer_pq, backend, peer_pub_dir, audit_log, tls, sni,
        // audit_signer, limits.
        assert_eq!(
            a.material_changes(&b),
            vec![
                TenantChange {
                    field: "listen",
                    kind: TenantChangeKind::Cold
                },
                TenantChange {
                    field: "audit_log",
                    kind: TenantChangeKind::Cold
                },
                TenantChange {
                    field: "limits",
                    kind: TenantChangeKind::Hot
                },
            ]
        );
    }

    // ================================================================
    //          Sprint 14 — TenantChangeKind classification
    // ================================================================

    #[test]
    fn limits_change_is_classified_hot() {
        let a = base_tenant();
        let mut b = base_tenant();
        b.limits = Some(TenantLimits {
            max_concurrent: Some(100),
            rate_limit_per_source: None,
        });
        let changes = a.material_changes(&b);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].field, "limits");
        assert_eq!(changes[0].kind, TenantChangeKind::Hot);
    }

    #[test]
    fn listen_change_is_classified_cold() {
        let a = base_tenant();
        let mut b = base_tenant();
        b.listen = "127.0.0.1:9991".into();
        let changes = a.material_changes(&b);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].field, "listen");
        assert_eq!(changes[0].kind, TenantChangeKind::Cold);
    }

    #[test]
    fn audit_signer_change_is_classified_cold() {
        let mut a = base_tenant();
        a.audit_signer = Some(AuditSignerConfig::Softkey {
            secret_key: "/x/sk".into(),
            public_key: "/x/pk".into(),
        });
        let mut b = a.clone();
        b.audit_signer = Some(AuditSignerConfig::Softkey {
            secret_key: "/y/sk".into(),
            public_key: "/y/pk".into(),
        });
        let changes = a.material_changes(&b);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].kind, TenantChangeKind::Cold);
    }

    #[test]
    fn mixed_hot_and_cold_changes_each_get_correct_kind() {
        let a = base_tenant();
        let mut b = base_tenant();
        b.listen = "127.0.0.1:9991".into();
        b.limits = Some(TenantLimits {
            max_concurrent: Some(100),
            rate_limit_per_source: None,
        });
        let changes = a.material_changes(&b);
        assert_eq!(changes.len(), 2);
        // Stable ordering: listen first (Cold), then limits (Hot).
        assert_eq!(changes[0].field, "listen");
        assert_eq!(changes[0].kind, TenantChangeKind::Cold);
        assert_eq!(changes[1].field, "limits");
        assert_eq!(changes[1].kind, TenantChangeKind::Hot);
    }

    // ================================================================
    //          Sprint 13 — resolve_one_serve_tcp
    // ================================================================

    #[test]
    fn resolve_one_serve_tcp_returns_resolved_single_tenant() {
        let cfg = Config::from_toml_str(SERVE_TCP_TOML).unwrap();
        let t = &cfg.tenants[0];
        let resolved = cfg
            .resolve_one_serve_tcp(t)
            .expect("single-tenant serve-tcp resolve");
        assert_eq!(resolved.id.name, "branch-sp");
        assert_eq!(resolved.listen, "127.0.0.1:8443");
        assert_eq!(resolved.peer_pq, "10.0.1.50:9999");
        assert!(resolved.limits.is_none());
    }

    #[test]
    fn resolve_one_serve_tcp_rejects_when_not_serve_tcp_role() {
        let cfg = Config::from_toml_str(SERVE_PQ_TOML).unwrap();
        let t = &cfg.tenants[0];
        let err = cfg.resolve_one_serve_tcp(t).unwrap_err();
        match err {
            ConfigError::Conflict(m) => {
                assert!(
                    m.contains("non-serve-tcp"),
                    "expected non-serve-tcp conflict, got: {m}"
                );
            }
            other => panic!("expected Conflict, got {other:?}"),
        }
    }

    #[test]
    fn resolve_one_serve_tcp_rejects_missing_peer_pq() {
        let cfg = Config::from_toml_str(SERVE_TCP_TOML).unwrap();
        let mut t = cfg.tenants[0].clone();
        t.peer_pq = None;
        let err = cfg.resolve_one_serve_tcp(&t).unwrap_err();
        match err {
            ConfigError::Missing(m) => {
                assert!(m.contains("peer_pq"), "expected peer_pq message, got: {m}");
            }
            other => panic!("expected Missing, got {other:?}"),
        }
    }

    /// Sprint 35: default poll interval is 5 seconds when the field
    /// is absent.
    #[test]
    fn rotation_policy_poll_interval_default_is_5s() {
        let p = RotationPolicy {
            max_entries: None,
            max_bytes: None,
            max_age_secs: None,
            poll_interval_ms: None,
            archive_pattern: default_archive_pattern(),
        };
        assert_eq!(p.poll_interval(), std::time::Duration::from_secs(5));
    }

    /// Sprint 35: explicit value is honored at millisecond
    /// resolution.
    #[test]
    fn rotation_policy_poll_interval_honors_explicit_value() {
        let p = RotationPolicy {
            max_entries: None,
            max_bytes: None,
            max_age_secs: None,
            poll_interval_ms: Some(250),
            archive_pattern: default_archive_pattern(),
        };
        assert_eq!(p.poll_interval(), std::time::Duration::from_millis(250));
    }

    /// Sprint 35: values below the 10 ms floor are clamped to 10 ms.
    /// Defends against operators accidentally configuring a busy-
    /// spin (e.g., poll_interval_ms = 0).
    #[test]
    fn rotation_policy_poll_interval_clamps_to_floor() {
        for low in [0u64, 1, 5, 9] {
            let p = RotationPolicy {
                max_entries: None,
                max_bytes: None,
                max_age_secs: None,
                poll_interval_ms: Some(low),
                archive_pattern: default_archive_pattern(),
            };
            assert_eq!(
                p.poll_interval(),
                std::time::Duration::from_millis(10),
                "poll_interval_ms={low} should clamp to 10ms"
            );
        }
    }
}
