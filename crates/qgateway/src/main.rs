//! qgateway — Cofre Soberano PQ reverse-proxy daemon (Sprint 4 multi-tenant).

#![forbid(unsafe_code)]

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use qaudit_core::{AuditLog, KeyPair, PublicKey};
use qgateway_core::{
    auditkey,
    config::TenantConfig,
    metrics::render_prometheus,
    run_serve_pq_tenant, run_serve_tcp_tenant, run_sni_group,
    tls::{
        build_reloadable_acceptor, build_reloadable_multi_sni_acceptor, TlsAcceptorHandle,
        TlsReloadTrigger,
    },
    AuditChannel, AuditSignerConfig, Config, MetricsRegistry, Role, SniDispatchTable,
    SniTenantContext,
};
use qtransport_cspq::{IdentityKey, PeerPolicy};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Notify;
use tracing::{error, info, warn};

/// `.skid` magic for QGateway transport secret identity files (ML-DSA-87 raw SK).
const SK_FILE_MAGIC: &[u8; 8] = b"CSPQSK01";

#[derive(Parser, Debug)]
#[command(
    name = "qgateway",
    version,
    about = "Cofre Soberano PQ — TCP↔CSPQ multi-tenant reverse-proxy sidecar."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Generate a new ML-DSA-87 transport identity keypair (`.skid` + `.cspqid.pub`).
    Keygen {
        /// Output secret-key file (`.skid`, 8 B magic + 4896 B raw SK; mode 0600 on unix).
        #[arg(long)]
        sk: PathBuf,
        /// Output public-key file (`.cspqid.pub`, 8 B magic + 2592 B raw PK).
        #[arg(long)]
        pk: PathBuf,
    },
    /// Generate a new audit signer keypair (`.audit.skid` + `.audit.pub`).
    AuditKeygen {
        /// Output audit secret-key file (`.audit.skid`).
        #[arg(long)]
        sk: PathBuf,
        /// Output audit public-key file (`.audit.pub`).
        #[arg(long)]
        pk: PathBuf,
    },
    /// Run the daemon using a TOML config file.
    Run {
        /// Config file (TOML).
        #[arg(long, default_value = "/etc/qgateway/sidecar.toml")]
        config: PathBuf,
    },
    /// Validate a TOML config file without starting the daemon.
    ///
    /// Sprint 37: dry-run validation. Loads + structurally validates the
    /// TOML (same path as `run`), then exercises every fallible resolution
    /// step the daemon would hit at startup — identity key file parse,
    /// per-tenant peer directory contents, audit signer file presence
    /// (softkey) or module + pin-env presence (PKCS#11), TLS cert/key
    /// pairs if present, audit log parent directory writability.
    ///
    /// Does NOT bind listen sockets, does NOT create audit log files,
    /// does NOT open PKCS#11 sessions. Safe to run against a production
    /// config on a machine where the daemon is already running.
    ///
    /// Exits 0 on success with a one-line summary; non-zero with a
    /// concrete error message on the first failure.
    Validate {
        /// Config file (TOML).
        #[arg(long, default_value = "/etc/qgateway/sidecar.toml")]
        config: PathBuf,
    },
    /// Show the public-key bytes from a `.cspqid.pub` file (hex).
    Pubkey {
        /// Path to a `.cspqid.pub` file.
        #[arg(long)]
        pk: PathBuf,
    },
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Keygen { sk, pk } => cmd_keygen(&sk, &pk),
        Cmd::AuditKeygen { sk, pk } => cmd_audit_keygen(&sk, &pk),
        Cmd::Run { config } => cmd_run(&config).await,
        Cmd::Validate { config } => cmd_validate(&config),
        Cmd::Pubkey { pk } => cmd_pubkey(&pk),
    }
}

fn cmd_keygen(sk_path: &Path, pk_path: &Path) -> Result<()> {
    let kp = KeyPair::generate().context("generating transport ML-DSA-87 keypair")?;
    let mut public = Vec::from(qtransport_cspq::IDENTITY_FILE_MAGIC.as_slice());
    public.extend_from_slice(kp.public().as_bytes());
    let sk_bytes = kp.secret().as_bytes();
    let mut blob = Vec::with_capacity(8 + sk_bytes.len());
    blob.extend_from_slice(SK_FILE_MAGIC);
    blob.extend_from_slice(sk_bytes);
    auditkey::write_keypair_files(sk_path, pk_path, &blob, &public)?;
    eprintln!(
        "qgateway: generated transport identity\n  sk: {}\n  pk: {}\n  fp: {}",
        sk_path.display(),
        pk_path.display(),
        hex::encode(&kp.public().as_bytes()[..16])
    );
    Ok(())
}

fn cmd_audit_keygen(sk_path: &Path, pk_path: &Path) -> Result<()> {
    let kp = auditkey::generate(sk_path, pk_path)?;
    eprintln!(
        "qgateway: generated audit signer\n  sk: {}\n  pk: {}\n  fp: {}",
        sk_path.display(),
        pk_path.display(),
        hex::encode(&kp.public().as_bytes()[..16])
    );
    Ok(())
}

fn cmd_pubkey(pk_path: &Path) -> Result<()> {
    let pk = IdentityKey::load_public(pk_path)
        .with_context(|| format!("loading {}", pk_path.display()))?;
    println!("{}", hex::encode(pk.as_bytes()));
    Ok(())
}

/// Sprint 37: dry-run config validation. Exercises every fallible
/// resolution step the daemon would hit at startup, but without
/// side effects (no audit log file creation, no listen socket
/// binding, no PKCS#11 session). Designed to be safe to run against
/// a production config on a host where the daemon is already running.
///
/// Exits 0 with a one-line summary on success; returns Err with the
/// first concrete failure on error (which `main` prints + exits
/// non-zero).
fn cmd_validate(config_path: &Path) -> Result<()> {
    // Step 1: TOML parse + structural validation. Already pure (no
    // I/O beyond reading the config file itself).
    let cfg = Config::load(config_path)
        .with_context(|| format!("loading config {}", config_path.display()))?;

    // Step 2: transport identity key files exist + parse. Uses the
    // exact same loader the daemon calls in cmd_run; if a file is
    // missing or its magic is wrong, this surfaces it the same way
    // the daemon would.
    let _identity = load_transport_identity(&cfg.identity_key, &cfg.identity_pub)
        .context("transport identity validation")?;

    // Step 3: per-tenant resolution. For each tenant, walk every
    // fallible source-of-truth without creating any output.
    for t in &cfg.tenants {
        validate_one_tenant(t, &cfg).with_context(|| format!("tenant {}", t.name))?;
    }

    // Step 4: parent of `metrics_listen` doesn't apply (the daemon
    // binds, we don't). We just sanity-parse the address string the
    // same way the daemon would.
    let _addr: std::net::SocketAddr = cfg.metrics_listen.parse().with_context(|| {
        format!(
            "metrics_listen \"{}\" is not a valid SocketAddr",
            cfg.metrics_listen
        )
    })?;

    println!(
        "ok: config valid; role={:?}; tenants={}; metrics_listen={}",
        cfg.role,
        cfg.tenants.len(),
        cfg.metrics_listen
    );
    Ok(())
}

fn validate_one_tenant(t: &TenantConfig, cfg: &Config) -> Result<()> {
    // 3a: peer trust directory exists + at least one .cspqid.pub.
    // PeerPolicy::from_dir is the same call build_tenant_runtime
    // makes; it parses every .cspqid.pub in the dir, so a corrupted
    // file surfaces here.
    let peer_policy = PeerPolicy::from_dir(&t.peer_pub_dir)
        .with_context(|| format!("peer_pub_dir {}", t.peer_pub_dir.display()))?;
    if peer_policy.is_empty() {
        return Err(anyhow!(
            "no peer .cspqid.pub files in {}",
            t.peer_pub_dir.display()
        ));
    }

    // 3b: listen address parses (the daemon binds, we don't).
    let _listen: std::net::SocketAddr = t
        .listen
        .parse()
        .with_context(|| format!("listen \"{}\" is not a valid SocketAddr", t.listen))?;

    // 3c: backend / peer_pq address parses depending on role.
    match cfg.role {
        qgateway_core::Role::ServePq => {
            let b = t
                .backend
                .as_deref()
                .ok_or_else(|| anyhow!("serve-pq tenant must declare `backend`"))?;
            let _: std::net::SocketAddr = b
                .parse()
                .with_context(|| format!("backend \"{b}\" is not a valid SocketAddr"))?;
        }
        qgateway_core::Role::ServeTcp => {
            let p = t
                .peer_pq
                .as_deref()
                .ok_or_else(|| anyhow!("serve-tcp tenant must declare `peer_pq`"))?;
            let _: std::net::SocketAddr = p
                .parse()
                .with_context(|| format!("peer_pq \"{p}\" is not a valid SocketAddr"))?;
        }
    }

    // 3d: audit_log path's parent directory exists. We do NOT
    // create the file (that would have a side effect on the
    // filesystem); instead we check the parent's existence so
    // operators catch typos in the path now rather than at
    // daemon-startup.
    if let Some(parent) = t.audit_log.parent() {
        if !parent.as_os_str().is_empty() && !parent.is_dir() {
            return Err(anyhow!(
                "audit_log parent directory does not exist: {}",
                parent.display()
            ));
        }
    }

    // 3e: effective audit signer resolves + its file dependencies
    // are checkable.
    let signer = cfg.effective_signer(t).ok_or_else(|| {
        anyhow!(
            "no audit_signer (declare [tenants.audit_signer] for this \
             tenant or a top-level [audit_signer] as the default)"
        )
    })?;
    match &signer {
        AuditSignerConfig::Softkey {
            secret_key,
            public_key,
        } => {
            // Same loader build_tenant_runtime calls; verifies
            // magic bytes + length + ML-DSA-87 parse. No chain
            // creation here.
            let _kp = auditkey::load(secret_key, public_key).with_context(|| {
                format!(
                    "audit signer files (sk={}, pk={})",
                    secret_key.display(),
                    public_key.display()
                )
            })?;
        }
        AuditSignerConfig::Pkcs11 {
            module, pin_env, ..
        } => {
            // We do NOT open a PKCS#11 session here. That would
            // require the HSM to be reachable + the PIN to be
            // exposed in our environment, neither of which is
            // appropriate for offline validation. Instead we
            // check the two operator-visible smells: module path
            // exists, pin_env is set in our environment.
            if !module.exists() {
                return Err(anyhow!(
                    "PKCS#11 module path does not exist: {}",
                    module.display()
                ));
            }
            if std::env::var(pin_env).is_err() {
                return Err(anyhow!(
                    "PKCS#11 pin_env \"{pin_env}\" is not set in the validate \
                     command's environment; the daemon will fail to authenticate \
                     to the HSM at startup unless that env var is populated"
                ));
            }
        }
    }

    // 3f: TLS cert/key pair if declared. We re-implement minimal
    // PEM parse here (rather than exposing qgateway_core::tls's
    // private helpers) so the validator stays decoupled from the
    // internal cert-loader type signature. Catches the operator
    // mistakes that matter: malformed PEM, empty file, wrong file
    // type. A semantic key/cert mismatch is not checked here (the
    // daemon would catch it at acceptor build time; checking here
    // would require rustls type plumbing this validator doesn't
    // need).
    if let Some(tls) = &t.tls {
        validate_tls_cert(&tls.cert)?;
        validate_tls_key(&tls.key)?;
    }

    Ok(())
}

fn validate_tls_cert(path: &Path) -> Result<()> {
    use rustls::pki_types::{pem::PemObject, CertificateDer};
    let mut found_any = false;
    for entry in CertificateDer::pem_file_iter(path)
        .with_context(|| format!("TLS cert {}", path.display()))?
    {
        let _ = entry.with_context(|| format!("TLS cert {} (malformed PEM)", path.display()))?;
        found_any = true;
    }
    if !found_any {
        return Err(anyhow!(
            "TLS cert {} contains no CERTIFICATE blocks",
            path.display()
        ));
    }
    Ok(())
}

fn validate_tls_key(path: &Path) -> Result<()> {
    use rustls::pki_types::{pem::PemObject, PrivateKeyDer};
    PrivateKeyDer::from_pem_file(path).with_context(|| {
        format!(
            "TLS key {} (expected valid PKCS#8, PKCS#1 RSA, or SEC1 EC PEM)",
            path.display()
        )
    })?;
    Ok(())
}

fn load_transport_identity(sk_path: &Path, pk_path: &Path) -> Result<IdentityKey> {
    let blob = std::fs::read(sk_path)
        .with_context(|| format!("reading transport SK {}", sk_path.display()))?;
    if blob.len() != 8 + qaudit_core::signing::SECRET_KEY_LEN {
        return Err(anyhow!(
            "transport SK file has invalid length: {} bytes",
            blob.len()
        ));
    }
    if &blob[..8] != SK_FILE_MAGIC {
        return Err(anyhow!("transport SK file has bad magic"));
    }
    let sk_bytes = &blob[8..8 + qaudit_core::signing::SECRET_KEY_LEN];
    let sk = qaudit_core::SecretKey::from_bytes(sk_bytes).context("decoding ML-DSA-87 SK")?;
    let pk = IdentityKey::load_public(pk_path)
        .with_context(|| format!("loading transport PK {}", pk_path.display()))?;
    if sk.derive_public()? != pk {
        return Err(anyhow!("transport public key does not match secret key"));
    }
    Ok(IdentityKey::new(KeyPair::from_parts(pk, sk)))
}

/// Build an `AuditLog` for the given path, using the configured audit signer.
///
/// If the log file already exists on disk it must have been written with the
/// SAME audit public key (otherwise we refuse to extend it).
fn build_audit_log_softkey(path: &Path, audit_kp: KeyPair, tenant_name: &str) -> Result<AuditLog> {
    if path.exists() {
        let log = AuditLog::open(path)
            .with_context(|| format!("opening existing audit log {}", path.display()))?;
        if log.header().pubkey.as_bytes() != audit_kp.public().as_bytes() {
            return Err(anyhow!(
                "audit log {} was signed by a different audit identity; \
                 fingerprint on disk: {} — refusing to extend",
                path.display(),
                hex::encode(&log.header().pubkey.as_bytes()[..16])
            ));
        }
        info!(
            tenant = tenant_name,
            log = %path.display(),
            entries = log.len(),
            "audit log re-opened (existing chain extends)"
        );
        let mut log = log;
        log.bind_keypair(audit_kp)?;
        Ok(log)
    } else {
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        std::fs::create_dir_all(parent).ok();
        let log = AuditLog::create_with_label(audit_kp, format!("qgateway/{tenant_name}"))?;
        log.save(path)?;
        info!(
            tenant = tenant_name,
            log = %path.display(),
            "audit log created (fresh chain)"
        );
        Ok(log)
    }
}

#[cfg(feature = "pkcs11")]
fn build_pkcs11_config(cfg: &AuditSignerConfig) -> Result<qaudit_hsm::Pkcs11Config> {
    use qaudit_hsm::Pkcs11Config;
    let AuditSignerConfig::Pkcs11 {
        module,
        slot,
        pin_env,
        key_label,
        pub_label,
        mechanism_id,
    } = cfg
    else {
        return Err(anyhow!(
            "internal: build_pkcs11_config called on softkey cfg"
        ));
    };
    let pin = std::env::var(pin_env)
        .with_context(|| format!("env var {pin_env} (PKCS#11 PIN) not set"))?;
    let mut pcfg = Pkcs11Config::new(module, *slot, key_label).with_pin(pin);
    if let Some(pl) = pub_label.as_ref() {
        pcfg = pcfg.with_pubkey_label(pl);
    }
    if let Some(mid) = *mechanism_id {
        pcfg = pcfg.with_mechanism_id(mid);
    }
    Ok(pcfg)
}

#[cfg(feature = "pkcs11")]
fn build_audit_log_pkcs11(
    path: &Path,
    cfg: &AuditSignerConfig,
    tenant_name: &str,
    metrics: &qgateway_core::MetricsRegistry,
) -> Result<AuditLog> {
    use qaudit_hsm::Pkcs11Signer;
    let pcfg = build_pkcs11_config(cfg)?;
    // Sprint 10: hook the initial session-open into the same metrics
    // registry the rotation factory uses. One MetricsHsmTelemetry per
    // tenant, shared between startup signer and rotation factory.
    let telemetry: std::sync::Arc<dyn qaudit_hsm::HsmTelemetry> =
        std::sync::Arc::new(MetricsHsmTelemetry {
            metrics: metrics.clone(),
        });
    let signer =
        Pkcs11Signer::open_with_telemetry(pcfg, telemetry).context("PKCS#11 audit signer")?;
    let log = if path.exists() {
        let log = AuditLog::open(path)?;
        // For PKCS#11 we can't compare keypair bytes; trust the operator's config.
        info!(
            tenant = tenant_name,
            log = %path.display(),
            entries = log.len(),
            "audit log re-opened (PKCS#11-signed chain extends)"
        );
        let mut log = log;
        log.bind_signer(signer)?;
        log
    } else {
        let log = AuditLog::create_with_signer(signer, format!("qgateway/{tenant_name}"))?;
        log.save(path)?;
        info!(
            tenant = tenant_name,
            log = %path.display(),
            "audit log created (PKCS#11-signed)"
        );
        log
    };
    Ok(log)
}

#[cfg(not(feature = "pkcs11"))]
fn build_audit_log_pkcs11(
    _path: &Path,
    _cfg: &AuditSignerConfig,
    _tenant_name: &str,
    _metrics: &qgateway_core::MetricsRegistry,
) -> Result<AuditLog> {
    Err(anyhow!(
        "PKCS#11 audit signer requested but qgateway was built without `pkcs11` feature; \
         rebuild with `cargo build --features pkcs11`"
    ))
}

fn open_pk(path: &Path) -> Result<PublicKey> {
    auditkey::load_pub(path)
}

async fn cmd_run(config_path: &Path) -> Result<()> {
    let cfg = Config::load(config_path)
        .with_context(|| format!("loading config {}", config_path.display()))?;
    info!(role = ?cfg.role, tenants = cfg.tenants.len(), "starting qgateway");

    let identity = Arc::new(load_transport_identity(
        &cfg.identity_key,
        &cfg.identity_pub,
    )?);

    // For each tenant: load peer policy, build audit signer/log, start audit channel.
    let mut tenant_state: Vec<TenantRuntime> = Vec::with_capacity(cfg.tenants.len());
    for t in &cfg.tenants {
        let rt = build_tenant_runtime(t, &cfg)?;
        info!(tenant = %t.name, "tenant ready");
        tenant_state.push(rt);
    }

    // Metrics HTTP server with aggregate exposition across all tenants.
    // Sprint 11.5: shared list so the SIGHUP apply step can append on
    // tenant-add. Cloned cheaply (Arc) into the metrics server task.
    let tenant_metrics_shared: SharedMetricsList = Arc::new(tokio::sync::RwLock::new(
        tenant_state.iter().map(|t| t.metrics.clone()).collect(),
    ));
    // Sprint 17: daemon-wide metrics surface. Shared between metrics
    // server (reads on /metrics) and the SIGHUP signal handler (bumps
    // counters on cycle outcomes).
    let daemon_metrics: Arc<qgateway_core::metrics::DaemonMetrics> =
        Arc::new(qgateway_core::metrics::DaemonMetrics::default());
    let metrics_handle = spawn_metrics_server(
        cfg.metrics_listen.clone(),
        tenant_metrics_shared.clone(),
        daemon_metrics.clone(),
    )
    .await?;

    let shutdown = Arc::new(Notify::new());

    // Per-tenant TLS reload triggers.
    // Sprint 20: promoted from Vec to Arc<RwLock<HashMap>> keyed by tenant
    // name so SIGHUP ADD can insert new TLS-enabled tenants' triggers and
    // SIGHUP REMOVE can purge them. SIGUSR1 iterates HashMap values.
    // Single-tenant TLS tenants now ARE individually removable.
    //
    // SNI groups still use a synthetic key "sni-group:<listen>" because
    // they aren't keyed by a single tenant name; SNI group remove
    // remains non-runtime (Sprint 21+ work).
    let reload_triggers_shared: Arc<
        tokio::sync::RwLock<std::collections::HashMap<String, TlsReloadTrigger>>,
    > = Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new()));
    // Sprint 23: shared per-listen-address map of SNI dispatch tables.
    // The SIGHUP arm looks up a running SNI group by its `listen`
    // address, calls `dispatch.load().with_tenant_added/removed` to
    // compute the successor table, then `dispatch.swap(new)` to
    // install it. Paired with the entry in reload_triggers_shared
    // keyed by "sni-group:<listen>" — same `listen` string forms
    // the join.
    //
    // The map's lifecycle in Sprint 23 is APPEND-ONLY at startup +
    // mutation-of-existing-entries via SIGHUP. First-tenant-in-new-
    // group (which would insert a new entry) and last-tenant-leaves
    // (which would remove an entry) are Sprint 24+ work because they
    // require spawning/draining the `run_sni_group` task too.
    let sni_dispatches_shared: Arc<
        tokio::sync::RwLock<
            std::collections::HashMap<String, Arc<qgateway_core::HotSniDispatchTable>>,
        >,
    > = Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new()));
    // Sprint 24: per-SNI-group shutdown Notify, keyed by listen address.
    // SNI groups historically used the daemon-wide shutdown (Sprint 18
    // §13.26.3 trade-off). Sprint 24 splits to per-group so the SIGHUP
    // arm can drain a single group when its last tenant is removed,
    // without taking down the whole daemon. The daemon-wide SIGTERM
    // path now walks this map to fan out shutdown to every group.
    let sni_group_shutdowns_shared: Arc<
        tokio::sync::RwLock<std::collections::HashMap<String, Arc<Notify>>>,
    > = Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new()));
    // Sprint 24: per-SNI-group JoinHandle, also keyed by listen address.
    // SIGHUP REMOVE awaits the handle after signalling shutdown when
    // draining a group whose last tenant just left. The daemon-wide
    // drain path also awaits these handles.
    let sni_group_tasks_shared: Arc<
        tokio::sync::RwLock<std::collections::HashMap<String, tokio::task::JoinHandle<Result<()>>>>,
    > = Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new()));

    // Spawn one task per tenant.
    // Sprint 18: split tracking by whether the task is INDIVIDUALLY removable:
    //   - tenant_tasks (Vec): non-removable tasks — SNI groups (shared
    //     listener across multiple tenants). Final drain at SIGTERM iterates
    //     this Vec.
    //   - tenant_tasks_by_name (Arc<RwLock<HashMap>>): individually removable
    //     tasks — single-tenant serve-tcp and serve-pq. SIGHUP REMOVE looks
    //     up the JoinHandle by name and awaits it with timeout.
    // Sprint 24: tenant_tasks Vec retained for forward-compat (no
    // current tenant kind populates it — SNI groups moved to per-group
    // shared maps in Sprint 24; single tenants always go to
    // tenant_tasks_by_name).
    let tenant_tasks: Vec<tokio::task::JoinHandle<Result<()>>> = Vec::new();
    let tenant_tasks_by_name: Arc<
        tokio::sync::RwLock<std::collections::HashMap<String, tokio::task::JoinHandle<Result<()>>>>,
    > = Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new()));
    match cfg.role {
        Role::ServeTcp => {
            // Sprint 6: resolve into LISTENER GROUPS, not flat tenants.
            // Single-tenant groups follow the existing path. Multi-tenant
            // groups share one listen port and dispatch by SNI.
            let groups = cfg
                .resolve_serve_tcp_groups()
                .map_err(|e| anyhow!("resolve serve-tcp groups: {e}"))?;
            let rt_by_name: std::collections::HashMap<String, &TenantRuntime> = tenant_state
                .iter()
                .map(|rt| (rt.name.clone(), rt))
                .collect();
            for group in groups {
                let identity = identity.clone();
                if !group.sni_dispatch {
                    // Single-tenant group → existing per-tenant accept loop.
                    let t = group.tenants.into_iter().next().unwrap();
                    let rt = rt_by_name
                        .get(&t.id.name)
                        .ok_or_else(|| anyhow!("internal: no runtime for tenant {}", t.id.name))?;
                    let peer_policy = rt.peer_policy.clone();
                    let audit_handle = rt.audit.handle();
                    let metrics = rt.metrics.clone();
                    let admission = rt.admission.clone();
                    // Sprint 18: per-tenant shutdown, not daemon-wide.
                    let shutdown = rt.shutdown.clone();
                    let tls_handle: Option<TlsAcceptorHandle> = if let Some(tls_cfg) =
                        t.tls.as_ref()
                    {
                        let (handle, trigger) =
                            build_reloadable_acceptor(tls_cfg, t.id.name.clone()).with_context(
                                || format!("TLS acceptor for tenant {}", t.id.name),
                            )?;
                        // Sprint 20: insert by tenant name so REMOVE can purge.
                        reload_triggers_shared
                            .write()
                            .await
                            .insert(t.id.name.clone(), trigger);
                        info!(tenant = %t.id.name, "TLS termination + hot-reload enabled");
                        Some(handle)
                    } else {
                        None
                    };
                    let has_tls = tls_handle.is_some();
                    let tenant_name = t.id.name.clone();
                    let handle = tokio::spawn(async move {
                        run_serve_tcp_tenant(
                            t,
                            identity,
                            peer_policy,
                            audit_handle,
                            metrics,
                            shutdown,
                            tls_handle,
                            Some(admission),
                        )
                        .await
                    });
                    // Sprint 20: TLS-enabled single tenants now go to the
                    // by-name map — REMOVE purges both the JoinHandle and
                    // the reload trigger by tenant name. Only SNI groups
                    // remain in the Vec (they share a listener across N
                    // tenants; runtime SNI remove is Sprint 21+).
                    let _ = has_tls;
                    tenant_tasks_by_name
                        .write()
                        .await
                        .insert(tenant_name, handle);
                } else {
                    // Multi-tenant SNI group: one bind, one multi-SNI
                    // acceptor, dispatch by negotiated server_name.
                    let listen = group.listen.clone();
                    let mut sni_entries: Vec<(String, String, qgateway_core::TlsConfig)> =
                        Vec::with_capacity(group.tenants.len());
                    let mut contexts: Vec<SniTenantContext> =
                        Vec::with_capacity(group.tenants.len());
                    for t in &group.tenants {
                        let sni = t.sni.clone().ok_or_else(|| {
                            anyhow!("internal: multi-tenant group member has no sni")
                        })?;
                        let tls_cfg = t.tls.clone().ok_or_else(|| {
                            anyhow!("internal: multi-tenant group member has no tls")
                        })?;
                        sni_entries.push((sni, t.id.name.clone(), tls_cfg));
                        let rt = rt_by_name.get(&t.id.name).ok_or_else(|| {
                            anyhow!("internal: no runtime for tenant {}", t.id.name)
                        })?;
                        contexts.push(SniTenantContext {
                            tenant: t.clone(),
                            peer_policy: rt.peer_policy.clone(),
                            audit: rt.audit.handle(),
                            metrics: rt.metrics.clone(),
                            // Sprint 9.5 / Sprint 16: shared admission
                            // controller built once in build_tenant_runtime
                            // and reused here so the SIGHUP apply step can
                            // swap() it on hot limits changes — the same
                            // controller instance is reachable from both
                            // the SNI dispatch path and the per-tenant
                            // runtime entry.
                            admission: rt.admission.clone(),
                        });
                    }
                    // Sprint 6.5: SNI groups get a reloadable acceptor via
                    // the multi-SNI reload coordinator. The trigger
                    // remembers every member's cert/key paths so SIGUSR1
                    // rebuilds the whole resolver atomically.
                    let group_label = format!("sni-group:{listen}");
                    let (tls_handle, trigger) =
                        build_reloadable_multi_sni_acceptor(sni_entries, &group_label)
                            .with_context(|| format!("multi-SNI acceptor for listen {listen}"))?;
                    // Sprint 20: synthetic key for SNI group trigger so it
                    // coexists with per-tenant TLS triggers in the same
                    // shared map. SIGUSR1 rebuilds it whole on any cert
                    // change; SIGHUP REMOVE never targets this key
                    // (SNI runtime remove is Sprint 21+).
                    reload_triggers_shared
                        .write()
                        .await
                        .insert(group_label.clone(), trigger);
                    info!(
                        listen = %listen,
                        group = %group_label,
                        "SNI multi-tenant group: TLS termination + hot-reload enabled"
                    );
                    let dispatch = SniDispatchTable::new(contexts)
                        .with_context(|| format!("SNI dispatch table for listen {listen}"))?;
                    // Sprint 22 (Stage B): wrap in HotSniDispatchTable so
                    // Sprint 23+'s SIGHUP arm can add/remove SNI tenants
                    // by computing a successor table via the Sprint 21
                    // builders and calling `dispatch.swap(new)`.
                    let dispatch = Arc::new(qgateway_core::HotSniDispatchTable::new(dispatch));
                    // Sprint 23: register the dispatch by listen address
                    // so the SIGHUP arm can find it by `[[tenants]].listen`
                    // and mutate it without restart.
                    sni_dispatches_shared
                        .write()
                        .await
                        .insert(listen.clone(), dispatch.clone());
                    info!(
                        listen = %listen,
                        n_tenants = group.tenants.len(),
                        "SNI multi-tenant group spawned (accept loop, hot-swappable dispatch)"
                    );
                    // Sprint 24: per-SNI-group shutdown Notify. The
                    // daemon-wide SIGTERM path walks
                    // sni_group_shutdowns_shared to fan out shutdown
                    // to every group. SIGHUP REMOVE notifies + awaits
                    // an individual group's handle when its last
                    // tenant leaves.
                    let sni_shutdown = Arc::new(Notify::new());
                    sni_group_shutdowns_shared
                        .write()
                        .await
                        .insert(listen.clone(), sni_shutdown.clone());
                    let listen_for_task = listen.clone();
                    let sni_handle = tokio::spawn(async move {
                        run_sni_group(
                            listen_for_task,
                            tls_handle,
                            dispatch,
                            identity,
                            sni_shutdown,
                        )
                        .await
                    });
                    sni_group_tasks_shared
                        .write()
                        .await
                        .insert(listen.clone(), sni_handle);
                }
            }
        }
        Role::ServePq => {
            let resolved = cfg
                .resolve_serve_pq()
                .map_err(|e| anyhow!("resolve serve-pq: {e}"))?;
            for (i, t) in resolved.into_iter().enumerate() {
                let rt = &tenant_state[i];
                let identity = identity.clone();
                let peer_policy = rt.peer_policy.clone();
                let audit_handle = rt.audit.handle();
                let metrics = rt.metrics.clone();
                let admission = rt.admission.clone();
                // Sprint 18: per-tenant shutdown.
                let shutdown = rt.shutdown.clone();
                let tenant_name = rt.name.clone();
                let handle = tokio::spawn(async move {
                    run_serve_pq_tenant(
                        t,
                        identity,
                        peer_policy,
                        audit_handle,
                        metrics,
                        shutdown,
                        Some(admission),
                    )
                    .await
                });
                tenant_tasks_by_name
                    .write()
                    .await
                    .insert(tenant_name, handle);
            }
        }
    }

    // Sprint 27: rotation targets, keyed by tenant name. Was a `Vec<...>`
    // through Sprint 26, which meant a tenant added at runtime via SIGHUP
    // ADD had no entry here — SIGUSR2 would skip its log rotation.
    // Surfaced by Sprint 27's integration test before the promotion. The
    // shared map lets SIGHUP ADD insert and SIGHUP REMOVE purge, matching
    // the pattern Sprint 20 used for `reload_triggers`.
    #[cfg(unix)]
    let rotation_targets_shared: Arc<
        tokio::sync::RwLock<std::collections::HashMap<String, RotationTarget>>,
    > = Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new()));
    // Sprint 28: monitor handles, keyed by tenant name. Was a `Vec` through
    // Sprint 27 — same Vec-vs-runtime-ADD bug pattern as `rotation_targets`
    // before the Sprint 27 fix. SIGHUP ADD now spawns a monitor for the
    // added tenant if the daemon has an auto-rotation policy; SIGHUP REMOVE
    // awaits the per-tenant monitor handle (it stops on its own once the
    // per-tenant shutdown Notify fires — Sprint 18 plumbing already did that
    // half; Sprint 28 just changes the monitor to listen to the per-tenant
    // notify instead of the daemon-wide one).
    #[cfg(unix)]
    let monitor_handles_shared: Arc<
        tokio::sync::RwLock<std::collections::HashMap<String, tokio::task::JoinHandle<()>>>,
    > = Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new()));
    #[cfg(unix)]
    {
        let mut targets = rotation_targets_shared.write().await;
        let mut monitors = monitor_handles_shared.write().await;
        for rt in &tenant_state {
            // ONE counter shared between SIGUSR2 path and monitor task.
            let counter = Arc::new(std::sync::atomic::AtomicU64::new(0));
            targets.insert(
                rt.name.clone(),
                RotationTarget {
                    tenant_name: rt.name.clone(),
                    channel: rt.audit.rotation_handle(),
                    log_path: rt.audit_log_path.clone(),
                    counter: counter.clone(),
                    policy: cfg.rotation.clone(),
                },
            );
            // Sprint 8.5: spawn auto-rotation monitor when a policy is set
            // AND any threshold is configured. Tenants without auto-policy
            // remain SIGUSR2-only (monitor would just return immediately).
            // Sprint 28: monitor now listens to the per-tenant shutdown
            // Notify so SIGHUP REMOVE can stop just this monitor without
            // taking down the whole daemon. SIGTERM signals every per-
            // tenant Notify, so the daemon-wide shutdown still drains
            // every monitor.
            if let Some(policy) = cfg.rotation.clone() {
                if policy.has_auto_trigger() {
                    // Sprint 35: honor `[rotation] poll_interval_ms` if set.
                    let poll = policy.poll_interval();
                    let monitor = qgateway_core::RotationMonitor::new(
                        rt.name.clone(),
                        rt.audit.rotation_handle(),
                        rt.audit_log_path.clone(),
                        policy,
                        counter,
                    )
                    .with_poll_interval(poll);
                    let handle = monitor.spawn(rt.shutdown.clone());
                    monitors.insert(rt.name.clone(), handle);
                }
            }
        }
        drop(targets);
        drop(monitors);
    }

    // Install signal handlers now that all reload triggers + rotation
    // targets are known. SIGTERM/Ctrl-C → notify shutdown; SIGUSR1 → fan
    // a TLS-cert reload across all TLS-enabled tenants; SIGUSR2 → request
    // an audit-log rotation for every tenant with a SignerFactory; SIGHUP
    // → re-load config, compute diff, apply ADD step for new tenants.
    //
    // Sprint 11.5: tenant name set is now SHARED — the apply step extends
    // it after a successful add so subsequent SIGHUPs see the updated set.
    let tenant_names_shared: Arc<tokio::sync::RwLock<std::collections::HashSet<String>>> = Arc::new(
        tokio::sync::RwLock::new(tenant_state.iter().map(|rt| rt.name.clone()).collect()),
    );
    // Sprint 14: shared tenant-config snapshot. Promoted from the
    // read-only Vec<TenantConfig> passed in Sprint 13 so the SIGHUP
    // apply step can extend it on each successful ADD. Material-change
    // detection now works for runtime-added tenants too.
    let tenant_configs_shared: Arc<tokio::sync::RwLock<Vec<TenantConfig>>> =
        Arc::new(tokio::sync::RwLock::new(cfg.tenants.clone()));
    // Sprint 16 (Stage B): shared by-name map from tenant name to its
    // `HotAdmissionController`. The SIGHUP arm looks up an existing
    // tenant's controller via this map when handling a Hot change to
    // `[tenants.limits]` and calls `swap()` to atomically replace the
    // inner controller. The apply step extends this map on each
    // successful ADD; tenant removal (Sprint 17) will purge entries.
    let tenant_admissions_shared: Arc<
        tokio::sync::RwLock<
            std::collections::HashMap<String, Arc<qgateway_core::HotAdmissionController>>,
        >,
    > = Arc::new(tokio::sync::RwLock::new(
        tenant_state
            .iter()
            .map(|rt| (rt.name.clone(), rt.admission.clone()))
            .collect(),
    ));
    // Sprint 18: shared by-name map from tenant name to its per-tenant
    // shutdown notify. SIGTERM/SIGINT fanout walks this map to notify
    // every running tenant; SIGHUP REMOVE notifies just one. The apply
    // step extends this map on each successful ADD; REMOVE purges.
    let tenant_shutdowns_shared: Arc<
        tokio::sync::RwLock<std::collections::HashMap<String, Arc<Notify>>>,
    > = Arc::new(tokio::sync::RwLock::new(
        tenant_state
            .iter()
            .map(|rt| (rt.name.clone(), rt.shutdown.clone()))
            .collect(),
    ));
    // Sprint 19: shared by-name audit-channel map. SIGHUP REMOVE looks
    // up the channel here and calls `shutdown_async()` before purging
    // the tenant from other shared maps. Replaces Sprint 18's
    // best-effort Drop-based cleanup.
    let tenant_audits_shared: Arc<
        tokio::sync::RwLock<std::collections::HashMap<String, Arc<qgateway_core::AuditChannel>>>,
    > = Arc::new(tokio::sync::RwLock::new(
        tenant_state
            .iter()
            .map(|rt| (rt.name.clone(), rt.audit.clone()))
            .collect(),
    ));
    #[cfg(unix)]
    let _signal_task = install_signal_handler(
        shutdown.clone(),
        reload_triggers_shared.clone(),
        rotation_targets_shared.clone(),
        config_path.to_path_buf(),
        tenant_names_shared.clone(),
        tenant_metrics_shared.clone(),
        identity.clone(),
        tenant_configs_shared.clone(),
        tenant_admissions_shared.clone(),
        daemon_metrics.clone(),
        tenant_shutdowns_shared.clone(),
        tenant_tasks_by_name.clone(),
        tenant_audits_shared.clone(),
        cfg.tenant_drain_timeout_secs,
        sni_dispatches_shared.clone(),
        sni_group_shutdowns_shared.clone(),
        sni_group_tasks_shared.clone(),
        monitor_handles_shared.clone(),
    );
    #[cfg(not(unix))]
    let _signal_task = install_signal_handler(
        shutdown.clone(),
        reload_triggers_shared.clone(),
        config_path.to_path_buf(),
        tenant_names_shared.clone(),
    );

    shutdown.notified().await;
    info!("draining tenants");
    // Sprint 24: fan out per-SNI-group shutdown FIRST, then await their
    // tasks. This replaces the Sprint 18 behavior where SNI groups
    // relied on the daemon-wide shutdown notify (now never signalled
    // for groups). The per-group Notify + JoinHandle pattern matches
    // what the SIGHUP arm uses to drain a single group when its last
    // tenant leaves.
    {
        let group_notifies = sni_group_shutdowns_shared.read().await;
        for notify in group_notifies.values() {
            notify.notify_waiters();
        }
    }
    {
        let mut group_tasks = sni_group_tasks_shared.write().await;
        let listens: Vec<String> = group_tasks.keys().cloned().collect();
        for listen in listens {
            if let Some(h) = group_tasks.remove(&listen) {
                let _ = h.await;
            }
        }
    }
    // Sprint 18: drain remaining non-SNI-group tasks (Vec is empty in
    // Sprint 24 since SNI groups moved out, kept for forward-compat)
    // AND removable single-tenant tasks (HashMap). SIGTERM/SIGINT has
    // already notified every per-tenant shutdown + the daemon-wide
    // shutdown.
    for h in tenant_tasks {
        let _ = h.await;
    }
    let mut by_name = tenant_tasks_by_name.write().await;
    let names: Vec<String> = by_name.keys().cloned().collect();
    for name in names {
        if let Some(h) = by_name.remove(&name) {
            let _ = h.await;
        }
    }
    drop(by_name);
    // Sprint 28: drain auto-rotation monitor tasks. Per-tenant SIGTERM
    // fanout above already signalled each tenant's shutdown Notify;
    // monitors observe that and return. Await every handle to ensure
    // they all finish before the daemon exits.
    {
        let mut monitors = monitor_handles_shared.write().await;
        let names: Vec<String> = monitors.keys().cloned().collect();
        for name in names {
            if let Some(h) = monitors.remove(&name) {
                let _ = h.await;
            }
        }
    }
    metrics_handle.abort();
    // Sprint 19: AuditChannel is now Arc<AuditChannel>. Use the
    // idempotent shutdown_async — the SIGHUP REMOVE path may have
    // already drained some channels; this call is a no-op for those.
    for rt in &tenant_state {
        rt.audit.shutdown_async().await;
    }
    drop(tenant_state);
    info!("qgateway stopped");
    Ok(())
}

/// Sprint 8: factory wrapping a softkey path pair. Each rotation cycle
/// re-loads the .audit.skid + .audit.pub and produces a fresh KeyPair
/// boxed as a Signer trait object. Same key across rotations — the new
/// log's header pubkey equals the old log's, which is exactly what
/// regulators expect for a non-incident-driven rotation.
struct SoftkeySignerFactory {
    sk_path: PathBuf,
    pk_path: PathBuf,
}

impl qgateway_core::SignerFactory for SoftkeySignerFactory {
    fn new_signer(&self) -> qaudit_core::Result<Box<dyn qaudit_core::Signer>> {
        let kp = auditkey::load(&self.sk_path, &self.pk_path).map_err(|e| {
            qaudit_core::Error::Internal(format!("SoftkeySignerFactory: load failed: {e:#}"))
        })?;
        Ok(Box::new(kp))
    }
}

/// Sprint 9: PKCS#11 `SignerFactory`. Wraps the hsm crate's
/// `Pkcs11SignerFactory` so we can impl the `qgateway_core::SignerFactory`
/// trait here (orphan rule: that trait is in qgateway-core, the
/// `Pkcs11SignerFactory` struct is in qaudit-hsm, neither crate can impl
/// the trait directly on the foreign type).
///
/// Each `new_signer()` opens a fresh HSM session — rotation cadences
/// (hours/days/months) make this trivially cheap.
#[cfg(feature = "pkcs11")]
struct Pkcs11SignerFactoryWrapper {
    inner: qaudit_hsm::Pkcs11SignerFactory,
}

#[cfg(feature = "pkcs11")]
impl qgateway_core::SignerFactory for Pkcs11SignerFactoryWrapper {
    fn new_signer(&self) -> qaudit_core::Result<Box<dyn qaudit_core::Signer>> {
        self.inner.open_new()
    }
}

/// Sprint 10: bridges qaudit-hsm's `HsmTelemetry` trait to qgateway-core's
/// `MetricsRegistry`. One instance per tenant (per-tenant metrics labels).
/// Cloned cheaply by the signer factory; held for the signer's lifetime.
#[cfg(feature = "pkcs11")]
struct MetricsHsmTelemetry {
    metrics: qgateway_core::MetricsRegistry,
}

#[cfg(feature = "pkcs11")]
impl qaudit_hsm::HsmTelemetry for MetricsHsmTelemetry {
    fn on_session_open(&self) {
        self.metrics
            .inner()
            .hsm_sessions_opened
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    fn on_session_open_failed(&self) {
        self.metrics
            .inner()
            .hsm_sessions_failed
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    fn on_sign_ok(&self) {
        self.metrics
            .inner()
            .hsm_sign_ops
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    fn on_sign_failed(&self) {
        self.metrics
            .inner()
            .hsm_sign_failures
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Sprint 11.5: build a fully-wired `TenantRuntime` from a single tenant
/// config + the surrounding daemon config (needed for `effective_signer`
/// precedence). Extracted from `cmd_run` so the SIGHUP apply step can
/// call it on newly-added tenants without restarting the daemon.
///
/// This helper deliberately does NOT touch shared state (metrics list,
/// tenant name set, accept-loop spawn). Callers wire the returned
/// runtime into those structures themselves.
fn build_tenant_runtime(t: &TenantConfig, cfg: &Config) -> Result<TenantRuntime> {
    let peer_policy = PeerPolicy::from_dir(&t.peer_pub_dir)
        .with_context(|| format!("loading peer dir {}", t.peer_pub_dir.display()))?;
    if peer_policy.is_empty() {
        return Err(anyhow!(
            "tenant {}: no peer .cspqid.pub files in {}",
            t.name,
            t.peer_pub_dir.display()
        ));
    }

    let effective_signer = cfg.effective_signer(t).ok_or_else(|| {
        anyhow!(
            "tenant {}: no audit_signer (declare [tenants.audit_signer] for \
             this tenant or a top-level [audit_signer] as the default)",
            t.name
        )
    })?;

    let metrics = MetricsRegistry::new(t.name.clone());

    let log = match &effective_signer {
        AuditSignerConfig::Softkey {
            secret_key,
            public_key,
        } => {
            let audit_kp = auditkey::load(secret_key, public_key).with_context(|| {
                format!(
                    "loading audit keypair (sk={} pk={})",
                    secret_key.display(),
                    public_key.display()
                )
            })?;
            build_audit_log_softkey(&t.audit_log, audit_kp, &t.name)?
        }
        sig @ AuditSignerConfig::Pkcs11 { .. } => {
            build_audit_log_pkcs11(&t.audit_log, sig, &t.name, &metrics)?
        }
    };

    let audit = match &effective_signer {
        AuditSignerConfig::Softkey {
            secret_key,
            public_key,
        } => {
            let factory = SoftkeySignerFactory {
                sk_path: secret_key.clone(),
                pk_path: public_key.clone(),
            };
            AuditChannel::spawn_with_rotation(
                log,
                t.audit_log.clone(),
                metrics.clone(),
                256,
                16,
                factory,
            )
        }
        #[cfg(feature = "pkcs11")]
        AuditSignerConfig::Pkcs11 { .. } => {
            let pcfg = build_pkcs11_config(&effective_signer)
                .with_context(|| format!("PKCS#11 factory cfg for tenant {}", t.name))?;
            let factory = Pkcs11SignerFactoryWrapper {
                inner: qaudit_hsm::Pkcs11SignerFactory::new(pcfg).with_telemetry(
                    std::sync::Arc::new(MetricsHsmTelemetry {
                        metrics: metrics.clone(),
                    }),
                ),
            };
            AuditChannel::spawn_with_rotation(
                log,
                t.audit_log.clone(),
                metrics.clone(),
                256,
                16,
                factory,
            )
        }
        #[cfg(not(feature = "pkcs11"))]
        AuditSignerConfig::Pkcs11 { .. } => {
            AuditChannel::spawn(log, t.audit_log.clone(), metrics.clone(), 256, 16)
        }
    };

    // Sprint 16 (Stage B): build the shared HotAdmissionController here
    // so the same instance is reachable both from the accept loop (via
    // the spawn arg) and from the SIGHUP apply step (via TenantRuntime).
    let (mc, rl) = match &t.limits {
        Some(l) => (
            l.max_concurrent,
            l.rate_limit_per_source
                .as_ref()
                .map(qgateway_core::RateLimitConfig::from),
        ),
        None => (None, None),
    };
    let admission = Arc::new(qgateway_core::HotAdmissionController::new(mc, rl));
    // Sprint 18: per-tenant shutdown notify. Notifying triggers the
    // accept loop to exit cleanly without affecting other tenants.
    let shutdown = Arc::new(Notify::new());

    Ok(TenantRuntime {
        name: t.name.clone(),
        peer_policy: Arc::new(peer_policy),
        metrics,
        // Sprint 19: wrap in Arc so the channel can be shared with the
        // tenant_audits_shared map for SIGHUP REMOVE drain.
        audit: Arc::new(audit),
        audit_log_path: t.audit_log.clone(),
        admission,
        shutdown,
    })
}

struct TenantRuntime {
    name: String,
    peer_policy: Arc<PeerPolicy>,
    metrics: MetricsRegistry,
    /// Sprint 19: wrapped in Arc so the same channel can live both here
    /// (for `handle()` and `rotation_handle()` accessors) and in the
    /// shared `tenant_audits_shared` map (for `shutdown_async()` on
    /// SIGHUP REMOVE).
    audit: Arc<AuditChannel>,
    /// Sprint 8: original audit log path (for archive naming on rotation).
    audit_log_path: PathBuf,
    /// Sprint 16 (Stage B): shared hot-swappable admission controller.
    /// Held here so the SIGHUP apply step can call `swap()` on hot
    /// changes to `[tenants.limits]` without restarting the accept loop.
    /// Cloned into the per-tenant accept-loop task at spawn time.
    admission: Arc<qgateway_core::HotAdmissionController>,
    /// Sprint 18: per-tenant shutdown notify. The accept loop selects on
    /// EITHER this notify OR the daemon-wide shutdown notify. Notifying
    /// only this one drains a single tenant (SIGHUP REMOVE); notifying
    /// the daemon-wide notify still drains everything (SIGTERM/SIGINT).
    /// The accept loop returns Ok(()) on either signal.
    shutdown: Arc<Notify>,
}

/// Sprint 11.5: shared tenant-metrics handle. The metrics server reads
/// this on every /metrics scrape; the SIGHUP apply step writes new
/// entries on tenant-add. `RwLock` chosen over `Mutex` because scrapes
/// vastly outnumber writes — typical deployment scrapes every 15s,
/// tenant-add happens on operator action.
type SharedMetricsList = Arc<tokio::sync::RwLock<Vec<MetricsRegistry>>>;

async fn spawn_metrics_server(
    addr: String,
    tenants: SharedMetricsList,
    // Sprint 17: daemon-wide metrics rendered alongside tenant series.
    daemon_metrics: Arc<qgateway_core::metrics::DaemonMetrics>,
) -> Result<tokio::task::JoinHandle<()>> {
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .with_context(|| format!("binding metrics {addr}"))?;
    info!(addr = %addr, "metrics server listening");
    let handle = tokio::spawn(async move {
        loop {
            let (mut sock, _) = match listener.accept().await {
                Ok(x) => x,
                Err(e) => {
                    warn!("metrics accept error: {e}");
                    continue;
                }
            };
            let tenants = tenants.clone();
            let daemon_metrics = daemon_metrics.clone();
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = [0u8; 1024];
                let _ =
                    tokio::time::timeout(std::time::Duration::from_secs(2), sock.read(&mut buf))
                        .await;
                let req = String::from_utf8_lossy(&buf);
                let path = req.split_whitespace().nth(1).unwrap_or("/");
                let (status, body, ctype) = if path == "/healthz" {
                    ("200 OK", "ok\n".to_string(), "text/plain")
                } else if path == "/metrics" {
                    // Sprint 11.5: clone the snapshot under the read lock,
                    // then release the lock before render_prometheus. The
                    // render is pure CPU and could hold the lock for a few
                    // ms with many tenants — releasing first lets concurrent
                    // SIGHUP apply add new tenants without head-of-line
                    // blocking.
                    let snapshot: Vec<MetricsRegistry> = tenants.read().await.clone();
                    let refs: Vec<&MetricsRegistry> = snapshot.iter().collect();
                    let mut body = render_prometheus(&refs);
                    // Sprint 17: append daemon-wide counters.
                    body.push_str(&qgateway_core::metrics::render_daemon_metrics(
                        &daemon_metrics,
                    ));
                    ("200 OK", body, "text/plain; version=0.0.4")
                } else {
                    ("404 Not Found", "not found\n".to_string(), "text/plain")
                };
                let resp = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    Ok(handle)
}

#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
fn install_signal_handler(
    notify: Arc<Notify>,
    // Sprint 20: promoted from Vec to Arc<RwLock<HashMap>>. The SIGHUP
    // arm extends on ADD (TLS-enabled tenants) and purges on REMOVE.
    // SIGUSR1 iterates HashMap values.
    reload_triggers: Arc<tokio::sync::RwLock<std::collections::HashMap<String, TlsReloadTrigger>>>,
    rotation_targets: Arc<tokio::sync::RwLock<std::collections::HashMap<String, RotationTarget>>>,
    // Sprint 11: SIGHUP support — re-read config from this path and report
    // the diff vs the daemon's startup tenant set.
    config_path: PathBuf,
    // Sprint 11.5: shared tenant name set — the apply step extends it
    // after a successful ADD so subsequent SIGHUPs see the updated set.
    tenant_names: Arc<tokio::sync::RwLock<std::collections::HashSet<String>>>,
    // Sprint 11.5: shared metrics list — apply step pushes the new
    // tenant's MetricsRegistry so /metrics scrapes include it.
    metrics_list: SharedMetricsList,
    // Sprint 11.5: identity key for new tenant accept loops. Cloned per
    // task spawn.
    identity: Arc<IdentityKey>,
    // Sprint 13: startup tenant snapshot for material-change detection.
    // Sprint 14: promoted to `Arc<RwLock<Vec<TenantConfig>>>` so the
    // apply step extends it on each successful ADD — material-change
    // detection now works for runtime-added tenants too, not just the
    // startup set.
    tenant_configs: Arc<tokio::sync::RwLock<Vec<TenantConfig>>>,
    // Sprint 16 (Stage B): shared by-name admission map. The SIGHUP arm
    // looks up an existing tenant's `HotAdmissionController` and calls
    // `swap()` on hot changes to `[tenants.limits]`. The apply step
    // extends this map on each successful ADD.
    tenant_admissions: Arc<
        tokio::sync::RwLock<
            std::collections::HashMap<String, Arc<qgateway_core::HotAdmissionController>>,
        >,
    >,
    // Sprint 17: daemon-wide metrics — the SIGHUP arm bumps these on
    // cycle outcomes (validation, add success/failure, hot apply).
    daemon_metrics: Arc<qgateway_core::metrics::DaemonMetrics>,
    // Sprint 18: per-tenant shutdown notify map. SIGTERM/SIGINT walks
    // this on shutdown to fan out the daemon-wide notify to every
    // tenant's individual notify; SIGHUP REMOVE notifies just one.
    tenant_shutdowns: Arc<tokio::sync::RwLock<std::collections::HashMap<String, Arc<Notify>>>>,
    // Sprint 18: by-name map of removable-tenant JoinHandles. SIGHUP
    // REMOVE looks up the handle, awaits it with a timeout, and on
    // success purges the corresponding entries from tenant_names,
    // tenant_metrics, tenant_configs, tenant_admissions, tenant_shutdowns,
    // and this map.
    tenant_tasks_map: Arc<
        tokio::sync::RwLock<std::collections::HashMap<String, tokio::task::JoinHandle<Result<()>>>>,
    >,
    // Sprint 19: shared audit-channel map. SIGHUP REMOVE calls
    // `shutdown_async()` on the tenant's channel before purging.
    tenant_audits: Arc<
        tokio::sync::RwLock<std::collections::HashMap<String, Arc<qgateway_core::AuditChannel>>>,
    >,
    // Sprint 19: operator-configurable drain timeout (seconds) for SIGHUP
    // REMOVE. Read from Config::tenant_drain_timeout_secs (default 30s).
    drain_timeout_secs: u64,
    // Sprint 23: shared per-listen-address map of SNI dispatch tables.
    // The SIGHUP arm uses this to compute successor tables on SNI tenant
    // ADD/REMOVE and swap them atomically.
    sni_dispatches: Arc<
        tokio::sync::RwLock<
            std::collections::HashMap<String, Arc<qgateway_core::HotSniDispatchTable>>,
        >,
    >,
    // Sprint 24: per-SNI-group shutdown Notify, keyed by listen.
    // The SIGHUP arm uses these for two purposes: (1) inserts a new
    // entry when spawning a brand-new SNI group via first-tenant-add;
    // (2) signals + awaits an entry's drain when REMOVE empties a
    // group.
    sni_group_shutdowns: Arc<tokio::sync::RwLock<std::collections::HashMap<String, Arc<Notify>>>>,
    sni_group_tasks: Arc<
        tokio::sync::RwLock<std::collections::HashMap<String, tokio::task::JoinHandle<Result<()>>>>,
    >,
    // Sprint 28: auto-rotation monitor handles, keyed by tenant name.
    // SIGHUP ADD spawns a new monitor for the added tenant if the
    // daemon has an auto-rotation policy; SIGHUP REMOVE awaits the
    // monitor handle after the per-tenant shutdown Notify fires.
    monitor_handles: Arc<
        tokio::sync::RwLock<std::collections::HashMap<String, tokio::task::JoinHandle<()>>>,
    >,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("SIGTERM handler");
        let mut sigusr1 =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined1())
                .expect("SIGUSR1 handler");
        let mut sigusr2 =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined2())
                .expect("SIGUSR2 handler");
        // Sprint 11: SIGHUP handler. Re-reads the config file and reports
        // a diff (new/removed/unchanged) via tracing. No runtime state
        // is mutated yet — that's Sprint 11.5 work. The validation pass
        // alone catches: TOML parse errors, schema-validation failures,
        // and operator confusion about which tenants the daemon thinks
        // it's running. Already actionable in production today.
        let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
            .expect("SIGHUP handler");
        loop {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    info!("SIGINT received, initiating shutdown");
                    // Sprint 18: fan out to every per-tenant notify so
                    // single-tenant accept loops (which now select on
                    // their per-tenant shutdown) drain. Daemon notify
                    // is also fired so SNI groups (still on daemon
                    // shutdown) drain too.
                    for sd in tenant_shutdowns.read().await.values() {
                        sd.notify_waiters();
                    }
                    notify.notify_waiters();
                    return;
                }
                _ = sigterm.recv() => {
                    info!("SIGTERM received, initiating shutdown");
                    for sd in tenant_shutdowns.read().await.values() {
                        sd.notify_waiters();
                    }
                    notify.notify_waiters();
                    return;
                }
                _ = sigusr1.recv() => {
                    // Sprint 20: read-lock the triggers map for the
                    // duration of the reload cycle. Concurrent SIGHUP
                    // ADD/REMOVE would need the write lock and will
                    // wait — acceptable because both are operator-
                    // initiated, not request-path.
                    let triggers_guard = reload_triggers.read().await;
                    if triggers_guard.is_empty() {
                        info!("SIGUSR1 received but no TLS tenants configured — ignoring");
                        continue;
                    }
                    info!(
                        n_tenants = triggers_guard.len(),
                        "SIGUSR1 received, reloading TLS certs"
                    );
                    let mut ok = 0usize;
                    let mut errs = 0usize;
                    for trigger in triggers_guard.values() {
                        match trigger.reload() {
                            Ok(_prev) => {
                                ok += 1;
                                info!(tenant = %trigger.tenant_name(), "TLS cert reloaded");
                            }
                            Err(e) => {
                                errs += 1;
                                error!(tenant = %trigger.tenant_name(),
                                       "TLS reload FAILED, keeping previous cert: {e:#}");
                            }
                        }
                    }
                    info!(reloaded = ok, failed = errs, "TLS reload cycle complete");
                }
                _ = sigusr2.recv() => {
                    // Sprint 27: read-lock the rotation targets map for the
                    // duration of the rotation cycle. Concurrent SIGHUP
                    // ADD/REMOVE would need the write lock and will wait —
                    // both are operator-initiated, never request-path.
                    let targets_guard = rotation_targets.read().await;
                    if targets_guard.is_empty() {
                        info!("SIGUSR2 received but no rotatable audit logs configured — ignoring");
                        continue;
                    }
                    info!(
                        n_tenants = targets_guard.len(),
                        "SIGUSR2 received, rotating audit logs"
                    );
                    for target in targets_guard.values() {
                        let counter = target
                            .counter
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                            + 1;
                        let now = chrono::Utc::now();
                        let archive_name = target
                            .policy
                            .as_ref()
                            .map(|p| p.render_archive_name(&target.tenant_name, counter, now))
                            .unwrap_or_else(|| {
                                // Default pattern when no [rotation] block.
                                format!(
                                    "{}-{}.qa",
                                    target.tenant_name,
                                    now.format("%Y%m%dT%H%M%SZ")
                                )
                            });
                        let archive_path = target
                            .log_path
                            .parent()
                            .unwrap_or_else(|| std::path::Path::new("."))
                            .join(&archive_name);
                        let new_label = format!("{}-{}", target.tenant_name, counter);
                        target
                            .channel
                            .request_rotation_silent(archive_path.clone(), new_label.clone());
                        info!(
                            tenant = %target.tenant_name,
                            archive = %archive_path.display(),
                            new_label = %new_label,
                            "audit rotation requested"
                        );
                    }
                }
                _ = sighup.recv() => {
                    // Sprint 11.5: validate + diff + apply ADD step. Reads
                    // the current tenant name set from shared state,
                    // validates the new config, computes diff. For each
                    // newly added tenant: builds the runtime, pushes its
                    // MetricsRegistry to the shared list (so /metrics
                    // includes it), and extends the shared name set.
                    //
                    // Tenant REMOVAL is still Sprint 12 work — removed
                    // tenants log a warning and require restart.
                    //
                    // Tenant CONFIGURATION CHANGE (same name, different
                    // settings) is still Sprint 12+ work — name-keyed
                    // diff treats same-name as unchanged.
                    //
                    // The new tenant's accept loop is NOT spawned here.
                    // Sprint 12 work: extract the per-role accept-loop
                    // spawn logic so SIGHUP can wire a fresh tenant into
                    // its serve_tcp / serve_pq / sni_group correctly.
                    // Sprint 11.5 ships the runtime build + metrics +
                    // name registration; the listener doesn't accept
                    // until next restart.
                    info!(config = %config_path.display(),
                          "SIGHUP received");
                    match Config::load(&config_path) {
                        Ok(new_cfg) => {
                            // Sprint 17: count this as a successful SIGHUP
                            // cycle (validation passed). Apply outcomes
                            // are counted separately below.
                            daemon_metrics
                                .sighup_cycles_total
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            let current_names = tenant_names.read().await.clone();
                            let new_names: std::collections::HashSet<String> =
                                new_cfg.tenants.iter().map(|t| t.name.clone()).collect();
                            let added: Vec<&String> = new_names
                                .difference(&current_names)
                                .collect();
                            let removed: Vec<&String> = current_names
                                .difference(&new_names)
                                .collect();
                            let unchanged: Vec<&String> = new_names
                                .intersection(&current_names)
                                .collect();

                            // Sprint 14: shared snapshot — works for
                            // runtime-added tenants too. Acquire read lock
                            // for the scan, release before the apply step
                            // (which needs the write lock for adding new
                            // tenants).
                            let mut config_changed_hot = 0usize;
                            let mut config_changed_cold = 0usize;
                            {
                                let configs_snapshot = tenant_configs.read().await;
                                for name in &unchanged {
                                    let prev = configs_snapshot
                                        .iter()
                                        .find(|t| &t.name == *name);
                                    let new_t = new_cfg
                                        .tenants
                                        .iter()
                                        .find(|t| &t.name == *name);
                                    if let (Some(p), Some(n)) = (prev, new_t) {
                                        let changes = p.material_changes(n);
                                        if !changes.is_empty() {
                                            // Sprint 14: split log by kind so
                                            // operators see which changes are
                                            // even theoretically hot-applicable.
                                            // The current apply path still
                                            // requires restart even for hot
                                            // changes — rebuilding the
                                            // AdmissionController in place is
                                            // Sprint 15. The classification
                                            // unblocks that future work and
                                            // also helps operators triage:
                                            // "limits change only — defer
                                            //  restart to next maintenance
                                            //  window"
                                            // vs
                                            // "listen change — must restart
                                            //  now or roll back the edit".
                                            let hot_fields: Vec<&'static str> = changes
                                                .iter()
                                                .filter(|c| matches!(c.kind, qgateway_core::config::TenantChangeKind::Hot))
                                                .map(|c| c.field)
                                                .collect();
                                            let cold_fields: Vec<&'static str> = changes
                                                .iter()
                                                .filter(|c| matches!(c.kind, qgateway_core::config::TenantChangeKind::Cold))
                                                .map(|c| c.field)
                                                .collect();
                                            if !hot_fields.is_empty() {
                                                // Sprint 16 (Stage B): actually
                                                // APPLY hot changes by looking
                                                // up the tenant's
                                                // HotAdmissionController and
                                                // swapping its inner. Currently
                                                // the only hot-classified field
                                                // is `limits`, so this branch
                                                // is specifically a limits-
                                                // change handler. If future
                                                // fields graduate to Hot, the
                                                // dispatch here will need to
                                                // grow into a match over
                                                // `field`.
                                                let admissions = tenant_admissions.read().await;
                                                if let Some(controller) = admissions.get(*name) {
                                                    let (mc, rl) = match &n.limits {
                                                        Some(l) => (
                                                            l.max_concurrent,
                                                            l.rate_limit_per_source
                                                                .as_ref()
                                                                .map(qgateway_core::RateLimitConfig::from),
                                                        ),
                                                        None => (None, None),
                                                    };
                                                    let _old = controller.swap(mc, rl);
                                                    info!(
                                                        tenant = %name,
                                                        fields = ?hot_fields,
                                                        kind = "hot",
                                                        "tenant limits hot-applied (new policy in effect for future connections; in-flight permits unaffected)"
                                                    );
                                                    // Sprint 17: count
                                                    // successful hot apply.
                                                    daemon_metrics
                                                        .limits_hot_applied_total
                                                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                                } else {
                                                    // Tenant not in admissions map — defensive
                                                    // log, should not happen in normal operation.
                                                    warn!(
                                                        tenant = %name,
                                                        fields = ?hot_fields,
                                                        kind = "hot",
                                                        "tenant configuration changed (hot-applicable) but no admission controller registered — restart required"
                                                    );
                                                }
                                                config_changed_hot += 1;
                                                daemon_metrics
                                                    .config_changed_hot_total
                                                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                            }
                                            if !cold_fields.is_empty() {
                                                warn!(
                                                    tenant = %name,
                                                    fields = ?cold_fields,
                                                    kind = "cold",
                                                    "tenant configuration changed (cold-only, restart required)"
                                                );
                                                config_changed_cold += 1;
                                                daemon_metrics
                                                    .config_changed_cold_total
                                                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                            }
                                        }
                                    }
                                }
                            }

                            info!(
                                added = added.len(),
                                removed = removed.len(),
                                unchanged = unchanged.len(),
                                config_changed_hot = config_changed_hot,
                                config_changed_cold = config_changed_cold,
                                "config reload diff"
                            );

                            // Apply ADD step.
                            let mut applied = 0usize;
                            let mut failed = 0usize;
                            for added_name in &added {
                                let cfg_for_tenant = new_cfg
                                    .tenants
                                    .iter()
                                    .find(|t| t.name == **added_name)
                                    .expect("added name must exist in new_cfg");
                                match build_tenant_runtime(cfg_for_tenant, &new_cfg) {
                                    Ok(rt) => {
                                        // Push to shared metrics list FIRST
                                        // so /metrics includes it before we
                                        // advertise the tenant as ready.
                                        metrics_list.write().await.push(rt.metrics.clone());
                                        tenant_names.write().await.insert(rt.name.clone());
                                        // Sprint 14: extend the shared
                                        // config snapshot so future SIGHUPs
                                        // can detect material changes on
                                        // this runtime-added tenant too.
                                        tenant_configs.write().await.push(cfg_for_tenant.clone());
                                        // Sprint 16 (Stage B): register the
                                        // new tenant's admission controller
                                        // so future SIGHUPs with limits
                                        // changes can find it.
                                        tenant_admissions
                                            .write()
                                            .await
                                            .insert(rt.name.clone(), rt.admission.clone());
                                        // Sprint 18: register the new
                                        // tenant's shutdown notify so
                                        // SIGTERM/SIGINT fanout and a
                                        // future SIGHUP REMOVE can find it.
                                        tenant_shutdowns
                                            .write()
                                            .await
                                            .insert(rt.name.clone(), rt.shutdown.clone());
                                        // Sprint 19: register the new
                                        // tenant's audit channel so a
                                        // future SIGHUP REMOVE can call
                                        // shutdown_async() on it.
                                        tenant_audits
                                            .write()
                                            .await
                                            .insert(rt.name.clone(), rt.audit.clone());
                                        // Sprint 27: register the new tenant's
                                        // rotation target so subsequent SIGUSR2
                                        // includes it. Pre-Sprint-27 this map
                                        // was a startup-populated Vec — any
                                        // tenant added at runtime would be
                                        // silently skipped by SIGUSR2.
                                        // The rotation_policy is the daemon-
                                        // level config's; per-tenant override
                                        // (if any) would need separate plumbing
                                        // — deferred until operators ask.
                                        let counter = Arc::new(
                                            std::sync::atomic::AtomicU64::new(0),
                                        );
                                        rotation_targets
                                            .write()
                                            .await
                                            .insert(
                                                rt.name.clone(),
                                                RotationTarget {
                                                    tenant_name: rt.name.clone(),
                                                    channel: rt.audit.rotation_handle(),
                                                    log_path: rt.audit_log_path.clone(),
                                                    counter: counter.clone(),
                                                    policy: new_cfg.rotation.clone(),
                                                },
                                            );
                                        // Sprint 28: spawn the per-tenant
                                        // auto-rotation monitor for the
                                        // runtime-added tenant. Pre-Sprint-28
                                        // this was startup-only — the
                                        // companion bug to Sprint 27's
                                        // SIGUSR2 fix. The monitor listens
                                        // to the per-tenant shutdown Notify
                                        // (rt.shutdown) so SIGHUP REMOVE
                                        // stops it without disturbing other
                                        // tenants' monitors.
                                        if let Some(policy) = new_cfg.rotation.clone() {
                                            if policy.has_auto_trigger() {
                                                // Sprint 35: honor
                                                // `[rotation] poll_interval_ms` for
                                                // runtime-added tenants too.
                                                let poll = policy.poll_interval();
                                                let monitor = qgateway_core::RotationMonitor::new(
                                                    rt.name.clone(),
                                                    rt.audit.rotation_handle(),
                                                    rt.audit_log_path.clone(),
                                                    policy,
                                                    counter,
                                                )
                                                .with_poll_interval(poll);
                                                let handle = monitor.spawn(rt.shutdown.clone());
                                                monitor_handles
                                                    .write()
                                                    .await
                                                    .insert(rt.name.clone(), handle);
                                                info!(
                                                    tenant = %rt.name,
                                                    "auto-rotation monitor spawned for runtime-added tenant"
                                                );
                                            }
                                        }

                                        // Sprint 12 + 13: spawn accept loop
                                        // for the runtime-added tenant.
                                        //  - ServePq always supported.
                                        //  - ServeTcp supported only if the
                                        //    tenant has no `[tls]` block AND
                                        //    no `sni` (single-tenant, plain
                                        //    TCP). TLS + SNI hot-add is
                                        //    Sprint 14 work.
                                        let spawned = match new_cfg.role {
                                            qgateway_core::Role::ServePq => {
                                                match new_cfg.resolve_one_serve_pq(cfg_for_tenant) {
                                                    Ok(resolved) => {
                                                        let identity_c = identity.clone();
                                                        let peer_policy_c = rt.peer_policy.clone();
                                                        let audit_handle = rt.audit.handle();
                                                        let metrics_c = rt.metrics.clone();
                                                        let admission_c = rt.admission.clone();
                                                        // Sprint 18: per-tenant shutdown so SIGHUP
                                                        // REMOVE can drain this tenant in isolation.
                                                        let shutdown_c = rt.shutdown.clone();
                                                        let tenant_name = rt.name.clone();
                                                        let handle = tokio::spawn(async move {
                                                            let res = run_serve_pq_tenant(
                                                                resolved,
                                                                identity_c,
                                                                peer_policy_c,
                                                                audit_handle,
                                                                metrics_c,
                                                                shutdown_c,
                                                                Some(admission_c),
                                                            ).await;
                                                            if let Err(ref e) = res {
                                                                error!("runtime-added serve-pq tenant exited: {e:#}");
                                                            }
                                                            res
                                                        });
                                                        tenant_tasks_map
                                                            .write()
                                                            .await
                                                            .insert(tenant_name, handle);
                                                        true
                                                    }
                                                    Err(e) => {
                                                        error!(
                                                            tenant = %rt.name,
                                                            "tenant resolve failed: {e}"
                                                        );
                                                        false
                                                    }
                                                }
                                            }
                                            qgateway_core::Role::ServeTcp => 'tcp_add: {
                                                // Sprint 23: SNI hot-add into an existing
                                                // group is now supported. The tenant must
                                                // declare both `sni` and `tls`, and an
                                                // existing SNI group must already be
                                                // serving on `cfg_for_tenant.listen` —
                                                // first-tenant-in-new-group (which would
                                                // require spawning a new run_sni_group
                                                // task) is still Sprint 24+ work.
                                                if cfg_for_tenant.sni.is_some() {
                                                    // Validate that the tenant also has
                                                    // a [tls] block (an SNI tenant without
                                                    // TLS makes no sense — operator error).
                                                    let Some(tls_cfg) = cfg_for_tenant.tls.as_ref() else {
                                                        error!(
                                                            tenant = %rt.name,
                                                            "SNI runtime add: tenant has `sni` but no `tls` block — invalid config"
                                                        );
                                                        break 'tcp_add false;
                                                    };
                                                    let listen = cfg_for_tenant.listen.clone();
                                                    let sni_value = cfg_for_tenant.sni.clone().unwrap();
                                                    // Look up the running group's dispatch
                                                    // and trigger by `listen`.
                                                    let dispatch_opt = sni_dispatches
                                                        .read()
                                                        .await
                                                        .get(&listen)
                                                        .cloned();
                                                    let dispatch = match dispatch_opt {
                                                        Some(d) => d,
                                                        None => {
                                                            // Sprint 24: no running group on
                                                            // this listen — spawn a fresh
                                                            // run_sni_group task with this
                                                            // tenant as its sole member.
                                                            // Resolve, build context, build
                                                            // multi-SNI acceptor with one
                                                            // entry, build dispatch with one
                                                            // context, spawn task, register
                                                            // in all four shared maps:
                                                            // reload_triggers, sni_dispatches,
                                                            // sni_group_shutdowns,
                                                            // sni_group_tasks.
                                                            let resolved = match new_cfg
                                                                .resolve_one_serve_tcp(cfg_for_tenant)
                                                            {
                                                                Ok(r) => r,
                                                                Err(e) => {
                                                                    error!(
                                                                        tenant = %rt.name,
                                                                        listen = %listen,
                                                                        "SNI runtime add (new group): resolve failed: {e}"
                                                                    );
                                                                    break 'tcp_add false;
                                                                }
                                                            };
                                                            let group_label = format!("sni-group:{listen}");
                                                            let entries = vec![(
                                                                sni_value.clone(),
                                                                rt.name.clone(),
                                                                tls_cfg.clone(),
                                                            )];
                                                            let (new_tls_handle, new_trigger) =
                                                                match qgateway_core::build_reloadable_multi_sni_acceptor(
                                                                    entries,
                                                                    &group_label,
                                                                ) {
                                                                    Ok(x) => x,
                                                                    Err(e) => {
                                                                        error!(
                                                                            tenant = %rt.name,
                                                                            listen = %listen,
                                                                            "SNI runtime add (new group): multi-SNI acceptor build failed: {e:#}"
                                                                        );
                                                                        break 'tcp_add false;
                                                                    }
                                                                };
                                                            let new_ctx = qgateway_core::SniTenantContext {
                                                                tenant: resolved,
                                                                peer_policy: rt.peer_policy.clone(),
                                                                audit: rt.audit.handle(),
                                                                metrics: rt.metrics.clone(),
                                                                admission: rt.admission.clone(),
                                                            };
                                                            let new_dispatch_inner = match qgateway_core::SniDispatchTable::new(vec![new_ctx]) {
                                                                Ok(d) => d,
                                                                Err(e) => {
                                                                    error!(
                                                                        tenant = %rt.name,
                                                                        listen = %listen,
                                                                        "SNI runtime add (new group): dispatch table build failed: {e:#}"
                                                                    );
                                                                    break 'tcp_add false;
                                                                }
                                                            };
                                                            let new_dispatch = Arc::new(
                                                                qgateway_core::HotSniDispatchTable::new(new_dispatch_inner)
                                                            );
                                                            let group_notify = Arc::new(Notify::new());
                                                            let listen_for_task = listen.clone();
                                                            let new_identity = identity.clone();
                                                            let new_dispatch_for_task = new_dispatch.clone();
                                                            let group_notify_for_task = group_notify.clone();
                                                            let new_task = tokio::spawn(async move {
                                                                qgateway_core::run_sni_group(
                                                                    listen_for_task,
                                                                    new_tls_handle,
                                                                    new_dispatch_for_task,
                                                                    new_identity,
                                                                    group_notify_for_task,
                                                                ).await
                                                            });
                                                            // Register in all four shared maps.
                                                            // No rollback path on these
                                                            // inserts — they are infallible
                                                            // RwLock writes; if the task
                                                            // panics post-spawn the maps stay
                                                            // consistent (the JoinHandle's
                                                            // Err is observed on next drain).
                                                            reload_triggers
                                                                .write()
                                                                .await
                                                                .insert(group_label, new_trigger);
                                                            sni_dispatches
                                                                .write()
                                                                .await
                                                                .insert(listen.clone(), new_dispatch.clone());
                                                            sni_group_shutdowns
                                                                .write()
                                                                .await
                                                                .insert(listen.clone(), group_notify);
                                                            sni_group_tasks
                                                                .write()
                                                                .await
                                                                .insert(listen.clone(), new_task);
                                                            info!(
                                                                tenant = %rt.name,
                                                                listen = %listen,
                                                                sni = %sni_value,
                                                                "SNI tenant added at runtime — new group spawned"
                                                            );
                                                            break 'tcp_add true;
                                                        }
                                                    };
                                                    let trigger_key = format!("sni-group:{listen}");
                                                    // We can't take the trigger out of
                                                    // the map (it must stay there for
                                                    // SIGUSR1 + future SIGHUP REMOVE).
                                                    // Resolve via resolve_one_serve_tcp
                                                    // to get the ServeTcpTenant.
                                                    let resolved = match new_cfg
                                                        .resolve_one_serve_tcp(cfg_for_tenant)
                                                    {
                                                        Ok(r) => r,
                                                        Err(e) => {
                                                            error!(
                                                                tenant = %rt.name,
                                                                "SNI runtime add: resolve failed: {e}"
                                                            );
                                                            break 'tcp_add false;
                                                        }
                                                    };
                                                    // Build SniTenantContext (mirrors the
                                                    // startup-time construction at L441).
                                                    let new_ctx = qgateway_core::SniTenantContext {
                                                        tenant: resolved,
                                                        peer_policy: rt.peer_policy.clone(),
                                                        audit: rt.audit.handle(),
                                                        metrics: rt.metrics.clone(),
                                                        admission: rt.admission.clone(),
                                                    };
                                                    // Compute the successor dispatch table
                                                    // BEFORE mutating cert set — if this
                                                    // fails (duplicate SNI), we haven't
                                                    // touched the cert state.
                                                    let new_dispatch = match dispatch
                                                        .load()
                                                        .with_tenant_added(new_ctx)
                                                    {
                                                        Ok(d) => d,
                                                        Err(e) => {
                                                            error!(
                                                                tenant = %rt.name,
                                                                listen = %listen,
                                                                "SNI runtime add: dispatch build failed: {e}"
                                                            );
                                                            break 'tcp_add false;
                                                        }
                                                    };
                                                    // Mutate cert set via the trigger.
                                                    // Hold the read lock for the duration
                                                    // — single critical section across
                                                    // cert mutation + dispatch swap so
                                                    // an interleaved SIGUSR1 sees them
                                                    // consistent.
                                                    let triggers_guard = reload_triggers
                                                        .read()
                                                        .await;
                                                    let trigger = match triggers_guard
                                                        .get(&trigger_key)
                                                    {
                                                        Some(t) => t,
                                                        None => {
                                                            error!(
                                                                tenant = %rt.name,
                                                                listen = %listen,
                                                                "SNI runtime add: no reload trigger for group — internal inconsistency"
                                                            );
                                                            break 'tcp_add false;
                                                        }
                                                    };
                                                    if let Err(e) = trigger.add_sni_entry(
                                                        rt.name.clone(),
                                                        sni_value.clone(),
                                                        tls_cfg.clone(),
                                                    ) {
                                                        error!(
                                                            tenant = %rt.name,
                                                            listen = %listen,
                                                            "SNI runtime add: cert mutation failed: {e:#}"
                                                        );
                                                        break 'tcp_add false;
                                                    }
                                                    // Both succeeded — swap dispatch.
                                                    // From here, new TLS handshakes for
                                                    // this SNI complete + dispatch.
                                                    let _old = dispatch.swap(new_dispatch);
                                                    drop(triggers_guard);
                                                    info!(
                                                        tenant = %rt.name,
                                                        listen = %listen,
                                                        sni = %sni_value,
                                                        "SNI tenant added at runtime — joining existing group"
                                                    );
                                                    break 'tcp_add true;
                                                }
                                                    // Sprint 20: build the TLS acceptor for
                                                    // this tenant if it has a [tls] block,
                                                    // and register the trigger by tenant
                                                    // name so SIGUSR1 reaches it and SIGHUP
                                                    // REMOVE can purge it.
                                                    let tls_build: Option<Option<TlsAcceptorHandle>> =
                                                        if let Some(tls_cfg) = cfg_for_tenant.tls.as_ref() {
                                                            match build_reloadable_acceptor(
                                                                tls_cfg,
                                                                rt.name.clone(),
                                                            ) {
                                                                Ok((handle, trigger)) => {
                                                                    reload_triggers
                                                                        .write()
                                                                        .await
                                                                        .insert(
                                                                            rt.name.clone(),
                                                                            trigger,
                                                                        );
                                                                    info!(
                                                                        tenant = %rt.name,
                                                                        "TLS termination + hot-reload enabled (runtime add)"
                                                                    );
                                                                    Some(Some(handle))
                                                                }
                                                                Err(e) => {
                                                                    error!(
                                                                        tenant = %rt.name,
                                                                        "TLS acceptor build failed: {e:#}"
                                                                    );
                                                                    None
                                                                }
                                                            }
                                                        } else {
                                                            Some(None)
                                                        };
                                                    let tls_handle = match tls_build {
                                                        Some(handle) => handle,
                                                        None => {
                                                            // TLS build failed — skip spawn,
                                                            // do not register the tenant.
                                                            // No trigger to roll back (insert
                                                            // happened only in Ok branch).
                                                            break 'tcp_add false;
                                                        }
                                                    };
                                                    match new_cfg.resolve_one_serve_tcp(cfg_for_tenant) {
                                                        Ok(resolved) => {
                                                            let identity_c = identity.clone();
                                                            let peer_policy_c = rt.peer_policy.clone();
                                                            let audit_handle = rt.audit.handle();
                                                            let metrics_c = rt.metrics.clone();
                                                            let admission_c = rt.admission.clone();
                                                            // Sprint 18: per-tenant shutdown.
                                                            let shutdown_c = rt.shutdown.clone();
                                                            let tenant_name = rt.name.clone();
                                                            let handle = tokio::spawn(async move {
                                                                let res = run_serve_tcp_tenant(
                                                                    resolved,
                                                                    identity_c,
                                                                    peer_policy_c,
                                                                    audit_handle,
                                                                    metrics_c,
                                                                    shutdown_c,
                                                                    tls_handle,
                                                                    Some(admission_c),
                                                                ).await;
                                                                if let Err(ref e) = res {
                                                                    error!("runtime-added serve-tcp tenant exited: {e:#}");
                                                                }
                                                                res
                                                            });
                                                            tenant_tasks_map
                                                                .write()
                                                                .await
                                                                .insert(tenant_name, handle);
                                                            true
                                                        }
                                                        Err(e) => {
                                                            error!(
                                                                tenant = %rt.name,
                                                                "tenant resolve failed: {e}"
                                                            );
                                                            // Sprint 20: purge the trigger we
                                                            // just inserted — resolve failed
                                                            // so no accept loop will use it.
                                                            reload_triggers
                                                                .write()
                                                                .await
                                                                .remove(&rt.name);
                                                            false
                                                        }
                                                    }
                                            }
                                        };

                                        if spawned {
                                            info!(
                                                tenant = %rt.name,
                                                role = ?new_cfg.role,
                                                "tenant ADDED at runtime — serving traffic"
                                            );
                                        } else {
                                            info!(
                                                tenant = %rt.name,
                                                role = ?new_cfg.role,
                                                "tenant registered (metrics + name set); accept loop pending Sprint 13 (serve-tcp / SNI runtime add)"
                                            );
                                        }
                                        // Keep the runtime alive: the tenant
                                        // task holds the AuditChannel via the
                                        // handle clone, but rt itself drops
                                        // here. The audit channel is kept
                                        // alive by the registered handle and
                                        // by the channel's own background
                                        // task — Drop on rt is a no-op.
                                        let _ = rt;
                                        applied += 1;
                                        // Sprint 17: count this as a
                                        // successful runtime add.
                                        daemon_metrics
                                            .tenants_added_total
                                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    }
                                    Err(e) => {
                                        error!(
                                            tenant = %added_name,
                                            "tenant ADD failed: {e:#}"
                                        );
                                        failed += 1;
                                        daemon_metrics
                                            .tenants_add_failed_total
                                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    }
                                }
                            }
                            // Sprint 18: tenant removal via SIGHUP.
                            // For each tenant in the `removed` set:
                            //  1. Look up its per-tenant shutdown notify
                            //     and signal it.
                            //  2. Look up its JoinHandle and await it
                            //     with a fixed 30s drain timeout.
                            //  3. On success: purge entries from
                            //     tenant_names, tenant_metrics, tenant_configs,
                            //     tenant_admissions, tenant_shutdowns,
                            //     tenant_tasks_map. Bump `tenants_removed_total`.
                            //  4. On timeout: leave entries in maps to
                            //     avoid double-drain races on next SIGHUP.
                            //     Bump `tenants_remove_failed_total`. Log
                            //     the timeout — operator can take manual
                            //     action.
                            //  5. SNI-group and TLS-single tenants are
                            //     NOT in tenant_tasks_map (they're in
                            //     the Vec); REMOVE logs a warn and skips
                            //     them. They still require daemon restart.
                            let mut removed_applied = 0usize;
                            let mut removed_failed = 0usize;
                            for name in &removed {
                                let name = (*name).clone();
                                // Sprint 23: detect SNI tenant removal first.
                                // Walk SNI dispatch entries; if the named
                                // tenant is in one of the groups, do an
                                // in-place SNI REMOVE (dispatch swap +
                                // cert mutation) without triggering the
                                // per-tenant shutdown path. SNI tenants
                                // don't have entries in tenant_shutdowns
                                // (the group's accept loop is daemon-wide
                                // shutdown).
                                //
                                // In-flight sessions of the SNI-removed
                                // tenant continue under the OLD context
                                // until natural end — documented in Sprint
                                // 22 §13.30.3. Hard drain via per-SNI-
                                // tenant Notify is Sprint 24+.
                                let sni_target: Option<(String, Arc<qgateway_core::HotSniDispatchTable>)> = {
                                    let dispatches = sni_dispatches.read().await;
                                    let mut found = None;
                                    for (listen, dispatch) in dispatches.iter() {
                                        if dispatch.load().tenant_names()
                                            .iter()
                                            .any(|n| n == &name)
                                        {
                                            found = Some((listen.clone(), dispatch.clone()));
                                            break;
                                        }
                                    }
                                    found
                                };
                                if let Some((listen, dispatch)) = sni_target {
                                    // Compute successor dispatch via Sprint 21 builder.
                                    let new_dispatch = match dispatch.load().with_tenant_removed(&name) {
                                        Some(d) => d,
                                        None => {
                                            // Race: tenant was in the table at the
                                            // lookup above but gone now. Treat as
                                            // already-removed; no failure counter bump.
                                            warn!(tenant = %name, listen = %listen,
                                                  "SNI runtime remove: tenant already absent from dispatch table");
                                            continue;
                                        }
                                    };
                                    // Mutate cert set + swap dispatch under the
                                    // triggers read lock for SIGUSR1 consistency.
                                    let trigger_key = format!("sni-group:{listen}");
                                    let triggers_guard = reload_triggers.read().await;
                                    let trigger = match triggers_guard.get(&trigger_key) {
                                        Some(t) => t,
                                        None => {
                                            error!(tenant = %name, listen = %listen,
                                                   "SNI runtime remove: no reload trigger for group — internal inconsistency");
                                            removed_failed += 1;
                                            daemon_metrics
                                                .tenants_remove_failed_total
                                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                            continue;
                                        }
                                    };
                                    if let Err(e) = trigger.remove_sni_entry(&name) {
                                        error!(tenant = %name, listen = %listen,
                                               "SNI runtime remove: cert mutation failed: {e:#}");
                                        removed_failed += 1;
                                        daemon_metrics
                                            .tenants_remove_failed_total
                                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                        continue;
                                    }
                                    let _old = dispatch.swap(new_dispatch);
                                    drop(triggers_guard);
                                    // Purge from common shared maps too — the
                                    // tenant_state entry exists (build_tenant_runtime
                                    // ran at startup) and so does the metrics entry.
                                    // The audit channel, however, was cloned into
                                    // the SniTenantContext at startup; in-flight
                                    // sessions hold AuditHandle references through
                                    // the old context. Purging here releases the
                                    // daemon-held Arc, but the channel's writer
                                    // task stays alive until all session-side
                                    // AuditHandle clones are dropped. This is
                                    // acceptable — graceful drain happens naturally
                                    // as sessions end.
                                    tenant_names.write().await.remove(&name);
                                    tenant_admissions.write().await.remove(&name);
                                    let audit_opt = tenant_audits.write().await.remove(&name);
                                    if let Some(audit) = audit_opt {
                                        audit.shutdown_async().await;
                                    }
                                    // Sprint 27: purge rotation target.
                                    rotation_targets.write().await.remove(&name);
                                    // Sprint 28: stop the auto-rotation monitor
                                    // for this SNI tenant if one was spawned.
                                    // SNI tenants don't have entries in
                                    // tenant_shutdowns (their accept loop uses
                                    // the per-SNI-group Notify, not per-tenant)
                                    // — so the monitor's `rt.shutdown` was
                                    // never going to be signalled by the
                                    // SIGTERM/SIGINT fanout. We dropped the
                                    // monitor's per-tenant Notify Arc when
                                    // tenant_state was constructed; we can't
                                    // reach it from here. The pragmatic fix:
                                    // abort the JoinHandle. The monitor's
                                    // poll loop is idle 99% of the time
                                    // (sleeping on poll_interval), so abort
                                    // is safe — no in-flight write to corrupt.
                                    let monitor_opt =
                                        monitor_handles.write().await.remove(&name);
                                    if let Some(h) = monitor_opt {
                                        h.abort();
                                        let _ = h.await;
                                    }
                                    {
                                        let mut configs = tenant_configs.write().await;
                                        configs.retain(|c| c.name != name);
                                    }
                                    {
                                        let mut metrics = metrics_list.write().await;
                                        metrics.retain(|m| m.tenant() != name);
                                    }
                                    info!(tenant = %name, listen = %listen,
                                          "SNI tenant removed at runtime (in-flight sessions continue under old context until natural end)");
                                    removed_applied += 1;
                                    daemon_metrics
                                        .tenants_removed_total
                                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    // Sprint 24: detect last-tenant-leaves-group.
                                    // If the post-remove dispatch table has zero
                                    // tenants, drain the group: signal the per-
                                    // group Notify, await the JoinHandle, purge
                                    // the group's entries from every shared map.
                                    // The reload trigger entry (synthetic
                                    // "sni-group:<listen>" key) is purged too;
                                    // SIGUSR1 will no longer try to reload its
                                    // certs. The TCP listener bound by
                                    // run_sni_group is released on task exit,
                                    // freeing the port for a future first-tenant-
                                    // in-new-group ADD on the same listen.
                                    let is_empty = dispatch.load().tenant_names().is_empty();
                                    if is_empty {
                                        info!(listen = %listen,
                                              "SNI group empty after remove — draining");
                                        let group_notify_opt = sni_group_shutdowns
                                            .read()
                                            .await
                                            .get(&listen)
                                            .cloned();
                                        if let Some(group_notify) = group_notify_opt {
                                            group_notify.notify_waiters();
                                        }
                                        let task_opt = sni_group_tasks
                                            .write()
                                            .await
                                            .remove(&listen);
                                        if let Some(task) = task_opt {
                                            let drain_result = tokio::time::timeout(
                                                std::time::Duration::from_secs(drain_timeout_secs),
                                                task,
                                            )
                                            .await;
                                            match drain_result {
                                                Ok(Ok(Ok(()))) => {
                                                    info!(listen = %listen,
                                                          "SNI group drained cleanly");
                                                }
                                                Ok(Ok(Err(e))) => {
                                                    warn!(listen = %listen,
                                                          "SNI group exited with error: {e:#}");
                                                }
                                                Ok(Err(join_err)) => {
                                                    warn!(listen = %listen,
                                                          "SNI group task join failed: {join_err}");
                                                }
                                                Err(_) => {
                                                    warn!(listen = %listen,
                                                          timeout_secs = drain_timeout_secs,
                                                          "SNI group drain timed out — listener may still hold the port");
                                                }
                                            }
                                        }
                                        // Purge group from all shared maps.
                                        sni_group_shutdowns.write().await.remove(&listen);
                                        sni_dispatches.write().await.remove(&listen);
                                        let trigger_key_drain = format!("sni-group:{listen}");
                                        reload_triggers
                                            .write()
                                            .await
                                            .remove(&trigger_key_drain);
                                        info!(listen = %listen,
                                              "SNI group purged from shared state");
                                    }
                                    continue;
                                }
                                // Step 1: signal shutdown.
                                let notify_opt = tenant_shutdowns
                                    .read()
                                    .await
                                    .get(&name)
                                    .cloned();
                                let Some(tenant_notify) = notify_opt else {
                                    warn!(tenant = %name,
                                          "tenant running but not individually removable (SNI group with no matching dispatch entry, or unknown tenant kind) — restart required");
                                    continue;
                                };
                                tenant_notify.notify_waiters();
                                // Step 2: await JoinHandle with timeout.
                                // Take ownership of the handle out of the map.
                                let handle_opt = tenant_tasks_map
                                    .write()
                                    .await
                                    .remove(&name);
                                let Some(handle) = handle_opt else {
                                    // Notify map said yes, tasks map said no —
                                    // race or inconsistent registration. Log
                                    // and skip (do not bump failed counter;
                                    // this is an internal-state issue, not a
                                    // drain timeout).
                                    warn!(tenant = %name,
                                          "tenant has shutdown notify but no JoinHandle in tasks_map — internal inconsistency, skipping removal");
                                    continue;
                                };
                                match tokio::time::timeout(
                                    std::time::Duration::from_secs(drain_timeout_secs),
                                    handle,
                                )
                                .await
                                {
                                    Ok(join_res) => {
                                        if let Err(e) = join_res {
                                            warn!(tenant = %name,
                                                  "tenant task panicked or was cancelled during drain: {e}");
                                        }
                                        // Step 3: purge from all shared maps.
                                        tenant_names.write().await.remove(&name);
                                        tenant_shutdowns.write().await.remove(&name);
                                        tenant_admissions.write().await.remove(&name);
                                        // Sprint 19: drain the audit
                                        // channel BEFORE purging it
                                        // from the shared map. The
                                        // accept loop has already
                                        // exited (we awaited the
                                        // JoinHandle above), so no
                                        // more events will arrive.
                                        // Calling shutdown_async()
                                        // signals the writer task to
                                        // flush its buffer and exit,
                                        // and awaits the task's
                                        // completion. Upper bound on
                                        // duration: batch flush time
                                        // (~ms).
                                        let audit_opt = tenant_audits
                                            .write()
                                            .await
                                            .remove(&name);
                                        if let Some(audit) = audit_opt {
                                            audit.shutdown_async().await;
                                        }
                                        // Sprint 20: purge TLS reload
                                        // trigger if this tenant was
                                        // TLS-enabled. No-op for plain
                                        // TCP tenants (no entry in map).
                                        // SNI group triggers use the
                                        // synthetic "sni-group:<listen>"
                                        // key; this code never targets
                                        // those because SNI tenants
                                        // aren't in tenant_shutdowns.
                                        let trigger_removed = reload_triggers
                                            .write()
                                            .await
                                            .remove(&name)
                                            .is_some();
                                        if trigger_removed {
                                            info!(tenant = %name,
                                                  "TLS reload trigger purged");
                                        }
                                        // Sprint 27: purge rotation target.
                                        rotation_targets.write().await.remove(&name);
                                        // Sprint 28: take the auto-rotation
                                        // monitor handle (if any). The per-
                                        // tenant shutdown Notify was already
                                        // signalled by the REMOVE branch
                                        // above (Sprint 18 plumbing); the
                                        // monitor's `tokio::select!` will
                                        // observe it and return on the next
                                        // poll boundary. Await briefly with
                                        // a 2s timeout — the monitor's loop
                                        // body is fast (just a stat() call),
                                        // so 2s is generous.
                                        let monitor_opt =
                                            monitor_handles.write().await.remove(&name);
                                        if let Some(h) = monitor_opt {
                                            let drain = tokio::time::timeout(
                                                std::time::Duration::from_secs(2),
                                                h,
                                            )
                                            .await;
                                            if drain.is_err() {
                                                warn!(tenant = %name,
                                                      "auto-rotation monitor did not drain in 2s after REMOVE");
                                            }
                                        }
                                        {
                                            let mut configs = tenant_configs.write().await;
                                            configs.retain(|c| c.name != name);
                                        }
                                        {
                                            let mut metrics = metrics_list.write().await;
                                            metrics.retain(|m| m.tenant() != name);
                                        }
                                        info!(tenant = %name,
                                              "tenant drained and removed (audit channel flushed)");
                                        removed_applied += 1;
                                        daemon_metrics
                                            .tenants_removed_total
                                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    }
                                    Err(_) => {
                                        // Timeout. Re-insert the handle so a
                                        // subsequent SIGHUP can retry (or
                                        // SIGTERM final drain handles it).
                                        // We do NOT re-insert because the
                                        // handle is consumed by tokio::time::timeout.
                                        // The accept loop has already been
                                        // notified; it should exit eventually.
                                        // Re-inserting requires owning the
                                        // handle, which we don't. Honest
                                        // trade-off: timeout leaves the
                                        // tenant in a "drained but not
                                        // cleaned up" state until daemon
                                        // restart. Bump failure counter so
                                        // operators see the issue.
                                        error!(tenant = %name,
                                               "tenant drain timed out after 30s — entry left in shared maps, restart required for full cleanup");
                                        removed_failed += 1;
                                        daemon_metrics
                                            .tenants_remove_failed_total
                                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    }
                                }
                            }
                            if !added.is_empty() || !removed.is_empty() || failed > 0 {
                                info!(
                                    added_applied = applied,
                                    added_failed = failed,
                                    removed_applied = removed_applied,
                                    removed_failed = removed_failed,
                                    "config reload apply summary"
                                );
                            } else {
                                info!("no tenant diff — config consistent with running set");
                            }
                        }
                        Err(e) => {
                            daemon_metrics
                                .sighup_failed_total
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            error!("SIGHUP config reload FAILED validation: {e:#}");
                            error!("daemon continues with previously-loaded config; \
                                    fix the TOML and re-send SIGHUP");
                        }
                    }
                }
            }
        }
    })
}

#[cfg(unix)]
struct RotationTarget {
    tenant_name: String,
    channel: qgateway_core::RotationHandle,
    log_path: PathBuf,
    counter: Arc<std::sync::atomic::AtomicU64>,
    policy: Option<qgateway_core::RotationPolicy>,
}

#[cfg(not(unix))]
fn install_signal_handler(
    notify: Arc<Notify>,
    _reload_triggers: Arc<tokio::sync::RwLock<std::collections::HashMap<String, TlsReloadTrigger>>>,
    _config_path: PathBuf,
    _tenant_names: Arc<tokio::sync::RwLock<std::collections::HashSet<String>>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        notify.notify_waiters();
    })
}

#[allow(dead_code)]
fn _retain_for_future_use(p: &Path) -> Result<PublicKey> {
    open_pk(p)
}

#[cfg(test)]
mod security_tests {
    use super::*;

    #[test]
    fn tls_key_validation_rejects_malformed_pem_body() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.pem");
        std::fs::write(
            &path,
            concat!(
                "-----BEGIN ",
                "PRIVATE KEY-----\n!!!not-base64!!!\n-----END PRIVATE KEY-----\n"
            ),
        )
        .unwrap();
        assert!(validate_tls_key(&path).is_err());
    }

    #[test]
    fn transport_key_generation_does_not_replace_existing_key() {
        let dir = tempfile::tempdir().unwrap();
        let sk = dir.path().join("identity.skid");
        let pk = dir.path().join("identity.cspqid.pub");
        cmd_keygen(&sk, &pk).unwrap();
        let original_sk = std::fs::read(&sk).unwrap();
        let original_pk = std::fs::read(&pk).unwrap();
        assert!(cmd_keygen(&sk, &pk).is_err());
        assert_eq!(std::fs::read(&sk).unwrap(), original_sk);
        assert_eq!(std::fs::read(&pk).unwrap(), original_pk);
        load_transport_identity(&sk, &pk).unwrap();
    }

    #[test]
    fn transport_identity_rejects_mismatched_keypair() {
        let dir = tempfile::tempdir().unwrap();
        let sk_a = dir.path().join("a.skid");
        let pk_a = dir.path().join("a.pub");
        let sk_b = dir.path().join("b.skid");
        let pk_b = dir.path().join("b.pub");
        cmd_keygen(&sk_a, &pk_a).unwrap();
        cmd_keygen(&sk_b, &pk_b).unwrap();
        assert!(load_transport_identity(&sk_a, &pk_b).is_err());
    }
}
