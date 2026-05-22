//! Sprint 34 — admission controller end-to-end integration test.
//!
//! Closes the long carry-over from Sprint 9.5. The admission controller
//! has comprehensive lib tests in `qgateway-core::admission` (the
//! semaphore-permit + token-bucket logic in isolation), but no test
//! currently exercises it inside the live daemon — proving that the
//! ACCEPT LOOP actually rejects connections when limits are reached,
//! the right Prometheus counter labels increment, slots release
//! correctly when sessions end, and no audit event leaks from a
//! rejected admission.
//!
//! Three scenarios:
//!
//! 1. **`max_concurrent=2`**: hold 2 sessions in flight, attempt a 3rd
//!    → 3rd dial gets TCP RST from the daemon (admission rejected at
//!    accept loop, before CSPQ handshake). `admission_rejected_quota_total`
//!    increments. Audit chain has no entry for the rejected attempt.
//!
//! 2. **Slot release on session close**: close one of the 2 in-flight
//!    sessions → next dial succeeds. Permit released.
//!
//! 3. **`rate_limit_per_source=1/sec` burst**: capacity=1, refill=1/sec.
//!    Two rapid back-to-back dials from the same IP — second one
//!    rejected with `reason="rate"`.
//!
//! Sprint 34 also adds the test fixture for `[tenants.limits]` configs.

mod common;

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use common::{
    pick_port, qgateway_bin, run_subcmd, scrape_metrics, tenant_counter_value, wait_for_metrics,
};
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use qaudit_core::{AuditLog, KeyPair, SecretKey};
use qtransport_cspq::{IdentityKey, PeerPolicy};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const SK_FILE_MAGIC: &[u8; 8] = b"CSPQSK01";

/// Sprint 34 fixture with `[tenants.limits]` support. Kept inline
/// (not promoted to `common/mod.rs`) because the limits surface is
/// specific to this sprint; if a future test needs it, promote.
struct AdmissionFixture {
    config_path: PathBuf,
    metrics_port: u16,
    tenant_ports: Vec<u16>,
    root: PathBuf,
    _tmp: tempfile::TempDir,
}

struct LimitsSpec {
    max_concurrent: Option<u32>,
    rate_capacity: Option<u32>,
    rate_refill_per_sec: Option<u32>,
}

impl AdmissionFixture {
    fn build(tenants: &[&str], limits: &LimitsSpec, backend: std::net::SocketAddr) -> Self {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let root = tmp.path().to_path_buf();

        let id_sk = root.join("daemon.skid");
        let id_pk = root.join("daemon.cspqid.pub");
        run_subcmd(&[
            "keygen",
            "--sk",
            id_sk.to_str().unwrap(),
            "--pk",
            id_pk.to_str().unwrap(),
        ]);
        let audit_sk = root.join("audit.skid");
        let audit_pk = root.join("audit.pub");
        run_subcmd(&[
            "audit-keygen",
            "--sk",
            audit_sk.to_str().unwrap(),
            "--pk",
            audit_pk.to_str().unwrap(),
        ]);
        let peer_dir = root.join("peers");
        std::fs::create_dir_all(&peer_dir).unwrap();
        std::fs::copy(&id_pk, peer_dir.join("self.cspqid.pub")).unwrap();

        let metrics_port = pick_port();
        let tenant_ports: Vec<u16> = tenants.iter().map(|_| pick_port()).collect();
        let cfg = make_config(
            &id_sk,
            &id_pk,
            &audit_sk,
            &audit_pk,
            &peer_dir,
            metrics_port,
            tenants
                .iter()
                .zip(&tenant_ports)
                .map(|(n, p)| (*n, *p))
                .collect::<Vec<_>>()
                .as_slice(),
            &root,
            backend,
            limits,
        );
        let config_path = root.join("sidecar.toml");
        std::fs::write(&config_path, cfg).unwrap();

        Self {
            config_path,
            metrics_port,
            tenant_ports,
            root,
            _tmp: tmp,
        }
    }

    fn audit_log_for(&self, name: &str) -> PathBuf {
        self.root.join(format!("{name}.qa"))
    }
}

#[allow(clippy::too_many_arguments)]
fn make_config(
    id_sk: &Path,
    id_pk: &Path,
    audit_sk: &Path,
    audit_pk: &Path,
    peer_dir: &Path,
    metrics_port: u16,
    tenants: &[(&str, u16)],
    audit_root: &Path,
    backend: std::net::SocketAddr,
    limits: &LimitsSpec,
) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "role = \"serve-pq\"\n\
         identity_key = \"{}\"\n\
         identity_pub = \"{}\"\n\
         metrics_listen = \"127.0.0.1:{metrics_port}\"\n\
         tenant_drain_timeout_secs = 5\n\
         \n\
         [audit_signer]\n\
         kind = \"softkey\"\n\
         secret_key = \"{}\"\n\
         public_key = \"{}\"\n\
         \n",
        id_sk.display(),
        id_pk.display(),
        audit_sk.display(),
        audit_pk.display(),
    ));
    for (name, port) in tenants {
        let audit_log = audit_root.join(format!("{name}.qa"));
        s.push_str(&format!(
            "[[tenants]]\n\
             name = \"{name}\"\n\
             listen = \"127.0.0.1:{port}\"\n\
             backend = \"{backend}\"\n\
             peer_pub_dir = \"{}\"\n\
             audit_log = \"{}\"\n",
            peer_dir.display(),
            audit_log.display(),
        ));
        // Emit `[tenants.limits]` sub-table if any limit is set.
        if limits.max_concurrent.is_some() || limits.rate_capacity.is_some() {
            s.push_str("[tenants.limits]\n");
            if let Some(mc) = limits.max_concurrent {
                s.push_str(&format!("max_concurrent = {mc}\n"));
            }
            if let (Some(cap), Some(refill)) = (limits.rate_capacity, limits.rate_refill_per_sec) {
                s.push_str(&format!(
                    "[tenants.limits.rate_limit_per_source]\n\
                     capacity = {cap}\n\
                     refill_per_sec = {refill}\n"
                ));
            }
        }
        s.push('\n');
    }
    s
}

struct DaemonGuard {
    child: Option<Child>,
}
impl DaemonGuard {
    fn spawn(config: &Path) -> Self {
        let child = Command::new(qgateway_bin())
            .arg("run")
            .arg("--config")
            .arg(config)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn");
        Self { child: Some(child) }
    }
    fn shutdown_gracefully(mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = kill(Pid::from_raw(child.id() as i32), Signal::SIGTERM);
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            loop {
                match child.try_wait() {
                    Ok(Some(_)) => return,
                    Ok(None) => {
                        if std::time::Instant::now() >= deadline {
                            let _ = child.kill();
                            let _ = child.wait();
                            return;
                        }
                        std::thread::sleep(Duration::from_millis(100));
                    }
                    Err(_) => {
                        let _ = child.kill();
                        let _ = child.wait();
                        return;
                    }
                }
            }
        }
    }
}
impl Drop for DaemonGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = kill(Pid::from_raw(child.id() as i32), Signal::SIGTERM);
            std::thread::sleep(Duration::from_millis(500));
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn load_transport_identity(sk_path: &Path, pk_path: &Path) -> IdentityKey {
    let blob = std::fs::read(sk_path).expect("read sk");
    assert!(blob.len() >= 8 + qaudit_core::signing::SECRET_KEY_LEN);
    assert_eq!(&blob[..8], SK_FILE_MAGIC, "sk magic");
    let sk_bytes = &blob[8..8 + qaudit_core::signing::SECRET_KEY_LEN];
    let sk = SecretKey::from_bytes(sk_bytes).expect("decode sk");
    let pk = IdentityKey::load_public(pk_path).expect("load pk");
    IdentityKey::new(KeyPair::from_parts(pk, sk))
}

/// Echo server that NEVER closes the client side — used to hold
/// sessions in-flight indefinitely. Sprint 34's max_concurrent test
/// needs the 2 admitted sessions to STAY admitted while a 3rd dial
/// is attempted.
async fn spawn_holding_server() -> (std::net::SocketAddr, Arc<tokio::sync::Notify>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
    let addr = listener.local_addr().expect("echo local_addr");
    let shutdown = Arc::new(tokio::sync::Notify::new());
    let shutdown_clone = shutdown.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown_clone.notified() => return,
                accept = listener.accept() => {
                    let Ok((mut sock, _)) = accept else { continue };
                    tokio::spawn(async move {
                        // Echo, but never close on EOF — keep the
                        // backend side of the proxy alive so the
                        // daemon's session-active count stays elevated.
                        let mut buf = [0u8; 4096];
                        loop {
                            match sock.read(&mut buf).await {
                                Ok(0) => {
                                    // Client closed — the daemon will
                                    // tear down its side. We return.
                                    return;
                                }
                                Ok(n) => {
                                    if sock.write_all(&buf[..n]).await.is_err() {
                                        return;
                                    }
                                }
                                Err(_) => return,
                            }
                        }
                    });
                }
            }
        }
    });
    (addr, shutdown)
}

/// Open a session and hold it. Returns the CSPQ stream wrapped in an
/// option so the test can explicitly drop (and thus release the
/// admission permit) at the chosen moment.
async fn open_holding_session(
    dial: std::net::SocketAddr,
    identity: Arc<IdentityKey>,
    policy: Arc<PeerPolicy>,
) -> std::io::Result<qtransport_cspq::CspqStream<TcpStream>> {
    let tcp = TcpStream::connect(dial).await?;
    let _ = tcp.set_nodelay(true);
    let mut cspq = qtransport_cspq::connect(tcp, &identity, &policy)
        .await
        .map_err(|e| std::io::Error::other(format!("cspq connect: {e}")))?;
    // Send a single byte + flush so the proxy is actively forwarding
    // — this ensures the daemon's `sessions_active` counter is up.
    cspq.write_all(b".").await?;
    cspq.flush().await?;
    // Read the echoed byte back to confirm the round-trip works
    // before we hand the stream to the caller for holding.
    let mut sink = [0u8; 1];
    cspq.read_exact(&mut sink).await?;
    Ok(cspq)
}

#[test]
fn max_concurrent_rejects_third_dial_and_emits_no_audit_event() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("test rt");
    let (echo_addr, _echo_shutdown) = rt.block_on(spawn_holding_server());

    let limits = LimitsSpec {
        max_concurrent: Some(2),
        rate_capacity: None,
        rate_refill_per_sec: None,
    };
    let fx = AdmissionFixture::build(&["alice"], &limits, echo_addr);
    let daemon = DaemonGuard::spawn(&fx.config_path);
    assert!(
        wait_for_metrics(fx.metrics_port, Duration::from_secs(15)),
        "daemon /metrics did not come up within 15s"
    );

    let identity = Arc::new(load_transport_identity(
        &fx.root.join("daemon.skid"),
        &fx.root.join("daemon.cspqid.pub"),
    ));
    let policy = Arc::new(PeerPolicy::single(identity.public().clone()));
    let dial_addr: std::net::SocketAddr =
        format!("127.0.0.1:{}", fx.tenant_ports[0]).parse().unwrap();

    let baseline = scrape_metrics(fx.metrics_port).expect("baseline /metrics");
    let quota_before = tenant_counter_value(
        &baseline,
        "qgateway_admission_rejected_quota_total",
        Some("alice"),
    );
    let opened_before =
        tenant_counter_value(&baseline, "qgateway_sessions_opened_total", Some("alice"));

    // Hold 2 sessions in-flight. We KEEP these streams alive across
    // the 3rd-dial attempt so their admission permits stay claimed.
    let s1 = rt
        .block_on(open_holding_session(
            dial_addr,
            identity.clone(),
            policy.clone(),
        ))
        .expect("session 1");
    let s2 = rt
        .block_on(open_holding_session(
            dial_addr,
            identity.clone(),
            policy.clone(),
        ))
        .expect("session 2");

    // Brief settle window so the daemon has finished spawning both
    // session tasks and the permits are observably held.
    std::thread::sleep(Duration::from_millis(300));

    // 3rd dial: must be rejected at the accept loop (TCP RST). The
    // CSPQ handshake never starts. We attempt with a short timeout
    // — if the daemon ACCEPTS the connection then drops, the client
    // sees Err quickly (kernel sends RST). If the daemon hangs
    // (would be a bug), the timeout catches it.
    let third = rt.block_on(async {
        tokio::time::timeout(Duration::from_secs(3), async {
            let tcp = TcpStream::connect(dial_addr).await?;
            let _ = tcp.set_nodelay(true);
            qtransport_cspq::connect(tcp, &identity, &policy)
                .await
                .map_err(|e| std::io::Error::other(format!("cspq connect: {e}")))
        })
        .await
    });
    match third {
        Ok(Ok(_)) => panic!("3rd dial succeeded despite max_concurrent=2"),
        Ok(Err(_)) => {
            // Expected: TCP-level or handshake-level error.
        }
        Err(_) => panic!("3rd dial hung — daemon did not promptly reject"),
    }

    // Brief settle so the daemon commits the rejection counter.
    std::thread::sleep(Duration::from_millis(300));

    let after_reject = scrape_metrics(fx.metrics_port).expect("post-reject /metrics");
    let quota_after = tenant_counter_value(
        &after_reject,
        "qgateway_admission_rejected_quota_total",
        Some("alice"),
    );
    assert!(
        quota_after > quota_before,
        "admission_rejected_quota_total did not increment: before={quota_before} after={quota_after}"
    );

    // Sessions opened counter: must show 2 (the held sessions) — the
    // rejected 3rd attempt must NOT have incremented it.
    let opened_after_reject = tenant_counter_value(
        &after_reject,
        "qgateway_sessions_opened_total",
        Some("alice"),
    );
    assert_eq!(
        opened_after_reject - opened_before,
        2,
        "expected exactly 2 sessions opened (the held ones); got delta {} — rejected dial may have leaked an open",
        opened_after_reject - opened_before
    );

    // Slot release: close one held session, dial again, MUST succeed.
    drop(s1);
    std::thread::sleep(Duration::from_millis(500));
    let s3 = rt
        .block_on(open_holding_session(
            dial_addr,
            identity.clone(),
            policy.clone(),
        ))
        .expect("post-release dial must succeed (slot freed when s1 dropped)");

    std::thread::sleep(Duration::from_millis(300));
    let after_release = scrape_metrics(fx.metrics_port).expect("post-release /metrics");
    let opened_after_release = tenant_counter_value(
        &after_release,
        "qgateway_sessions_opened_total",
        Some("alice"),
    );
    assert_eq!(
        opened_after_release - opened_before,
        3,
        "expected 3 total sessions opened (2 originally + 1 after release); got delta {}",
        opened_after_release - opened_before
    );

    // Cleanup: drop both remaining streams so the daemon's drain is
    // not blocked on stuck sessions.
    drop(s2);
    drop(s3);
    std::thread::sleep(Duration::from_millis(300));

    daemon.shutdown_gracefully();
    std::thread::sleep(Duration::from_millis(500));

    // Audit chain: exactly 3 session.open + 3 session.close entries
    // (from the 3 admitted sessions). The rejected dial contributed
    // zero — compliance-relevant invariant.
    let log = AuditLog::open(fx.audit_log_for("alice")).expect("audit parse");
    log.verify().expect("audit verify");
    let opens = log
        .entries()
        .iter()
        .filter(|e| e.event.action == "session.open")
        .count();
    let closes = log
        .entries()
        .iter()
        .filter(|e| e.event.action == "session.close")
        .count();
    assert_eq!(
        opens, 3,
        "expected 3 session.open (the admitted sessions); got {opens}"
    );
    assert_eq!(closes, 3, "expected 3 session.close; got {closes}");
}

#[test]
fn rate_limit_per_source_rejects_burst_above_capacity() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("test rt");
    let (echo_addr, _echo_shutdown) = rt.block_on(spawn_holding_server());

    // capacity=1, refill=1/sec → second back-to-back dial from the
    // same source IP within 1s is rejected with reason="rate".
    let limits = LimitsSpec {
        max_concurrent: None,
        rate_capacity: Some(1),
        rate_refill_per_sec: Some(1),
    };
    let fx = AdmissionFixture::build(&["alice"], &limits, echo_addr);
    let daemon = DaemonGuard::spawn(&fx.config_path);
    assert!(
        wait_for_metrics(fx.metrics_port, Duration::from_secs(15)),
        "daemon /metrics did not come up within 15s"
    );

    let identity = Arc::new(load_transport_identity(
        &fx.root.join("daemon.skid"),
        &fx.root.join("daemon.cspqid.pub"),
    ));
    let policy = Arc::new(PeerPolicy::single(identity.public().clone()));
    let dial_addr: std::net::SocketAddr =
        format!("127.0.0.1:{}", fx.tenant_ports[0]).parse().unwrap();

    let baseline = scrape_metrics(fx.metrics_port).expect("baseline /metrics");
    let rate_before = tenant_counter_value(
        &baseline,
        "qgateway_admission_rejected_rate_total",
        Some("alice"),
    );

    // First dial: consumes the 1 token in the bucket. Must succeed.
    let s1 = rt
        .block_on(open_holding_session(
            dial_addr,
            identity.clone(),
            policy.clone(),
        ))
        .expect("first dial must succeed (1 token available)");

    // Second dial within <1s of the first: rate limiter rejects.
    let second = rt.block_on(async {
        tokio::time::timeout(Duration::from_secs(2), async {
            let tcp = TcpStream::connect(dial_addr).await?;
            let _ = tcp.set_nodelay(true);
            qtransport_cspq::connect(tcp, &identity, &policy)
                .await
                .map_err(|e| std::io::Error::other(format!("cspq connect: {e}")))
        })
        .await
    });
    match second {
        Ok(Ok(_)) => panic!("second dial succeeded — rate limiter did not enforce"),
        Ok(Err(_)) => {}
        Err(_) => panic!("second dial hung"),
    }

    std::thread::sleep(Duration::from_millis(300));
    let after = scrape_metrics(fx.metrics_port).expect("post-rate /metrics");
    let rate_after = tenant_counter_value(
        &after,
        "qgateway_admission_rejected_rate_total",
        Some("alice"),
    );
    assert!(
        rate_after > rate_before,
        "admission_rejected_rate_total did not increment: before={rate_before} after={rate_after}"
    );

    drop(s1);
    daemon.shutdown_gracefully();
}
