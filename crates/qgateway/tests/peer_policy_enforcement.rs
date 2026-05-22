//! Sprint 31 — peer-policy enforcement: untrusted identity is rejected
//! at handshake; no `session.open` entry appears in the audit chain.
//!
//! Sprint 30 proved that a TRUSTED CSPQ peer's session events land in
//! the audit chain. Sprint 31 proves the negative: a peer dialing with
//! an identity NOT in the tenant's `peer_pub_dir` is rejected at the
//! CSPQ handshake, the daemon increments `qgateway_sessions_failed_total`,
//! and crucially the audit chain remains EMPTY of `session.open` /
//! `session.close` entries for that connection.
//!
//! This is the test compliance auditors will demand: prove that the
//! allow-listed peer-key check actually denies untrusted callers. Lib
//! tests in qtransport-cspq cover the `PeerPolicy::accepts` logic in
//! isolation; this test proves the policy is wired in to the live
//! daemon's accept loop.
//!
//! Architecture:
//!
//!   ┌────────────┐  CSPQ over TCP   ┌──────────────┐  plain TCP   ┌─────────┐
//!   │ test       │ ──────────────→  │ qgateway     │ ──────────→  │ echo    │
//!   │ (untrusted │ ←──── REJECT     │ (serve-pq)   │              │ server  │
//!   │  identity) │                  └──────────────┘              └─────────┘
//!         │
//!         │ uses a freshly-generated identity that
//!         │ is NOT in the daemon's peer_pub_dir
//!
//! Expected outcomes:
//!   - `qtransport_cspq::connect` returns Err on the client side.
//!   - The daemon's `qgateway_sessions_failed_total` counter increments.
//!   - The audit log file parses + verifies (chain integrity preserved).
//!   - The audit log file contains NO `session.open` / `session.close`
//!     entries for the rejected attempt.
//!
//! Then a sanity sub-case: a TRUSTED identity (the daemon's own,
//! mirrored from Sprint 30) succeeds, and `session.open` + `session.close`
//! events DO appear. This proves the test would have failed loudly if
//! the daemon were accidentally accepting all peers.

mod common;

use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use common::*;
use qaudit_core::{AuditLog, KeyPair, SecretKey};
use qtransport_cspq::{IdentityKey, PeerPolicy};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const SK_FILE_MAGIC: &[u8; 8] = b"CSPQSK01";

/// Load a transport identity from its on-disk skid + pub files. Same
/// loader as Sprint 30 (duplicated because not re-exported from the
/// binary; one-time cost, six lines).
fn load_transport_identity(sk_path: &Path, pk_path: &Path) -> IdentityKey {
    let blob = std::fs::read(sk_path).expect("read sk");
    assert!(blob.len() >= 8 + qaudit_core::signing::SECRET_KEY_LEN);
    assert_eq!(&blob[..8], SK_FILE_MAGIC, "sk magic");
    let sk_bytes = &blob[8..8 + qaudit_core::signing::SECRET_KEY_LEN];
    let sk = SecretKey::from_bytes(sk_bytes).expect("decode sk");
    let pk = IdentityKey::load_public(pk_path).expect("load pk");
    IdentityKey::new(KeyPair::from_parts(pk, sk))
}

/// Generate a fresh CSPQ identity using the daemon's own `keygen`
/// subcommand. Returns the loaded identity. The new identity is NOT
/// copied into any `peer_pub_dir`, so the daemon will reject it.
fn generate_untrusted_identity(tmp_root: &Path, label: &str) -> IdentityKey {
    let sk_path = tmp_root.join(format!("{label}.skid"));
    let pk_path = tmp_root.join(format!("{label}.cspqid.pub"));
    let out = Command::new(qgateway_bin())
        .args([
            "keygen",
            "--sk",
            sk_path.to_str().unwrap(),
            "--pk",
            pk_path.to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn keygen");
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        panic!("untrusted keygen failed: {stderr}");
    }
    load_transport_identity(&sk_path, &pk_path)
}

async fn spawn_echo_server() -> (std::net::SocketAddr, Arc<tokio::sync::Notify>) {
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
                        let mut buf = [0u8; 4096];
                        loop {
                            match sock.read(&mut buf).await {
                                Ok(0) => return,
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

/// Attempt one CSPQ session with the given identity. Returns Ok on
/// successful handshake + data round-trip; Err on any failure
/// (including handshake rejection — which is the expected outcome
/// for the untrusted-identity sub-case).
async fn attempt_session(
    dial_addr: std::net::SocketAddr,
    identity: Arc<IdentityKey>,
    peer_policy: Arc<PeerPolicy>,
    payload: &[u8],
) -> std::io::Result<Vec<u8>> {
    let tcp = TcpStream::connect(dial_addr).await?;
    let _ = tcp.set_nodelay(true);
    let mut cspq = qtransport_cspq::connect(tcp, &identity, &peer_policy)
        .await
        .map_err(|e| std::io::Error::other(format!("cspq connect: {e}")))?;
    cspq.write_all(payload).await?;
    cspq.flush().await?;
    let mut out = vec![0u8; payload.len()];
    cspq.read_exact(&mut out).await?;
    cspq.shutdown().await?;
    Ok(out)
}

#[test]
fn untrusted_peer_is_rejected_and_emits_no_audit_event() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("test rt");

    let fx = Fixture::build(&["alice"]);
    let (echo_addr, _echo_shutdown) = rt.block_on(spawn_echo_server());
    fx.write_config_with_backend(&[("alice", fx.tenant_ports[0])], echo_addr);

    let daemon = DaemonGuard::spawn(&fx.config_path);
    assert!(
        wait_for_metrics(fx.metrics_port, Duration::from_secs(15)),
        "daemon /metrics did not come up within 15s"
    );

    // Generate a FRESH identity that the daemon does NOT trust. The
    // fixture's peer_pub_dir contains only `self.cspqid.pub` (a copy
    // of the daemon's own identity, used by Sprint 30's trusted-peer
    // test). This new identity's pubkey is nowhere in that dir.
    let untrusted = Arc::new(generate_untrusted_identity(&fx.root, "attacker"));

    // From the client side we still need a peer policy that admits
    // the daemon — but the daemon's policy is what rejects us.
    let daemon_pubkey =
        IdentityKey::load_public(fx.root.join("daemon.cspqid.pub")).expect("load daemon pub");
    let client_side_policy = Arc::new(PeerPolicy::single(daemon_pubkey));

    let dial_addr: std::net::SocketAddr =
        format!("127.0.0.1:{}", fx.tenant_ports[0]).parse().unwrap();

    // Baseline counters. The session counters are emitted per-tenant
    // with a `{tenant="alice"}` label, so use the labelled helper.
    let baseline = scrape_metrics(fx.metrics_port).expect("baseline /metrics");
    let failed_before =
        tenant_counter_value(&baseline, "qgateway_sessions_failed_total", Some("alice"));
    let opened_before =
        tenant_counter_value(&baseline, "qgateway_sessions_opened_total", Some("alice"));

    // Attempt the untrusted handshake. MUST fail.
    let result = rt.block_on(attempt_session(
        dial_addr,
        untrusted.clone(),
        client_side_policy.clone(),
        b"this payload should never reach the backend",
    ));
    assert!(
        result.is_err(),
        "untrusted peer's handshake succeeded — peer-policy enforcement BROKEN. got: {result:?}"
    );

    // Give the daemon a moment to commit the failure counter.
    std::thread::sleep(Duration::from_millis(500));

    let after = scrape_metrics(fx.metrics_port).expect("post-reject /metrics");
    let failed_after =
        tenant_counter_value(&after, "qgateway_sessions_failed_total", Some("alice"));
    let opened_after =
        tenant_counter_value(&after, "qgateway_sessions_opened_total", Some("alice"));

    assert!(
        failed_after > failed_before,
        "sessions_failed_total did not increment after untrusted reject: before={failed_before} after={failed_after}"
    );
    assert_eq!(
        opened_after, opened_before,
        "sessions_opened_total moved on a REJECTED handshake — daemon emitted session.open for an untrusted peer. before={opened_before} after={opened_after}"
    );

    // Shut down cleanly so the audit channel flushes whatever it has
    // (which should be: nothing — header only).
    daemon.shutdown_gracefully();
    std::thread::sleep(Duration::from_millis(500));

    // Audit log must parse + verify (chain integrity preserved).
    let alice_log = AuditLog::open(fx.audit_log_for("alice")).expect("alice audit log parse");
    alice_log.verify().expect("alice audit chain verify");

    // And it must contain ZERO session.open / session.close entries
    // — the rejected handshake never emitted one.
    let entries = alice_log.entries();
    let session_events: Vec<_> = entries
        .iter()
        .filter(|e| e.event.action == "session.open" || e.event.action == "session.close")
        .collect();
    assert!(
        session_events.is_empty(),
        "audit chain contains {} session events from a rejected handshake: {:?}",
        session_events.len(),
        session_events
            .iter()
            .map(|e| e.event.action.clone())
            .collect::<Vec<_>>()
    );
}

#[test]
fn trusted_peer_succeeds_after_untrusted_attempt() {
    // Sanity case: prove the test infrastructure WOULD have caught a
    // false-positive. After an untrusted reject, a trusted peer's
    // handshake must still succeed and emit a session.open + close.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("test rt");

    let fx = Fixture::build(&["alice"]);
    let (echo_addr, _echo_shutdown) = rt.block_on(spawn_echo_server());
    fx.write_config_with_backend(&[("alice", fx.tenant_ports[0])], echo_addr);

    let daemon = DaemonGuard::spawn(&fx.config_path);
    assert!(
        wait_for_metrics(fx.metrics_port, Duration::from_secs(15)),
        "daemon /metrics did not come up within 15s"
    );

    let untrusted = Arc::new(generate_untrusted_identity(&fx.root, "attacker"));
    let trusted = Arc::new(load_transport_identity(
        &fx.root.join("daemon.skid"),
        &fx.root.join("daemon.cspqid.pub"),
    ));
    let policy = Arc::new(PeerPolicy::single(trusted.public().clone()));

    let dial_addr: std::net::SocketAddr =
        format!("127.0.0.1:{}", fx.tenant_ports[0]).parse().unwrap();

    // First: untrusted is rejected.
    let bad = rt.block_on(attempt_session(
        dial_addr,
        untrusted,
        policy.clone(),
        b"reject me",
    ));
    assert!(bad.is_err(), "untrusted dial should have been rejected");

    // Then: trusted succeeds.
    let payload = b"trusted session after rejected one\n";
    let echoed = rt
        .block_on(attempt_session(dial_addr, trusted, policy, payload))
        .expect("trusted dial must succeed");
    assert_eq!(echoed, payload, "trusted echo round-trip mismatch");

    std::thread::sleep(Duration::from_millis(500));
    daemon.shutdown_gracefully();
    std::thread::sleep(Duration::from_millis(500));

    let log = AuditLog::open(fx.audit_log_for("alice")).expect("audit parse");
    log.verify().expect("audit verify");

    // The trusted session must have emitted exactly one session.open
    // + one session.close. The untrusted attempt emitted neither.
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
        opens, 1,
        "expected exactly 1 session.open from the trusted dial; got {opens}"
    );
    assert_eq!(
        closes, 1,
        "expected exactly 1 session.close from the trusted dial; got {closes}"
    );
}
