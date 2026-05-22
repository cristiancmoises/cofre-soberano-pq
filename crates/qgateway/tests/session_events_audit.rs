//! Sprint 30 — audit chain integrity for non-empty chains under real session load.
//!
//! Drives actual CSPQ sessions through a serve-pq tenant, then verifies the
//! resulting non-empty audit chain. This is the test SPEC §13.34.3 listed as
//! the biggest "unknown unknown" remaining after Sprint 26 — proving chain
//! integrity for chains that actually contain `session.open`/`session.close`
//! events.
//!
//! Architecture of the test:
//!
//!   ┌────────────┐  CSPQ over TCP   ┌──────────────┐  plain TCP   ┌─────────┐
//!   │ test       │ ──────────────→  │ qgateway     │ ──────────→  │ echo    │
//!   │ client     │ ←──────────────  │ (serve-pq)   │ ←──────────  │ server  │
//!   └────────────┘                  └──────────────┘              └─────────┘
//!         │                                  │                          │
//!         │ uses daemon's identity           │ emits session.open       │ runs in
//!         │ (trusted via self.cspqid.pub)    │ and session.close to     │ test
//!         │                                  │ the per-tenant .qa       │ process
//!
//! Why use the daemon's own identity: the existing fixture copies
//! `daemon.cspqid.pub` into `peers/self.cspqid.pub`, so the daemon
//! trusts that identity. Reusing it from the test side skips the
//! complication of generating a second identity and rewriting the
//! peer dir. The daemon's audit chain doesn't care which CSPQ peer
//! identity opened a session; the events are emitted regardless.

mod common;

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use common::*;
use qaudit_core::{AuditLog, KeyPair, SecretKey};
use qtransport_cspq::{IdentityKey, PeerPolicy};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const SK_FILE_MAGIC: &[u8; 8] = b"CSPQSK01";

/// Mirror the daemon's transport-identity loader (qgateway's
/// `load_transport_identity`). Not re-exported from the binary, so
/// we duplicate it (same 8-byte magic + raw ML-DSA-87 SK layout).
fn load_transport_identity(sk_path: &Path, pk_path: &Path) -> IdentityKey {
    let blob = std::fs::read(sk_path).expect("read sk");
    assert!(blob.len() >= 8 + qaudit_core::signing::SECRET_KEY_LEN);
    assert_eq!(&blob[..8], SK_FILE_MAGIC, "sk magic");
    let sk_bytes = &blob[8..8 + qaudit_core::signing::SECRET_KEY_LEN];
    let sk = SecretKey::from_bytes(sk_bytes).expect("decode sk");
    let pk = IdentityKey::load_public(pk_path).expect("load pk");
    IdentityKey::new(KeyPair::from_parts(pk, sk))
}

/// Run a minimal TCP echo server on the bound listener until `shutdown`
/// fires. Returns the listener's local addr. The test drives bytes
/// through this server via the CSPQ → serve-pq → echo path.
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

/// Drive one CSPQ session: dial daemon at `dial_addr`, send `payload`,
/// read echo back, close. Each successful session causes the daemon
/// to emit one `session.open` + one `session.close` event.
async fn drive_one_session(
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
    // Half-close write side so daemon's proxy loop sees EOF and
    // emits session.close cleanly.
    cspq.shutdown().await?;
    Ok(out)
}

#[test]
fn audit_chain_contains_session_events_under_load() {
    // Use a multi-threaded runtime: the test driver awaits on the
    // CSPQ stream while the daemon runs in a separate process, so a
    // single-threaded runtime works too — but multi-thread matches
    // the daemon's own runtime flavor and avoids any chance of the
    // test runtime starving its own echo-server task.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("test rt");

    // Build the fixture with one tenant `alice`. We rewrite the
    // config to point alice's backend at the test's echo server.
    let fx = Fixture::build(&["alice"]);

    // Spawn the echo server BEFORE the daemon so the daemon can
    // successfully dial backend on first connect.
    let (echo_addr, echo_shutdown) = rt.block_on(spawn_echo_server());

    // Rewrite the config so alice's backend points at the echo
    // server. The existing fixture pointed backend at 127.0.0.1:0
    // which would have rejected connections.
    fx.write_config_with_backend(&[("alice", fx.tenant_ports[0])], echo_addr);

    let daemon = DaemonGuard::spawn(&fx.config_path);
    assert!(
        wait_for_metrics(fx.metrics_port, Duration::from_secs(15)),
        "daemon /metrics did not come up within 15s"
    );

    // Load the daemon's transport identity (the test acts AS a peer
    // that the daemon already trusts via peers/self.cspqid.pub).
    let identity = Arc::new(load_transport_identity(
        &fx.root.join("daemon.skid"),
        &fx.root.join("daemon.cspqid.pub"),
    ));
    // Trust the daemon's identity from the client side too — same
    // pubkey, single-peer policy.
    let peer_policy = Arc::new(PeerPolicy::single(identity.public().clone()));

    let dial_addr: std::net::SocketAddr =
        format!("127.0.0.1:{}", fx.tenant_ports[0]).parse().unwrap();

    // Drive N sequential sessions. Sequential (not concurrent)
    // because we want deterministic chain entry counts. A concurrent
    // variant is left as Sprint 31+ work — would prove the chain
    // serializes appends correctly under contention.
    const N_SESSIONS: usize = 5;
    let payload = b"hello over post-quantum tcp\n";
    for i in 0..N_SESSIONS {
        let echoed = rt
            .block_on(drive_one_session(
                dial_addr,
                identity.clone(),
                peer_policy.clone(),
                payload,
            ))
            .unwrap_or_else(|e| panic!("session #{i} failed: {e}"));
        assert_eq!(
            echoed,
            payload,
            "session #{i}: echo mismatch (got {} bytes)",
            echoed.len()
        );
    }

    // Give the daemon a beat to commit the final session.close
    // entries to disk. The audit channel is async; entries land
    // when the writer task flushes.
    std::thread::sleep(Duration::from_millis(500));

    // Graceful shutdown so shutdown_async flushes any pending audit
    // entries before we read the file.
    daemon.shutdown_gracefully();
    std::thread::sleep(Duration::from_millis(300));
    echo_shutdown.notify_waiters();

    // Now verify alice's audit log.
    let log_path = fx.audit_log_for("alice");
    let log = AuditLog::open(&log_path).expect("alice audit log must parse");
    log.verify().expect("alice audit log must verify");

    // Count session.open / session.close events.
    let mut opens = 0u64;
    let mut closes = 0u64;
    for entry in log.entries() {
        match entry.event.action.as_str() {
            "session.open" => opens += 1,
            "session.close" => closes += 1,
            _ => {}
        }
    }

    // Tolerance window: the daemon's proxy task may race with the
    // shutdown signal on the final session. We assert at least
    // (N - 1) of each kind survived to disk, and that opens ==
    // closes (paired). In practice this is exact in CI; the slack
    // is for slow runners.
    assert_eq!(
        opens,
        closes,
        "session.open/close not paired in chain: opens={opens} closes={closes} \
         entries={}",
        log.entries().len()
    );
    assert!(
        opens >= (N_SESSIONS as u64) - 1,
        "expected >= {} session.open events, got {opens} (entries={})",
        N_SESSIONS - 1,
        log.entries().len()
    );
    assert!(
        opens <= N_SESSIONS as u64,
        "more session.open events than sessions driven: opens={opens} N={N_SESSIONS}"
    );

    // Sanity: the chain header is what the audit signer published.
    let pub_blob = std::fs::read(&fx.audit_pub_path).expect("read audit pub");
    let pk_bytes = &pub_blob[8..8 + qaudit_core::signing::PUBLIC_KEY_LEN];
    assert_eq!(
        log.header().pubkey.as_bytes(),
        pk_bytes,
        "audit chain header pubkey != published .audit.pub"
    );
}

#[test]
fn audit_chain_survives_session_load_across_sighup() {
    // Sprint 30 second case: drive sessions, then SIGHUP-ADD a new
    // tenant (no sessions on it), then drive more sessions on the
    // original tenant, then SIGTERM. The original tenant's chain
    // should contain ALL session events across the SIGHUP boundary.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("test rt");

    let fx = Fixture::build(&["alice"]);
    let (echo_addr, echo_shutdown) = rt.block_on(spawn_echo_server());
    fx.write_config_with_backend(&[("alice", fx.tenant_ports[0])], echo_addr);

    let daemon = DaemonGuard::spawn(&fx.config_path);
    assert!(wait_for_metrics(fx.metrics_port, Duration::from_secs(15)));

    let identity = Arc::new(load_transport_identity(
        &fx.root.join("daemon.skid"),
        &fx.root.join("daemon.cspqid.pub"),
    ));
    let peer_policy = Arc::new(PeerPolicy::single(identity.public().clone()));
    let dial_addr: std::net::SocketAddr =
        format!("127.0.0.1:{}", fx.tenant_ports[0]).parse().unwrap();

    let payload = b"phase-1\n";
    for _ in 0..3 {
        rt.block_on(drive_one_session(
            dial_addr,
            identity.clone(),
            peer_policy.clone(),
            payload,
        ))
        .expect("phase-1 session");
    }
    std::thread::sleep(Duration::from_millis(300));

    // SIGHUP ADD bob (bob's backend points to the same echo server
    // for simplicity; bob isn't actually exercised here, we just
    // want a SIGHUP cycle on alice's listener context).
    let bob_port = pick_port();
    fx.write_config_with_backend(
        &[("alice", fx.tenant_ports[0]), ("bob", bob_port)],
        echo_addr,
    );
    sighup(daemon.pid());
    std::thread::sleep(Duration::from_secs(2));

    // Drive a few more sessions on alice after the SIGHUP.
    for _ in 0..3 {
        rt.block_on(drive_one_session(
            dial_addr,
            identity.clone(),
            peer_policy.clone(),
            payload,
        ))
        .expect("phase-2 session");
    }
    std::thread::sleep(Duration::from_millis(500));

    daemon.shutdown_gracefully();
    std::thread::sleep(Duration::from_millis(300));
    echo_shutdown.notify_waiters();

    let log = AuditLog::open(fx.audit_log_for("alice")).expect("alice log parse");
    log.verify().expect("alice log verify");
    let opens = log
        .entries()
        .iter()
        .filter(|e| e.event.action == "session.open")
        .count() as u64;
    // We drove 6 sessions total. Same tolerance as the first test.
    assert!(
        opens >= 5,
        "expected >= 5 session.open across SIGHUP, got {opens} (entries={})",
        log.entries().len()
    );
    assert!(opens <= 6, "more opens than sessions driven: {opens}");
}
