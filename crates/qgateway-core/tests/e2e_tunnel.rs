//! Sprint 4 e2e acceptance: multi-tenant gateway pair with graceful close.
//!
//! Validates:
//! - 2 tenants on each side, isolated audit logs + metrics
//! - Tenants only route traffic for their own listen port
//! - Graceful close protocol (zero-length EOF marker) → shutdown_reason: clean
//! - Metrics use proper tenant labels in Prometheus exposition

use qaudit_core::{AuditLog, KeyPair};
use qgateway_core::{
    metrics::render_prometheus, run_serve_pq_tenant, run_serve_tcp_tenant, AuditChannel,
    AuditSignerConfig, MetricsRegistry, ServePqTenant, ServeTcpTenant, TenantId,
};
use qtransport_cspq::{IdentityKey, PeerPolicy};
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;

/// Test-only: the resolved-tenant types carry an effective AuditSignerConfig
/// post-Sprint-5, but the runtime functions never read it (only main.rs does).
/// Tests that construct these types directly use this dummy.
fn dummy_signer_cfg() -> AuditSignerConfig {
    AuditSignerConfig::Softkey {
        secret_key: PathBuf::from("/dev/null/test.skid"),
        public_key: PathBuf::from("/dev/null/test.pub"),
    }
}

async fn pick_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let p = l.local_addr().unwrap().port();
    drop(l);
    p
}

async fn spawn_echo(addr: String) -> tokio::task::JoinHandle<()> {
    let l = TcpListener::bind(&addr).await.unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = match l.accept().await {
                Ok(x) => x,
                Err(_) => return,
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                loop {
                    match s.read(&mut buf).await {
                        Ok(0) => return,
                        Ok(n) => {
                            if s.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                        }
                        Err(_) => return,
                    }
                }
            });
        }
    })
}

fn writable_log(tmp: &TempDir, name: &str) -> (AuditLog, PathBuf) {
    let kp = KeyPair::generate().unwrap();
    let log = AuditLog::create_with_label(kp, name).unwrap();
    let path = tmp.path().join(format!("{name}.qa"));
    log.save(&path).unwrap();
    (log, path)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn multi_tenant_isolation_and_graceful_close() {
    let tmp = TempDir::new().unwrap();

    // Two tenants: "sp" and "rj". Each has its own ports, echo backend,
    // peer policy, audit log, metrics registry.
    let echo_sp = pick_port().await;
    let echo_rj = pick_port().await;
    let pq_sp = pick_port().await;
    let pq_rj = pick_port().await;
    let tcp_sp = pick_port().await;
    let tcp_rj = pick_port().await;

    let _echo_sp_task = spawn_echo(format!("127.0.0.1:{echo_sp}")).await;
    let _echo_rj_task = spawn_echo(format!("127.0.0.1:{echo_rj}")).await;

    // Identity keys: one per gateway side (A and B). All tenants share an
    // identity per Cofre Soberano deployment.
    let id_a = Arc::new(IdentityKey::generate().unwrap());
    let id_b = Arc::new(IdentityKey::generate().unwrap());
    let policy_a = Arc::new(PeerPolicy::single(id_b.public().clone()));
    let policy_b = Arc::new(PeerPolicy::single(id_a.public().clone()));

    // Per-tenant metrics + audit channels.
    let metrics_a_sp = MetricsRegistry::new("sp");
    let metrics_a_rj = MetricsRegistry::new("rj");
    let metrics_b_sp = MetricsRegistry::new("sp");
    let metrics_b_rj = MetricsRegistry::new("rj");

    let (log_a_sp, log_a_sp_path) = writable_log(&tmp, "gw-a-sp");
    let (log_a_rj, log_a_rj_path) = writable_log(&tmp, "gw-a-rj");
    let (log_b_sp, log_b_sp_path) = writable_log(&tmp, "gw-b-sp");
    let (log_b_rj, log_b_rj_path) = writable_log(&tmp, "gw-b-rj");
    let audit_a_sp =
        AuditChannel::spawn(log_a_sp, log_a_sp_path.clone(), metrics_a_sp.clone(), 64, 4);
    let audit_a_rj =
        AuditChannel::spawn(log_a_rj, log_a_rj_path.clone(), metrics_a_rj.clone(), 64, 4);
    let audit_b_sp =
        AuditChannel::spawn(log_b_sp, log_b_sp_path.clone(), metrics_b_sp.clone(), 64, 4);
    let audit_b_rj =
        AuditChannel::spawn(log_b_rj, log_b_rj_path.clone(), metrics_b_rj.clone(), 64, 4);

    let shutdown_a = Arc::new(Notify::new());
    let shutdown_b = Arc::new(Notify::new());

    // B side (serve-pq): spawn 2 tenants.
    {
        let t = ServePqTenant {
            id: TenantId { name: "sp".into() },
            listen: format!("127.0.0.1:{pq_sp}"),
            backend: format!("127.0.0.1:{echo_sp}"),
            peer_pub_dir: tmp.path().join("unused"),
            audit_log: log_b_sp_path.clone(),
            audit_signer: dummy_signer_cfg(),
            limits: None,
        };
        let id_b = id_b.clone();
        let policy_b = policy_b.clone();
        let audit = audit_b_sp.handle();
        let metrics = metrics_b_sp.clone();
        let shutdown = shutdown_b.clone();
        tokio::spawn(async move {
            run_serve_pq_tenant(t, id_b, policy_b, audit, metrics, shutdown, None).await
        });
    }
    {
        let t = ServePqTenant {
            id: TenantId { name: "rj".into() },
            listen: format!("127.0.0.1:{pq_rj}"),
            backend: format!("127.0.0.1:{echo_rj}"),
            peer_pub_dir: tmp.path().join("unused"),
            audit_log: log_b_rj_path.clone(),
            audit_signer: dummy_signer_cfg(),
            limits: None,
        };
        let id_b = id_b.clone();
        let policy_b = policy_b.clone();
        let audit = audit_b_rj.handle();
        let metrics = metrics_b_rj.clone();
        let shutdown = shutdown_b.clone();
        tokio::spawn(async move {
            run_serve_pq_tenant(t, id_b, policy_b, audit, metrics, shutdown, None).await
        });
    }

    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    // A side (serve-tcp): spawn 2 tenants.
    {
        let t = ServeTcpTenant {
            id: TenantId { name: "sp".into() },
            listen: format!("127.0.0.1:{tcp_sp}"),
            peer_pq: format!("127.0.0.1:{pq_sp}"),
            peer_pub_dir: tmp.path().join("unused"),
            audit_log: log_a_sp_path.clone(),
            tls: None,
            sni: None,
            audit_signer: dummy_signer_cfg(),
            limits: None,
        };
        let id_a = id_a.clone();
        let policy_a = policy_a.clone();
        let audit = audit_a_sp.handle();
        let metrics = metrics_a_sp.clone();
        let shutdown = shutdown_a.clone();
        tokio::spawn(async move {
            run_serve_tcp_tenant(t, id_a, policy_a, audit, metrics, shutdown, None, None).await
        });
    }
    {
        let t = ServeTcpTenant {
            id: TenantId { name: "rj".into() },
            listen: format!("127.0.0.1:{tcp_rj}"),
            peer_pq: format!("127.0.0.1:{pq_rj}"),
            peer_pub_dir: tmp.path().join("unused"),
            audit_log: log_a_rj_path.clone(),
            tls: None,
            sni: None,
            audit_signer: dummy_signer_cfg(),
            limits: None,
        };
        let id_a = id_a.clone();
        let policy_a = policy_a.clone();
        let audit = audit_a_rj.handle();
        let metrics = metrics_a_rj.clone();
        let shutdown = shutdown_a.clone();
        tokio::spawn(async move {
            run_serve_tcp_tenant(t, id_a, policy_a, audit, metrics, shutdown, None, None).await
        });
    }

    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    // Two clients: one per tenant. Each sends through its own tunnel.
    let sp_msg = b"hello from sp tenant".to_vec();
    let rj_msg = b"hello from rj tenant longer payload here".to_vec();

    let mut sp_client = TcpStream::connect(format!("127.0.0.1:{tcp_sp}"))
        .await
        .unwrap();
    sp_client.write_all(&sp_msg).await.unwrap();
    sp_client.flush().await.unwrap();
    let mut sp_buf = vec![0u8; sp_msg.len()];
    sp_client.read_exact(&mut sp_buf).await.unwrap();
    assert_eq!(sp_buf, sp_msg);
    // Drop closes the TCP, triggering graceful-close protocol.
    drop(sp_client);

    let mut rj_client = TcpStream::connect(format!("127.0.0.1:{tcp_rj}"))
        .await
        .unwrap();
    rj_client.write_all(&rj_msg).await.unwrap();
    rj_client.flush().await.unwrap();
    let mut rj_buf = vec![0u8; rj_msg.len()];
    rj_client.read_exact(&mut rj_buf).await.unwrap();
    assert_eq!(rj_buf, rj_msg);
    drop(rj_client);

    // Allow audit channels to flush + graceful close roundtrips.
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;

    shutdown_a.notify_waiters();
    shutdown_b.notify_waiters();

    drop(audit_a_sp.handle());
    drop(audit_a_rj.handle());
    drop(audit_b_sp.handle());
    drop(audit_b_rj.handle());
    audit_a_sp.shutdown().await;
    audit_a_rj.shutdown().await;
    audit_b_sp.shutdown().await;
    audit_b_rj.shutdown().await;

    // Audit logs verify and contain proper tenant metadata.
    for (path, expected_tenant) in &[
        (&log_a_sp_path, "sp"),
        (&log_a_rj_path, "rj"),
        (&log_b_sp_path, "sp"),
        (&log_b_rj_path, "rj"),
    ] {
        let log = AuditLog::open(path).expect("open log");
        log.verify().expect("log verifies");
        let actions: Vec<&str> = log
            .entries()
            .iter()
            .map(|e| e.event.action.as_str())
            .collect();
        assert!(
            actions.contains(&"session.open"),
            "{} missing session.open; got {actions:?}",
            path.display()
        );
        assert!(
            actions.contains(&"session.close"),
            "{} missing session.close; got {actions:?}",
            path.display()
        );
        // Every session emits with the right tenant metadata.
        for entry in log.entries() {
            assert_eq!(
                entry.event.metadata.get("tenant").map(String::as_str),
                Some(*expected_tenant),
                "log {} entry has wrong tenant: {:?}",
                path.display(),
                entry.event.metadata
            );
        }
        // Graceful close: shutdown_reason on the session.close entry MUST be "clean".
        let close = log
            .entries()
            .iter()
            .find(|e| e.event.action == "session.close")
            .expect("session.close present");
        assert_eq!(
            close
                .event
                .metadata
                .get("shutdown_reason")
                .map(String::as_str),
            Some("clean"),
            "{} did not record clean close; got {:?}",
            path.display(),
            close.event.metadata
        );
    }

    // Per-tenant metrics isolated.
    use std::sync::atomic::Ordering;
    assert_eq!(
        metrics_a_sp.inner().sessions_opened.load(Ordering::Relaxed),
        1
    );
    assert_eq!(
        metrics_a_rj.inner().sessions_opened.load(Ordering::Relaxed),
        1
    );
    assert_eq!(
        metrics_b_sp.inner().sessions_opened.load(Ordering::Relaxed),
        1
    );
    assert_eq!(
        metrics_b_rj.inner().sessions_opened.load(Ordering::Relaxed),
        1
    );

    // Aggregated Prometheus exposition has both tenant labels.
    let rendered = render_prometheus(&[&metrics_a_sp, &metrics_a_rj]);
    assert!(rendered.contains("qgateway_sessions_opened_total{tenant=\"sp\"} 1"));
    assert!(rendered.contains("qgateway_sessions_opened_total{tenant=\"rj\"} 1"));
    // HELP block emitted only once per metric.
    assert_eq!(
        rendered
            .matches("# TYPE qgateway_sessions_opened_total")
            .count(),
        1
    );
}
