//! Sprint 26 — audit chain integrity across SIGHUP cycles.
//!
//! Proves the compliance invariant: every per-tenant audit log file is
//! a valid chain (header parseable, all signatures verify) AFTER the
//! tenant has gone through one or more SIGHUP lifecycle events.
//!
//! Two scenarios:
//!
//! 1. **survivor**: tenant `alice` exists for the daemon's lifetime;
//!    SIGHUP ADDs `bob` and SIGHUP REMOVEs `bob` happen around her,
//!    then SIGTERM. Alice's audit log must verify.
//!
//! 2. **transient**: tenant `bob` is ADDed at runtime then REMOVEd
//!    before SIGTERM. The REMOVE path's `shutdown_async` should flush
//!    bob's audit channel cleanly so bob's log file is also a valid
//!    chain (even if empty of business events).
//!
//! This is the first test that proves the audit-write half of the
//! daemon is correct end-to-end across the lifecycle. All previous
//! audit tests (48 in qaudit-core) exercise the chain machinery in
//! isolation; this one exercises it inside the live daemon.

mod common;

use std::time::Duration;

use common::*;
use qaudit_core::AuditLog;

#[test]
fn audit_chains_remain_valid_across_sighup_cycle() {
    let fx = Fixture::build(&["alice"]);
    let daemon = DaemonGuard::spawn(&fx.config_path);

    assert!(
        wait_for_metrics(fx.metrics_port, Duration::from_secs(15)),
        "daemon /metrics did not come up within 15s"
    );

    // Pre-condition: alice's audit log exists and parses (just the
    // header at this point; no business events yet).
    let alice_log_path = fx.audit_log_for("alice");
    assert!(
        alice_log_path.exists(),
        "alice audit log not created at startup: {alice_log_path:?}"
    );
    let alice_initial =
        AuditLog::open(&alice_log_path).expect("alice initial audit log must parse");
    alice_initial
        .verify()
        .expect("alice initial audit log must verify");

    // Add bob.
    let bob_port = pick_port();
    fx.write_config_with(&[("alice", fx.tenant_ports[0]), ("bob", bob_port)]);
    sighup(daemon.pid());
    std::thread::sleep(Duration::from_secs(2));

    // Bob's audit log must now exist + parse + verify.
    let bob_log_path = fx.audit_log_for("bob");
    assert!(
        bob_log_path.exists(),
        "bob audit log not created on SIGHUP ADD: {bob_log_path:?}"
    );
    let bob_post_add = AuditLog::open(&bob_log_path).expect("bob audit log must parse after ADD");
    bob_post_add
        .verify()
        .expect("bob audit log must verify after ADD");

    // Remove bob.
    fx.write_config_with(&[("alice", fx.tenant_ports[0])]);
    sighup(daemon.pid());
    std::thread::sleep(Duration::from_secs(2));

    // After REMOVE, bob's audit channel went through `shutdown_async`,
    // which flushes any pending writer-task buffer. The file must
    // still parse and verify.
    let bob_post_remove =
        AuditLog::open(&bob_log_path).expect("bob audit log must parse after REMOVE");
    bob_post_remove
        .verify()
        .expect("bob audit log must verify after REMOVE");

    // Alice's chain must be untouched by bob's lifecycle.
    let alice_mid = AuditLog::open(&alice_log_path).expect("alice audit log must parse mid-test");
    alice_mid
        .verify()
        .expect("alice audit log must verify mid-test");

    // Clean shutdown — daemon flushes alice's audit channel.
    daemon.shutdown_gracefully();
    // Small grace period after SIGTERM to let the channel writer task
    // observe shutdown and finalize the file (the daemon's own exit
    // log line "qgateway stopped" is emitted only after this).
    std::thread::sleep(Duration::from_millis(300));

    let alice_final =
        AuditLog::open(&alice_log_path).expect("alice audit log must parse after SIGTERM");
    alice_final
        .verify()
        .expect("alice audit log must verify after SIGTERM");
}

#[test]
fn audit_chains_verify_against_provided_pubkey() {
    // Same scenario as above but using the audit_signer public key file
    // explicitly — this is the verification path an external auditor
    // would take (they receive the .audit.pub from the operator out of
    // band, and verify the .qa file against that key).
    let fx = Fixture::build(&["alice"]);
    let daemon = DaemonGuard::spawn(&fx.config_path);

    assert!(
        wait_for_metrics(fx.metrics_port, Duration::from_secs(15)),
        "daemon /metrics did not come up within 15s"
    );

    // Force one full SIGHUP cycle (ADD + REMOVE) to stress the
    // shared audit_signer (same key used by alice + bob in this
    // fixture; the daemon-level `[audit_signer]` block).
    let bob_port = pick_port();
    fx.write_config_with(&[("alice", fx.tenant_ports[0]), ("bob", bob_port)]);
    sighup(daemon.pid());
    std::thread::sleep(Duration::from_secs(2));
    fx.write_config_with(&[("alice", fx.tenant_ports[0])]);
    sighup(daemon.pid());
    std::thread::sleep(Duration::from_secs(2));

    daemon.shutdown_gracefully();
    std::thread::sleep(Duration::from_millis(300));

    // Load the published audit public key (the file an auditor would
    // get out of band).
    let provided_pk = qaudit_core_audit_pub_load(&fx.audit_pub_path);

    // Verify each tenant's log against the externally provided key.
    for name in ["alice", "bob"] {
        let path = fx.audit_log_for(name);
        let log = AuditLog::open(&path).unwrap_or_else(|e| panic!("{name} audit log open: {e:#}"));
        // The header's embedded pubkey must match the external one
        // bit-for-bit (alice + bob both use the daemon-level signer).
        assert_eq!(
            log.header().pubkey.as_bytes(),
            provided_pk.as_bytes(),
            "{name}'s header pubkey != externally provided pubkey"
        );
        log.verify()
            .unwrap_or_else(|e| panic!("{name} audit log failed verify: {e:#}"));
    }
}

/// Reads the daemon's `.audit.pub` file (8-byte magic + raw ML-DSA-87
/// pubkey) into a `qaudit_core::PublicKey`. Mirrors the daemon's own
/// `auditkey::load_pub` (not pub-exported from qgateway-core for
/// integration tests, so we duplicate the 6-line loader here).
fn qaudit_core_audit_pub_load(path: &std::path::Path) -> qaudit_core::PublicKey {
    const AUDIT_PK_MAGIC: &[u8; 8] = b"AUDITPK0";
    let blob = std::fs::read(path).expect("reading audit pubkey file");
    assert!(blob.len() >= 8 + qaudit_core::signing::PUBLIC_KEY_LEN);
    assert_eq!(&blob[..8], AUDIT_PK_MAGIC, "audit pubkey magic mismatch");
    let pk_bytes = &blob[8..8 + qaudit_core::signing::PUBLIC_KEY_LEN];
    qaudit_core::PublicKey::from_bytes(pk_bytes).expect("decoding audit pubkey")
}
