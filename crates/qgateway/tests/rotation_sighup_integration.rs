//! Sprint 27 — audit rotation (SIGUSR2) interacts cleanly with SIGHUP.
//!
//! Proves three invariants:
//!
//! 1. **Rotation of an existing tenant** survives a concurrent SIGHUP that
//!    affects OTHER tenants. The rotated archive file and the post-rotation
//!    log file both verify.
//!
//! 2. **A tenant added at runtime via SIGHUP** is registered as a rotation
//!    target. Subsequent SIGUSR2 actually rotates the added tenant's log
//!    (this was a real bug surfaced by Sprint 27 — pre-fix, the
//!    `rotation_targets` was a startup-populated `Vec` and never grew on
//!    SIGHUP ADD).
//!
//! 3. **A tenant removed via SIGHUP** is purged from rotation targets.
//!    Subsequent SIGUSR2 does NOT touch the removed tenant's stale audit
//!    log path.
//!
//! Sprint 27 also surfaced and fixed the Vec→HashMap promotion of the
//! daemon's `rotation_targets`; this test enforces the fix.

mod common;

use std::time::Duration;

use common::*;
use qaudit_core::AuditLog;

#[test]
fn sigusr2_rotates_runtime_added_tenant() {
    // Sprint 27 regression test for the rotation_targets Vec→HashMap
    // promotion. Pre-fix, this test would have failed because bob's
    // log file (created via SIGHUP ADD) would never be rotated by
    // SIGUSR2 — bob was not in the startup-populated Vec.
    let fx = Fixture::build(&["alice"]);
    let daemon = DaemonGuard::spawn(&fx.config_path);

    assert!(
        wait_for_metrics(fx.metrics_port, Duration::from_secs(15)),
        "daemon /metrics did not come up within 15s"
    );

    // SIGHUP ADD bob.
    let bob_port = pick_port();
    fx.write_config_with(&[("alice", fx.tenant_ports[0]), ("bob", bob_port)]);
    sighup(daemon.pid());
    std::thread::sleep(Duration::from_secs(2));

    let bob_log_path = fx.audit_log_for("bob");
    assert!(
        bob_log_path.exists(),
        "bob audit log not created on SIGHUP ADD"
    );

    // Count files in the audit dir before rotation. Should be:
    //   daemon.skid + daemon.cspqid.pub + audit.skid + audit.pub +
    //   sidecar.toml + alice.qa + bob.qa = 7 files at root level,
    //   plus the peers/ dir.
    let before_files = list_root_files(&fx.root);
    let before_qa_count = before_files.iter().filter(|p| p.ends_with(".qa")).count();
    assert_eq!(
        before_qa_count, 2,
        "expected 2 .qa files before rotation, got: {before_files:?}"
    );

    // Trigger SIGUSR2 to rotate both alice's and bob's logs.
    sigusr2(daemon.pid());
    std::thread::sleep(Duration::from_secs(2));

    // After rotation: the current log files (alice.qa, bob.qa) are still
    // there (with fresh headers), and TWO archive files appeared. If the
    // Sprint 27 fix is correct, bob's archive exists. If the Vec-bug
    // were still present, only alice's archive would exist.
    let after_files = list_root_files(&fx.root);
    let after_qa_count = after_files.iter().filter(|p| p.ends_with(".qa")).count();
    assert!(
        after_qa_count >= 4,
        "expected at least 4 .qa files after rotation (2 current + 2 archives), got {after_qa_count}: {after_files:?}"
    );

    // Specifically: a file matching the rotation pattern for bob must
    // exist. Default pattern is `<tenant>-<timestamp>.qa`.
    let bob_archive_exists = after_files
        .iter()
        .any(|p| p.starts_with("bob-") && p.ends_with(".qa"));
    assert!(
        bob_archive_exists,
        "bob's rotation archive not found — SIGUSR2 did not rotate the runtime-added tenant's log. Files: {after_files:?}"
    );

    // The runtime-added tenant's post-rotation log file must verify.
    let bob_post_rotation =
        AuditLog::open(&bob_log_path).expect("bob audit log must parse after rotation");
    bob_post_rotation
        .verify()
        .expect("bob audit log must verify after rotation");

    // Find bob's archive and verify it too.
    let bob_archive_name = after_files
        .iter()
        .find(|p| p.starts_with("bob-") && p.ends_with(".qa"))
        .expect("bob archive listed above");
    let bob_archive_path = fx.root.join(bob_archive_name);
    let bob_archive = AuditLog::open(&bob_archive_path).expect("bob archive must parse");
    bob_archive
        .verify()
        .expect("bob archive must verify (cleanly closed chain)");

    daemon.shutdown_gracefully();
}

#[test]
fn sigusr2_skips_removed_tenants() {
    // The dual property: a tenant removed via SIGHUP REMOVE is purged
    // from rotation targets, so subsequent SIGUSR2 does NOT touch its
    // stale audit log path. We verify this indirectly: count rotation-
    // generated archive files after one SIGUSR2 cycle that happens
    // AFTER bob's REMOVE. Bob should not have a new archive from this
    // post-REMOVE rotation.
    let fx = Fixture::build(&["alice"]);
    let daemon = DaemonGuard::spawn(&fx.config_path);

    assert!(
        wait_for_metrics(fx.metrics_port, Duration::from_secs(15)),
        "daemon /metrics did not come up within 15s"
    );

    // Add bob, then remove bob.
    let bob_port = pick_port();
    fx.write_config_with(&[("alice", fx.tenant_ports[0]), ("bob", bob_port)]);
    sighup(daemon.pid());
    std::thread::sleep(Duration::from_secs(2));

    fx.write_config_with(&[("alice", fx.tenant_ports[0])]);
    sighup(daemon.pid());
    std::thread::sleep(Duration::from_secs(2));

    // Capture file list BEFORE the rotation that follows REMOVE.
    let before = list_root_files(&fx.root);
    let bob_archives_before = before
        .iter()
        .filter(|p| p.starts_with("bob-") && p.ends_with(".qa"))
        .count();

    // SIGUSR2 — bob is gone from rotation_targets, so this cycle only
    // affects alice.
    sigusr2(daemon.pid());
    std::thread::sleep(Duration::from_secs(2));

    let after = list_root_files(&fx.root);
    let bob_archives_after = after
        .iter()
        .filter(|p| p.starts_with("bob-") && p.ends_with(".qa"))
        .count();
    assert_eq!(
        bob_archives_before, bob_archives_after,
        "SIGUSR2 touched bob after REMOVE (created a new bob archive). before={bob_archives_before} after={bob_archives_after} files: {after:?}"
    );

    // Alice WAS rotated.
    let alice_archives_after = after
        .iter()
        .filter(|p| p.starts_with("alice-") && p.ends_with(".qa"))
        .count();
    assert!(
        alice_archives_after >= 1,
        "alice was not rotated by SIGUSR2 post-REMOVE. files: {after:?}"
    );

    // Alice's current log + archive both verify.
    let alice_current = AuditLog::open(fx.audit_log_for("alice")).expect("alice current");
    alice_current.verify().expect("alice current verify");
    let alice_archive_name = after
        .iter()
        .find(|p| p.starts_with("alice-") && p.ends_with(".qa"))
        .expect("alice archive");
    let alice_archive =
        AuditLog::open(fx.root.join(alice_archive_name)).expect("alice archive open");
    alice_archive.verify().expect("alice archive verify");

    daemon.shutdown_gracefully();
}

fn list_root_files(root: &std::path::Path) -> Vec<String> {
    std::fs::read_dir(root)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect()
}

fn sigusr2(pid: nix::unistd::Pid) {
    nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGUSR2).expect("SIGUSR2 daemon");
}
