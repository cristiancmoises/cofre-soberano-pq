//! Sprint 37 — `qgateway validate` subcommand integration test.
//!
//! Proves four invariants:
//!
//! 1. **Happy path**: a known-good config (produced by the existing
//!    `common::Fixture`) validates successfully and exits 0.
//!
//! 2. **Error paths**: four common operator mistakes produce non-zero
//!    exit and a stderr message identifying the offending field:
//!       - identity_key file missing
//!       - peer_pub_dir missing
//!       - audit signer key missing
//!       - malformed TOML
//!
//! 3. **Non-interference**: `validate` does NOT bind the tenant's
//!    listen port — proven by running a separate listener on that
//!    port concurrently and confirming `validate` still exits 0.
//!    The documented RUNBOOK.md §3.2 workaround ("spin up a test
//!    daemon on alternate ports") was needed precisely because
//!    `validate` didn't exist; this test enforces that the new
//!    subcommand replaces that workaround.
//!
//! 4. **No side effects**: `validate` does NOT create the audit log
//!    file on disk (which `cmd_run` does at startup). Proven by
//!    checking the audit log path does not exist after the
//!    subcommand returns.

mod common;

use std::process::{Command, Stdio};

use common::{qgateway_bin, Fixture};

#[test]
fn validate_accepts_good_config() {
    let fx = Fixture::build(&["alice"]);
    let out = Command::new(qgateway_bin())
        .arg("validate")
        .arg("--config")
        .arg(&fx.config_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn validate");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "validate should accept good config; exit={:?} stdout={stdout} stderr={stderr}",
        out.status.code()
    );
    assert!(
        stdout.contains("ok:"),
        "expected 'ok:' prefix in stdout; got: {stdout}"
    );
    assert!(
        stdout.contains("tenants=1"),
        "expected tenant count summary; got: {stdout}"
    );
}

#[test]
fn validate_does_not_create_audit_log_file() {
    let fx = Fixture::build(&["alice"]);
    let alice_log = fx.audit_log_for("alice");
    // The fixture does NOT spawn a daemon, so the audit log should
    // not exist yet. Confirm baseline.
    assert!(
        !alice_log.exists(),
        "precondition: alice audit log shouldn't exist before validate"
    );

    let out = Command::new(qgateway_bin())
        .arg("validate")
        .arg("--config")
        .arg(&fx.config_path)
        .output()
        .expect("spawn validate");
    assert!(out.status.success(), "validate must succeed on good config");

    // After validate, audit log STILL shouldn't exist — validate
    // must not create files.
    assert!(
        !alice_log.exists(),
        "validate created audit log on disk: {} (validate must have no side effects)",
        alice_log.display()
    );
}

#[test]
fn validate_does_not_bind_listen_port() {
    // Sprint 37 closes RUNBOOK.md §3.2's documented workaround. The
    // workaround existed because validation previously required
    // running an actual daemon, which would conflict with a daemon
    // already running on the same listen port. This test enforces
    // that validate is non-interfering: we manually bind the tenant's
    // port from the test, then run validate, then confirm validate
    // exited 0 (it didn't try to bind).
    let fx = Fixture::build(&["alice"]);
    let alice_port = fx.tenant_ports[0];

    // Hold the port from the test process. If validate tried to
    // bind, it would fail with EADDRINUSE.
    let _hold = std::net::TcpListener::bind(("127.0.0.1", alice_port))
        .expect("test must be able to bind alice's port to prove non-interference");

    let out = Command::new(qgateway_bin())
        .arg("validate")
        .arg("--config")
        .arg(&fx.config_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn validate");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "validate must NOT bind listen ports; exit={:?} stdout={stdout} stderr={stderr}",
        out.status.code()
    );
}

#[test]
fn validate_rejects_missing_identity_key_file() {
    let fx = Fixture::build(&["alice"]);
    // Delete the identity SK file — daemon would fail to start.
    std::fs::remove_file(fx.root.join("daemon.skid")).expect("remove sk");

    let out = Command::new(qgateway_bin())
        .arg("validate")
        .arg("--config")
        .arg(&fx.config_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn validate");
    assert!(
        !out.status.success(),
        "validate should reject missing identity SK; exit={:?}",
        out.status.code()
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("transport")
            || stderr.contains("identity")
            || stderr.contains("daemon.skid"),
        "stderr should name the missing file or 'identity/transport'; got: {stderr}"
    );
}

#[test]
fn validate_rejects_missing_peer_dir() {
    let fx = Fixture::build(&["alice"]);
    // Empty the peer dir — daemon would fail with "no peer .cspqid.pub".
    let peer_dir = fx.root.join("peers");
    for entry in std::fs::read_dir(&peer_dir).unwrap() {
        let _ = std::fs::remove_file(entry.unwrap().path());
    }

    let out = Command::new(qgateway_bin())
        .arg("validate")
        .arg("--config")
        .arg(&fx.config_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn validate");
    assert!(
        !out.status.success(),
        "validate should reject empty peer dir; exit={:?}",
        out.status.code()
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("peer") || stderr.contains("cspqid"),
        "stderr should name the peer-related failure; got: {stderr}"
    );
}

#[test]
fn validate_rejects_missing_audit_signer_key() {
    let fx = Fixture::build(&["alice"]);
    // Delete the audit signer SK — daemon would fail to load the
    // audit keypair at tenant resolution.
    std::fs::remove_file(fx.root.join("audit.skid")).expect("remove audit sk");

    let out = Command::new(qgateway_bin())
        .arg("validate")
        .arg("--config")
        .arg(&fx.config_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn validate");
    assert!(
        !out.status.success(),
        "validate should reject missing audit signer SK; exit={:?}",
        out.status.code()
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("audit") || stderr.contains("signer") || stderr.contains("skid"),
        "stderr should name the audit-related failure; got: {stderr}"
    );
}

#[test]
fn validate_rejects_malformed_toml() {
    let fx = Fixture::build(&["alice"]);
    // Corrupt the TOML — append a stray brace to break parse.
    let mut content = std::fs::read_to_string(&fx.config_path).unwrap();
    content.push_str("\n}\n[invalid section\n");
    std::fs::write(&fx.config_path, content).unwrap();

    let out = Command::new(qgateway_bin())
        .arg("validate")
        .arg("--config")
        .arg(&fx.config_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn validate");
    assert!(
        !out.status.success(),
        "validate should reject malformed TOML; exit={:?}",
        out.status.code()
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.to_lowercase().contains("config") || stderr.to_lowercase().contains("parse"),
        "stderr should name the parse failure; got: {stderr}"
    );
}
