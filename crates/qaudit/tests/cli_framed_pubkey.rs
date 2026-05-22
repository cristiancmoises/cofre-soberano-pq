//! v1.0.1 — `qaudit verify --pk` and `qaudit verify-chain --pk` accept the
//! 2600-byte framed public-key file produced by `qgateway audit-keygen`
//! (8-byte `AUDITPK0` magic + 2592 B raw ML-DSA-87), not just the bare
//! 2592-byte raw file produced by `qaudit init`.
//!
//! This regression test exists because v1.0.0 shipped with `qaudit verify`
//! calling `PublicKey::from_bytes` directly on whatever was on disk,
//! which only accepts the raw length. An operator who held the framed
//! audit-pubkey from the gateway side and ran `qaudit verify --pk` got
//! a hard error instead of a successful verification.

use std::process::Command;
use tempfile::TempDir;

fn qaudit_bin() -> std::path::PathBuf {
    std::env::var_os("CARGO_BIN_EXE_qaudit")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .join("target/debug/qaudit")
        })
}

fn run(args: &[&str], cwd: &std::path::Path) -> std::process::Output {
    Command::new(qaudit_bin())
        .args(args)
        .current_dir(cwd)
        .output()
        .expect("spawn qaudit")
}

fn assert_ok(out: &std::process::Output, ctx: &str) {
    if !out.status.success() {
        panic!(
            "{ctx}: qaudit exited with {:?}\nstdout: {}\nstderr: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

#[test]
fn verify_accepts_raw_2592_byte_pubkey_file() {
    let tmp = TempDir::new().expect("tempdir");
    let cwd = tmp.path();

    assert_ok(
        &run(&["init", "--log", "audit.qa", "--label", "raw-test"], cwd),
        "init",
    );
    assert_ok(
        &run(
            &[
                "append",
                "--log",
                "audit.qa",
                "--actor",
                "test",
                "--action",
                "evt",
                "--resource",
                "x://y",
            ],
            cwd,
        ),
        "append",
    );

    // `qaudit init` writes the bare 2592-byte raw form by default.
    let raw_pk = std::fs::read(cwd.join("audit.pk")).expect("read raw pk");
    assert_eq!(raw_pk.len(), 2592, "qaudit init must write raw 2592 B");

    assert_ok(
        &run(&["verify", "--log", "audit.qa", "--pk", "audit.pk"], cwd),
        "verify --pk raw",
    );
}

#[test]
fn verify_accepts_framed_2600_byte_pubkey_file() {
    let tmp = TempDir::new().expect("tempdir");
    let cwd = tmp.path();

    assert_ok(
        &run(
            &["init", "--log", "audit.qa", "--label", "framed-test"],
            cwd,
        ),
        "init",
    );
    assert_ok(
        &run(
            &[
                "append",
                "--log",
                "audit.qa",
                "--actor",
                "test",
                "--action",
                "evt",
                "--resource",
                "x://y",
            ],
            cwd,
        ),
        "append",
    );

    // Synthesize a 2600-byte framed file: 8 B "AUDITPK0" magic + 2592 B raw.
    let raw_pk = std::fs::read(cwd.join("audit.pk")).expect("read raw pk");
    let mut framed = Vec::with_capacity(2600);
    framed.extend_from_slice(b"AUDITPK0");
    framed.extend_from_slice(&raw_pk);
    assert_eq!(framed.len(), 2600);
    let framed_path = cwd.join("framed.pub");
    std::fs::write(&framed_path, &framed).expect("write framed");

    // Verify with the framed file should succeed identically.
    let out = run(&["verify", "--log", "audit.qa", "--pk", "framed.pub"], cwd);
    assert_ok(&out, "verify --pk framed");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("ok:") && stdout.contains("entries verified"),
        "stdout did not look like a successful verify: {stdout}"
    );
}

#[test]
fn verify_rejects_2600_byte_file_without_magic() {
    let tmp = TempDir::new().expect("tempdir");
    let cwd = tmp.path();

    assert_ok(
        &run(&["init", "--log", "audit.qa", "--label", "bogus-test"], cwd),
        "init",
    );
    assert_ok(
        &run(
            &[
                "append",
                "--log",
                "audit.qa",
                "--actor",
                "test",
                "--action",
                "evt",
                "--resource",
                "x://y",
            ],
            cwd,
        ),
        "append",
    );

    // 2600 bytes of zeros — wrong magic, must be refused.
    std::fs::write(cwd.join("bogus.pub"), vec![0u8; 2600]).expect("write bogus");

    let out = run(&["verify", "--log", "audit.qa", "--pk", "bogus.pub"], cwd);
    assert!(
        !out.status.success(),
        "verify must refuse 2600-byte file without magic"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("magic") || stderr.contains("AUDITPK0"),
        "rejection message did not mention magic: {stderr}"
    );
}
