//! v1.0.1 — `qaudit append` resolves `--sk`/`--pk` from the log filename
//! by default (matching v1.0.1 `qaudit init`), and falls back to the
//! legacy `qaudit.sk` / `qaudit.pk` filenames in `$PWD` when the derived
//! files do not exist.
//!
//! v1.0.0 hardcoded `default_value = "qaudit.sk"` and `"qaudit.pk"`,
//! which made it impossible to keep multiple audit logs in the same
//! directory without colliding key filenames. v1.0.1 derives the names
//! from the `--log` argument so multi-tenant operators can have
//! `tenant-a.qa` + `tenant-a.sk` + `tenant-a.pk` side by side with
//! `tenant-b.qa` + `tenant-b.sk` + `tenant-b.pk` without surprise.

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
fn append_derives_sk_pk_from_log_filename() {
    let tmp = TempDir::new().expect("tempdir");
    let cwd = tmp.path();

    // init writes `tenant-a.sk` and `tenant-a.pk` next to the log.
    assert_ok(
        &run(&["init", "--log", "tenant-a.qa", "--label", "A"], cwd),
        "init",
    );
    assert!(cwd.join("tenant-a.sk").exists());
    assert!(cwd.join("tenant-a.pk").exists());

    // append without --sk/--pk must resolve to the same derived names.
    let out = run(
        &[
            "append",
            "--log",
            "tenant-a.qa",
            "--actor",
            "test",
            "--action",
            "evt",
            "--resource",
            "x://y",
        ],
        cwd,
    );
    assert_ok(&out, "append with derived keys");
}

#[test]
fn append_does_not_collide_across_logs_in_same_directory() {
    // The v1.0.0 footgun: two logs in the same directory share
    // `qaudit.sk` / `qaudit.pk`, the second `init` clobbered the first.
    let tmp = TempDir::new().expect("tempdir");
    let cwd = tmp.path();

    assert_ok(
        &run(&["init", "--log", "a.qa", "--label", "A"], cwd),
        "init a",
    );
    assert_ok(
        &run(&["init", "--log", "b.qa", "--label", "B"], cwd),
        "init b",
    );

    // Each log has its own keypair.
    assert!(cwd.join("a.sk").exists() && cwd.join("a.pk").exists());
    assert!(cwd.join("b.sk").exists() && cwd.join("b.pk").exists());

    // Append to a.qa and b.qa independently must both succeed using
    // derived defaults, with no cross-contamination.
    assert_ok(
        &run(
            &[
                "append",
                "--log",
                "a.qa",
                "--actor",
                "u",
                "--action",
                "evt.a",
                "--resource",
                "x://y",
            ],
            cwd,
        ),
        "append a",
    );
    assert_ok(
        &run(
            &[
                "append",
                "--log",
                "b.qa",
                "--actor",
                "u",
                "--action",
                "evt.b",
                "--resource",
                "x://y",
            ],
            cwd,
        ),
        "append b",
    );

    // Both logs verify cleanly.
    assert_ok(&run(&["verify", "--log", "a.qa"], cwd), "verify a");
    assert_ok(&run(&["verify", "--log", "b.qa"], cwd), "verify b");
}

#[test]
fn append_legacy_qaudit_sk_pk_fallback_in_cwd() {
    // Backwards compatibility: operators upgrading from v1.0.0 may still
    // have `qaudit.sk` / `qaudit.pk` from the legacy `init` layout. If the
    // derived `<log-stem>.sk` does not exist but `qaudit.sk` does, append
    // should pick up the legacy file rather than erroring.
    let tmp = TempDir::new().expect("tempdir");
    let cwd = tmp.path();

    // Simulate v1.0.0 layout: init with explicit legacy names.
    assert_ok(
        &run(
            &[
                "init",
                "--log",
                "legacy.qa",
                "--sk",
                "qaudit.sk",
                "--pk",
                "qaudit.pk",
                "--label",
                "legacy",
            ],
            cwd,
        ),
        "legacy init",
    );
    assert!(cwd.join("qaudit.sk").exists());
    assert!(cwd.join("qaudit.pk").exists());
    assert!(!cwd.join("legacy.sk").exists());

    // append without --sk/--pk should fall back to qaudit.sk / qaudit.pk
    // since the derived names don't exist.
    let out = run(
        &[
            "append",
            "--log",
            "legacy.qa",
            "--actor",
            "u",
            "--action",
            "evt",
            "--resource",
            "x://y",
        ],
        cwd,
    );
    assert_ok(&out, "append with legacy fallback");
}

#[test]
fn append_honors_explicit_sk_pk_paths() {
    let tmp = TempDir::new().expect("tempdir");
    let cwd = tmp.path();

    assert_ok(
        &run(
            &[
                "init", "--log", "x.qa", "--sk", "mysk.bin", "--pk", "mypk.bin", "--label",
                "explicit",
            ],
            cwd,
        ),
        "init",
    );

    let out = run(
        &[
            "append",
            "--log",
            "x.qa",
            "--sk",
            "mysk.bin",
            "--pk",
            "mypk.bin",
            "--actor",
            "u",
            "--action",
            "evt",
            "--resource",
            "x://y",
        ],
        cwd,
    );
    assert_ok(&out, "append explicit");
}

#[test]
fn append_rejects_mismatched_secret_without_modifying_log() {
    let tmp = tempfile::TempDir::new().unwrap();
    let binary = std::path::PathBuf::from(env!("CARGO_BIN_EXE_qaudit"));
    for name in ["a.qa", "b.qa"] {
        assert!(std::process::Command::new(&binary)
            .args(["init", "--log", name])
            .current_dir(tmp.path())
            .output()
            .unwrap()
            .status
            .success());
    }
    let before = std::fs::read(tmp.path().join("a.qa")).unwrap();
    let result = std::process::Command::new(&binary)
        .args([
            "append", "--log", "a.qa", "--sk", "b.sk", "--pk", "a.pk", "--actor", "demo",
            "--action", "test",
        ])
        .current_dir(tmp.path())
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("valid keypair"));
    assert_eq!(std::fs::read(tmp.path().join("a.qa")).unwrap(), before);
}
