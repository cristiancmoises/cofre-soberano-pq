//! v1.0.1 — Verify that `qaudit init` derives sk/pk paths from the log
//! filename when `--sk` / `--pk` are not given, so multiple logs can
//! coexist in the same directory without overwriting each other.

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
fn init_derives_key_paths_from_log_stem() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();

    // init log A — keys must land as a.sk / a.pk
    let out = run(&["init", "--log", "a.qa", "--label", "log-a"], dir);
    assert_ok(&out, "init a.qa");

    assert!(dir.join("a.qa").exists(), "a.qa missing");
    assert!(dir.join("a.sk").exists(), "a.sk missing");
    assert!(dir.join("a.pk").exists(), "a.pk missing");

    // legacy names should NOT be present
    assert!(
        !dir.join("qaudit.sk").exists(),
        "init must not write qaudit.sk by default in v1.0.1"
    );
    assert!(
        !dir.join("qaudit.pk").exists(),
        "init must not write qaudit.pk by default in v1.0.1"
    );

    // init log B in the same dir — must not overwrite A's keys
    let out = run(&["init", "--log", "b.qa", "--label", "log-b"], dir);
    assert_ok(&out, "init b.qa");

    assert!(dir.join("b.qa").exists(), "b.qa missing");
    assert!(dir.join("b.sk").exists(), "b.sk missing");
    assert!(dir.join("b.pk").exists(), "b.pk missing");
    // and A's keys are still there, untouched
    assert!(dir.join("a.sk").exists(), "a.sk gone after init b.qa");
    assert!(dir.join("a.pk").exists(), "a.pk gone after init b.qa");

    // appending to A picks up A's keys via the derived defaults
    let out = run(
        &[
            "append",
            "--log",
            "a.qa",
            "--sk",
            "a.sk",
            "--pk",
            "a.pk",
            "--actor",
            "u:test",
            "--action",
            "evt",
            "--resource",
            "test://x",
        ],
        dir,
    );
    assert_ok(&out, "append to a.qa");

    // verify still passes
    let out = run(&["verify", "--log", "a.qa"], dir);
    assert_ok(&out, "verify a.qa");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("1 entries verified"),
        "expected 1 entry, got: {stdout}"
    );
}

#[test]
fn init_with_explicit_paths_still_honored() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();

    // Explicit --sk / --pk override the derived defaults.
    let out = run(
        &[
            "init",
            "--log",
            "weird.qa",
            "--sk",
            "custom-signer.key",
            "--pk",
            "custom-signer.pub",
            "--label",
            "explicit",
        ],
        dir,
    );
    assert_ok(&out, "init with explicit paths");

    assert!(dir.join("custom-signer.key").exists());
    assert!(dir.join("custom-signer.pub").exists());
    assert!(!dir.join("weird.sk").exists());
    assert!(!dir.join("weird.pk").exists());
}

#[test]
fn init_refuses_to_overwrite_without_force() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();

    let out = run(&["init", "--log", "x.qa"], dir);
    assert_ok(&out, "first init");

    // Second init without --force must refuse, preserving the existing key.
    let out = run(&["init", "--log", "x.qa"], dir);
    assert!(
        !out.status.success(),
        "second init without --force must fail"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("refusing to overwrite"),
        "expected refusal message, got: {stderr}"
    );
}

#[test]
fn init_rejects_colliding_output_paths_before_writing() {
    let tmp = TempDir::new().unwrap();
    let out = run(
        &["init", "--log", "same.qa", "--sk", "./same.qa", "--force"],
        tmp.path(),
    );
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("distinct"));
    assert!(!tmp.path().join("same.qa").exists());
    assert!(!tmp.path().join("same.pk").exists());
}

#[cfg(unix)]
#[test]
fn init_force_restricts_existing_secret_permissions() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = TempDir::new().unwrap();
    std::fs::write(tmp.path().join("test.sk"), "old key").unwrap();
    std::fs::set_permissions(
        tmp.path().join("test.sk"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    let out = run(&["init", "--log", "test.qa", "--force"], tmp.path());
    assert_ok(&out, "replace permissive secret file");
    assert_eq!(
        std::fs::metadata(tmp.path().join("test.sk"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
}

#[cfg(unix)]
#[test]
fn init_refuses_symlink_outputs_even_with_force() {
    let tmp = TempDir::new().unwrap();
    let victim = tmp.path().join("victim");
    std::fs::write(&victim, "preserve this").unwrap();
    std::os::unix::fs::symlink("victim", tmp.path().join("test.sk")).unwrap();
    let out = run(&["init", "--log", "test.qa", "--force"], tmp.path());
    assert!(!out.status.success());
    assert_eq!(std::fs::read_to_string(victim).unwrap(), "preserve this");
    assert!(!tmp.path().join("test.qa").exists());
}

#[test]
fn export_and_pubkey_refuse_to_overwrite_source_log() {
    let tmp = TempDir::new().unwrap();
    assert_ok(&run(&["init", "--log", "test.qa"], tmp.path()), "init");
    let before = std::fs::read(tmp.path().join("test.qa")).unwrap();
    for command in ["export", "pubkey"] {
        let out = run(
            &[command, "--log", "test.qa", "--out", "./test.qa"],
            tmp.path(),
        );
        assert!(!out.status.success());
        assert_eq!(std::fs::read(tmp.path().join("test.qa")).unwrap(), before);
    }
}

#[test]
fn rotate_refuses_to_overwrite_input_even_with_force() {
    let tmp = TempDir::new().unwrap();
    assert_ok(&run(&["init", "--log", "test.qa"], tmp.path()), "init");
    let before = std::fs::read(tmp.path().join("test.qa")).unwrap();
    let out = run(
        &[
            "rotate",
            "--in",
            "test.qa",
            "--out",
            "./test.qa",
            "--sk",
            "test.sk",
            "--pk",
            "test.pk",
            "--new-label",
            "next",
            "--force",
        ],
        tmp.path(),
    );
    assert!(!out.status.success());
    assert_eq!(std::fs::read(tmp.path().join("test.qa")).unwrap(), before);
}
