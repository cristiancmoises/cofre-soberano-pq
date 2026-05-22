//! Sprint 7.5 — CLI integration test for `qaudit rotate` and
//! `qaudit verify-chain`. Drives the actual binary as a subprocess
//! through a 3-link rotation chain and asserts the verifier accepts.

use std::process::Command;
use tempfile::TempDir;

fn qaudit_bin() -> std::path::PathBuf {
    // CARGO_BIN_EXE_<name> is set by cargo when building integration tests.
    // Falls back to debug build path if the env var isn't set (rare).
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
fn cli_three_link_rotation_chain_verifies() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();

    // 1. init the chain root
    let out = run(
        &[
            "init", "--log", "a.qa", "--sk", "a.sk", "--pk", "a.pk", "--label", "log-a",
        ],
        dir,
    );
    assert_ok(&out, "init");

    // 2. append an event to a
    let out = run(
        &[
            "append", "--log", "a.qa", "--sk", "a.sk", "--pk", "a.pk", "--action", "test1",
            "--actor", "u",
        ],
        dir,
    );
    assert_ok(&out, "append a");

    // 3. rotate a → b
    let out = run(
        &[
            "rotate",
            "--in",
            "a.qa",
            "--out",
            "b.qa",
            "--sk",
            "a.sk",
            "--pk",
            "a.pk",
            "--new-label",
            "log-b",
        ],
        dir,
    );
    assert_ok(&out, "rotate a→b");

    // 4. append to b
    let out = run(
        &[
            "append", "--log", "b.qa", "--sk", "a.sk", "--pk", "a.pk", "--action", "test2",
            "--actor", "u",
        ],
        dir,
    );
    assert_ok(&out, "append b");

    // 5. rotate b → c
    let out = run(
        &[
            "rotate",
            "--in",
            "b.qa",
            "--out",
            "c.qa",
            "--sk",
            "a.sk",
            "--pk",
            "a.pk",
            "--new-label",
            "log-c",
        ],
        dir,
    );
    assert_ok(&out, "rotate b→c");

    // 6. verify the full 3-link chain
    let out = run(
        &[
            "verify-chain",
            "--log",
            "a.qa",
            "--log",
            "b.qa",
            "--log",
            "c.qa",
        ],
        dir,
    );
    assert_ok(&out, "verify-chain");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("ok: 3 logs"),
        "expected '3 logs' in stdout: {stdout}"
    );
    assert!(
        stdout.contains("log-a") && stdout.contains("log-b") && stdout.contains("log-c"),
        "expected all three labels in stdout: {stdout}"
    );
}

#[test]
fn cli_verify_chain_rejects_missing_link() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();

    // Build a→b→c just like above…
    for cmd in [
        vec![
            "init", "--log", "a.qa", "--sk", "a.sk", "--pk", "a.pk", "--label", "log-a",
        ],
        vec![
            "append", "--log", "a.qa", "--sk", "a.sk", "--pk", "a.pk", "--action", "t", "--actor",
            "u",
        ],
        vec![
            "rotate",
            "--in",
            "a.qa",
            "--out",
            "b.qa",
            "--sk",
            "a.sk",
            "--pk",
            "a.pk",
            "--new-label",
            "log-b",
        ],
        vec![
            "rotate",
            "--in",
            "b.qa",
            "--out",
            "c.qa",
            "--sk",
            "a.sk",
            "--pk",
            "a.pk",
            "--new-label",
            "log-c",
        ],
    ] {
        let out = run(&cmd, dir);
        assert_ok(&out, &cmd.join(" "));
    }

    // …then attempt to verify a→c skipping b.
    let out = run(&["verify-chain", "--log", "a.qa", "--log", "c.qa"], dir);
    assert!(
        !out.status.success(),
        "verify-chain must FAIL when a link is missing"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let combined = format!("{stderr}{stdout}");
    // The error message should reference one of the chain integrity
    // properties — prev_log_id, prev_log_final_root, or the rotation_close
    // metadata mismatch.
    assert!(
        combined.contains("prev_log_id")
            || combined.contains("rotation_close")
            || combined.contains("new_log_id"),
        "expected chain integrity error in output, got: {combined}"
    );
}

#[test]
fn cli_cross_key_rotation_chain_verifies() {
    // Sprint 9: rotate with --new-sk/--new-pk → new segment under a
    // different audit key. Chain verification works because each segment
    // is verified under its own header pubkey.
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();

    // 1. init the chain root with key K1.
    assert_ok(
        &run(
            &[
                "init", "--log", "a.qa", "--sk", "k1.sk", "--pk", "k1.pk", "--label", "log-a",
            ],
            dir,
        ),
        "init k1",
    );
    // 2. init a SECOND keypair for the new segment.
    assert_ok(
        &run(
            &[
                "init",
                "--log",
                "throwaway.qa",
                "--sk",
                "k2.sk",
                "--pk",
                "k2.pk",
                "--label",
                "tmp",
            ],
            dir,
        ),
        "init k2",
    );
    std::fs::remove_file(dir.join("throwaway.qa")).unwrap();

    // 3. append one event under K1.
    assert_ok(
        &run(
            &[
                "append", "--log", "a.qa", "--sk", "k1.sk", "--pk", "k1.pk", "--action", "t",
                "--actor", "u",
            ],
            dir,
        ),
        "append a",
    );
    // 4. cross-key rotate: --sk/--pk = K1, --new-sk/--new-pk = K2.
    let out = run(
        &[
            "rotate",
            "--in",
            "a.qa",
            "--out",
            "b.qa",
            "--sk",
            "k1.sk",
            "--pk",
            "k1.pk",
            "--new-sk",
            "k2.sk",
            "--new-pk",
            "k2.pk",
            "--new-label",
            "log-b-k2",
        ],
        dir,
    );
    assert_ok(&out, "cross-key rotate");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("(cross-key)"),
        "expected '(cross-key)' marker in stderr: {stderr}"
    );
    assert!(
        stderr.contains("new pubkey"),
        "expected new pubkey hex in stderr: {stderr}"
    );

    // 5. append under K2.
    assert_ok(
        &run(
            &[
                "append", "--log", "b.qa", "--sk", "k2.sk", "--pk", "k2.pk", "--action", "t2",
                "--actor", "u",
            ],
            dir,
        ),
        "append b",
    );

    // 6. verify chain WITHOUT --pk (cross-key chain → per-segment pubkeys).
    let out = run(&["verify-chain", "--log", "a.qa", "--log", "b.qa"], dir);
    assert_ok(&out, "verify-chain cross-key");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("ok: 2 logs"),
        "expected '2 logs' in stdout: {stdout}"
    );
}

#[test]
fn cli_cross_key_rotation_rejects_same_key() {
    // Sprint 9: supplying --new-sk/--new-pk that equal --sk/--pk is an
    // operator error (defeats the purpose). Detect and refuse.
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();
    assert_ok(
        &run(
            &[
                "init", "--log", "a.qa", "--sk", "k1.sk", "--pk", "k1.pk", "--label", "log-a",
            ],
            dir,
        ),
        "init k1",
    );
    let out = run(
        &[
            "rotate",
            "--in",
            "a.qa",
            "--out",
            "b.qa",
            "--sk",
            "k1.sk",
            "--pk",
            "k1.pk",
            "--new-sk",
            "k1.sk",
            "--new-pk",
            "k1.pk",
            "--new-label",
            "log-b",
        ],
        dir,
    );
    assert!(
        !out.status.success(),
        "cross-key rotate with same key must FAIL"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("SAME audit key") || stderr.contains("same audit key"),
        "expected same-key error message, got: {stderr}"
    );
}

#[test]
fn cli_cross_key_rotation_requires_both_flags() {
    // --new-sk without --new-pk (or vice versa) is an operator error.
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();
    assert_ok(
        &run(
            &[
                "init", "--log", "a.qa", "--sk", "k1.sk", "--pk", "k1.pk", "--label", "log-a",
            ],
            dir,
        ),
        "init k1",
    );
    let out = run(
        &[
            "rotate",
            "--in",
            "a.qa",
            "--out",
            "b.qa",
            "--sk",
            "k1.sk",
            "--pk",
            "k1.pk",
            "--new-sk",
            "k2.sk",
            "--new-label",
            "log-b",
        ],
        dir,
    );
    assert!(
        !out.status.success(),
        "rotate with --new-sk but no --new-pk must FAIL"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("must be supplied together"),
        "expected 'must be supplied together' error, got: {stderr}"
    );
}
