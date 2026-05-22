//! Sprint 28 — auto-rotation monitor for runtime-added tenants.
//!
//! Companion to Sprint 27. Sprint 27 fixed `rotation_targets` so SIGUSR2
//! reaches runtime-added tenants. Sprint 28 fixes the auto-rotation
//! `RotationMonitor` task spawn so a tenant added at runtime via SIGHUP
//! ADD gets its OWN per-tenant monitor task — without it, an operator
//! with a size/age-based auto-rotation policy who adds tenants at
//! runtime would see those tenants' logs grow forever.
//!
//! The test uses a deliberately aggressive `max_age_secs = 1` policy so
//! auto-rotation fires within the test's runtime. In production an
//! operator would use minutes or hours.

mod common;

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use common::{pick_port, qgateway_bin, run_subcmd, scrape_metrics, sighup, wait_for_metrics};
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use qaudit_core::AuditLog;

/// Sprint 28 fixture — like `common::Fixture` but writes a `[rotation]`
/// block with an aggressive auto-trigger so the monitor fires within
/// test wall-clock. Kept inline to avoid generalizing the common
/// fixture for one test's quirk.
struct RotationFixture {
    config_path: PathBuf,
    metrics_port: u16,
    tenant_ports: Vec<u16>,
    root: PathBuf,
    _tmp: tempfile::TempDir,
}

impl RotationFixture {
    fn build(tenants: &[&str]) -> Self {
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path().to_path_buf();
        let id_sk = root.join("daemon.skid");
        let id_pk = root.join("daemon.cspqid.pub");
        run_subcmd(&[
            "keygen",
            "--sk",
            id_sk.to_str().unwrap(),
            "--pk",
            id_pk.to_str().unwrap(),
        ]);
        let audit_sk = root.join("audit.skid");
        let audit_pk = root.join("audit.pub");
        run_subcmd(&[
            "audit-keygen",
            "--sk",
            audit_sk.to_str().unwrap(),
            "--pk",
            audit_pk.to_str().unwrap(),
        ]);
        let peer_dir = root.join("peers");
        std::fs::create_dir_all(&peer_dir).unwrap();
        std::fs::copy(&id_pk, peer_dir.join("self.cspqid.pub")).unwrap();
        let metrics_port = pick_port();
        let tenant_ports: Vec<u16> = tenants.iter().map(|_| pick_port()).collect();
        let cfg_text = make_config_with_rotation(
            &id_sk,
            &id_pk,
            &audit_sk,
            &audit_pk,
            &peer_dir,
            metrics_port,
            &tenants
                .iter()
                .zip(&tenant_ports)
                .map(|(n, p)| (*n, *p))
                .collect::<Vec<_>>(),
            &root,
        );
        let config_path = root.join("sidecar.toml");
        std::fs::write(&config_path, cfg_text).unwrap();
        Self {
            config_path,
            metrics_port,
            tenant_ports,
            root,
            _tmp: tmp,
        }
    }

    fn audit_log_for(&self, name: &str) -> PathBuf {
        self.root.join(format!("{name}.qa"))
    }

    fn write_config_with(&self, tenants: &[(&str, u16)]) {
        let id_sk = self.root.join("daemon.skid");
        let id_pk = self.root.join("daemon.cspqid.pub");
        let audit_sk = self.root.join("audit.skid");
        let audit_pk = self.root.join("audit.pub");
        let peer_dir = self.root.join("peers");
        let s = make_config_with_rotation(
            &id_sk,
            &id_pk,
            &audit_sk,
            &audit_pk,
            &peer_dir,
            self.metrics_port,
            tenants,
            &self.root,
        );
        std::fs::write(&self.config_path, s).unwrap();
    }
}

#[allow(clippy::too_many_arguments)]
fn make_config_with_rotation(
    id_sk: &Path,
    id_pk: &Path,
    audit_sk: &Path,
    audit_pk: &Path,
    peer_dir: &Path,
    metrics_port: u16,
    tenants: &[(&str, u16)],
    audit_root: &Path,
) -> String {
    let mut s = String::new();
    // [rotation] block: 1-second max age, default poll interval (1s).
    // The monitor checks the file's mtime each poll; once it's >1s old,
    // it triggers rotation. Daemon-wide policy applies to every tenant
    // (no per-tenant overrides yet).
    s.push_str(&format!(
        "role = \"serve-pq\"\n\
         identity_key = \"{}\"\n\
         identity_pub = \"{}\"\n\
         metrics_listen = \"127.0.0.1:{metrics_port}\"\n\
         tenant_drain_timeout_secs = 5\n\
         \n\
         [audit_signer]\n\
         kind = \"softkey\"\n\
         secret_key = \"{}\"\n\
         public_key = \"{}\"\n\
         \n\
         [rotation]\n\
         max_age_secs = 1\n\
         poll_interval_ms = 100\n\
         \n",
        id_sk.display(),
        id_pk.display(),
        audit_sk.display(),
        audit_pk.display(),
    ));
    for (name, port) in tenants {
        let audit_log = audit_root.join(format!("{name}.qa"));
        s.push_str(&format!(
            "[[tenants]]\n\
             name = \"{name}\"\n\
             listen = \"127.0.0.1:{port}\"\n\
             backend = \"127.0.0.1:0\"\n\
             peer_pub_dir = \"{}\"\n\
             audit_log = \"{}\"\n\
             \n",
            peer_dir.display(),
            audit_log.display(),
        ));
    }
    s
}

struct DaemonGuard {
    child: Option<Child>,
}

impl DaemonGuard {
    fn spawn(config: &Path) -> Self {
        let child = Command::new(qgateway_bin())
            .arg("run")
            .arg("--config")
            .arg(config)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn");
        Self { child: Some(child) }
    }

    fn pid(&self) -> Pid {
        Pid::from_raw(self.child.as_ref().unwrap().id() as i32)
    }
}

impl Drop for DaemonGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = kill(Pid::from_raw(child.id() as i32), Signal::SIGTERM);
            std::thread::sleep(Duration::from_millis(500));
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn list_archives(root: &Path, tenant: &str) -> Vec<String> {
    let prefix = format!("{tenant}-");
    std::fs::read_dir(root)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with(&prefix) && n.ends_with(".qa"))
        .collect()
}

#[test]
fn auto_rotation_fires_for_runtime_added_tenant() {
    // Sprint 28 regression test: a tenant added via SIGHUP ADD must
    // get its OWN per-tenant auto-rotation monitor. Pre-fix, the
    // monitor was spawned only at startup — runtime-added tenants
    // would never auto-rotate.
    let fx = RotationFixture::build(&["alice"]);
    let daemon = DaemonGuard::spawn(&fx.config_path);

    assert!(
        wait_for_metrics(fx.metrics_port, Duration::from_secs(15)),
        "daemon /metrics did not come up within 15s"
    );

    // Wait for alice's startup monitor to fire at least once.
    // Sprint 35: poll_interval_ms=100 in the fixture, so the monitor
    // checks every 100ms; with max_age_secs=1, the file must be
    // ≥1s old. 1.5s gives one safe age+poll cycle.
    std::thread::sleep(Duration::from_millis(1500));
    let alice_archives = list_archives(&fx.root, "alice");
    assert!(
        !alice_archives.is_empty(),
        "alice's startup monitor did not auto-rotate within 1.5s. files: {:?}",
        list_root_files(&fx.root)
    );

    // Now add bob via SIGHUP. With the Sprint 28 fix, bob gets a
    // monitor task. Pre-fix, bob would never auto-rotate.
    let bob_port = pick_port();
    fx.write_config_with(&[("alice", fx.tenant_ports[0]), ("bob", bob_port)]);
    sighup(daemon.pid());

    // Give bob's log file time to age past max_age_secs AND for the
    // monitor to poll at least once. 1.5s = age threshold + several
    // 100ms polls past the SIGHUP processing.
    std::thread::sleep(Duration::from_millis(1500));

    let bob_archives = list_archives(&fx.root, "bob");
    assert!(
        !bob_archives.is_empty(),
        "bob (runtime-added) did not auto-rotate — Sprint 28 fix not active. files: {:?}",
        list_root_files(&fx.root)
    );

    // Verify the chain integrity of bob's archive.
    let bob_archive_path = fx.root.join(&bob_archives[0]);
    let bob_archive = AuditLog::open(&bob_archive_path).expect("bob archive parse");
    bob_archive
        .verify()
        .expect("bob archive must verify (cleanly closed chain)");
    // And bob's current log file (with fresh chain after rotation).
    let bob_current = AuditLog::open(fx.audit_log_for("bob")).expect("bob current parse");
    bob_current
        .verify()
        .expect("bob post-rotation current log must verify");
}

#[test]
fn auto_rotation_monitor_stopped_on_remove() {
    // Sprint 28: after SIGHUP REMOVE, the tenant's monitor task is
    // stopped (per-tenant Notify already signalled by the REMOVE
    // branch). We verify indirectly: count bob's archives just
    // after REMOVE, sleep past the auto-rotation poll period, then
    // count again. Should be unchanged.
    let fx = RotationFixture::build(&["alice"]);
    let daemon = DaemonGuard::spawn(&fx.config_path);

    assert!(
        wait_for_metrics(fx.metrics_port, Duration::from_secs(15)),
        "daemon /metrics did not come up within 15s"
    );

    let bob_port = pick_port();
    fx.write_config_with(&[("alice", fx.tenant_ports[0]), ("bob", bob_port)]);
    sighup(daemon.pid());
    std::thread::sleep(Duration::from_millis(1500));

    // Capture bob's archive count BEFORE remove.
    let bob_before = list_archives(&fx.root, "bob").len();
    assert!(
        bob_before >= 1,
        "bob should have rotated at least once before REMOVE (after 1.5s @ 100ms poll, max_age_secs=1)"
    );

    // Remove bob.
    fx.write_config_with(&[("alice", fx.tenant_ports[0])]);
    sighup(daemon.pid());
    std::thread::sleep(Duration::from_secs(1));

    // Bob's monitor is stopped now. Sleep past several poll intervals
    // — no new bob archives should appear (because (a) the monitor
    // task is gone, and (b) bob's audit channel is closed; the
    // rotation_handle on a closed channel is a no-op).
    // Sprint 35: poll_interval_ms=100 so 1.5s covers many poll
    // cycles.
    let bob_archives_just_after_remove = list_archives(&fx.root, "bob");
    std::thread::sleep(Duration::from_millis(1500));
    let bob_archives_later = list_archives(&fx.root, "bob");
    assert_eq!(
        bob_archives_just_after_remove.len(),
        bob_archives_later.len(),
        "bob's monitor still firing after REMOVE — Sprint 28 stop-on-REMOVE not active. before={bob_archives_just_after_remove:?} after={bob_archives_later:?}"
    );

    // Sanity check: alice's monitor IS still firing. With
    // poll_interval_ms=100, several polls + the >1s age threshold
    // need to elapse before a fresh rotation. 1.5s gives margin.
    let alice_before = list_archives(&fx.root, "alice").len();
    std::thread::sleep(Duration::from_millis(1500));
    let alice_after = list_archives(&fx.root, "alice").len();
    assert!(
        alice_after > alice_before,
        "alice's monitor stopped firing — Sprint 28 REMOVE bug broke survivor's monitor too. before={alice_before} after={alice_after}"
    );

    // Daemon still healthy — /metrics still responds.
    assert!(
        scrape_metrics(fx.metrics_port).is_ok(),
        "daemon /metrics gone after REMOVE"
    );
}

fn list_root_files(root: &Path) -> Vec<String> {
    std::fs::read_dir(root)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect()
}
