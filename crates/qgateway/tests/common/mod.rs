//! Shared fixture for qgateway integration tests.
//!
//! Sprint 25: extracted the daemon-spawn + config-gen + /metrics scrape
//! helpers from `sighup_integration.rs` into this common module so
//! Sprint 26's audit-chain test can reuse them.
//!
//! Cargo compiles each integration test (each top-level `tests/*.rs`)
//! as its own crate, so a helper used by only one of them looks
//! "dead" to the compiler when the other crate is being checked.
//! The blanket allow is the standard idiom for `tests/common/`.

#![allow(dead_code)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;

/// Path to the qgateway binary under test.
pub fn qgateway_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_qgateway"))
}

/// Pick an unused TCP port by binding to `127.0.0.1:0`.
pub fn pick_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    drop(l);
    port
}

/// Run a qgateway subcommand, panicking on failure.
pub fn run_subcmd(args: &[&str]) {
    let out = Command::new(qgateway_bin())
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .expect("spawning qgateway subcommand");
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        panic!("qgateway {args:?} failed: {stderr}");
    }
}

/// Fixture: temp dir with daemon transport identity + audit signer keys +
/// peer trust dir.
pub struct Fixture {
    pub config_path: PathBuf,
    pub metrics_port: u16,
    pub tenant_ports: Vec<u16>,
    pub root: PathBuf,
    pub audit_pub_path: PathBuf,
    pub _tmp: tempfile::TempDir,
}

impl Fixture {
    /// Build a fixture with `n_tenants` named "alice", "bob", "carol", ...
    pub fn build(tenant_names: &[&str]) -> Self {
        let tmp = tempfile::TempDir::new().expect("tempdir");
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
        let tenant_ports: Vec<u16> = tenant_names.iter().map(|_| pick_port()).collect();

        let config_path = root.join("sidecar.toml");
        let tenants: Vec<(&str, u16)> = tenant_names
            .iter()
            .copied()
            .zip(tenant_ports.iter().copied())
            .collect();
        let cfg = make_config(
            &id_sk,
            &id_pk,
            &audit_sk,
            &audit_pk,
            &peer_dir,
            metrics_port,
            &tenants,
            &root,
            None,
        );
        std::fs::write(&config_path, cfg).unwrap();

        Self {
            config_path,
            metrics_port,
            tenant_ports,
            root,
            audit_pub_path: audit_pk,
            _tmp: tmp,
        }
    }

    /// Path to a tenant's audit log file.
    pub fn audit_log_for(&self, name: &str) -> PathBuf {
        self.root.join(format!("{name}.qa"))
    }

    /// Rewrite the config file with a new tenant set; the daemon needs a
    /// SIGHUP to pick up the change.
    pub fn write_config_with(&self, tenants: &[(&str, u16)]) {
        let id_sk = self.root.join("daemon.skid");
        let id_pk = self.root.join("daemon.cspqid.pub");
        let audit_sk = self.root.join("audit.skid");
        let audit_pk = self.root.join("audit.pub");
        let peer_dir = self.root.join("peers");
        let cfg = make_config(
            &id_sk,
            &id_pk,
            &audit_sk,
            &audit_pk,
            &peer_dir,
            self.metrics_port,
            tenants,
            &self.root,
            None,
        );
        std::fs::write(&self.config_path, cfg).unwrap();
    }

    /// Sprint 30: like `write_config_with` but every tenant's backend
    /// points at `backend` instead of the placeholder `127.0.0.1:0`.
    /// Used by the session-events tests which need the daemon to be
    /// able to actually proxy bytes to a live echo server.
    pub fn write_config_with_backend(
        &self,
        tenants: &[(&str, u16)],
        backend: std::net::SocketAddr,
    ) {
        let id_sk = self.root.join("daemon.skid");
        let id_pk = self.root.join("daemon.cspqid.pub");
        let audit_sk = self.root.join("audit.skid");
        let audit_pk = self.root.join("audit.pub");
        let peer_dir = self.root.join("peers");
        let cfg = make_config(
            &id_sk,
            &id_pk,
            &audit_sk,
            &audit_pk,
            &peer_dir,
            self.metrics_port,
            tenants,
            &self.root,
            Some(backend),
        );
        std::fs::write(&self.config_path, cfg).unwrap();
    }
}

#[allow(clippy::too_many_arguments)]
fn make_config(
    id_sk: &Path,
    id_pk: &Path,
    audit_sk: &Path,
    audit_pk: &Path,
    peer_dir: &Path,
    metrics_port: u16,
    tenants: &[(&str, u16)],
    audit_root: &Path,
    backend_override: Option<std::net::SocketAddr>,
) -> String {
    let mut s = String::new();
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
         \n",
        id_sk.display(),
        id_pk.display(),
        audit_sk.display(),
        audit_pk.display(),
    ));
    let backend_str = backend_override
        .map(|a| a.to_string())
        .unwrap_or_else(|| "127.0.0.1:0".to_string());
    for (name, port) in tenants {
        let audit_log = audit_root.join(format!("{name}.qa"));
        s.push_str(&format!(
            "[[tenants]]\n\
             name = \"{name}\"\n\
             listen = \"127.0.0.1:{port}\"\n\
             backend = \"{backend_str}\"\n\
             peer_pub_dir = \"{}\"\n\
             audit_log = \"{}\"\n\
             \n",
            peer_dir.display(),
            audit_log.display(),
        ));
    }
    s
}

pub struct DaemonGuard {
    child: Option<Child>,
}

impl DaemonGuard {
    pub fn spawn(config: &Path) -> Self {
        let mut cmd = Command::new(qgateway_bin());
        cmd.arg("run")
            .arg("--config")
            .arg(config)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let child = cmd.spawn().expect("spawning qgateway run");
        Self { child: Some(child) }
    }

    pub fn pid(&self) -> Pid {
        Pid::from_raw(self.child.as_ref().unwrap().id() as i32)
    }

    /// Send SIGTERM and await graceful exit.
    pub fn shutdown_gracefully(mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = kill(Pid::from_raw(child.id() as i32), Signal::SIGTERM);
            // Give the daemon up to 10s to drain.
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            loop {
                match child.try_wait() {
                    Ok(Some(_)) => return,
                    Ok(None) => {
                        if std::time::Instant::now() >= deadline {
                            let _ = child.kill();
                            let _ = child.wait();
                            return;
                        }
                        std::thread::sleep(Duration::from_millis(100));
                    }
                    Err(_) => {
                        let _ = child.kill();
                        let _ = child.wait();
                        return;
                    }
                }
            }
        }
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

pub fn wait_for_metrics(port: u16, timeout: Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if scrape_metrics(port).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

pub fn scrape_metrics(port: u16) -> std::io::Result<String> {
    use std::io::Read;
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", port))?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")?;
    let mut buf = String::new();
    stream.read_to_string(&mut buf)?;
    Ok(buf)
}

pub fn counter_value(metrics: &str, name: &str) -> u64 {
    for line in metrics.lines() {
        if line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix(name) {
            if rest.starts_with(' ') || rest.starts_with('\t') {
                if let Some(v) = rest.split_whitespace().next() {
                    return v.parse().unwrap_or(0);
                }
            }
        }
    }
    0
}

/// Sprint 31: read a tenant-labelled Prometheus counter. Daemon-wide
/// counters use [`counter_value`]; per-tenant counters (which the
/// `qgateway-core` metrics module emits as
/// `<name>{tenant="<tenant>"} <value>`) need to match the label
/// suffix as well. Sums across all tenants matching `name` if
/// `tenant` is `None`; matches one tenant exactly if `Some`.
pub fn tenant_counter_value(metrics: &str, name: &str, tenant: Option<&str>) -> u64 {
    let mut total = 0u64;
    for line in metrics.lines() {
        if line.starts_with('#') {
            continue;
        }
        let Some(rest) = line.strip_prefix(name) else {
            continue;
        };
        if !rest.starts_with('{') {
            continue;
        }
        let close = match rest.find('}') {
            Some(i) => i,
            None => continue,
        };
        let labels = &rest[1..close];
        let value_part = rest[close + 1..].trim();
        let value: u64 = match value_part.split_whitespace().next() {
            Some(v) => v.parse().unwrap_or(0),
            None => 0,
        };
        if let Some(want) = tenant {
            let needle = format!("tenant=\"{want}\"");
            if labels.contains(&needle) {
                return value;
            }
        } else {
            total = total.saturating_add(value);
        }
    }
    total
}

pub fn sighup(pid: Pid) {
    kill(pid, Signal::SIGHUP).expect("SIGHUP daemon");
}
