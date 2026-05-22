//! # qaudit
//!
//! Command-line interface for post-quantum signed audit logs.
//!
//! ```text
//!   qaudit init    --log audit.qa  [--label "qvault-prod-sp"]
//!   qaudit append  --log audit.qa  --actor "svc:qvault" --action "object.put" --resource "vault://prod/x" [--meta k=v ...]
//!   qaudit verify  --log audit.qa
//!   qaudit inspect --log audit.qa  [--limit N] [--json]
//!   qaudit pubkey  --log audit.qa  [--out pub.bin] [--hex]
//!   qaudit info    --log audit.qa
//! ```

#![forbid(unsafe_code)]

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use qaudit_core::{AuditEvent, AuditLog, KeyPair, PublicKey, SecretKey};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "qaudit",
    version,
    about = "Post-quantum signed audit log — Cofre Soberano PQ.",
    long_about = "qaudit creates, appends to, and verifies append-only audit logs \
                  signed entry-by-entry with ML-DSA-87 (FIPS 204) and chained with \
                  BLAKE3 over a Merkle Mountain Range. Logs are offline-verifiable \
                  by any party holding the public key."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Initialize a new log and write its key files.
    Init(InitArgs),
    /// Append a new event to an existing log.
    Append(AppendArgs),
    /// Verify every signature and chain link in a log.
    Verify(VerifyArgs),
    /// Inspect a log's contents.
    Inspect(InspectArgs),
    /// Export the log's public key.
    Pubkey(PubkeyArgs),
    /// Show header metadata only.
    Info(InfoArgs),
    /// Export the log for a regulator (Bacen XML or NDJSON).
    Export(ExportArgs),
    /// Sprint 7.5: rotate a log offline — appends `rotation_close` to the
    /// input log, creates a new file with `rotation_open` as its first
    /// event, preserves cryptographic chain integrity between the two.
    Rotate(RotateArgs),
    /// Sprint 7.5: verify a multi-file rotation chain. Pass each file in
    /// order from the chain root forward; every adjacent pair is checked
    /// for `prev_log_id` / `prev_log_final_root` consistency and the
    /// rotation_close → rotation_open sentinels are validated.
    VerifyChain(VerifyChainArgs),
}

#[derive(clap::Args, Debug)]
struct InitArgs {
    /// Path to the new log file (`.qa`).
    #[arg(long)]
    log: PathBuf,
    /// Path where the secret key will be stored (raw FIPS 204 bytes, mode 0600).
    ///
    /// If omitted, defaults to `<log-stem>.sk` next to the log file.
    /// Example: `--log /var/audit/tenant-a.qa` produces `/var/audit/tenant-a.sk`.
    #[arg(long)]
    sk: Option<PathBuf>,
    /// Path where the public key will be stored (raw FIPS 204 bytes).
    ///
    /// If omitted, defaults to `<log-stem>.pk` next to the log file.
    #[arg(long)]
    pk: Option<PathBuf>,
    /// Human-readable label written to the log header.
    #[arg(long, default_value = "")]
    label: String,
    /// Overwrite existing files at the target paths.
    #[arg(long)]
    force: bool,
}

#[derive(clap::Args, Debug)]
struct AppendArgs {
    /// Path to an existing log file.
    #[arg(long)]
    log: PathBuf,
    /// Secret key file (raw FIPS 204 bytes).
    ///
    /// If omitted, defaults to `<log-stem>.sk` next to the log file.
    /// Falls back to `qaudit.sk` in `$PWD` for backwards compatibility
    /// with v1.0.0 layouts.
    #[arg(long)]
    sk: Option<PathBuf>,
    /// Public key file (raw FIPS 204 bytes). Must match the log's header.
    ///
    /// If omitted, defaults to `<log-stem>.pk` next to the log file.
    /// Falls back to `qaudit.pk` in `$PWD` for backwards compatibility
    /// with v1.0.0 layouts.
    #[arg(long)]
    pk: Option<PathBuf>,
    /// Event actor (e.g. `"svc:qvault"`, `"user:joao.silva"`).
    #[arg(long)]
    actor: String,
    /// Event action verb (e.g. `"object.put"`, `"login"`).
    #[arg(long)]
    action: String,
    /// Resource identifier (e.g. `"vault://prod/file.pdf"`).
    #[arg(long, default_value = "")]
    resource: String,
    /// Outcome label (default `ok`).
    #[arg(long, default_value = "ok")]
    outcome: String,
    /// Metadata key=value pair (repeatable).
    #[arg(long = "meta", value_parser = parse_kv)]
    meta: Vec<(String, String)>,
}

#[derive(clap::Args, Debug)]
struct VerifyArgs {
    /// Path to the log file to verify.
    #[arg(long)]
    log: PathBuf,
    /// Optional independent public key to verify against (must match header).
    #[arg(long)]
    pk: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
struct InspectArgs {
    /// Path to the log file.
    #[arg(long)]
    log: PathBuf,
    /// Limit the number of entries shown.
    #[arg(long)]
    limit: Option<usize>,
    /// Emit each entry as a single JSON object per line.
    #[arg(long)]
    json: bool,
}

#[derive(clap::Args, Debug)]
struct PubkeyArgs {
    /// Path to the log file.
    #[arg(long)]
    log: PathBuf,
    /// Write key to this file (binary).
    #[arg(long)]
    out: Option<PathBuf>,
    /// Print hex to stdout instead of binary.
    #[arg(long)]
    hex: bool,
}

#[derive(clap::Args, Debug)]
struct InfoArgs {
    /// Path to the log file.
    #[arg(long)]
    log: PathBuf,
}

/// Output format for `qaudit export`.
#[derive(clap::ValueEnum, Clone, Copy, Debug)]
enum ExportFormat {
    /// Bacen/CVM/ANPD XML schema v1 (default).
    Xml,
    /// Newline-delimited JSON, one entry per line.
    Jsonl,
}

#[derive(clap::Args, Debug)]
struct ExportArgs {
    /// Path to the log file.
    #[arg(long)]
    log: PathBuf,
    /// Output format.
    #[arg(long, value_enum, default_value_t = ExportFormat::Xml)]
    format: ExportFormat,
    /// Output file path. Stdout if omitted.
    #[arg(long)]
    out: Option<PathBuf>,
    /// Skip the pre-export verification step. NOT RECOMMENDED.
    #[arg(long)]
    no_verify: bool,
}

fn parse_kv(s: &str) -> Result<(String, String), String> {
    let (k, v) = s
        .split_once('=')
        .ok_or_else(|| format!("expected key=value, got `{s}`"))?;
    Ok((k.to_string(), v.to_string()))
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let result = match cli.cmd {
        Cmd::Init(a) => cmd_init(a),
        Cmd::Append(a) => cmd_append(a),
        Cmd::Verify(a) => cmd_verify(a),
        Cmd::Inspect(a) => cmd_inspect(a),
        Cmd::Pubkey(a) => cmd_pubkey(a),
        Cmd::Info(a) => cmd_info(a),
        Cmd::Export(a) => cmd_export(a),
        Cmd::Rotate(a) => cmd_rotate(a),
        Cmd::VerifyChain(a) => cmd_verify_chain(a),
    };

    // Treat a closed downstream pipe as a clean exit (Unix convention).
    // Without this, `qaudit inspect | head` panics on the SIGPIPE that
    // the runtime turns into a write-stdout failure.
    if let Err(ref e) = result {
        if let Some(io_err) = e.downcast_ref::<std::io::Error>() {
            if io_err.kind() == std::io::ErrorKind::BrokenPipe {
                return Ok(());
            }
        }
    }
    result
}

fn ensure_overwritable(path: &std::path::Path, force: bool) -> Result<()> {
    if path.exists() && !force {
        anyhow::bail!(
            "refusing to overwrite existing file {} (pass --force)",
            path.display()
        );
    }
    Ok(())
}

fn write_secret(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .with_context(|| format!("opening {} for write", path.display()))?;
    f.write_all(bytes)?;
    f.flush()?;
    Ok(())
}

fn cmd_init(a: InitArgs) -> Result<()> {
    let sk_path = a.sk.unwrap_or_else(|| derive_key_path(&a.log, "sk"));
    let pk_path = a.pk.unwrap_or_else(|| derive_key_path(&a.log, "pk"));

    ensure_overwritable(&a.log, a.force)?;
    ensure_overwritable(&sk_path, a.force)?;
    ensure_overwritable(&pk_path, a.force)?;

    let kp = KeyPair::generate().context("ML-DSA-87 keygen failed")?;
    let pk_bytes = kp.public().as_bytes().to_vec();
    let sk_bytes = kp.secret().as_bytes().to_vec();

    write_secret(&sk_path, &sk_bytes)?;
    std::fs::write(&pk_path, &pk_bytes)
        .with_context(|| format!("writing public key {}", pk_path.display()))?;

    let log = AuditLog::create_with_label(kp, a.label.clone()).context("creating audit log")?;
    log.save(&a.log)
        .with_context(|| format!("writing log {}", a.log.display()))?;

    eprintln!("qaudit: initialized");
    eprintln!("  log:        {}", a.log.display());
    eprintln!(
        "  public key: {} ({} bytes)",
        pk_path.display(),
        pk_bytes.len()
    );
    eprintln!(
        "  secret key: {} ({} bytes, mode 0600 on unix)",
        sk_path.display(),
        sk_bytes.len()
    );
    eprintln!("  log id:     {}", log.header().log_id);
    eprintln!("  suite:      {}", log.header().suite);
    if !a.label.is_empty() {
        eprintln!("  label:      {}", a.label);
    }
    eprintln!();
    eprintln!("To append entries later:");
    eprintln!(
        "  qaudit append --log {} --sk {} --pk {} \\",
        a.log.display(),
        sk_path.display(),
        pk_path.display()
    );
    eprintln!("                --actor ... --action ... --resource ...");
    Ok(())
}

/// Derive `<log-stem>.<ext>` next to the log file. Falls back to
/// `qaudit.<ext>` in the current directory if the log path has no stem
/// (e.g. just `/` or empty).
fn derive_key_path(log_path: &std::path::Path, ext: &str) -> PathBuf {
    let parent = log_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    let stem = log_path
        .file_stem()
        .map(|s| s.to_owned())
        .unwrap_or_else(|| std::ffi::OsString::from("qaudit"));
    let mut name = stem;
    name.push(".");
    name.push(ext);
    parent.join(name)
}

/// v1.0.1: resolve a `--sk`/`--pk` path for `qaudit append`, with three
/// stages, in order:
///
/// 1. **Explicit flag** — if the user passed `--sk path` or `--pk path`,
///    use that verbatim.
/// 2. **Derived next to the log** — `<log-stem>.<ext>` next to the log file
///    (matches what `qaudit init` writes by default in v1.0.1).
/// 3. **Legacy fallback** — `qaudit.<ext>` in `$PWD` (matches v1.0.0
///    layout where `qaudit init` always wrote fixed filenames).
///
/// Returns the first stage that actually points to an existing file. If
/// none exists, returns the v1.0.1 derived path so the error message
/// surfaces the *new* convention to the operator.
fn resolve_key_path(
    explicit: Option<&std::path::Path>,
    log_path: &std::path::Path,
    ext: &str,
) -> Result<PathBuf> {
    if let Some(p) = explicit {
        return Ok(p.to_path_buf());
    }
    let derived = derive_key_path(log_path, ext);
    if derived.exists() {
        return Ok(derived);
    }
    // Legacy fallback for v1.0.0 layouts.
    let legacy = PathBuf::from(format!("qaudit.{ext}"));
    if legacy.exists() {
        return Ok(legacy);
    }
    // Neither exists; return the v1.0.1 path so the caller's error
    // message points at the modern convention.
    Ok(derived)
}

fn load_keypair(sk_path: &std::path::Path, pk_path: &std::path::Path) -> Result<KeyPair> {
    let sk_bytes = std::fs::read(sk_path)
        .with_context(|| format!("reading secret key {}", sk_path.display()))?;
    let pk_bytes = std::fs::read(pk_path)
        .with_context(|| format!("reading public key {}", pk_path.display()))?;
    let sk = SecretKey::from_bytes(&sk_bytes).context("decoding secret key")?;
    let pk = PublicKey::from_bytes(&pk_bytes).context("decoding public key")?;
    Ok(KeyPair::from_parts(pk, sk))
}

fn cmd_append(a: AppendArgs) -> Result<()> {
    let mut log =
        AuditLog::open(&a.log).with_context(|| format!("opening log {}", a.log.display()))?;

    let sk_path = resolve_key_path(a.sk.as_deref(), &a.log, "sk")?;
    let pk_path = resolve_key_path(a.pk.as_deref(), &a.log, "pk")?;

    let kp = load_keypair(&sk_path, &pk_path)?;
    if kp.public().as_bytes() != log.header().pubkey.as_bytes() {
        anyhow::bail!(
            "supplied --pk does not match the log's stored public key; refusing to append"
        );
    }

    let event = AuditEvent::builder()
        .actor(a.actor.clone())
        .action(a.action.clone())
        .resource(a.resource.clone())
        .outcome(a.outcome.clone());
    let event = a
        .meta
        .iter()
        .fold(event, |b, (k, v)| b.meta(k.clone(), v.clone()))
        .build();

    log.bind_keypair(kp)
        .context("rebinding signing keypair to loaded log")?;
    let entry = log.append(event).context("signing & appending entry")?;
    let idx = entry.index;
    let root_hex = hex::encode(entry.new_root);

    log.save(&a.log)
        .with_context(|| format!("rewriting log {}", a.log.display()))?;

    eprintln!("qaudit: appended");
    eprintln!("  index:    {idx}");
    eprintln!("  new root: {root_hex}");
    Ok(())
}

fn cmd_verify(a: VerifyArgs) -> Result<()> {
    let mut log =
        AuditLog::open(&a.log).with_context(|| format!("opening log {}", a.log.display()))?;
    if let Some(pk_path) = a.pk.as_ref() {
        let pk_bytes = std::fs::read(pk_path)
            .with_context(|| format!("reading public key {}", pk_path.display()))?;
        let pk = qaudit_core::decode_pubkey_any(&pk_bytes).context("decoding public key")?;
        if pk.as_bytes() != log.header().pubkey.as_bytes() {
            anyhow::bail!("supplied --pk does not match the log's header pubkey");
        }
        log.override_pubkey(pk);
    }
    log.verify().context("audit log failed verification")?;
    println!(
        "ok: {} entries verified, root = {}",
        log.len(),
        hex::encode(log.current_root())
    );
    Ok(())
}

fn cmd_inspect(a: InspectArgs) -> Result<()> {
    use std::io::Write;
    let log = AuditLog::open(&a.log).with_context(|| format!("opening log {}", a.log.display()))?;
    let n = log.len() as usize;
    let take = a.limit.unwrap_or(n).min(n);
    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    if a.json {
        for e in log.entries().iter().take(take) {
            let v = serde_json::json!({
                "index": e.index,
                "appended_at": e.appended_at,
                "actor": e.event.actor,
                "action": e.event.action,
                "resource": e.event.resource,
                "outcome": e.event.outcome,
                "metadata": e.event.metadata,
                "prev_root": hex::encode(e.prev_root),
                "new_root": hex::encode(e.new_root),
                "signature_prefix": hex::encode(&e.signature.as_bytes()[..16]),
            });
            writeln!(out, "{v}")?;
        }
    } else {
        writeln!(
            out,
            "log_id = {}   suite = {}   entries = {}",
            log.header().log_id,
            log.header().suite,
            log.len()
        )?;
        if !log.header().label.is_empty() {
            writeln!(out, "label  = {}", log.header().label)?;
        }
        writeln!(out)?;
        for e in log.entries().iter().take(take) {
            writeln!(
                out,
                "[{:>6}] {}  {} :: {} -> {} ({})",
                e.index,
                e.appended_at.format("%Y-%m-%d %H:%M:%SZ"),
                e.event.actor,
                e.event.action,
                e.event.resource,
                e.event.outcome
            )?;
            if !e.event.metadata.is_empty() {
                for (k, v) in &e.event.metadata {
                    writeln!(out, "           meta.{k} = {v}")?;
                }
            }
            writeln!(out, "           root = {}", hex::encode(e.new_root))?;
        }
        if take < n {
            writeln!(
                out,
                "\n…{} more entries omitted (use --limit to widen)",
                n - take
            )?;
        }
    }
    Ok(())
}

fn cmd_pubkey(a: PubkeyArgs) -> Result<()> {
    let log = AuditLog::open(&a.log).with_context(|| format!("opening log {}", a.log.display()))?;
    let bytes = log.header().pubkey.as_bytes();
    if let Some(out) = a.out.as_ref() {
        std::fs::write(out, bytes).with_context(|| format!("writing {}", out.display()))?;
        eprintln!("qaudit: wrote {} bytes to {}", bytes.len(), out.display());
    } else if a.hex {
        println!("{}", hex::encode(bytes));
    } else {
        use std::io::Write;
        std::io::stdout().lock().write_all(bytes)?;
    }
    Ok(())
}

fn cmd_info(a: InfoArgs) -> Result<()> {
    let log = AuditLog::open(&a.log).with_context(|| format!("opening log {}", a.log.display()))?;
    let h = log.header();
    println!("log file:      {}", a.log.display());
    println!("log_id:        {}", h.log_id);
    println!("suite:         {}", h.suite);
    println!("wire_version:  {}", h.wire_version);
    println!("created_at:    {}", h.created_at);
    println!(
        "label:         {}",
        if h.label.is_empty() {
            "<none>"
        } else {
            h.label.as_str()
        }
    );
    println!(
        "pubkey:        {}… ({} bytes)",
        hex::encode(&h.pubkey.as_bytes()[..16]),
        h.pubkey.as_bytes().len()
    );
    println!("entries:       {}", log.len());
    println!("current root:  {}", hex::encode(log.current_root()));
    Ok(())
}

fn cmd_export(a: ExportArgs) -> Result<()> {
    let log = AuditLog::open(&a.log).with_context(|| format!("opening log {}", a.log.display()))?;
    if !a.no_verify {
        log.verify()
            .context("pre-export verification failed; refusing to export an invalid log")?;
    }
    let payload = match a.format {
        ExportFormat::Xml => qaudit_core::export_xml(&log).context("XML export")?,
        ExportFormat::Jsonl => qaudit_core::export_jsonl(&log).context("JSONL export")?,
    };
    if let Some(out) = a.out.as_ref() {
        std::fs::write(out, payload.as_bytes())
            .with_context(|| format!("writing {}", out.display()))?;
        eprintln!(
            "qaudit: wrote {} bytes to {} (format: {:?})",
            payload.len(),
            out.display(),
            a.format
        );
    } else {
        use std::io::Write;
        std::io::stdout().lock().write_all(payload.as_bytes())?;
    }
    Ok(())
}

// ============================================================================
//              Sprint 7.5 — `qaudit rotate` + `qaudit verify-chain`
// ============================================================================

#[derive(clap::Args, Debug)]
struct RotateArgs {
    /// Path to the CURRENT log file (will be modified: `rotation_close` event
    /// will be appended in place; the resulting file is sealed and read-only
    /// from the daemon's perspective).
    #[arg(long)]
    r#in: PathBuf,
    /// Path where the NEW log file will be created (must not exist unless
    /// `--force` is passed). Its first event is `rotation_open`.
    #[arg(long)]
    out: PathBuf,
    /// Path to the audit secret key file (raw FIPS 204 ML-DSA-87 bytes).
    /// The same key signs both the `rotation_close` event on the input and
    /// the `rotation_open` event on the output. For cross-key rotation (a
    /// rare incident-response case), use the library API directly.
    #[arg(long)]
    sk: PathBuf,
    /// Path to the audit public key file. Verified to match the input log's
    /// header before any modification — guards against using the wrong key.
    #[arg(long)]
    pk: PathBuf,
    /// Label for the new log (e.g. `"audit-2026-02"`). Stored in the new
    /// header and referenced from the old log's `rotation_close.metadata`.
    #[arg(long)]
    new_label: String,
    /// Optional pre-computed log id for the new log (32-char hex). Empty or
    /// absent = randomly generated. Useful for reproducible scripted
    /// rotation in tests / CI.
    #[arg(long, default_value = "")]
    new_log_id: String,
    /// Sprint 9: optional NEW secret key path for cross-key rotation. When
    /// supplied together with `--new-pk`, the new log segment is signed
    /// under a DIFFERENT audit key than the old segment — the canonical
    /// incident-response workflow when a previous audit key is suspected
    /// compromised. The old log's `rotation_close` is still signed with
    /// the old `--sk`; only `rotation_open` and subsequent events use the
    /// new key. Verification of the resulting chain works per-segment.
    #[arg(long)]
    new_sk: Option<PathBuf>,
    /// Sprint 9: optional NEW public key path. Must be supplied together
    /// with `--new-sk`. The factory mints the new signer from this pair.
    #[arg(long)]
    new_pk: Option<PathBuf>,
    /// Overwrite an existing --out file. Default: refuse.
    #[arg(long)]
    force: bool,
}

#[derive(clap::Args, Debug)]
struct VerifyChainArgs {
    /// Path to each log file in the chain, in order from the root forward.
    /// Repeat `--log` once per file: `--log a.qa --log b.qa --log c.qa`.
    /// Two-file chains are the minimum; single-file "chains" should use
    /// `qaudit verify` instead.
    #[arg(long, required = true)]
    log: Vec<PathBuf>,
    /// Optional audit public key — if supplied, must match every log's
    /// stored header pubkey. Cross-key chains (different pubkey per
    /// segment) are detected automatically and verified per-segment; do not
    /// pass `--pk` in that case.
    #[arg(long)]
    pk: Option<PathBuf>,
}

fn cmd_rotate(a: RotateArgs) -> Result<()> {
    use qaudit_core::Signer;

    if a.out.exists() && !a.force {
        anyhow::bail!(
            "refusing to overwrite existing --out file {} (pass --force)",
            a.out.display()
        );
    }
    // Sprint 9: validate cross-key flags together. Either both or neither.
    let cross_key = match (a.new_sk.as_ref(), a.new_pk.as_ref()) {
        (Some(_), Some(_)) => true,
        (None, None) => false,
        (Some(_), None) | (None, Some(_)) => {
            anyhow::bail!(
                "--new-sk and --new-pk must be supplied together (cross-key rotation), \
                 or both omitted (same-key rotation)"
            );
        }
    };

    let mut old =
        AuditLog::open(&a.r#in).with_context(|| format!("opening log {}", a.r#in.display()))?;
    let kp = load_keypair(&a.sk, &a.pk)?;
    if kp.public().as_bytes() != old.header().pubkey.as_bytes() {
        anyhow::bail!(
            "supplied --pk does not match the input log's stored public key; \
             rotation refused (use the correct audit key, or for cross-key \
             rotation use the library API)"
        );
    }
    old.bind_keypair(kp.clone())
        .context("rebinding signing keypair to loaded log")?;

    // Sprint 9: pick the new signer based on cross-key flags.
    let new_signer: Box<dyn Signer> = if cross_key {
        let new_sk = a.new_sk.as_ref().expect("validated above");
        let new_pk = a.new_pk.as_ref().expect("validated above");
        let new_kp = load_keypair(new_sk, new_pk).with_context(|| {
            format!(
                "loading new audit keypair (--new-sk={}, --new-pk={})",
                new_sk.display(),
                new_pk.display()
            )
        })?;
        if new_kp.public().as_bytes() == kp.public().as_bytes() {
            anyhow::bail!(
                "--new-sk/--new-pk are the SAME audit key as --sk/--pk; either omit \
                 the --new-* flags for same-key rotation, or supply a different key"
            );
        }
        Box::new(new_kp)
    } else {
        // Same-key rotation: a fresh handle on the same key.
        Box::new(kp) as Box<dyn Signer>
    };

    let (sealed_old, new_open) = old
        .rotate_to(new_signer, &a.new_label, &a.new_log_id)
        .context("rotating log")?;

    sealed_old
        .save(&a.r#in)
        .with_context(|| format!("rewriting sealed input log {}", a.r#in.display()))?;
    new_open
        .save(&a.out)
        .with_context(|| format!("writing new log {}", a.out.display()))?;

    eprintln!(
        "qaudit: rotated{}",
        if cross_key { " (cross-key)" } else { "" }
    );
    eprintln!(
        "  sealed:  {} ({} entries)",
        a.r#in.display(),
        sealed_old.len()
    );
    eprintln!("    final root: {}", hex::encode(sealed_old.current_root()));
    eprintln!(
        "    new_log_id: {}",
        hex::encode(new_open.header().log_id.0)
    );
    eprintln!(
        "  new:     {} ({} entries)",
        a.out.display(),
        new_open.len()
    );
    eprintln!("    label: {:?}", new_open.header().label);
    if cross_key {
        eprintln!(
            "    new pubkey: {}",
            hex::encode(new_open.header().pubkey.as_bytes())
        );
        eprintln!("  NOTE: new segment uses a DIFFERENT audit key.");
        eprintln!("        Verify each segment under its own header pubkey;");
        eprintln!("        DO NOT pass --pk to `qaudit verify-chain` on this chain.");
    }
    Ok(())
}

fn cmd_verify_chain(a: VerifyChainArgs) -> Result<()> {
    if a.log.len() < 2 {
        anyhow::bail!(
            "verify-chain requires at least 2 --log arguments; for a single              file use `qaudit verify`"
        );
    }

    let mut logs: Vec<AuditLog> = Vec::with_capacity(a.log.len());
    for path in &a.log {
        let mut log =
            AuditLog::open(path).with_context(|| format!("opening log {}", path.display()))?;
        if let Some(pk_path) = a.pk.as_ref() {
            let pk_bytes = std::fs::read(pk_path)
                .with_context(|| format!("reading public key {}", pk_path.display()))?;
            let pk = qaudit_core::decode_pubkey_any(&pk_bytes).context("decoding public key")?;
            if pk.as_bytes() != log.header().pubkey.as_bytes() {
                anyhow::bail!(
                    "supplied --pk does not match log {} header pubkey                      (cross-key chain detected — omit --pk to verify per-segment)",
                    path.display()
                );
            }
            log.override_pubkey(pk);
        }
        logs.push(log);
    }

    let refs: Vec<&AuditLog> = logs.iter().collect();
    AuditLog::verify_chain(&refs).context("audit chain failed verification")?;

    let total_entries: u64 = logs.iter().map(|l| l.len()).sum();
    let final_root_hex = hex::encode(logs.last().unwrap().current_root());
    println!(
        "ok: {} logs, {} entries total, terminal root = {}",
        logs.len(),
        total_entries,
        final_root_hex
    );
    for (i, log) in logs.iter().enumerate() {
        println!(
            "  [{i}] {} entries — log_id={} label={:?}",
            log.len(),
            hex::encode(log.header().log_id.0),
            log.header().label
        );
    }
    Ok(())
}
