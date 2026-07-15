# Changelog

🇧🇷 **Português:** [CHANGELOG.pt-BR.md](CHANGELOG.pt-BR.md)

All notable changes to this project will be documented in this file.

The format is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The **wire protocol** and **`.qa` audit log format** are governed by an
explicit `suite` identifier in every chain header
(`suite = "cspq-2026"` in this release). Any change that breaks
suite-compatibility will require both a major version bump **and** a
new suite identifier.

---

## [1.0.2] — 2026-07-15

Documentation-accuracy and HSM-hardening release. **No wire-protocol,
`.qa` file-format, or audit-suite change** — `1.0.0` ↔ `1.0.1` ↔ `1.0.2`
are fully compatible in both directions, and mixed-version deployments
remain safe (`suite = "cspq-2026"`).

### Fixed

- **PKCS#11 key lookup now filters on `CKA_CLASS`.**
  `find_key_by_label` matched on `CKA_LABEL` alone and returned the first
  object found. Because the audit private and public keys are allowed to
  share a label (`pubkey_label` defaults to `key_label`), the lookup could
  return the public-key handle where a private-key handle was required,
  making `C_Sign` fail. The lookup now constrains the search to
  `CKO_PRIVATE_KEY` / `CKO_PUBLIC_KEY` as appropriate.
  (`crates/qaudit-hsm/src/pkcs11.rs`)

- **HSM signing context requirement is now documented honestly.** A code
  comment claimed the ML-DSA domain-separation context was "applied by
  qaudit-core before calling sign()". It is not: the context
  (`b"cofre-soberano-pq/qaudit/v1"`) is applied *inside* the software
  signer via FIPS-204 `try_sign(msg, ctx)`, so an HSM mechanism that does
  not bind the same context produces signatures that fail
  `qaudit_core::verify`. The comment now states the parity requirement and
  points operators at the `live_hsm_sign_verify` gate they must run before
  trusting an HSM in production. (`crates/qaudit-hsm/src/pkcs11.rs`)

- **`docs/SMOKE_TEST.md` `sidecar.toml` examples now parse.** The client
  and server examples used keys the loader rejects
  (`identity_sk`/`identity_pk`, top-level `audit_sk`/`audit_pk`,
  `[[tenant]]`, `peer_dir`). They now use the real schema
  (`identity_key`/`identity_pub`, an `[audit_signer]` block, `[[tenants]]`,
  `peer_pub_dir`) and were verified with `qgateway validate`.

- **Runbook/HSM docs no longer reference a nonexistent subcommand.**
  `docs/RUNBOOK.md` and `docs/HSM.md` invoked `qgateway audit-verify
  --pubkey …`, which does not exist. Replaced with the real
  `qaudit verify --pk …` (which accepts the framed `.audit.pub` produced
  by `qgateway audit-keygen`).

- **Documentation metric names and samples corrected.** The admission
  module documented a nonexistent `qgateway_admission_rejected_total{reason=…}`
  metric — the exporter emits `qgateway_admission_rejected_quota_total` and
  `qgateway_admission_rejected_rate_total`, each with a `tenant="…"` label.
  The HSM metrics sample in `docs/HSM.md` was missing that mandatory
  `tenant="…"` label. The audit-emitter doc claimed backpressure "drops the
  oldest" entry — `emit()` uses `try_send`, so it drops the newest
  (incoming) entry and preserves already-queued ones. The `.audit.pub` /
  `.audit.skid` magic in `crates/qgateway-core/src/auditkey.rs` was
  documented as `AUDITPK01`/`AUDITSK01`; the real 8-byte magic is
  `AUDITPK0`/`AUDITSK0`. The `README.md` portal example passed
  `--pk qaudit.pk`; `qaudit init` writes `audit.pk`.

- **`qaudit-portal` module docs corrected.** The crate doc described a
  "paginated entry table", but the HTML view renders the full table
  (pagination exists only on the JSON `/api/entries` endpoint); and an
  orphaned `///` doc comment was being attached to `main()`.

### Added

- **Brazilian Portuguese (pt-BR) documentation.** Faithful translations of
  the flagship docs for the Brazil-first audience (Bacen, CVM, ANPD,
  SUSEP): `README.pt-BR.md`, `docs/RUNBOOK.pt-BR.md`, `docs/HSM.pt-BR.md`,
  `docs/SMOKE_TEST.pt-BR.md`, and `CHANGELOG.pt-BR.md`. All code, commands,
  configuration keys, flags, and crypto identifiers are preserved verbatim;
  the English documents remain normative for licensing terms.

### Changed

- Clippy hygiene: collapsed two `else { if … }` blocks flagged by
  `clippy::collapsible_else_if` (`crates/qgateway-core/src/gateway.rs`,
  `crates/qgateway-core/src/tls.rs`) and removed an unused test import
  under `--features pkcs11`. No behavioural change. Workspace is clippy-clean
  on both the default feature set and `--features qaudit-hsm/pkcs11`.

### Wire / format compatibility

`1.0.1` ↔ `1.0.2`: **fully compatible**. No changes to the wire protocol,
the `.qa` file format, or the audit suite identifier.

---

## [1.0.1] — 2026-05-22

### Fixed

- **`qaudit inspect` no longer panics on broken pipe.** Piping
  `qaudit inspect` into `head`, `less`, or any consumer that closes its
  stdin early used to surface as
  `thread 'main' panicked … failed printing to stdout: Broken pipe`.
  Output now goes through a locked stdout handle and the `main` entry
  point treats `ErrorKind::BrokenPipe` as a clean exit (Unix
  convention). Exit code is 0 in this case.
  (`crates/qaudit/src/main.rs`)

- **All `--pk` flags accept both raw and framed public-key formats.**
  v1.0.0 required exactly 2592 bytes of raw ML-DSA-87 public-key
  material everywhere it took a `--pk` flag (`qaudit verify`,
  `qaudit verify-chain`, `qaudit-portal`), and rejected the 2600-byte
  format produced by `qgateway audit-keygen` (which prefixes 8 bytes of
  `AUDITPK0` magic). The decoder is now shared in `qaudit-core` as the
  public `decode_pubkey_any` function, used by all three call sites.
  Auto-detection is by length, with the magic verified for the framed
  case; bogus 2600-byte files without the magic prefix are rejected
  with a clear diagnostic. Lib tests in `qaudit-core` plus CLI
  integration tests in `qaudit` cover both happy paths and both
  rejection paths. (`crates/qaudit-core/src/signing.rs`,
  `crates/qaudit/src/main.rs`,
  `crates/qaudit-portal/src/main.rs`,
  `crates/qaudit/tests/cli_framed_pubkey.rs`)

- **`qaudit init` no longer overwrites peer keys silently when run in
  the same directory.** v1.0.0 defaulted `--sk qaudit.sk` /
  `--pk qaudit.pk` regardless of the `--log` argument, so two
  `init` invocations in the same directory destroyed the first log's
  signing key without warning. Defaults are now derived from the log
  filename: `--log /var/audit/tenant-a.qa` produces
  `/var/audit/tenant-a.sk` and `/var/audit/tenant-a.pk`. Explicit
  `--sk` / `--pk` continue to override. Three integration tests added
  covering the derived-default, explicit-override, and refuse-overwrite
  paths. (`crates/qaudit/src/main.rs`,
  `crates/qaudit/tests/cli_init_defaults.rs`)

- **`qaudit append` resolves `--sk` and `--pk` from the log filename
  by default.** v1.0.0 hardcoded `qaudit.sk` and `qaudit.pk` in
  `$PWD`, which meant `append` only worked when the operator first
  `cd`'d to the key directory and never had more than one log in that
  directory. v1.0.1 derives `<log-stem>.sk` and `<log-stem>.pk` next
  to the log file. A v1.0.0-compatibility fallback to legacy
  `qaudit.sk` / `qaudit.pk` in `$PWD` is preserved so existing
  deployments do not break on upgrade. Four CLI integration tests
  cover derived-default, no-collision-across-logs, legacy fallback,
  and explicit override. (`crates/qaudit/src/main.rs`,
  `crates/qaudit/tests/cli_append_defaults.rs`)

### Added

- **`docs/SMOKE_TEST.md`** — operator-agnostic end-to-end production
  validation procedure. Two hosts, public internet, real PQ handshake,
  audit chain cross-verified. Includes reference numbers from a
  Brazil ↔ Germany run over a VPN exit.

- **`CHANGELOG.md`** — this file.

### Changed

- `README.md` documents the new key-derivation behaviour of
  `qaudit init` and links the smoke-test guide.

### Wire / format compatibility

`1.0.0` ↔ `1.0.1`: **fully compatible**. No changes to the wire
protocol, no changes to the `.qa` file format, no changes to the
audit suite identifier. Logs written under 1.0.0 verify under 1.0.1
and vice versa. Mixed-version deployments are safe.

---

## [1.0.0] — 2026-05-20

First stable public release. Cuts off the v0.x sprint sequence; from
this point forward, semver applies.

### Highlights

- **QAudit**: PQ-signed Merkle audit log (ML-DSA-87 / FIPS 204 +
  BLAKE3 MMR), CLI, library, HSM-pluggable signer, read-only web
  portal for auditors.
- **QTransport CSPQ**: reference post-quantum transport (ML-KEM-1024 /
  FIPS 203 + ML-DSA-87 + ChaCha20-Poly1305 + HKDF-SHA3-256). Forward
  secrecy, mutual authentication, replay protection.
- **QGateway**: sidecar reverse-proxy daemon. Drop in front of any
  TCP service; clients keep talking plain TCP locally, the gateway
  tunnels CSPQ to the peer. Multi-tenant, multi-listener, hot-reload
  via SIGHUP, audit emission per session.
- 227 tests under `--locked`, zero `unsafe` outside vetted FFI,
  `cargo clippy -- -D warnings` clean, build reproducible via pinned
  `Cargo.lock` and `rust-toolchain.toml`.
- AGPL-3.0-only source license with a parallel commercial license
  available for organisations that cannot accept AGPL terms.

See `SPEC.md` and `docs/RUNBOOK.md` for full design and operations
detail. See git history for the per-sprint changelog of v0.x.
