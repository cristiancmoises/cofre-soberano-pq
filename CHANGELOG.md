# Changelog

All notable changes to this project will be documented in this file.

The format is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The **wire protocol** and **`.qa` audit log format** are governed by an
explicit `suite` identifier in every chain header
(`suite = "cspq-2026"` in this release). Any change that breaks
suite-compatibility will require both a major version bump **and** a
new suite identifier.

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
