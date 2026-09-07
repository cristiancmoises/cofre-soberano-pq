# Cofre Soberano PQ — Operator Runbook

🇧🇷 **Português:** [RUNBOOK.pt-BR.md](RUNBOOK.pt-BR.md)

Production deployment, daily operations, and troubleshooting for the
qgateway sidecar. This document is the **operator-facing** companion
to `SPEC.md` (which is the design spec). If you're deploying or running
the gateway in production, read this first.

For HSM-backed key custody, see `HSM.md`.


## Audit verification and portal access

Run `qaudit verify --log audit.qa --pk audit.pk` with a key whose provenance
was established outside the log. `qaudit inspect` only displays contents;
its output does not prove integrity. Exported XML uses the project's own
schema and does not imply regulatory approval.

Keep the final root, entry count, and ordered segment inventory outside the
signing host. Detecting complete trailing-entry removal or replay of an older
valid log requires these checkpoints. Header labels/times and `appended_at`
are not authenticated in wire-v1. A signed event time is not independently
trusted time.

The portal loads a read-only startup snapshot; `/api/verify` reports that
snapshot's result. Restart it after selecting a new file or consistent copy
of the log. `/healthz` only confirms HTTP liveness. The portal has no built-in
authentication: retain the loopback binding and use an SSH tunnel or
authenticated reverse proxy for remote access.

```bash
qaudit-portal --log audit.qa --pk audit.pk --listen 127.0.0.1:8080
# English interface: http://127.0.0.1:8080/?lang=en
# HTML pagination: ?offset=0&limit=50 (maximum 200)
# JSON pagination: /api/entries?offset=0&limit=100 (maximum 1000)
```

![English audit portal](../screenshots/portal-en.png)

Maintain **one writer per `.qa` file**, including CLI processes and daemons.
Atomic replacement protects against partial rewrites; it does not implement
interprocess mutual exclusion. Independent writers need operational
serialization to avoid lost updates.

Before `qaudit rotate`, stop the log's writer and back up both segments.
Rotation publishes the new file before replacing the old one; those writes
are not one atomic transaction. On failure, preserve both files and verify
the chain before resuming writes.

---

## 1. Audience and scope

This runbook assumes the reader is a Linux systems operator comfortable
with:

- systemd unit files
- TOML config
- Prometheus scraping
- Reading `journalctl -u <unit>` output
- Running unprivileged daemons with restricted capabilities

It does **not** assume cryptographic expertise. The post-quantum primitives
(ML-KEM-1024, ML-DSA-87, ChaCha20-Poly1305) are baked into the binary;
operators only interact with `.skid` / `.cspqid.pub` key files and the
audit `.audit.pub` artifact.

---

## 2. Production deployment

### 2.1 Binary distribution

Each release publishes a platform-labelled binary bundle, a source archive,
an SBOM, a machine-readable manifest, `SHA256SUMS`, and detached ML-DSA-87 and
Sigstore signatures. The canonical GNU/Linux binary bundle contains:

```
cofre-soberano-pq-vX.Y.Z-<rust-host-triple>/
├── bin/
│   ├── qaudit
│   ├── qaudit-portal
│   ├── qgateway              # standard gateway build
│   └── qgateway-pkcs11       # gateway built with the pkcs11 feature
├── docs/
│   ├── RUNBOOK.md / RUNBOOK.pt-BR.md
│   ├── HSM.md / HSM.pt-BR.md
│   └── SMOKE_TEST.md / SMOKE_TEST.pt-BR.md
├── README.md / README.pt-BR.md
├── LICENSE-AGPL
├── LICENSE-COMMERCIAL
├── NOTICE
├── SPEC.md
└── systemd/
    └── qgateway.service      # reference unit file
```

Before extraction or installation, verify every downloaded file against
`SHA256SUMS`, then verify both detached-signature families with the public
verification keys you have already trusted. Project anchors are tracked in
[`release-keys/`](../release-keys/); confirm their fingerprints through an
independent channel on first use. Keys downloaded alongside an artifact
do not by themselves establish its authenticity. Confirm that
`release-manifest.json` names the expected version, commit, Rust 1.95.0
toolchain, target triple, build features, sizes, and hashes. The CycloneDX SBOM
is `cofre-soberano-pq-vX.Y.Z.cdx.json`. Do not install an artifact when a hash
or signature fails; checksums alone do not authenticate a release.

To verify signatures with OpenSSL 3.5+ (ML-DSA) and Cosign 3.1.3,
set the path to your already trusted anchors and run from the download
directory. Start with `SHA256SUMS`; repeat both signature checks for every
bundle, source archive, SBOM, and manifest before installation.

```bash
COFRE_KEYS=/path/to/trusted/release-keys
COFRE_ASSET=SHA256SUMS
openssl pkeyutl -verify -pubin \
  -inkey "$COFRE_KEYS/release-mldsa87-public.pem" \
  -in "$COFRE_ASSET" -sigfile "$COFRE_ASSET.mldsa87.sig" \
  -pkeyopt context-string:cofre-soberano-pq-release-v1
cosign verify-blob --key "$COFRE_KEYS/release-sigstore-public.pem" \
  --bundle "$COFRE_ASSET.sigstore.json" "$COFRE_ASSET"
sha256sum -c SHA256SUMS
```

The v1.0.4 FreeBSD supplement targets FreeBSD 14.4 amd64 and contains
`qaudit`, `qaudit-portal`, and `qgateway` with PKCS#11 enabled. Verify
`SHA256SUMS.freebsd` and the FreeBSD archive using the same two signature
commands above, setting `COFRE_ASSET` to each filename. On FreeBSD, check the
archive digest with the native [sha256 utility](https://man.freebsd.org/cgi/man.cgi?query=sha256&sektion=1):

```sh
read -r COFRE_EXPECTED COFRE_ARCHIVE < SHA256SUMS.freebsd
sha256 -c "$COFRE_EXPECTED" "$COFRE_ARCHIVE"
```

Its embedded `native-build-metadata.json` records the native compiler, build
features, and validation results;
the original release manifest and SBOM describe the GNU/Linux build. The
FreeBSD bundle omits systemd files; the service installation steps below
apply to GNU/Linux.

Install the standard gateway, or install the PKCS#11 variant under the
operational name `qgateway` when HSM support is required:

```bash
# Create the service account before installing owned directories.
id -u qgateway >/dev/null 2>&1 || \
  sudo useradd --system --no-create-home --shell /usr/sbin/nologin qgateway
sudo install -m 0755 bin/qgateway /usr/local/bin/qgateway
# HSM deployment alternative:
# sudo install -m 0755 bin/qgateway-pkcs11 /usr/local/bin/qgateway
sudo install -m 0644 systemd/qgateway.service /etc/systemd/system/qgateway.service
sudo install -d -o root -g root -m 0755 /etc/qgateway
sudo install -d -o qgateway -g qgateway -m 0750 /var/lib/qgateway
sudo install -d -o qgateway -g qgateway -m 0750 /var/log/qgateway
```

### 2.2 Key generation

Generate the daemon's transport identity (ML-DSA-87 keypair):

```bash
sudo qgateway keygen \
    --sk /etc/qgateway/daemon.skid \
    --pk /etc/qgateway/daemon.cspqid.pub
sudo chown qgateway:qgateway /etc/qgateway/daemon.skid /etc/qgateway/daemon.cspqid.pub
sudo chmod 0400 /etc/qgateway/daemon.skid
sudo chmod 0444 /etc/qgateway/daemon.cspqid.pub
```

Generate the audit signer keypair (separate ML-DSA-87 keypair, used to
sign audit log entries):

```bash
sudo qgateway audit-keygen \
    --sk /etc/qgateway/audit.skid \
    --pk /etc/qgateway/audit.pub
sudo chown qgateway:qgateway /etc/qgateway/audit.skid /etc/qgateway/audit.pub
sudo chmod 0400 /etc/qgateway/audit.skid
sudo chmod 0444 /etc/qgateway/audit.pub
```

**Critical**: the `.audit.pub` file is the artifact you publish to
auditors. It is the public key against which they verify the audit
chain. Treat it as a publishable contract — once distributed, you
cannot rotate it without breaking historical verification.

For HSM-backed audit signing (recommended for production), see `HSM.md`.

### 2.3 Peer trust directory

For each tenant that accepts CSPQ connections, create a directory of
trusted peer public keys:

```bash
sudo install -d -o qgateway -g qgateway -m 0750 /etc/qgateway/peers/alice
# Copy the peer's .cspqid.pub file into the directory:
sudo install -m 0444 alice-peer.cspqid.pub /etc/qgateway/peers/alice/
```

Each `*.cspqid.pub` file in the directory is treated as a trusted peer.
A peer NOT in this directory is rejected at handshake with
`Error::UntrustedPeer` (proven by integration test §13.39).

### 2.4 Config file

Minimal `/etc/qgateway/sidecar.toml`:

```toml
role = "serve-pq"
identity_key = "/etc/qgateway/daemon.skid"
identity_pub = "/etc/qgateway/daemon.cspqid.pub"
metrics_listen = "127.0.0.1:9100"
tenant_drain_timeout_secs = 10

[audit_signer]
kind = "softkey"
secret_key = "/etc/qgateway/audit.skid"
public_key = "/etc/qgateway/audit.pub"

[[tenants]]
name = "alice"
listen = "0.0.0.0:8443"
backend = "127.0.0.1:8080"
peer_pub_dir = "/etc/qgateway/peers/alice"
audit_log = "/var/log/qgateway/alice.qa"

  [tenants.limits]
  max_concurrent = 1000

  [tenants.limits.rate_limit_per_source]
  capacity = 100
  refill_per_sec = 50
```

The schema is enforced by `qgateway-core` and its evolution is recorded in the
SPEC sprint contracts. Validate the effective file with
`qgateway validate --config <path>`. Key knobs:

| Field | Purpose | Production guidance |
|---|---|---|
| `role` | `serve-pq` or `serve-tcp` | One per daemon; mixing roles requires separate daemons |
| `metrics_listen` | Prometheus scrape endpoint | Bind to loopback or management VLAN, NEVER to a public interface |
| `tenant_drain_timeout_secs` | SIGTERM drain deadline | 10s is sane; lower for fast restarts, higher for long-lived sessions |
| `tenants.limits.max_concurrent` | Per-tenant session cap | Set based on backend capacity, not on gateway memory |
| `tenants.limits.rate_limit_per_source` | Per-source-IP token bucket | `capacity` = max burst; `refill_per_sec` = steady-state |
| `[rotation] max_age_secs` | Auto-rotate log when older than N seconds | Set per compliance requirement (Bacen typically expects daily) |
| `[rotation] poll_interval_ms` | How often the rotation monitor checks thresholds (Sprint 35) | Default 5000ms; lower for tight deadlines |

### 2.5 systemd unit

Install the reviewed `systemd/qgateway.service` from the binary bundle as shown
in §2.1. The tracked and packaged file is authoritative; it includes the
SIGHUP reload contract, network-online ordering, filesystem restrictions,
process hardening, and resource limits.

Enable + start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now qgateway.service
sudo systemctl status qgateway.service
```

### 2.6 Verify deploy

```bash
# 1. Daemon is running
systemctl is-active qgateway.service

# 2. Metrics endpoint responds
curl -s http://127.0.0.1:9100/metrics | head -20

# 3. Listen port is bound
ss -tlnp | grep qgateway

# 4. Audit log was created (header-only at this point)
sudo -u qgateway test -f /var/log/qgateway/alice.qa && echo "audit log ok"

# 5. Audit chain header parses
sudo -u qgateway qaudit verify \
    --log /var/log/qgateway/alice.qa \
    --pk /etc/qgateway/audit.pub
```

If any of these fail, see §6 Troubleshooting.

---

## 3. Daily operations

### 3.1 Signal contract

| Signal | Effect | Audit-relevant? |
|---|---|---|
| `SIGTERM` | Graceful shutdown: drain in-flight sessions up to `tenant_drain_timeout_secs`, flush audit channels, exit | Yes — all pending audit events flushed |
| `SIGINT` | Same as SIGTERM | Yes |
| `SIGHUP` | Reload config: ADD new tenants, REMOVE missing tenants, apply hot-changes to `[tenants.limits]` | Yes — emits no audit events itself, but newly-added tenants begin emitting from their own chains |
| `SIGUSR1` | TLS certificate hot-reload across all TLS-enabled tenants | No |
| `SIGUSR2` | Audit log rotation across all tenants. Current `.qa` files renamed to archive pattern, fresh chain head opens | Yes — final entry in archive marks rotation point |
| `SIGKILL` | **DO NOT USE** — bypasses drain, may leave audit channel mid-write | Yes (badly) — last entries may be lost |

### 3.2 Reload config (SIGHUP)

Workflow:

1. Edit `/etc/qgateway/sidecar.toml`
2. Validate offline: `qgateway validate --config /path/to/new.toml`
   (Sprint 37). The `validate` subcommand exercises every fallible
   startup step (identity key parse, per-tenant peer dir, audit
   signer files, TLS PEM, audit-log parent directory writability)
   without binding listen sockets, creating any audit log files, or
   opening PKCS#11 sessions. It is safe to run against a production
   config on a host where the daemon is already running. Exit code
   is `0` on success with a one-line summary; non-zero with a
   concrete error message identifying the offending field on
   failure.
3. Reload: `sudo systemctl reload qgateway.service` (sends SIGHUP)
4. Verify: `curl -s http://127.0.0.1:9100/metrics | grep sighup`

Expected counters after a successful reload:
- `qgateway_sighup_cycles_total` increases by 1
- `qgateway_tenants_added_total` increases by the number of new tenants
- `qgateway_tenants_removed_total` increases by the number of removed tenants
- `qgateway_sighup_failed_total` **stays at 0**

If `sighup_failed_total` increments, the config was rejected — check
`journalctl -u qgateway` for the validation error. The previous config
remains active.

**What SIGHUP can and cannot change at runtime** (SPEC §13.x):

| Change | Hot-apply | Requires restart |
|---|---|---|
| Add a tenant | ✅ | |
| Remove a tenant | ✅ | |
| Change `max_concurrent` | ✅ | |
| Change `rate_limit_per_source` | ✅ | |
| Change `peer_pub_dir` contents (files) | ✅ (loaded on next handshake) | |
| Change `audit_log` path | | ✅ |
| Change `backend` / `peer_pq` | | ✅ |
| Change `[audit_signer]` | | ✅ |
| Change `role` | | ✅ |
| Add/change `[tls]` block on existing tenant | | ✅ |

For cold-change tenants, REMOVE then ADD in two SIGHUP cycles works,
but the old session-cleanup window applies.

### 3.3 Rotate TLS certs (SIGUSR1)

For TLS-enabled tenants only. Replace the cert/key files on disk, then:

```bash
sudo kill -USR1 $(pidof qgateway)
# or via systemctl:
sudo systemctl kill -s USR1 qgateway.service
```

Reload is atomic: new connections use the new cert; in-flight sessions
use the snapshot they were accepted under. If reload fails (malformed
cert, key/cert mismatch), the previous acceptor is retained and the
error is logged. Operators should grep journalctl for the failure.

### 3.4 Rotate audit logs (SIGUSR2)

```bash
sudo systemctl kill -s USR2 qgateway.service
```

For every tenant:
1. Current `<tenant>.qa` is renamed to `<tenant>-<timestamp>.qa` (or
   the pattern configured in `[rotation] archive_pattern`)
2. A fresh chain head is written to the new `<tenant>.qa`
3. The archive file is now read-only and can be moved to long-term
   storage (e.g., to an S3-compatible object store) for compliance
   retention

Auto-rotation (configured via `[rotation] max_age_secs` /
`max_bytes` / `max_entries`) does the same thing automatically. The
monitor task checks every `poll_interval_ms` (default 5000ms; tunable
since Sprint 35).

**Long-term audit retention** (your compliance officer cares):
- Move archived `.qa` files to immutable storage within 24 hours of
  rotation
- Retain for the period your regulator requires (Bacen Resolution
  4658 typically expects 5 years for security-relevant logs)
- Verify each archive immediately after rotation:
  ```bash
  qaudit verify --log <archive>.qa --pk audit.pub
  ```
  This is the same command an auditor runs to validate the chain
  cryptographically; passing it in your retention pipeline catches
  storage corruption immediately rather than five years later.

### 3.5 Graceful restart

```bash
sudo systemctl restart qgateway.service
```

Equivalent to SIGTERM + start. Drain proceeds for up to
`tenant_drain_timeout_secs` (default 10s); any sessions still
in-flight after the deadline are dropped. Operators should not
restart during business-critical windows without first observing
`qgateway_sessions_active`:

```bash
curl -s http://127.0.0.1:9100/metrics | grep sessions_active
```

If sessions_active > 0 and the workload is long-lived (e.g.,
streaming), set `tenant_drain_timeout_secs` higher or schedule
the restart for a quiet period.

---

## 4. Metrics reference

Scrape `/metrics` on the configured `metrics_listen` port. Metric format
is Prometheus exposition; per-tenant counters carry a `tenant="<name>"`
label.

### 4.1 Per-tenant data-plane

| Metric | Type | Meaning | Action threshold |
|---|---|---|---|
| `qgateway_sessions_opened_total` | counter | Cumulative successful handshakes | Trend; sudden drop → backend issue |
| `qgateway_sessions_closed_total` | counter | Cumulative session closes (normal end) | Should track _opened_total |
| `qgateway_sessions_failed_total` | counter | Cumulative handshake failures | Rate > 1% → investigate (bad peer? attacker?) |
| `qgateway_sessions_active` | gauge | Currently open sessions | Near `max_concurrent` → scale |
| `qgateway_bytes_c2s_total` | counter | Client→server bytes after CSPQ decrypt | Capacity planning |
| `qgateway_bytes_s2c_total` | counter | Server→client bytes after CSPQ encrypt | Capacity planning |
| `qgateway_handshake_seconds_bucket` | histogram | Handshake latency distribution | p99 > 500ms → HSM under load |

### 4.2 Per-tenant audit

| Metric | Type | Meaning | Action threshold |
|---|---|---|---|
| `qgateway_audit_events_total` | counter | Total events written to chain | Should track 2 × sessions_opened (open+close) |
| `qgateway_audit_failures_total` | counter | Audit-channel backpressure drops | **>0 = data loss** — investigate immediately |
| `qgateway_audit_rotations_total` | counter | Rotations triggered (signal or auto) | Operational visibility |

### 4.3 Per-tenant admission

| Metric | Type | Meaning | Action threshold |
|---|---|---|---|
| `qgateway_admission_rejected_quota_total` | counter | Sessions rejected due to `max_concurrent` | Persistent > 0 → raise quota or scale |
| `qgateway_admission_rejected_rate_total` | counter | Sessions rejected due to rate limit | Spike → DoS attempt or misconfigured client |

### 4.4 HSM (if `[audit_signer] kind = "pkcs11"`)

| Metric | Meaning | Action threshold |
|---|---|---|
| `qgateway_hsm_sessions_opened_total` | HSM sessions opened | Trend |
| `qgateway_hsm_sessions_failed_total` | HSM session-open failures | >0 → HSM unreachable, check `HSM.md` |
| `qgateway_hsm_sign_ops_total` | Sign operations attempted | Should track audit_events_total |
| `qgateway_hsm_sign_failures_total` | Sign failures | **>0 = audit chain at risk** — investigate immediately |

### 4.5 Daemon-wide (no tenant label)

| Metric | Meaning | Action threshold |
|---|---|---|
| `qgateway_sighup_cycles_total` | SIGHUP reloads that passed validation | Operational visibility |
| `qgateway_sighup_failed_total` | SIGHUP reloads rejected at validation | >0 → check journalctl, fix config |
| `qgateway_tenants_added_total` | Tenants added at runtime | Operational visibility |
| `qgateway_tenants_add_failed_total` | Tenant-add attempts that failed | >0 → check journalctl |
| `qgateway_tenants_removed_total` | Tenants removed at runtime | Operational visibility |
| `qgateway_tenants_remove_failed_total` | Tenant-remove attempts that failed | >0 → check journalctl |
| `qgateway_limits_hot_applied_total` | Hot-applied changes to `[tenants.limits]` | Operational visibility |
| `qgateway_config_changed_hot_total` | Tenants with hot-changeable diffs in last SIGHUP | Operational visibility |
| `qgateway_config_changed_cold_total` | Tenants requiring restart due to cold-only diffs | >0 → schedule restart |

### 4.6 Suggested alerts

```yaml
# Prometheus alerting rules
groups:
- name: qgateway
  rules:
  - alert: QgatewayAuditFailures
    expr: increase(qgateway_audit_failures_total[5m]) > 0
    for: 1m
    severity: critical
    annotations:
      summary: "Audit channel dropped events on {{ $labels.tenant }}"
      runbook: "RUNBOOK.md §5.1"

  - alert: QgatewayHsmSignFailures
    expr: increase(qgateway_hsm_sign_failures_total[5m]) > 0
    for: 1m
    severity: critical
    annotations:
      summary: "HSM sign operations failing — audit chain at risk"
      runbook: "HSM.md §4"

  - alert: QgatewayHighHandshakeFailureRate
    expr: |
      rate(qgateway_sessions_failed_total[5m])
      / rate(qgateway_sessions_opened_total[5m]) > 0.05
    for: 5m
    severity: warning
    annotations:
      summary: "Handshake failure rate > 5% on {{ $labels.tenant }}"
      runbook: "RUNBOOK.md §6.2"

  - alert: QgatewaySighupRejected
    expr: increase(qgateway_sighup_failed_total[5m]) > 0
    severity: warning
    annotations:
      summary: "Config reload rejected — old config still active"
      runbook: "RUNBOOK.md §6.3"

  - alert: QgatewayAdmissionQuotaPersistent
    expr: rate(qgateway_admission_rejected_quota_total[10m]) > 0
    for: 10m
    severity: warning
    annotations:
      summary: "Persistent admission rejections on {{ $labels.tenant }} — raise max_concurrent or scale"
```

---

## 5. Compliance and audit chain handling

### 5.1 What the audit chain proves

Each tenant's `.qa` file is a **cryptographically signed sequential
event log** where:

1. Each entry contains: timestamp, actor, action, resource, optional
   metadata, and an ML-DSA-87 signature
2. Each entry's signature input includes the **hash of the previous
   entry** — any tampering with one entry breaks the chain from that
   point forward
3. The chain header carries the daemon's audit public key, so an
   auditor receiving the file out-of-band can verify with no shared
   secrets beyond `audit.pub`

This means an auditor can answer **"prove this exact sequence of
sessions occurred"** without trusting your infrastructure.

### 5.2 External verification

To verify a chain offline (the auditor's workflow):

```bash
# Verify against the public key embedded in the chain header
qaudit verify --log /path/to/alice.qa

# Verify against an externally-provided public key (the auditor's
# preferred mode — proves the chain header's pubkey matches the
# pubkey you published)
qaudit verify \
    --log /path/to/alice.qa \
    --pk /path/to/audit.pub
```

Sprint 26 + Sprint 30 integration tests prove the chain survives
SIGHUP cycles, session traffic, and external pubkey verification
end-to-end inside the live daemon. See SPEC §13.34 and §13.38.

### 5.3 Long-term retention pipeline

Suggested workflow:

1. Daemon auto-rotates daily (via `[rotation] max_age_secs = 86400`)
   or on size threshold
2. A separate process (cron, systemd timer) picks up archived `.qa`
   files from `/var/log/qgateway/` and:
   - Runs `qaudit verify` on each (catches storage corruption
     immediately)
   - Uploads to immutable object storage (S3 Object Lock, MinIO with
     compliance mode, etc.)
   - Records the SHA-256 of each archive in a separate ledger for
     tamper-evident inventory
3. Local archives are deleted after the upload + verify is confirmed
4. Retention period in immutable storage matches your regulator's
   requirement

### 5.4 Bacen / LGPD mapping

Cofre Soberano PQ provides building blocks that map to Brazilian
regulatory requirements but does NOT itself constitute compliance.
The full mapping is outside this runbook's scope. Headline points:

- **Bacen Resolution 4658/2018** (cybersecurity): the audit chain
  satisfies §IV's "registration and analysis of security incidents"
  requirement provided it is retained and made available to BCB
  examiners
- **LGPD (Lei 13.709/2018)**: the chain records "actor" (the CSPQ
  peer identity) and "action" (session.open / session.close); if
  personal data flows through the proxied backend, additional
  data-controller obligations apply that this gateway does not
  address
- **Post-quantum readiness**: ML-KEM-1024 (FIPS 203) and ML-DSA-87
  (FIPS 204) are NIST-standardised algorithms, suitable for
  Bacen's anticipated cryptographic-agility requirements

A formal compliance mapping document is a Sprint 36+ deliverable
when concrete bank PoC requirements arrive.

---

## 6. Troubleshooting

### 6.1 Audit failures spike (`qgateway_audit_failures_total > 0`)

**What it means**: the audit channel's bounded buffer overflowed.
The channel drops the OLDEST pending entry on backpressure (SPEC
§7.x) — this is data loss for compliance.

**Causes**:
- Disk full or slow (audit writer can't fsync fast enough)
- HSM under load (if PKCS#11 signer) — each event needs a sign op
- Pathological burst of events (rare; would require >10 K events/sec)

**Remedy**:
1. Check disk: `df -h /var/log/qgateway`
2. Check fsync latency: `iostat -x 1` — look for high `await` on the
   audit disk
3. If HSM-backed: `curl -s :9100/metrics | grep hsm_sign` — sign-op
   p99 latency
4. If sustained: investigate the source of event burst (proxy traffic
   volume, audit-event verbosity)

### 6.2 High handshake failure rate

**Causes** (ordered by likelihood):
- A client is misconfigured with the wrong CSPQ identity (untrusted
  peer rejection — proven by Sprint 31 integration test)
- A port scanner is hitting the listener (proven by Sprint 32:
  daemon survives, counter increments, no audit events leak)
- The legitimate clients' identities are not in `peer_pub_dir`

**Diagnose**:
```bash
journalctl -u qgateway --since "5 minutes ago" | grep -i "handshake\|untrusted"
```

If the error is `UntrustedPeer { peer_id: <hex> }`, the dialer's
identity is not in `peer_pub_dir`. Either add it (if legitimate) or
ignore (if attacker).

### 6.3 SIGHUP reload rejected

**Symptom**: `qgateway_sighup_failed_total` incremented, old config
still active.

**Diagnose**:
```bash
journalctl -u qgateway --since "1 minute ago" | grep -i "config\|sighup"
```

The error message identifies the offending field. Common causes:
- Tenant name collision (two `[[tenants]]` blocks with same name)
- Missing `peer_pub_dir` (path doesn't exist)
- Invalid `listen` address (port already in use)
- TLS cert and key mismatch

**Remedy**: fix the config file and SIGHUP again. The daemon retains
the previous working config so the gateway stays serving.

### 6.4 Tenant added at runtime not behaving correctly

**Background**: Sprints 27 and 28 caught two production bugs where
runtime-added tenants (via SIGHUP ADD) didn't get fully wired into
the rotation and auto-rotation pipelines. Both are fixed. If you
observe a runtime-added tenant whose audit log never rotates:

1. Confirm the daemon was built from a tagged release at or after
   v1.0 (which includes Sprints 27 + 28)
2. `curl -s :9100/metrics | grep rotation` — confirm
   `qgateway_audit_rotations_total{tenant="<new>"}` is being emitted
3. If still missing, file a bug report with:
   - SIGHUP cycle history
   - Config diff at the time of ADD
   - The runtime-added tenant's `.qa` file size + last mtime

### 6.5 Sessions reported as active long after clients disconnected

**Symptom**: `qgateway_sessions_active{tenant=...}` shows a large
number but no traffic flows.

**Causes**:
- Backend never closes its side of the proxy (long-lived TCP)
- TCP keepalive isn't firing because `net.ipv4.tcp_keepalive_time`
  is too high (default 7200s on Linux)
- A stuck session in the proxy loop (rare; would indicate a daemon
  bug)

**Remedy**:
- Lower the kernel keepalive: `sysctl net.ipv4.tcp_keepalive_time=300`
- Adjust the application protocol to close sessions cleanly
- If you suspect a daemon bug, capture: PID, `/proc/<pid>/stack`
  via `cat /proc/<pid>/task/*/stack`, journal output, and file an
  issue

### 6.6 PKCS#11 / HSM errors

See `HSM.md` §4 for HSM-specific troubleshooting.

### 6.7 Restart loop

`sudo systemctl status qgateway.service` shows `failed (Result: exit-code)` and `Restart=on-failure` keeps re-triggering.

**Diagnose**: `journalctl -u qgateway --since "5 minutes ago" -p err`

Common causes:
- Config file unreadable (permissions)
- Listen port already in use
- Audit log path unwritable
- Identity/audit key file missing or corrupted (magic bytes don't match)

Stop the restart loop while diagnosing:
```bash
sudo systemctl stop qgateway.service
# fix the issue
sudo systemctl start qgateway.service
```

---

## 7. Upgrade procedure

Cofre Soberano PQ does NOT support online upgrade across major
versions. The procedure for a major version bump:

1. Stage the new binary at `/usr/local/bin/qgateway.new`
2. Drain: `sudo systemctl stop qgateway.service` (or wait for a
   maintenance window)
3. Swap: `sudo mv /usr/local/bin/qgateway.new /usr/local/bin/qgateway`
4. Restart: `sudo systemctl start qgateway.service`
5. Verify: §2.6

For compatible version bumps within the same major (for example, the current
release → the next patch release),
the same procedure works but downtime is shorter. The wire protocol
(CSPQ v1) is stable across the v1.x line.

**Migration to a future CSPQ v2** (planned 2028, per SPEC §16): NOT
backward compatible at the wire level. A v1↔v2 mixed deployment is
out of scope for v1.x.

---

## 8. Observability extras

### 8.1 Recommended Prometheus scrape interval

15 seconds. The session-level counters (`sessions_opened`, etc.)
increment frequently enough that 60s loses fidelity; the per-tenant
gauges (`sessions_active`) are sample-and-hold so longer intervals
miss transients.

### 8.2 Recommended Grafana dashboard panels

(A reference dashboard JSON is not yet shipped; planned Sprint 36+
if operator demand justifies it.)

Suggested layout:

- **Row 1: Capacity** — `sessions_active` per tenant (line), `bytes_c2s + bytes_s2c` rate (line)
- **Row 2: Quality** — handshake p50/p95/p99 (heatmap), `sessions_failed` rate (line)
- **Row 3: Compliance** — `audit_events` rate, `audit_failures` (alert-eligible), `audit_rotations` (vertical lines)
- **Row 4: Operations** — `sighup_cycles_total` (per-day step), `tenants_added/removed` (events)
- **Row 5 (if HSM)** — `hsm_sign` rate + failures, HSM p99 latency

### 8.3 Log aggregation

The daemon writes structured logs to stderr via `tracing`. Common
production setup:

- systemd captures stderr to the journal
- Fluentd / Vector / Loki Promtail scrapes the journal
- Long-term log storage retention should match audit-chain retention
  (5 years for Bacen contexts)

Sensitive fields (peer identity hashes, source IPs) ARE logged. If
your compliance context restricts logging IPs (e.g., LGPD-sensitive
deployments), use `RUST_LOG=qgateway=warn` to reduce verbosity.

---

## 9. Incident response

If you suspect a security incident (compromised key, unauthorised
access, audit chain tamper):

1. **Do not delete the audit log files.** They are evidence.
2. **Do not stop the daemon abruptly** unless the threat is active.
   A clean SIGTERM flushes pending events; SIGKILL may lose them.
3. **Preserve a snapshot** of `/var/log/qgateway/` immediately:
   ```bash
   sudo tar -czf /tmp/audit-snapshot-$(date +%Y%m%dT%H%M%S).tar.gz \
       /var/log/qgateway/ /etc/qgateway/audit.pub
   ```
4. **Verify the chains** to detect tampering:
   ```bash
   for f in /var/log/qgateway/*.qa; do
       qaudit verify --log "$f" --pk /etc/qgateway/audit.pub
   done
   ```
   A `verify failed` result on a previously-valid chain is strong
   evidence of tampering.
5. **If the audit signer key is suspected compromised**: the entire
   chain history signed by that key is suspect. Generate a new
   `audit.skid` / `audit.pub`, restart the daemon with the new keys,
   and document the rotation timestamp. Historical chains remain
   verifiable against the old `audit.pub` but the cutoff timestamp
   needs to be recorded in your incident report.

---

## 10. Where this runbook is incomplete

Honest list of gaps for v1.0 ship:

- **No reference Grafana dashboard JSON.** Suggested panels in §8.2.
- **No formal Bacen / LGPD compliance mapping document.** Headline guidance in §5.4.
- **No backup / disaster-recovery procedure.** Implicit: the `.skid` files are the irreplaceable secrets; back them up offline (HSM-backed deployments push this to the HSM).
- **No Kubernetes / containerised deployment guide.** The `Dockerfile` in the repo is a starting point; a Helm chart would be Sprint 38+ if operator demand justifies.

These gaps are documented honestly so deployment teams know what's
production-ready and what's pending.
