# Cofre Soberano PQ — PKCS#11 HSM Integration

🇧🇷 **Português:** [HSM.pt-BR.md](HSM.pt-BR.md)

Hardware-security-module backing for the audit signer. Production
deployments in regulated industries (Brazilian banking, government)
typically require that signing keys never leave a certified hardware
boundary; this document walks through the configuration and operational
posture for that path.

For non-HSM deployments, the `softkey` signer (file-based ML-DSA-87
secret key) is documented in `RUNBOOK.md` §2.2.

---

## 1. Why HSM-backed audit signing

The audit chain is the compliance artifact. If an attacker obtains the
audit signing key, they can:

- Generate forged entries indistinguishable from legitimate ones
- Backdate the chain to make their activity appear consistent with
  pre-incident audit state
- Convince a regulator that the gateway recorded a sequence of events
  that never actually occurred

With a correctly configured and independently validated HSM, the intended
properties are:

- Even with full root access to the gateway host, the attacker cannot
  exfiltrate the key bytes
- HSM-side audit records may provide an independent operation trail when the
  selected appliance and policy enable that feature
- Certification and attestation evidence come from the HSM vendor and the
  operator's provisioning process; qgateway does not generate hardware
  attestation evidence

The trade-off: a sign call now requires a round-trip to the HSM
(typically network — even local PCIe HSMs serialise through a single
device handle). Sprint 35's poll-interval work and the daemon's batched
audit writer mitigate the latency cost, but high-throughput deployments
should benchmark.

---

## 2. Supported PKCS#11 implementations

Cofre Soberano PQ depends on `qaudit-hsm` (workspace crate) with the
`pkcs11` feature. The implementation is generic across vendors that
expose an ML-DSA-87 key and a mechanism supported by the implementation.
Validate its ID against the chosen module, firmware, and driver.

Compatibility status:

| HSM | Status | Notes |
|---|---|---|
| **SoftHSM2** | 🟡 Compile/unit-test only | Useful for exercising generic PKCS#11 code, but it cannot host the ML-DSA-87 key required by the live test. |
| **YubiHSM2** | 🟡 Not live-tested | Confirm ML-DSA-87 mechanism support with the exact hardware, firmware, and driver. |
| **Thales Luna** | 🟡 Not live-tested | Firmware- and capability-dependent; confirm the mechanism with the vendor. |
| **Utimaco SecurityServer** | 🟡 Not live-tested | Firmware- and capability-dependent; confirm the mechanism with the vendor. |

CI compiles and unit-tests the optional `pkcs11` path. The live
`qaudit-hsm::pkcs11::tests::live_hsm_sign_verify` test is ignored by default
because it requires a provisioned ML-DSA-87 device. Run that round trip against
the exact production module before deployment; a successful build is not proof
of HSM interoperability.

The adapter defaults to `0x8000_0001`, a vendor-defined mechanism.
Set `mechanism_id` to the value documented for your module. The existence
of a mechanism ID alone does not establish ML-DSA-87 support.

If your HSM doesn't yet expose ML-DSA-87 at the PKCS#11 layer, the
softkey fallback is honest: ship with file-based keys at restrictive
permissions (0400, on an encrypted filesystem if your threat model
warrants) until HSM vendor support catches up.

---

## 3. Configuration

### 3.1 Provisioning the HSM key

The audit signing keypair must be generated **on the HSM**, not
imported. Importing defeats the purpose of HSM custody (the secret
key transited a host where it could have been logged or backed up).

Provisioning and public-key export are vendor-specific. This repository does
not ship an `qaudit-hsm-tool` provisioning binary. Use the HSM vendor's
documented tooling or SDK to:

1. generate an ML-DSA-87 private/public keypair inside the device;
2. assign the `CKA_LABEL` values used by `key_label` and `pub_label`;
3. export only the public key as raw 2592-byte ML-DSA-87 bytes (or the
   `AUDITPK0`-framed form accepted by the QAudit tools); and
4. record the module, firmware, mechanism ID, and public-key hash in the
   deployment evidence.

For example, token initialization may start with a vendor command such as the
following, but it does not provision an ML-DSA key by itself:

```bash
# Initialize a SoftHSM2 token
softhsm2-util --init-token --slot 0 --label "qgateway-audit" \
    --so-pin 1234 --pin 5678
```

SoftHSM2 does not provide the required live ML-DSA-87 path; the example is only
for generic PKCS#11 development. After vendor-specific provisioning, retain the
exported public key as `/etc/qgateway/audit.pub` for auditor distribution.
QAudit accepts either raw ML-DSA-87 public-key bytes or the framed
`.audit.pub` form, so verification is independent of signer custody.

### 3.2 Daemon config

`/etc/qgateway/sidecar.toml`, replacing the top-level `[audit_signer]` default
or using `[tenants.audit_signer]` for a tenant-specific HSM identity:

```toml
[audit_signer]
kind         = "pkcs11"
module       = "/usr/lib/softhsm/libsofthsm2.so"
slot         = 0
pin_env      = "QGATEWAY_HSM_PIN"
key_label    = "audit-2026"
# Optional: separate label if the HSM stores pub and priv distinctly
# pub_label  = "audit-2026-pub"
# Set the mechanism ID documented by your vendor.
# Default 0x80000001 is vendor-defined; it is not a portable standard ID.
# mechanism_id = 0x80000123
```

### 3.3 PIN handling

The PIN is **never** in the config file. The `pin_env` field names
an environment variable from which the daemon reads the PIN at startup
(and after each SIGHUP that touches the signer block).

For systemd:

```ini
[Service]
EnvironmentFile=/etc/qgateway/hsm.env
```

Where `/etc/qgateway/hsm.env` (mode 0400, owned by `qgateway`) contains:

```
QGATEWAY_HSM_PIN=your_actual_pin_here
```

The systemd `EnvironmentFile` directive ensures the PIN is loaded into
the daemon's process environment but not into the unit file (which may
be readable by other users). Operators should NOT pass the PIN via the
shell or systemd `Environment=` directive — both leak via `ps -e` or
`/proc/<pid>/environ` (though the latter is usually restricted by
default).

For HSM-supplied PED keys or smart-card unlock (Thales Luna PED) — the
`pin_env` mechanism is bypassed; the operator authenticates the HSM
out-of-band before starting the daemon. The pin_env field in this case
holds a dummy variable name; what matters is that the daemon's
PKCS#11 session inherits the HSM's already-authenticated state.

### 3.4 Verify the daemon connected to the HSM

After starting:

```bash
curl -s http://127.0.0.1:9100/metrics | grep hsm_

# Expected output (counters at 0 initially, will increment with traffic).
# Every metric carries a per-tenant `tenant="<name>"` label — the exporter
# emits one line per tenant registry:
qgateway_hsm_sessions_opened_total{tenant="alice"} 1
qgateway_hsm_sessions_failed_total{tenant="alice"} 0
qgateway_hsm_sign_ops_total{tenant="alice"} 0
qgateway_hsm_sign_failures_total{tenant="alice"} 0
```

`hsm_sessions_opened_total = 1` confirms the daemon opened its PKCS#11
session at startup. `hsm_sessions_failed_total > 0` indicates a
connection problem — see §4.

---

## 4. Troubleshooting

### 4.1 `hsm_sessions_failed_total` > 0 at startup

Common causes (check the journal):

| Error fragment | Cause |
|---|---|
| `CKR_TOKEN_NOT_PRESENT` | Wrong `slot` number, or the HSM is disconnected |
| `CKR_PIN_INCORRECT` | Wrong PIN in `QGATEWAY_HSM_PIN` env var |
| `CKR_USER_PIN_LOCKED` | Too many failed PIN attempts; HSM admin must unlock |
| `CKR_KEY_HANDLE_INVALID` | `key_label` doesn't match a key on the HSM |
| `CKR_MECHANISM_INVALID` | `mechanism_id` not supported by this HSM firmware |
| Library not found | `module` path is wrong |

Diagnose by trying the vendor's CLI tool with the same params before
suspecting qgateway. `pkcs11-tool` (from OpenSC):

```bash
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --list-slots
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --slot 0 \
    --list-objects --pin 5678
```

### 4.2 `hsm_sign_failures_total` increments under load

The daemon failed to sign one or more audit events. **This is a
critical incident** — audit chain integrity may be at risk.

Likely causes:

- **HSM session timeout**: some HSMs idle out sessions after N
  minutes of inactivity. The daemon's session-management layer
  (qaudit-hsm) re-opens on `CKR_SESSION_CLOSED`, but a burst of
  events arriving during reconnect may fail. Mitigation:
  configure the HSM for a longer session lifetime, or send a
  heartbeat sign-op via cron.
- **HSM under load**: shared HSM across multiple applications;
  sign-op queue is saturated. Mitigation: dedicated slot or
  scale the HSM.
- **HSM firmware bug**: rare, but observed in early ML-DSA
  vendor implementations. Mitigation: file with vendor; consider
  softkey fallback temporarily if regulator permits.

If `hsm_sign_failures_total > 0` is sustained:

1. Page the on-call operator immediately (Prometheus alert in
   `RUNBOOK.md` §4.6 catches this)
2. Determine whether the chain still verifies:
   ```bash
   qaudit verify --log /var/log/qgateway/<tenant>.qa \
       --pk /etc/qgateway/audit.pub
   ```
3. If verification fails, the chain has a gap — initiate incident
   response per `RUNBOOK.md` §9

The daemon does NOT silently skip failed sign operations. A sign
failure causes the audit channel to record the failure to the
`hsm_sign_failures_total` counter AND drop the event (rather than
inserting an unsigned entry that would invalidate the chain). This
is a deliberate trade-off: the chain stays cryptographically valid
but operators must catch failures via metrics.

### 4.3 Handshake p99 latency increased after enabling HSM

Each session.open + session.close emits an audit event, which means
two HSM sign operations per session. If the HSM is the bottleneck:

1. Measure: `curl -s :9100/metrics | grep hsm_sign`
2. Compute sign-op rate: `rate(qgateway_hsm_sign_ops_total[5m])`
3. Compare to HSM vendor spec (sign-ops/sec)

If the rate is near the HSM's spec, consider:

- Batching multiple audit events per sign (NOT YET IMPLEMENTED;
  Sprint 36+ work)
- Upgrading HSM hardware
- Using tenant-specific softkey signers for non-critical tenants and HSM
  signers only for compliance-critical tenants. Per-tenant overrides are
  already supported through `[tenants.audit_signer]`; an omitted override
  inherits the top-level default.

### 4.4 Rotating the HSM key

If a key needs rotation (suspected compromise, scheduled rotation
per organisational policy, or HSM firmware upgrade requiring re-gen):

1. Generate a new keypair on the HSM with a new label
   (e.g., `audit-2027`)
2. Export the new public key to a new path
   (e.g., `/etc/qgateway/audit-2027.pub`)
3. Distribute the new public key to auditors out-of-band; mark the
   cutover timestamp
4. Trigger SIGUSR2 (audit log rotation) — current chains close
   under the old key; new chains start under whatever the daemon
   currently knows
5. Edit config: change `key_label` to the new label, change the
   exported pubkey path
6. SIGHUP — the daemon picks up the new key (audit signer is one of
   the cold-restart fields; SIGHUP currently fails on this. Real
   key rotation requires a full restart: `systemctl restart` after
   the SIGUSR2 rotation completes)

Historical chains signed by the OLD key remain verifiable against
the old `.audit.pub`. The cutover timestamp + the old/new pubkey
pair must be retained in your compliance ledger so auditors can
verify the right historical period against the right key.

---

## 5. Honest limitations and roadmap

### 5.1 What HSM custody does NOT protect against

- **Application-layer code injection** that runs in the daemon
  process can still call the HSM (the HSM only sees authenticated
  sign requests; it can't tell whether the request came from
  legitimate audit-event flow or from injected code). Mitigation:
  the daemon's `#![forbid(unsafe_code)]` posture + minimal
  dependency surface + pinned, locked release builds. But ultimately:
  defense-in-depth, not silver bullet.
- **Physical attack on the HSM itself**. Most HSMs are FIPS 140-2
  / 140-3 Level 3 certified for tamper-evidence, but determined
  state-level adversaries with extended physical access have
  historically defeated even high-assurance modules. Out of scope
  for this gateway; the HSM vendor's hardening is your boundary.
- **Side-channel attacks on the host**. If the HSM's PKCS#11
  library has timing side-channels in the host process, an
  attacker observing the host process can extract information.
  ML-DSA-87 implementations are still maturing on this front;
  vendor-specific.

### 5.2 Roadmap items (operator-demand-gated)

- Sign-op batching (sign N events with one HSM round-trip)
- HSM cluster awareness (failover across redundant HSMs)
- Native key-attestation flow (cryptographic proof to auditors that
  the daemon's running pubkey was generated on the certified HSM)

### 5.3 Recommended hardening checklist

Before going live with HSM-backed audit signing:

- [ ] HSM is in a separately-secured rack with physical access
      logging
- [ ] HSM admin credentials and operator credentials are split
      (different humans for `--so-pin` and `--pin`)
- [ ] The `audit.pub` file has been distributed to auditors and
      its SHA-256 has been recorded in your compliance ledger
- [ ] Prometheus alerts on `hsm_sign_failures_total` and
      `hsm_sessions_failed_total` are wired to the on-call rotation
- [ ] A documented HSM-failover procedure exists (what happens if
      the HSM is unreachable for 10 minutes during business hours)
- [ ] The PIN env file is mode 0400, owned by `qgateway`, and is
      NOT in version control or backup snapshots that operators
      without HSM access can read
- [ ] An incident playbook (`RUNBOOK.md` §9) is reviewed and the
      on-call team has practised the audit-chain verification step
- [ ] At least one HSM rotation has been practised on a non-prod
      slot to validate the rotation procedure
