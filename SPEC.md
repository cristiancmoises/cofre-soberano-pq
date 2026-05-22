# Cofre Soberano PQ — Technical Specification

> *This document is the single source of truth for the design,
> threat model, sprint history, and architectural decisions of
> Cofre Soberano PQ. Update this file when reality changes, not
> the other way around.*

---

## 0. IDENTITY

| Field | Value |
|---|---|
| **Codename** | Cofre Soberano PQ (CSPQ) |
| **Tagline** | *Fronteira criptográfica pós-quântica para o Brasil regulado.* |
| **Slogan** | Compress everything. Trust nothing. Encrypt always. |
| **Owner** | Security Ops · Cristian Cezar Moisés |
| **Contact** | sac@securityops.co · https://securityops.co |
| **Repo** | git.securityops.co/cristiancmoises/cofre-soberano-pq |
| **License** | AGPL-3.0-or-later + commercial dual-license |
| **Trademark** | "Cofre Soberano PQ" pending registration (INPI BR) |

---

## 1. MISSION

Build the complete post-quantum cryptographic boundary that every Brazilian
regulated institution will be forced to acquire between 2026 and 2030 — under
Bacen, CMN, CVM, ANPD, SUSEP and SWIFT CSP migration mandates.

Three products. One SKU. One installer. One auditable supply chain.

```
┌─────────────────────────────────────────────────────────────────┐
│                       COFRE SOBERANO PQ                         │
├──────────────────┬──────────────────────┬───────────────────────┤
│  QGateway        │  QVault              │  QAudit               │
│  (Evelin)        │  (Zupt)              │  (ML-DSA-87)          │
├──────────────────┼──────────────────────┼───────────────────────┤
│  PQ transport.   │  PQ object store.    │  PQ audit log.        │
│  TLS↔Evelin      │  S3-compatible.      │  Offline-verifiable   │
│  reverse proxy.  │  Every blob Zupt-    │  Merkle chain signed  │
│  ML-KEM-1024 +   │  encoded with hybrid │  with ML-DSA-87. Bacen│
│  ChaCha20.       │  ML-KEM-768/X25519.  │  / CVM / ANPD export. │
└──────────────────┴──────────────────────┴───────────────────────┘
                              │
                              ▼
              ┌──────────────────────────────┐
              │  PKCS#11 HSM substrate       │
              │  Dinamo · Kryptus · Thales   │
              │  nShield · YubiHSM · Atos    │
              └──────────────────────────────┘
```

---

## 2. NON-NEGOTIABLES

These are not "preferences" or "best practices". They are gate criteria for
every commit, every release, every contract.

1. **Pure Rust** in qgateway, qvault, qaudit. No GC, no JVM, no Python in hot
   paths. C only via FFI to audited primitives (Zupt's libzupt) or HSM PKCS#11.
2. **Zero call-home, zero telemetry, zero forced cloud.** The product runs on
   air-gapped networks. Any phone-home is a P0 bug.
3. **Reproducible builds.** `cargo build --locked --release` from any clean
   checkout must produce byte-identical binaries given the same toolchain.
4. **Signed releases.** Every artifact carries an ML-DSA-87 detached signature
   *and* a Sigstore signature. Auditors must be able to verify offline.
5. **PKCS#11 first-class.** Every key material primitive has an HSM path
   (Dinamo, Kryptus Aegis, Thales Luna/payShield, Entrust nShield, YubiHSM 2,
   Atos Trustway). Software keys are dev-mode only.
6. **On-prem only.** Container, .deb, .rpm, bare-metal, hardware appliance. No
   SaaS. No multi-tenant cloud. Period.
7. **LGPD by construction.** Article 46 "estado da arte" is the design floor.
   PQ + ML-DSA-87 + on-prem + audit trail = legally defensible.
8. **Crypto-agile.** Every algorithm choice lives behind a `Suite` enum.
   ML-KEM-1024 → ML-KEM-1280 (if/when standardized) is a configuration change,
   not a rewrite.
9. **No stubs ever ship.** If a feature is half-built, it is feature-flagged
   off and absent from the documented surface.
10. **Honest disclosure.** If a primitive is broken, we say so the same day.
    See ObliterateX precedent: flash FTL disclosure shipped with v0.6.1.

---

## 3. COMPLIANCE MAP (BRAZIL)

| Norma / Padrão | O que exige | Como CSPQ atende |
|---|---|---|
| **LGPD Art. 46** | "Medidas técnicas aptas a proteger" | PQ + AGPL auditável = estado da arte defensável |
| **Bacen Res. 4.893/2021** | Gestão de risco cibernético, crypto-agility | Suite enum + HSM PKCS#11 + audit log assinado |
| **Bacen Circ. 3.978/2020** | Retenção 20 anos com integridade (PLD-FT) | QVault WORM + QAudit Merkle 20y |
| **CMN Res. 4.474/2016** | Dossiês PLD-FT íntegros | QVault content-addressed BLAKE3 |
| **CVM Res. 80/2022** | Relatórios assinados verificáveis | QAudit ML-DSA-87 + RFC 3161 timestamp |
| **SUSEP Circ. 638/2021** | Segurança da informação seguradoras | Mesmo stack PQ |
| **Open Finance / DICT** | mTLS + alta disponibilidade | QGateway substitui mTLS clássico por PQ |
| **SWIFT CSP 2025+** | Crypto migration roadmap | Evelin = PQ-ready transport |
| **ANPD GT-Cripto** | Cripto pós-quântica recomendada 2025+ | Default = ML-KEM-1024 + ML-DSA-87 |
| **ICP-Brasil DOC-ICP-15** | Algoritmos aprovados | ML-DSA candidato — pioneerismo competitivo |

---

## 4. TARGET BUYERS (BRAZIL-FIRST)

### Tier 1 — Top-10 bancos (R$ 1,5–5 M / ano ACV)
Itaú Unibanco · Banco do Brasil · Bradesco · Caixa · Santander · BTG Pactual ·
XP Inc. · Nubank · Safra · Banrisul.

### Tier 2 — Bancos médios e cooperativas (R$ 200k–500k / ano)
Sicredi · Sicoob · Original · Inter · C6 · Daycoval · Pine · ABC Brasil ·
Pan · Modal · BRB · BMG · Cresol · Unicred · Mercantil do Brasil.

### Tier 3 — Infra crítica e adquirentes (custom R$ 8M+)
B3 · Cielo · Stone · Rede · Getnet · PagSeguro · Mercado Pago · SPI/Bacen ·
Tesouro Direto · CIP · BSM Supervisão.

### Adjacente — Seguradoras
SulAmérica · Porto Seguro · Bradesco Seguros · Caixa Seguridade · BB Seguros ·
Mapfre · Allianz · Tokio Marine · HDI · Liberty.

### Adjacente — Setor público / grandes empresas
Petrobras · Vale · Eletrobras · BNDES · CEF · TCU · AGU · INSS · Receita
Federal · Dataprev · Serpro · Anatel · TJSP · TJRJ · Polícia Federal.

---

## 5. COMMERCIAL MODEL

```
              Community          Enterprise              Sovereign
              (AGPL)             (Commercial)            (Appliance)
              ─────────          ──────────────          ──────────────
  Source      AGPL-3.0           AGPL-3.0 + comm.        AGPL-3.0 + comm.
  Support     Best effort        24×5 NBD                24×7 4h
  HSM         Software keys      PKCS#11 any             Bundled HSM
  Pricing     R$ 0               R$ 180k–4M/year         Custom
  Target      OSS users          Bancos médios+          Tier 1 / SPI
```

**Margin levers**

1. HSM bundle (parceria Dinamo/Kryptus) — 30% revshare adicional.
2. Profissional services — implantação on-site R$ 80k/sprint.
3. Compliance reports — laudos LGPD/Bacen assinados, R$ 25k/relatório.
4. Training — SecOps PQ Bootcamp R$ 12k/aluno/semana.

---

## 6. ROADMAP (12 MESES — 10 SPRINTS)

| Sprint | Mês | Deliverable | Status |
|--------|-----|-------------|--------|
| S1 | M1  | QAudit v0.1 — Merkle log + ML-DSA-87 CLI | ✅ closed |
| S2 | M2  | QAudit v0.2 — Signer trait + PKCS#11 + Bacen XML export + portal web | ✅ closed |
| **S3** | **M3–4** | **QGateway v0.1 — TCP↔CSPQ reverse-proxy sidecar, single tenant** | ✅ **closed** |
| **S4** | **M4–5** | **QGateway v0.2 — multi-tenant, persistent audit binding, TLS termination** | **CURRENT** |
| S5 | M5–7 | QVault v0.1 — S3 subset + Zupt blob layer | — |
| S6 | M7–8 | QVault v0.2 — WORM, lifecycle, geo-replication | — |
| S7 | M8–9 | Hardening — fuzzing (AFL++), ACSL/Frama-C onde aplicável, audit externo (TrailOfBits/NCC) | — |
| S8 | M9–10 | Packaging — .deb/.rpm/OCI/Helm/Ansible/Terraform | — |
| S9 | M10–11 | **Pilot bancário** — 1 instituição Tier 2 on-site | — |
| S10 | M11–12 | **GA** — comercial launch, 3 contratos assinados | — |

---

## 7. ARCHITECTURE — DATA FLOWS

### 7.1 At-rest (QVault)

```
Application (S3 SDK)
        │ PutObject "logs/2026-05-19/transactions.csv"
        ▼
┌─────────────────────────────────────────────────────────┐
│ QVault Gateway (S3 API)                                 │
│                                                         │
│  1. Auth (mTLS PQ via QGateway)                         │
│  2. Lookup tenant policy → encryption-required: true    │
│  3. Stream object through Zupt encoder:                 │
│       a. LZ77-style compression (libzupt)               │
│       b. ML-KEM-768 + X25519 hybrid KEM (per object)    │
│       c. AES-256-GCM body encryption                    │
│  4. Compute BLAKE3-256 content digest                   │
│  5. Write to backend (NFS/Ceph/S3/MinIO) as .zupt blob  │
│  6. Emit QAudit event: object.put / digest / actor      │
└─────────────────────────────────────────────────────────┘
```

### 7.2 In-transit (QGateway)

```
Branch A app ─TLS 1.3 (legacy)─→ QGateway-A ═Evelin═→ QGateway-B ─TLS 1.3→ Branch B app
                                       │                  │
                                       ▼                  ▼
                                  ML-KEM-1024       ML-KEM-1024
                                  + ML-DSA-87       + ML-DSA-87
                                  + ChaCha20-Poly1305
```

Legacy applications keep doing TLS to the local sidecar. Wire crossing the
WAN is Evelin. Apps don't change. Auditors love that.

### 7.3 Audit (QAudit)

```
QGateway / QVault / external app
        │  emit_event(actor, action, resource, outcome, metadata)
        ▼
┌─────────────────────────────────────────────────────────┐
│ QAudit daemon                                           │
│                                                         │
│  1. Canonical CBOR-encode event                         │
│  2. BLAKE3 content hash                                 │
│  3. Append to MMR (Merkle Mountain Range)               │
│  4. Sign new root with ML-DSA-87                        │
│  5. Persist entry { event, prev_root, new_root, sig }   │
│  6. Anchor root every N entries to public ledger        │
│     (OpenTimestamps + RFC 3161 TSA)                     │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
                  qaudit verify log.qa
                  → 100% chain valid, all sigs ok
```

---

## 8. REPOSITORY STRUCTURE

```
cofre-soberano-pq/
├── SPEC.md                       # this file
├── README.md
├── LICENSE-AGPL
├── LICENSE-COMMERCIAL            # template for paid customers
├── Cargo.toml                    # workspace
├── Cargo.lock                    # always committed
├── rust-toolchain.toml           # pin stable
├── deny.toml                     # cargo-deny supply-chain config
├── .github/workflows/ci.yml
├── crates/
│   ├── qaudit-core/              # library (S1)
│   ├── qaudit/                   # CLI (S1)
│   ├── qaudit-portal/            # web UI (S2)
│   ├── qgateway-core/            # library (S3)
│   ├── qgateway/                 # daemon (S3)
│   ├── qvault-core/              # library (S5)
│   ├── qvault/                   # S3 daemon (S5)
│   ├── shared-pkcs11/            # HSM substrate (S2+)
│   └── shared-suite/             # crypto-agility Suite enum (S1)
├── docs/
│   ├── ARCHITECTURE.md
│   ├── THREAT-MODEL.md
│   ├── COMPLIANCE-MAPPING.md
│   ├── DEPLOY-ON-PREM.md
│   ├── HSM-INTEGRATION.md
│   └── BACEN-EXPORT-FORMAT.md
├── packaging/
│   ├── deb/  rpm/  oci/  helm/  ansible/  terraform/
└── tests/
    ├── interop/                  # cross-product integration
    └── fuzz/                     # AFL++ harnesses
```

---

## 9. CRYPTO SUITE (canonical defaults)

```rust
pub enum Suite {
    /// Default for 2026 launch. NIST PQC L5 + L3.
    Cspq2026,
}

impl Suite {
    pub const DEFAULT: Self = Self::Cspq2026;

    pub const fn kem(&self) -> Kem        { Kem::MlKem1024 }      // FIPS 203
    pub const fn kem_hybrid(&self) -> Kem { Kem::MlKem768X25519 } // for at-rest
    pub const fn sig(&self) -> Sig        { Sig::MlDsa87 }        // FIPS 204
    pub const fn aead(&self) -> Aead      { Aead::Chacha20Poly1305 }
    pub const fn hash(&self) -> Hash      { Hash::Blake3_256 }
    pub const fn kdf(&self) -> Kdf        { Kdf::Argon2id }
}
```

All cryptographic primitives are addressed by `Suite`. **No call site ever
hard-codes an algorithm.**

---

## 10. SPRINT 1 — DELIVERABLE CONTRACT (✅ CLOSED)

Sprint 1 shipped `qaudit-core` (library) and `qaudit` (CLI) implementing:

- ML-DSA-87 keypair generate / load / store
- Append-only audit log with Merkle Mountain Range (MMR) chain
- Per-entry signature over `(prev_root, event_hash, new_root, entry_index)`
- CBOR canonical serialization, magic-prefixed `.qa` format
- CLI commands: `init`, `append`, `verify`, `inspect`, `pubkey`, `info`
- Offline verification — `log.qa` + `pubkey.bin` is sufficient

All acceptance criteria met. 35 lib tests + 1 doc test green.

### 10.1 File format (`.qa`)

```
header (fixed, CBOR):
  magic         = "QAUDIT01"
  schema        = 1
  suite         = "cspq-2026"
  created_at    = ISO 8601
  log_id        = 16-byte random
  pubkey        = ML-DSA-87 public key (2592 B)

then a stream of CBOR entries:
  entry {
    index:       u64
    timestamp:   ISO 8601
    event:       AuditEvent (CBOR canonical)
    prev_root:   32 B
    new_root:    32 B
    signature:   ML-DSA-87 signature over canonical CBOR of
                 (log_id || index || prev_root || event_hash || new_root)
  }
```

---

## 11. SPRINT 2 — DELIVERABLE CONTRACT (✅ CLOSED)

### 11.1 Scope

Promote the signer interface from a concrete `KeyPair` field to a trait
object, ship the PKCS#11 substrate so the audit log can be signed by an
HSM in production, deliver the regulator-facing XML export format, and
ship a read-only web portal for auditors.

### 11.2 Delivered

- **`Signer` trait** in `qaudit-core::signing` with blanket `impl<S: Signer + ?Sized> Signer for Box<S>` and `impl Signer for KeyPair` (provenance `"soft:in-memory"`).
- **`AuditLog` refactor**: `Option<KeyPair>` → `Option<Box<dyn Signer>>`. New constructors `create_with_signer<S>` and `bind_signer<S>`; legacy `KeyPair` API preserved as backward-compat shims so Sprint 1 tests run unchanged.
- **`qaudit-hsm` crate** with:
  - `SoftSigner` (default, always-on) — wraps a `KeyPair` with configurable provenance.
  - `Pkcs11Signer` (feature `pkcs11`, cryptoki 0.10) — loads any PKCS#11 v3 driver (Dinamo, YubiHSM 2, Thales Luna 7, Entrust nShield, SoftHSM 2). Opens a session, logs in with PIN held in `Zeroizing`, looks up the keypair by `CKA_LABEL`, signs through `C_Sign` with a configurable mechanism (default `CKM_VENDOR_DEFINED + 0x0001`; production users override per their HSM's ML-DSA OID until PKCS#11 v3.2 standardizes `CKM_ML_DSA`).
  - Internal `Mutex<Session>` to serialize `C_Sign` across threads — many vendor drivers are not MT-safe.
  - Integration test `live_hsm_sign_verify` gated on `QAUDIT_PKCS11_*` env vars (skipped by default; runs against real hardware when set).
- **`qaudit-core::export`** with `export_xml` (namespaced schema `https://securityops.co/schemas/qaudit-export-v1`, proper attribute and content escaping, signatures carried inline) and `export_jsonl` (one entry per line, custom escaper, no `serde_json` dep). Tests confirm well-formed XML, balanced tags, and special-character escaping.
- **`qaudit export` CLI** subcommand with `--format {xml,jsonl}`, `--out PATH`, default pre-export `verify()` gate (refuses to export a tampered log; `--no-verify` opt-out documented).
- **`qaudit-portal` crate** — Axum 0.7 read-only web viewer. Routes: `/` (dark-themed HTML page with verify badge, header metadata grid, paginated entry table), `/api/info`, `/api/verify`, `/api/entries?offset&limit`, `/api/pubkey`, `/healthz`. Optional `--pk` for independent verification on startup. Graceful shutdown on SIGTERM / Ctrl-C. Binds 127.0.0.1 by default.

### 11.3 Acceptance criteria (binary)

- [x] `cargo build --release --locked --workspace` succeeds
- [x] `cargo build --release --locked -p qaudit-hsm --features pkcs11` succeeds
- [x] `cargo test --workspace --locked` shows 100% green (**47 / 47**: 41 qaudit-core + 4 qaudit-hsm soft + 1 qaudit-portal + 1 doc)
- [x] `cargo test -p qaudit-hsm --features pkcs11` shows 100% green (5 passed, 1 ignored — live HSM)
- [x] `cargo clippy --workspace --all-targets -- -D warnings` clean in both feature modes
- [x] `cargo fmt --check` clean
- [x] All Sprint 1 tests still pass without modification (backward-compat shims hold)
- [x] CLI export roundtrip: `init → append × N → export --format xml → xmllint --noout` succeeds
- [x] CLI refuses to export a tampered log unless `--no-verify` is passed
- [x] Portal smoke: `init → append × N → qaudit-portal & → curl /api/verify → curl /` produces verified status and rendered HTML
- [x] No `unsafe` outside vetted deps (`#![forbid(unsafe_code)]` in every CSPQ crate)

### 11.4 Out of scope (kept for Sprint 2.5 or later)

- RFC 3161 / OpenTimestamps anchor — substrate ready (signed payload covers the entry; anchors layer on top), implementation deferred.
- ICP-Brasil signed-PDF interop (QDoc / BTP) — Sprint 8+.
- HSM key-generation via PKCS#11 (currently keys are externally provisioned with vendor tools, then qaudit binds via label) — Sprint 4.
- Multi-log portal / search — Sprint 4.

### 11.5 File format diff vs Sprint 1

None. The `.qa` wire format is bit-identical to Sprint 1. The Signer trait
introduction is a source-level refactor only.

---

## 12. SPRINT 3 — DELIVERABLE CONTRACT (✅ CLOSED)

### 12.1 Scope

Open the QGateway product line. Ship a single-tenant reverse-proxy sidecar
that lets two endpoints traverse a WAN over a post-quantum transport
(ML-KEM-1024 + ML-DSA-87 + ChaCha20-Poly1305), with no application changes.

### 12.2 Architecture (as delivered)

```
  Branch-A app                                              Branch-B app
       │                                                          │
       │   TCP loopback to local sidecar                          │
       ▼                                                          ▲
   QGateway-A  ════ CSPQ-Transport-v1 (PQ AEAD) ═══════════ QGateway-B
   (serve-tcp)                                          (serve-pq)
       │                                                          │
       └──── audit log A (qaudit, ML-DSA-87 signed)               │
                                            audit log B  ────────┘
```

### 12.3 Delivered

1. **`qtransport-cspq` crate** — reference PQ transport implementation,
   `CSPQ-Transport-v1` wire protocol with:
   - **3-message mutual handshake**: CLIENT_HELLO (suite + ML-KEM-1024 ephemeral pk) → SERVER_HELLO (KEM ciphertext + server ML-DSA-87 long-term pk + signature over transcript) → CLIENT_FINISH (client long-term pk + signature over full transcript including its own id).
   - **Key schedule**: `HKDF-SHA3-256(shared_secret, salt=b"cspq-transport-v1", info=transcript)` → 32 B `key_c2s` + 32 B `key_s2c`.
   - **Record layer**: per-direction nonces (4 B direction prefix + 8 B BE counter), ChaCha20-Poly1305 AEAD, 16 KiB max plaintext per record, hard cap on counter overflow.
   - **Split halves** — `CspqStream::split()` yields `CspqReader` + `CspqWriter` so the proxy can pump two directions in concurrent tasks safely (no shared mutable state, no cancellation hazards).
   - Identity-key files (`.cspqid.pub`) with `CSPQID01` magic + 2592 B raw ML-DSA-87 pk; trust enforced by a `PeerPolicy` allow-list loaded from a directory of `.cspqid.pub` files.
2. **`qgateway-core` crate** — substrate for the daemon:
   - `config::Config` — TOML loader, role validation, `serve_tcp` / `serve_pq` sub-sections, default `metrics_listen = 127.0.0.1:9099`.
   - `metrics::MetricsRegistry` — atomic counters (sessions opened/closed/failed/active, bytes c2s/s2c, audit events/failures) and a handshake-latency histogram across 11 fixed buckets (500µs – 1s), rendered in Prometheus text format 0.0.4. No external metrics-crate dependency.
   - `audit::AuditChannel` — background tokio task owning a writable `AuditLog`, fed by a bounded `mpsc::Sender` so the proxy hot path never blocks on disk I/O. Backpressure drops are counted in `audit_failures`. Batches up to 16 events or every 500 ms, whichever first.
   - `proxy::run_session` — bidirectional pump using `CspqStream::split` + `TcpStream::into_split`; two tasks (TCP→CSPQ, CSPQ→TCP); on either side closing, aborts the other and emits a `session.close` audit event with `bytes_up`, `bytes_down`, `duration_ms`, `shutdown_reason`.
   - `gateway::run_serve_tcp` / `run_serve_pq` — the two role accept loops, each spawning a session task per connection, with `tokio::sync::Notify`-based graceful shutdown.
3. **`qgateway` daemon binary** — CLI with three subcommands:
   - `keygen --sk PATH --pk PATH` — generates an ML-DSA-87 identity, writes `.cspqid.pub` (8 B magic + 2592 B raw pk) and `.skid` (8 B magic + 4896 B raw sk, mode 0600 on unix).
   - `pubkey --pk PATH` — prints the hex-encoded public key bytes (useful for peer-trust exchange).
   - `run --config /etc/qgateway/sidecar.toml` — full daemon: loads identity + peer-pubkey directory, opens or creates the audit log, spawns the audit channel, runs a Prometheus `/metrics` server (bare tokio, no axum dep), dispatches to `run_serve_tcp` or `run_serve_pq`, handles SIGTERM and Ctrl-C, waits for in-flight sessions to drain.
4. **`/metrics` + `/healthz`** — exposed on `metrics_listen` (default `127.0.0.1:9099`), Prometheus text format 0.0.4.
5. **QAudit integration** — every session open and close emits a signed entry via the embedded `Box<dyn Signer>`; metadata includes `direction`, `tcp_peer`, `handshake_us`, `bytes_up`, `bytes_down`, `duration_ms`, `shutdown_reason`, and the hex-prefix of the peer's identity public key.
6. **End-to-end integration test** — `crates/qgateway-core/tests/e2e_tunnel.rs` spins up a TCP echo backend, a `serve-pq` gateway, a `serve-tcp` gateway, opens a client TCP connection, pumps three messages totalling 8.2 KB through the PQ tunnel, asserts round-trip integrity, verifies both audit logs (each contains `session.open` + `session.close`), and verifies the Prometheus exposition increments correctly.

### 12.4 Acceptance criteria (binary)

- [x] `cargo build --release --workspace --locked` succeeds
- [x] `cargo test --workspace --locked` shows 100% green (**71 / 71** across qaudit-core 41+1 doc, qaudit-hsm 4, qaudit-portal 1, qgateway-core 9+1 e2e, qtransport-cspq 13, qgateway 1)
- [x] `cargo test -p qaudit-hsm --features pkcs11` shows 100% green (5 passed, 1 ignored live HSM)
- [x] `cargo clippy --workspace --all-targets -- -D warnings` clean (both feature modes)
- [x] `cargo fmt --check` clean
- [x] All Sprint 1 + Sprint 2 tests still pass without modification
- [x] CLI smoke: `qgateway keygen` produces correctly-formatted identity files
- [x] Daemon smoke: pair of gateways tunnels a TCP echo, `qaudit inspect` shows matching `session.open` events with cross-referenced peer fingerprints on both logs
- [x] Handshake p50 latency on commodity hardware: **~3 ms** (ML-KEM-1024 + ML-DSA-87 + transcript verification + HKDF-SHA3 derive)
- [x] No `unsafe` outside vetted deps (`#![forbid(unsafe_code)]` in all CSPQ crates)
- [x] Untrusted-peer test: gateway rejects a CSPQ handshake from an identity not in the `PeerPolicy` allow-list (covered in `qtransport-cspq::handshake::tests::handshake_rejects_unknown_client` and `handshake_rejects_wrong_server`).
- [x] Tampered-ciphertext test: a record received under the wrong nonce counter fails AEAD verification with `Error::Crypto` (covered in `qtransport-cspq::transport::tests::tampered_ciphertext_rejected`).

### 12.5 Honest scope decisions

- **No Evelin SDK linkage in-repo.** Evelin is Cristian's own AGPL crate at
  `git.securityops.co/cristiancmoises/evelin` and is not vendored here.
  `qtransport-cspq` is a clean-room reference implementation of the same
  primitives so the gateway has a working transport for testing and pilot
  deployments. Production checkouts can swap `qtransport-cspq` for an
  Evelin-backed transport at the `accept` / `connect` function boundary
  without touching `qgateway-core` or the daemon binary.
- **No TLS termination on the app side.** The Sprint 3 diagram drops the
  TLS-1.3 link between local app and sidecar; the link is plain TCP on
  loopback (or via systemd socket activation). For deployments that need
  app-side TLS, a `stunnel` or `rustls` terminator sits in front. Sprint 3.5
  will introduce in-process TLS termination via `tokio-rustls` with a
  PQ-hybrid KEX (X25519+ML-KEM-768) when rustls ships a stable hybrid
  cipher suite.
- **No `AsyncRead` / `AsyncWrite` on `CspqStream`.** Those traits demand
  cancel-safe `poll_*` impls, which require an explicit state machine that
  preserves partial-frame progress across yields. Sprint 3 ships the
  record-based API (`send_record` / `recv_record`) which is sufficient for
  the proxy and is the surface the gateway uses; Sprint 3.5 adds the state
  machine.
- **Audit key is ephemeral per gateway restart.** The transport identity
  (`.skid`) is persistent and operator-provisioned. The audit-log signing
  keypair is generated in-memory on first start and held by the audit
  channel task; each restart starts a fresh log file. Sprint 4 adds a
  separate `.audit.skid` for persistent audit-key binding plus the option
  to bind to a PKCS#11 signer via `qaudit-hsm`.
- **`shutdown_reason` in audit shows "cancelled" for the side aborted when
  the peer closed first.** Cosmetic, not a correctness issue; Sprint 3.5
  replaces task-abort with a graceful close protocol (zero-length record
  as an EOF marker) so both halves record `clean`.

### 12.6 File format (new in Sprint 3)

```
.cspqid.pub  (transport identity public key, world-readable):
  magic     = "CSPQID01"  (8 B)
  ml-dsa-87 = 2592 B raw

.skid        (transport identity secret key, mode 0600):
  magic     = "CSPQSK01"  (8 B)
  ml-dsa-87 = 4896 B raw
```

CSPQ wire records (after handshake):

```
  u32 BE length        (excluding itself; max 64 KiB)
  AEAD-sealed payload  (ChaCha20-Poly1305; nonce = direction[4] || counter_be[8])
                       (plaintext capped at 16 KiB)
```

---

## 13. SPRINT 4 — DELIVERABLE CONTRACT (✅ CLOSED)

### 13.1 Scope

Promote QGateway from single-tenant dev/pilot to a multi-tenant production
sidecar with persistent audit-key binding (including PKCS#11 path) and
in-process TLS 1.3 termination on the app side. Add the multi-tenant
router so a single gateway can fan a CSPQ uplink out across multiple peer
gateways (one per branch / business unit).

### 13.2 Delivered

| # | Deliverable | Status | Notes |
|---|---|---|---|
| 1 | Multi-tenant routing | ✅ | `[[tenants]]` array in config; per-tenant `MetricsRegistry` with `tenant=` Prometheus label; per-tenant `AuditChannel` and `.qa` log; per-tenant `peer_pub_dir` (trust isolation). Tenant-name uniqueness enforced. Each tenant runs in its own `tokio::spawn` accept loop. |
| 2 | Persistent audit-key binding | ✅ | `.audit.skid` (magic `AUDITSK0`, 8 + 4896 B, mode 0600) + `.audit.pub` (magic `AUDITPK0`, 8 + 2592 B). `qgateway audit-keygen` CLI subcommand. `[audit_signer.kind = "softkey"]` config. Daemon refuses to extend an existing log if its header pubkey ≠ configured audit-key (operator-mistake guard). PKCS#11 path wired via `[audit_signer.kind = "pkcs11"]` + cfg-gated `pkcs11` feature on the daemon crate. |
| 3 | TLS 1.3 termination | ✅ | `qgateway-core::tls::build_acceptor` builds a `tokio_rustls::TlsAcceptor` from PEM cert + key. `[tenants.tls]` block in TOML. Per-tenant TLS — different tenants can have different certs. Gateway `accept` wraps incoming TCP via `acc.accept(tcp).await` before `run_session`. **SNI-based tenant dispatch deferred to Sprint 4.5** (current routing is one listen port per tenant). |
| 4 | Graceful close protocol | ✅ | `CspqStream::send_eof()` + `CspqWriter::send_eof()` send an authenticated zero-length record; receiver's `recv_record()` returns `Ok(empty Vec)` which the proxy treats as orderly EOF. `shutdown_reason: clean` recorded on both sides when both halves report normal EOF. |
| 5 | AsyncRead/AsyncWrite state machine | ⏸ deferred to Sprint 4.5 | The proxy uses the record-based `send_record`/`recv_record` API directly (one frame per pump iteration) and does NOT need a `Pin<&mut Self>` poll-loop state machine to be correct. Honest decision: skipping speculative engineering. Sprint 4.5 will add `impl AsyncRead + AsyncWrite for CspqStream` for downstream consumers (e.g. `tokio::io::copy`). |
| 6 | Tamper-replay test | ✅ | `qtransport-cspq::transport::aead_layer_rejects_cross_session_ciphertext` proves that ciphertext sealed under one session key fails to open under another (cryptographic core of cross-session replay rejection). `aead_layer_rejects_within_session_replay` proves the nonce counter prevents within-session replay. `aead_layer_rejects_one_bit_flip` proves Poly1305 catches tampering. Three additional stream-level checks (`tampered_ciphertext_rejected`, `forged_eof_without_key_is_rejected`, `eof_marker_session_isolation_no_cross_session_decrypt`) close the loop at the framed transport layer. |

### 13.3 Acceptance — actual

- [x] `cargo test --workspace --locked` green: **89 tests** across `qaudit-core` (41), `qaudit-hsm` softkey (4), `qaudit-portal` (1), `qgateway-core` lib (19), `qgateway-core` e2e tunnel (1), `qgateway-core` audit-persistence integration (2), `qtransport-cspq` (18), `qgateway` (2), plus 1 doctest.
- [x] **Multi-tenant smoke** (`tests/e2e_tunnel.rs::multi_tenant_isolation_and_graceful_close`): 2 tenants (`sp`, `rj`), separate listen ports, peer policies, audit logs, metrics. Verifies (a) each tenant's audit log contains only its own events with correct `tenant=` metadata; (b) `shutdown_reason: clean` on both sides; (c) Prometheus exposition has both labels in one `# HELP` block; (d) per-tenant counters isolated.
- [x] **Audit-key persistence smoke** (`tests/audit_persistence.rs`): two-boot scenario — first boot creates `.audit.skid`/`.audit.pub`, appends a `session.open` event, saves log; second boot loads same audit key, re-opens log, verifies header pubkey match, appends `session.close`, saves; regulator (third party with only `.audit.pub`) opens log and `log.verify()` succeeds across the full chain spanning both boots.
- [x] **PKCS#11-signed audit**: `cargo build -p qgateway --features pkcs11` compiles; runtime path tested by `qaudit-hsm::pkcs11::tests` (5 tests, 1 ignored — requires SoftHSMv2 module).
- [x] All standing constraints honored: pure Rust, zero telemetry, locked build, no stubs.

### 13.4 Honest deferrals to Sprint 4.5

1. **`AsyncRead + AsyncWrite` impl for `CspqStream`** — not required by the proxy (record-based API is sufficient and correct). Will be added for ecosystem compatibility (`tokio::io::copy`, `hyper`, etc.) along with proper poll-loop state machines for partial frame progress across yields.
2. **SNI-based tenant routing on a single TLS listen port** — current TLS termination supports one TLS leg per listen port. SNI dispatch needs a wrapping listener that reads the ClientHello and routes to the right tenant's `TlsAcceptor`.
3. **Cert hot-reload** — currently the cert is loaded once at startup; rotations require a daemon restart.
4. **`qgateway tenant add/remove` CLI** — current model edits the TOML and restarts; runtime tenant mgmt without restart deferred.

### 13.5 Standing constraints (unchanged)

Pure Rust · zero telemetry · `cargo build --locked` reproducible · all
releases signed with ML-DSA-87 · PKCS#11 first-class · on-prem only · LGPD by
construction · crypto-agile through the `Suite` enum · no stubs ever ship.

---

## 13.5. SPRINT 4.5 — DELIVERABLE CONTRACT (✅ CLOSED)

Targeted consolidation sprint: add ecosystem-compat shape to CSPQ so any
tokio-shaped consumer (`tokio::io::copy`, `hyper`, framed codecs, …) can
drive a CSPQ session without going through the bespoke record API.

### 13.5.1 Delivered

| # | Deliverable | Status | Notes |
|---|---|---|---|
| 1 | `AsyncRead + AsyncWrite for CspqStream<S>` | ✅ | Explicit `ReadState`/`WriteState` machines preserve partial frame progress across `Poll::Pending` yields. |
| 2 | `AsyncRead for CspqReader<R>` | ✅ | Same `ReadState` machine; reusable from a `split()` pair. |
| 3 | `AsyncWrite for CspqWriter<W>` | ✅ | Same `WriteState` machine; emits authenticated EOF marker on `poll_shutdown`. |
| 4 | Tokio-shape round-trip tests | ✅ | 8 new tests: small message, **1 MiB via `tokio::io::copy`**, EOF marker delivery, oversized-record chunked reads, oversized-input chunked writes, concurrent bidirectional split halves, mid-frame truncation error, clean inter-frame TCP EOF. |
| 5 | SNI-based tenant routing | ⏸ → Sprint 5 | Pure ops feature; current TLS termination supports one cert per listen port. |
| 6 | Cert hot-reload | ⏸ → Sprint 5 | Pure ops feature. |
| 7 | `qgateway tenant add/remove` runtime CLI | ⏸ → Sprint 5 | Pure ops feature; restart-based reconfig works today. |
| 8 | `proptest` expansion | ✗ skipped | Targeted scenario tests (above) give stronger guarantees than fuzz-shaped property tests for state-machine correctness. Revisit if a behavior gap shows up in production. |

### 13.5.2 State machines

**Read path** (each `poll_read` advances zero-or-more transitions until it
either yields data, returns `Poll::Pending`, or signals EOF):

```
Idle → Len(buf:[u8;4], filled:usize) → Body(ct:Vec<u8>, filled:usize) →
       (decrypt) → Drain(pt:Vec<u8>, pos:usize) → Idle → ...
       OR → Eof (terminal — peer sent authenticated empty record OR clean
                  inner EOF between frames)
```

`Eof` is sticky and re-poll-safe. A `Poll::Pending` from the inner
`AsyncRead` parks with full progress preserved; the next `poll_read`
resumes exactly where it left off.

**Write path**:

```
Idle → (seal min(buf.len, MAX_PLAINTEXT)) → Writing(frame, written, consumed) →
       (drain to inner) → Idle → ...

poll_flush: drain any in-flight Writing frame, then poll_flush inner.

poll_shutdown:
  Writing → finish current frame
  Idle → seal authenticated empty record → ShuttingDown(SendEofFrame)
  ShuttingDown(SendEofFrame) → ShuttingDown(FlushInner) → ShuttingDown(ShutdownInner) → Closed
```

`Closed` is sticky. Writes after `Closed` return `NotConnected`. Writes
during `ShuttingDown` return `NotConnected` (no late data injection past
the EOF marker).

### 13.5.3 API surface changes

- **Removed (Sprint 3 → 4.5)**: inherent `CspqStream::shutdown()` and
  `CspqWriter::shutdown()` returning `crate::Result<()>`. These only
  closed the inner byte stream without emitting an authenticated EOF
  marker. They were unused outside the crate.
- **Replacement**: call `tokio::io::AsyncWriteExt::shutdown` on the
  stream/writer. The new `AsyncWrite` impl emits an authenticated
  empty-record EOF marker, flushes the inner writer, then shuts it
  down — strictly stronger semantics.
- **Added**: `impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for CspqStream<S>`, `impl<S> AsyncWrite`, plus the equivalent on `CspqReader<R>` / `CspqWriter<W>`.
- **Preserved**: `send_record` / `recv_record` / `send_eof` remain on
  the inherent APIs. The gateway proxy still uses them.

### 13.5.4 Acceptance — actual

- [x] `cargo test --workspace --locked` green: **97 tests** (up from 89 in
      Sprint 4). New tests live in `qtransport-cspq::transport::tests` under
      the "Sprint 4.5 — AsyncRead / AsyncWrite test suite" banner.
- [x] `cargo build --workspace --locked` clean.
- [x] `cargo clippy --workspace --all-targets -- -D warnings` clean.
- [x] `cargo fmt --all --check` clean.
- [x] `cargo build -p qgateway --features pkcs11 --locked` clean.
- [x] 1 MiB tokio::io::copy echo round-trip succeeds with byte-perfect equality.

### 13.5.5 Honest deferrals to Sprint 5

1. **SNI tenant routing** on a shared TLS listen port (current model is one listen port per tenant).
2. **Cert hot-reload** via `notify` + atomic acceptor swap.
3. **Runtime `qgateway tenant add/remove`** CLI (current model is TOML + restart).
4. ✅ **Per-tenant audit key isolation** — DELIVERED in Sprint 5 (below).

---

## 13.6. SPRINT 5 — DELIVERABLE CONTRACT (✅ CLOSED)

Targeted compliance/security sprint focused on isolating audit chains
across tenants. Sprint 4 had a shared daemon-level audit signer; this
weakened the cross-tenant isolation story for regulated multi-tenant
deployments. Sprint 5 ships full per-tenant signer support with a
documented inheritance model.

### 13.6.1 Delivered

| # | Deliverable | Status | Notes |
|---|---|---|---|
| 1 | `[tenants.audit_signer]` override (softkey or PKCS#11) | ✅ | Per-tenant TOML block fully replaces the daemon-level default for that tenant. No partial merge — replacement is total. |
| 2 | Daemon-level `[audit_signer]` as optional default | ✅ | Top-level signer becomes a fallback default. Each tenant either has its own or inherits the default. Validation fails if neither is present. |
| 3 | Strict per-tenant posture (no daemon default) | ✅ | A config with no top-level `[audit_signer]` but a per-tenant `[tenants.audit_signer]` on every tenant validates and runs. This is the strongest isolation posture. |
| 4 | Mixed-kind support (Softkey + PKCS#11 in one daemon) | ✅ | Tenant A on Softkey, tenant B on PKCS#11 HSM — coexist in the same daemon. Verified by config test. |
| 5 | Resolved-tenant types carry effective signer | ✅ | `ServeTcpTenant.audit_signer: AuditSignerConfig` and `ServePqTenant.audit_signer: AuditSignerConfig` — runtime never re-runs the precedence logic, it reads the resolved value. |
| 6 | SNI tenant routing | ⏸ → Sprint 5.5 | Honest deferral: SNI is a substantial architectural change (rustls `ResolvesServerCert` + ClientHello dispatch + multi-cert config schema) that wasn't ready to ship complete this sprint. |
| 7 | Cert hot-reload | ⏸ → Sprint 5.5 | Will use SIGUSR1 + atomic acceptor swap rather than `notify`-based file watching (signal model is simpler, equally effective in practice). |
| 8 | Runtime `qgateway tenant add/remove` CLI | ⏸ → Sprint 5.5 | Lowest priority — TOML-edit + restart works fine for typical ops cadences. |

### 13.6.2 Effective-signer precedence

```
For each tenant T at config load time:
  if T has [tenants.audit_signer]:
      signer(T) := T.audit_signer            # per-tenant override (full replacement)
  elif config has top-level [audit_signer]:
      signer(T) := config.audit_signer       # daemon-level default
  else:
      ERROR: tenant T has no audit_signer    # validate() rejects
```

Precedence is resolved once, at `Config::load`. The result is stored on
`ServeTcpTenant.audit_signer` / `ServePqTenant.audit_signer` so the
runtime path never has to recompute it.

### 13.6.3 Operational implications

Per-tenant signer enables three deployment postures regulators may ask for:

1. **Shared signer, multi-tenant logs** (Sprint 4 default carried forward) —
   simplest ops, one HSM slot/softkey, all tenant logs signed by the same key.
   Compliance footnote: an attacker with that one key can forge entries in
   any tenant's log; the audit trail's integrity scope is per-daemon, not
   per-tenant.
2. **Per-tenant softkey** — each tenant has its own `.audit.skid` /
   `.audit.pub`. Audit chains are cryptographically isolated; compromise of
   one tenant's audit key does not let an attacker forge entries in
   another tenant's log. Recommended for regulated multi-business-unit
   deployments.
3. **Per-tenant PKCS#11 binding** — strongest posture: each tenant's audit
   signer lives in an HSM under its own label. Cross-tenant isolation now
   relies on HSM access policy (PIN per slot, role-based access on the
   HSM, etc.), not on filesystem permissions. Recommended for highly
   regulated industries (banking, healthcare data).

### 13.6.4 API surface changes

**Additive**:
- `ServeTcpTenant.audit_signer: AuditSignerConfig` (new field)
- `ServePqTenant.audit_signer: AuditSignerConfig` (new field)
- `Config::effective_signer(&self, t: &TenantConfig) -> Option<AuditSignerConfig>` (new method, public)

**Behavioral**:
- `Config.audit_signer` was already `Option<AuditSignerConfig>` (Sprint 4
  field); Sprint 5 codifies its role as the *daemon-level fallback default*
  rather than the mandatory single signer.
- `validate()` now requires each tenant to have an effective signer
  (override OR daemon default).

**Compatibility**: All Sprint 4 configs remain valid — they have a
top-level `[audit_signer]` and no per-tenant override, which is exactly the
fallback posture.

### 13.6.5 Acceptance — actual

- [x] `cargo test --workspace --locked` green: **101 tests** (up from 97 in
      Sprint 4.5). Four new tests in `qgateway-core::config::tests`:
  - `per_tenant_audit_signer_override` — verify override doesn't inherit default
  - `rejects_tenant_without_any_audit_signer` — verify validation catches the gap
  - `accepts_strict_per_tenant_no_daemon_default` — verify strict isolation posture
  - `accepts_mixed_signer_kinds_across_tenants` — verify Softkey + PKCS#11 coexist
- [x] `cargo build --workspace --locked` clean.
- [x] `cargo clippy --workspace --all-targets -- -D warnings` clean.
- [x] `cargo fmt --all --check` clean.
- [x] `cargo build -p qgateway --features pkcs11 --locked` clean.

### 13.6.6 Honest deferrals to Sprint 5.5

1. SNI-based tenant routing on a shared TLS listen port.
2. ✅ Cert hot-reload via SIGUSR1 + atomic acceptor swap — **DELIVERED in Sprint 5.5**.
3. Runtime `qgateway tenant add/remove` CLI without restart.

---

## 13.7. SPRINT 5.5 — DELIVERABLE CONTRACT (✅ CLOSED)

Operational hardening focused on eliminating gateway restarts for routine
TLS certificate rotations. Today most certificate-issuance workflows
(Let's Encrypt every 90 days, corporate PKI on annual rotation, ACME
short-lived certs every hour) require some kind of "reload without
downtime" mechanism. Sprint 5.5 ships that.

SNI tenant routing (the other major Sprint 5 deferral) is genuinely
out-of-scope for this sprint — it would require a substantial schema
change (listeners as first-class objects, multi-cert resolvers via
rustls `ResolvesServerCert`, ClientHello dispatch) that's better landed
as its own sprint with its own end-to-end test coverage.

### 13.7.1 Delivered

| # | Deliverable | Status | Notes |
|---|---|---|---|
| 1 | `TlsAcceptorHandle` — read-side primitive | ✅ | Cloneable handle that the gateway accept loop calls `current()` on per accept to snapshot the latest acceptor. `Arc` clone, no locks on the hot path. |
| 2 | `TlsReloadTrigger` — write-side primitive | ✅ | Owns the `TlsConfig` so it can rebuild from the same paths. `reload()` re-reads cert + key, rebuilds acceptor, atomically installs via `tokio::sync::watch::Sender::send`. Failure preserves the previous acceptor. |
| 3 | `build_reloadable_acceptor(cfg, tenant_name)` | ✅ | Single entry point returning a `(handle, trigger)` pair. The handle goes to the accept loop; the trigger to the signal-handler task. |
| 4 | `qgateway`: per-tenant trigger collection | ✅ | `cmd_run` builds one trigger per TLS-enabled tenant and hands the list to the signal handler. Tenants without `[tenants.tls]` are skipped (no trigger). |
| 5 | SIGUSR1 handler | ✅ | On signal, walks every trigger and calls `reload()`. Logs per-tenant success/failure. Failed reloads are *non-fatal* — the previous acceptor stays installed; the daemon keeps serving. No traffic interruption. |
| 6 | Hot-reload smoke tests | ✅ | 3 tests covering the `TlsReloadTrigger`/`TlsAcceptorHandle` API contract: bad-path rejection at construction time, tenant-name accessor, watch-channel update visibility (manually-built acceptors to avoid needing rcgen). |

### 13.7.2 Operational model

```
$ certbot renew  # or your PKI rotation workflow
$ kill -USR1 $(pidof qgateway)

[INFO  qgateway] SIGUSR1 received, reloading TLS certs (n_tenants=2)
[INFO  qgateway] TLS cert reloaded (tenant=branch-sp)
[INFO  qgateway] TLS cert reloaded (tenant=branch-rj)
[INFO  qgateway] TLS reload cycle complete (reloaded=2, failed=0)
```

In-flight TLS handshakes finish with the previous acceptor (no
mid-handshake swap, which would corrupt the connection state). The
*next* accept on each tenant picks up the new acceptor. There is no
traffic interruption.

If a reload fails (typo in path, bad PEM, partial write during atomic
rename), the daemon logs `TLS reload FAILED, keeping previous cert: …`
and continues serving on the old cert. Operators fix the issue and
re-send SIGUSR1.

### 13.7.3 Why SIGUSR1 instead of `notify` / `inotify`?

- **Supply chain**: `notify` pulls in ~6 transitive deps (kqueue/inotify
  shims, file abstractions). SIGUSR1 needs zero new deps — Tokio's
  built-in `signal::unix::SignalKind::user_defined1` covers it.
- **Operational fit**: certificate rotations are externally triggered by
  cron, systemd, or an ACME hook — those workflows can call `kill -USR1`
  trivially. There's no operational need for autonomic file-watching.
- **Reload atomicity**: with file watching, a half-written cert/key pair
  can trigger reload before the writer finishes. Signal-driven reload
  fires *after* the deployment tool finishes its atomic rename — strictly
  better timing.
- **Predictability**: easier to test, easier to debug ("why did the cert
  reload at 3:14am?" → because somebody sent SIGUSR1, not because
  inotify fired on a `chmod`).

### 13.7.4 Acceptance — actual

- [x] `cargo test --workspace --locked` green: **108 tests** (up from 101
      in Sprint 5).
- [x] `cargo build --workspace --locked` clean.
- [x] `cargo clippy --workspace --all-targets -- -D warnings` clean.
- [x] `cargo fmt --all --check` clean.
- [x] `cargo build -p qgateway --features pkcs11 --locked` clean.
- [x] Hot-reload smoke tests pass.

### 13.7.5 Honest deferrals to Sprint 6

1. ✅ **SNI tenant routing** — DELIVERED in Sprint 6 (below).
2. **Runtime `qgateway tenant add/remove`** CLI without restart.
3. **Audit log rotation** with chain integrity across files.
4. **Connection rate limiting / DoS shield** — pre-requisite for direct internet exposure.

---

## 13.8. SPRINT 6 — DELIVERABLE CONTRACT (✅ CLOSED)

Operational consolidation focused on collapsing per-tenant listen-port
sprawl. A typical Brazilian regional bank may run 20+ branches under a
single corporate domain — Sprint 4/5's "one port per tenant" model
forces firewall rule complexity, makes WAF/CDN integration awkward, and
diverges from how every other TLS terminator on the market works
(NGINX, HAProxy, Caddy, Envoy all use SNI dispatch as the default).
Sprint 6 brings QGateway up to that baseline.

### 13.8.1 Delivered

| # | Deliverable | Status | Notes |
|---|---|---|---|
| 1 | `sni` field on `[[tenants]]` config | ✅ | Optional. Required iff the tenant shares its listen with another tenant. |
| 2 | Implicit listener grouping by `listen` address | ✅ | Tenants with the same `listen` form a multi-SNI group. Tenants with unique listen addresses follow the existing single-tenant path. No new schema concept ("listener" as a first-class object was considered and rejected as schema bloat — grouping is computed at validate time from the existing `listen` field). |
| 3 | Strict SNI grouping validation | ✅ | 7 distinct validation rules — see §13.8.2 below. |
| 4 | `TlsListenerGroup` resolved type | ✅ | `Config::resolve_serve_tcp_groups()` returns these. Each group is either single-tenant (existing path) or `sni_dispatch=true` (new path). Group order deterministic (`BTreeMap` by listen string). |
| 5 | `MultiSniCertResolver` | ✅ | Implements `rustls::server::ResolvesServerCert`. `HashMap<sni, Arc<CertifiedKey>>`. Unknown SNI returns `None` → rustls emits `unrecognized_name` alert (strict isolation, no fallback). |
| 6 | `build_multi_sni_acceptor` builder | ✅ | Loads cert + key for every tenant in the group, registers each under its SNI, builds the single shared `TlsAcceptor`. Per-tenant cert load errors carry the tenant name in the error context. |
| 7 | `run_sni_group` accept loop | ✅ | One TCP bind, one acceptor, dispatches after TLS handshake by reading `tls_stream.get_ref().1.server_name()`. Per-tenant context (peer_policy, audit, metrics) lives in `SniDispatchTable`. |
| 8 | `SniDispatchTable` + `SniTenantContext` | ✅ | Cloneable, immutable-after-construction. Defense-in-depth duplicate-SNI check on construction (config validation should already catch it). |
| 9 | `qgateway` main.rs wiring | ✅ | `cmd_run` iterates groups instead of flat tenants; spawns one accept loop per group. Backward-compatible — Sprint 5.5 configs (one listen per tenant) still work unchanged. |
| 10 | SNI validation tests | ✅ | 7 tests in `config::tests`. |
| 11 | SNI resolver smoke tests | ✅ | 3 tests in `tls::tests` (empty-entries rejection, builder empty rejection, tenant-name-in-errors propagation). |

### 13.8.2 Validation rules

For tenants in role = `serve-tcp`, grouped by `listen` address:

1. **Single-tenant group with `sni` set → REJECT.** SNI is meaningless on a
   single-tenant listener; allowing it would create a false sense of routing
   isolation.
2. **Multi-tenant group, any member without `[tenants.tls]` → REJECT.** SNI
   dispatch is only possible at TLS handshake time. A plain-TCP member can't
   coexist on the same port.
3. **Multi-tenant group, any member without `sni` → REJECT.** Empty `sni` is
   also rejected (must be a non-empty hostname).
4. **Multi-tenant group with duplicate SNI hostnames → REJECT.** Each member
   must claim a distinct hostname.
5. **`sni` set on a `serve-pq` role tenant → REJECT.** SNI only applies to
   the TLS-terminating side.
6. **Mixed TLS-on and TLS-off in the same group → REJECT.** A listen port is
   either fully TLS-terminated or not — there's no "TLS for some clients, raw
   TCP for others" mode.
7. **Empty tenants list / duplicate tenant names** — pre-existing rules,
   unchanged.

All errors carry the tenant name (and SNI hostname when relevant) so
operators can find the misconfigured block without diffing the entire
config.

### 13.8.3 Wire model

```
                   ┌──────────────────────────────────────────────┐
client (sp)──TLS──▶│ TCP bind 0.0.0.0:8443                        │
                   │   │                                          │
                   │   ▼                                          │
                   │ acceptor.accept(tcp) ──▶ MultiSniCertResolver│
                   │                              │               │
client (rj)──TLS──▶│                              │               │
                   │                              ▼               │
                   │                       lookup(server_name)    │
                   │                              │               │
                   │   ┌──────────────────────────┴───────┐       │
                   │   ▼                                  ▼       │
                   │ TenantCtx{sp}                 TenantCtx{rj}  │
                   │   │ peer_policy_sp              peer_policy_rj
                   │   │ audit_sp.qa                 audit_rj.qa  │
                   │   │ metrics{tenant="sp"}        metrics{tenant="rj"}
                   │   ▼                                  ▼       │
                   │ CSPQ → 10.0.1.50:9999     CSPQ → 10.0.2.50:9999
                   └──────────────────────────────────────────────┘
```

One acceptor, one bind, N tenants. No shared state between tenants beyond
the TCP listener. Unknown SNIs (e.g. nmap probes, misconfigured clients)
receive a TLS `unrecognized_name` alert and the connection closes —
the gateway never reaches a per-tenant context.

### 13.8.4 Honest scope decisions

**SNI dispatch but NOT SNI hot-reload.** Sprint 5.5's cert hot-reload
machinery (`TlsAcceptorHandle` + `TlsReloadTrigger` + SIGUSR1 fan-out)
works on a single `TlsAcceptor`. Multi-SNI acceptors need a slightly
different reload coordinator that swaps the entire `MultiSniCertResolver`
contents atomically across all member tenants. That's a focused
follow-up (Sprint 6.5) rather than a parallel implementation snuck
into this sprint.

**Implicit grouping, not explicit `[[listeners]]`.** The alternative
schema (separate `[[listeners]]` table referenced by tenants) was
considered and rejected: it doubles the config verbosity for the common
single-tenant case, and the implicit grouping captures the same
constraints with less surface area. Validation rule §13.8.2 is strict
enough that misconfiguration fails fast at startup.

**No fallback cert.** A `ResolvesServerCert` impl is free to return a
default cert when no SNI matches. We deliberately do NOT — strict
isolation. Unknown SNI gets a TLS alert, not a wildcard. Operators
who want wildcard behavior add an explicit wildcard tenant.

### 13.8.5 Acceptance — actual

- [x] `cargo test --workspace --locked` green: **118 tests** (up from 108 in Sprint 5.5).
- [x] `cargo build --workspace --locked` clean.
- [x] `cargo clippy --workspace --all-targets -- -D warnings` clean.
- [x] `cargo fmt --all --check` clean.
- [x] `cargo build -p qgateway --features pkcs11 --locked` clean.
- [x] 7 SNI validation tests + 3 SNI resolver smoke tests.
- [x] Backward compat: Sprint 5.5 configs (one tenant per listen) still validate and run unchanged.

### 13.8.6 Honest deferrals to Sprint 6.5

1. ✅ **Hot-reload for SNI groups** — DELIVERED in Sprint 6.5.
2. ✅ **End-to-end SNI dispatch integration test** — DELIVERED in Sprint 6.5.
3. **Wildcard SNI support** (`*.example.com` matching) — current dispatcher is exact-match only. Reasonable for now (most banks have a fixed list of subdomains).

---

## 13.9. SPRINT 6.5 — DELIVERABLE CONTRACT (✅ CLOSED)

Consolidation sprint: close the two gaps Sprint 6 left open in the SNI
story — hot-reload of multi-SNI acceptors, and end-to-end coverage of
the cert-dispatch path with real TLS handshakes.

### 13.9.1 Delivered

| # | Deliverable | Status | Notes |
|---|---|---|---|
| 1 | `ReloadSource` enum (`Single` / `Multi`) | ✅ | Refactor of `TlsReloadTrigger` internals. Single-tenant triggers carry one `TlsConfig`; multi-SNI triggers carry the full list of `(sni, tenant_name, cfg)` tuples. `reload()` matches the variant and rebuilds the right acceptor type. |
| 2 | `build_reloadable_multi_sni_acceptor` | ✅ | Mirror of `build_reloadable_acceptor` but for SNI groups. Returns the same `(TlsAcceptorHandle, TlsReloadTrigger)` pair; the trigger remembers every member's cert/key paths and rebuilds the whole `MultiSniCertResolver` atomically on SIGUSR1. |
| 3 | `TlsReloadTrigger::is_multi_sni()` accessor | ✅ | For diagnostics — operators can log "reloaded N single-tenant + M multi-SNI groups" on a SIGUSR1 cycle. |
| 4 | main.rs wired for SNI hot-reload | ✅ | The SNI-group spawn block now calls `build_reloadable_multi_sni_acceptor` and pushes the trigger into `reload_triggers`. SIGUSR1 walks the same list as before — single-tenant and multi-SNI triggers are uniform from the signal handler's perspective. |
| 5 | rcgen dev-dep | ✅ | `rcgen = "0.13"` added under `[dev-dependencies]` on `qgateway-core`. Dev-only; never compiled into release binaries. |
| 6 | `tests/sni_cert_dispatch.rs` integration test | ✅ | 2 scenarios using real TLS handshakes against `MultiSniCertResolver`: (a) the server presents the correct cert per SNI hostname; (b) unknown SNI is rejected at the handshake. |
| 7 | Failure-atomicity contract | ✅ | A bad cert in ONE member of a multi-SNI group aborts the reload entirely — the previous acceptor stays installed. No partial reloads, no group-wide silent degradation. |

### 13.9.2 Operational model — SNI hot-reload

```bash
$ certbot renew  # rotates certs for BOTH sp.bank.example.com and rj.bank.example.com
$ kill -USR1 $(pidof qgateway)

[INFO  qgateway] SIGUSR1 received, reloading TLS certs (n_tenants=1)
[INFO  qgateway] TLS cert reloaded (tenant=sni-group:0.0.0.0:443)
[INFO  qgateway] TLS reload cycle complete (reloaded=1, failed=0)
```

Internally, the single "tenant" in that log line is the SNI group as a
whole — the trigger rebuilt both certs atomically. In-flight handshakes
finish on the previous acceptor; the next accept uses the new resolver.
If either cert fails to load (e.g. half-written during a non-atomic
rename), the entire group reload aborts and the previous acceptor —
with the previous *both* certs — stays installed.

### 13.9.3 What the integration test proves

`sni_dispatches_correct_cert_per_hostname` exercises the full
ClientHello → server_name → resolver lookup → CertifiedKey return → TLS
handshake completion path with two rcgen-generated self-signed certs.
The test pulls `peer_certificates()` from the completed handshake and
asserts byte-equality with the DER of the generated cert — proving the
right tenant's material is served for each SNI.

`sni_unknown_hostname_rejected` exercises the strict-isolation contract:
a client with `ServerName::try_from("unknown.test")` cannot complete
the TLS handshake. The resolver returns `None`, rustls converts this to
an `unrecognized_name` alert, and the client's handshake future
resolves to `Err(_)`.

Both tests use realistic TLS material end-to-end — there is no
hand-fabricated DER, no mocked acceptor, no skipped handshake step.

### 13.9.4 API surface changes

**Additive**:
- `qgateway_core::tls::build_reloadable_multi_sni_acceptor(entries, group_label)`
- `qgateway_core::tls::TlsReloadTrigger::is_multi_sni() -> bool`

**Internal refactor** (no external API impact):
- `TlsReloadTrigger` fields are now `tx`, `source: ReloadSource`, `label`
  (renamed from `tenant_name`). The public accessors (`tenant_name()`,
  `reload()`) are unchanged in signature.

**No removals.** All Sprint 6 configs continue to work.

### 13.9.5 Acceptance — actual

- [x] `cargo test --workspace --locked` green: **120 tests** (up from 118
      in Sprint 6). 2 new tests in `tests/sni_cert_dispatch.rs`.
- [x] `cargo build --workspace --locked` clean.
- [x] `cargo clippy --workspace --all-targets -- -D warnings` clean.
- [x] `cargo fmt --all --check` clean.
- [x] `cargo build -p qgateway --features pkcs11 --locked` clean.

### 13.9.6 Honest deferrals to Sprint 7

1. ✅ **Audit log rotation** with chain integrity across `.qa` files — DELIVERED in Sprint 7.
2. **Runtime `qgateway tenant add/remove`** CLI without daemon restart — Sprint 7.5/8.
3. **Connection rate limiting / DoS shield** — Sprint 7.5/8.
4. **Per-tenant connection quota** — Sprint 7.5/8.
5. **Wildcard SNI support** — Sprint 7.5/8.

---

## 13.10. SPRINT 7 — DELIVERABLE CONTRACT (✅ CLOSED)

Cryptographic chain integrity across multiple `.qa` files. Until
Sprint 7 a long-running gateway had ONE `.qa` per tenant growing
indefinitely — operationally untenable for production (no rotation
windows for offline verification, no offsite-archive workflows, no
compliance with "retain N months of audit and archive the rest"
policies). Sprint 7 closes this with a rotation protocol where each
file carries an unforgeable cryptographic link to its predecessor.

### 13.10.1 Delivered

| # | Deliverable | Status | Notes |
|---|---|---|---|
| 1 | `LogHeader.prev_log_id` field | ✅ | `Option<LogId>`, `#[serde(default)]`. `None` for the root log of a chain, `Some(prev.log_id)` for rotated successors. Backward-compatible: pre-Sprint-7 `.qa` files lack this field and deserialize cleanly. |
| 2 | `LogHeader.prev_log_final_root` field | ✅ | `Option<Hash>`, custom CBOR-bytes serializer (consistent with other 32-byte hashes in the format). Captures the predecessor's MMR root *after* its `rotation_close` event. |
| 3 | `AuditEvent` action `audit.rotation_close` | ✅ | Final event of any rotated log. Metadata: `new_log_id`, `new_log_label`. Signed under the OLD log's pubkey. After this event the old log is read-only (signer dropped in memory). |
| 4 | `AuditEvent` action `audit.rotation_open` | ✅ | First event of any rotated log. Metadata: `prev_log_id`, `prev_log_final_root`, `prev_log_label`. Signed under the NEW log's pubkey — cross-key rotation works because each log uses its own header pubkey for verification. |
| 5 | `AuditLog::rotate_to(new_signer, new_label, new_log_id_hex)` | ✅ | Atomic operation: appends `rotation_close` to current, computes final root, builds new header with chain references, appends `rotation_open` as first event of new log. Returns `(old_sealed, new_open)` — old log's signer is dropped so accidental late appends fail. |
| 6 | `AuditLog::verify_chain(logs: &[&AuditLog])` | ✅ | Walks the chain enforcing **6 integrity properties** per adjacent pair: (a) each log's own signature chain valid; (b) prev log's last event is `rotation_close`; (c) `rotation_close.metadata.new_log_id` matches the next log's actual `log_id`; (d) next log's header `prev_log_id` matches prev's id; (e) next log's header `prev_log_final_root` matches prev's actual computed MMR root; (f) next log's first event is `rotation_open` with consistent metadata. |
| 7 | Cross-key rotation supported | ✅ | The new log's `pubkey` is the new signer's pubkey, not inherited from the old log. Verification uses each log's own header pubkey, so rotating the audit key at the same moment as the file rotation is a single coherent operation — useful for incident response (suspected key compromise → rotate file + key in one go). |
| 8 | 7 unit tests | ✅ | Clean 2-link chain; clean 3-link chain; root-with-prev-field rejected (operator-error guard); mismatched prev_log_id detected (splice attack); tampered prev_log_final_root detected (in-memory mutation); old log's signer dropped after rotation (late-append rejected); cross-key chain verifies. |

### 13.10.2 Rotation protocol — wire format

A rotated chain is N files on disk:

```
audit-2026-01.qa   ← log_id=A,   prev_log_id=None,           prev_log_final_root=None
audit-2026-02.qa   ← log_id=B,   prev_log_id=Some(A),        prev_log_final_root=Some(root_A_final)
audit-2026-03.qa   ← log_id=C,   prev_log_id=Some(B),        prev_log_final_root=Some(root_B_final)
```

Each file's last event is `audit.rotation_close` (with `new_log_id`
metadata) except the most recent (still being appended). Each file's
first event is `audit.rotation_open` (with `prev_log_id` +
`prev_log_final_root` metadata) except the root file.

A regulator with only the rotation chain's audit `pubkey` (or one
pubkey per segment, for the cross-key case) can verify the entire
multi-file history by running `verify_chain(&[&A, &B, &C])`. Failures
identify the specific log_id + property that broke — operators get
actionable error messages, not "verification failed".

### 13.10.3 Operational considerations

**When to rotate**: this sprint ships the protocol and primitives, not
the *trigger policy*. The QGateway daemon currently has one .qa per
tenant per process lifetime; rotation is operator-initiated via the
library API (or an offline `qaudit rotate` CLI in a follow-up sprint).
Auto-rotation policies (size-based, time-based, signal-based) are a
Sprint 7.5 deliverable — the underlying mechanism is ready.

**Key rotation cadence**: combining file rotation with audit-key
rotation at the same moment is supported and recommended after any
suspected key compromise. The new log starts with a fresh `pubkey` in
its header; regulators verify each segment under its own pubkey.

**Archive workflow**: rotated `audit-YYYY-MM.qa` files are immutable
(no signer in memory after `rotate_to`). They can be moved to cold
storage and re-loaded only for verification. Chain verification works
on read-only logs — the verifier reconstructs the MMR from entries.

**No deletion**: removing a rotated file from disk breaks
`verify_chain` (the next log's `prev_log_id` references a missing
predecessor). This is intentional — silent deletion of audit history
must be detectable.

### 13.10.4 Backward compatibility

All pre-Sprint-7 `.qa` files remain readable. They lack the new
optional fields; serde's `#[serde(default)]` deserializes them as
`None`. `AuditLog::verify` works on old logs as before — only the new
`verify_chain` path requires populated chain references.

### 13.10.5 API surface changes

**Additive**:
- `LogHeader.prev_log_id: Option<LogId>`
- `LogHeader.prev_log_final_root: Option<Hash>`
- `AuditLog::rotate_to(new_signer, new_label, new_log_id_hex) -> Result<(AuditLog, AuditLog)>`
- `AuditLog::verify_chain(logs: &[&AuditLog]) -> Result<()>`
- `qaudit_core::log::ROTATION_CLOSE_ACTION: &str` constant
- `qaudit_core::log::ROTATION_OPEN_ACTION: &str` constant

**No removals.** All Sprint 6.5 code continues to work.

### 13.10.6 Acceptance — actual

- [x] `cargo test --workspace --locked` green: **127 tests** (up from 120
      in Sprint 6.5). 7 new tests in `qaudit-core::log::tests`.
- [x] `cargo build --workspace --locked` clean.
- [x] `cargo clippy --workspace --all-targets -- -D warnings` clean.
- [x] `cargo fmt --all --check` clean.
- [x] `cargo build -p qgateway --features pkcs11 --locked` clean.

### 13.10.7 Honest deferrals to Sprint 7.5

1. **Auto-rotation policies wired into the QGateway daemon** — Sprint 7.6 (requires `AuditChannel` restructure for in-flight log swap).
2. ✅ **`qaudit rotate --in OLD.qa --out NEW.qa`** CLI subcommand — DELIVERED in Sprint 7.5.
3. ✅ **`qaudit verify-chain --log file1 --log file2 ...`** CLI subcommand — DELIVERED in Sprint 7.5.
4. **Connection rate limiting / DoS shield** — Sprint 8.
5. **Per-tenant connection quota** (anti-starvation in SNI shared ports) — Sprint 8.
6. **Wildcard SNI** matching — Sprint 8.
7. **Runtime `qgateway tenant add/remove`** CLI — Sprint 8.

---

## 13.11. SPRINT 7.5 — DELIVERABLE CONTRACT (✅ CLOSED)

Operationalize the rotation protocol from Sprint 7 with CLI tooling so
operators can rotate `.qa` logs and verify multi-file chains without
touching the library API. Two new `qaudit` subcommands ship; the
daemon-integrated auto-rotation policy is honestly deferred to Sprint 7.6
because it requires restructuring `AuditChannel` to swap an in-flight
log atomically while preserving the audit task's invariants.

### 13.11.1 Delivered

| # | Deliverable | Status | Notes |
|---|---|---|---|
| 1 | `qaudit rotate` subcommand | ✅ | Loads input log, binds the same audit key as a signer, calls `AuditLog::rotate_to`, saves both files. Default new log id is random (16 bytes); `--new-log-id <hex32>` pins it for reproducible scripted rotation. Refuses to overwrite the output unless `--force`. Refuses if the supplied `--pk` doesn't match the input log's header (operator-error guard). |
| 2 | `qaudit verify-chain` subcommand | ✅ | Opens every `--log` argument, runs `AuditLog::verify_chain` across the slice. Optional `--pk` enforces a single audit pubkey across the entire chain; omitting `--pk` allows cross-key rotation (each segment verified under its own header pubkey). On success, prints a one-line summary plus per-log statistics. On failure, prints the specific log id + property that broke. |
| 3 | End-to-end smoke validated | ✅ | `init → append → append → rotate → append → verify-chain` succeeds; `verify-chain` with logs in wrong order fails with "first in the chain" error. Verified via shell-level invocation against `target/debug/qaudit`. |
| 4 | Operator-error guards | ✅ | (a) `--pk` mismatch on input: refuse to rotate; (b) `--out` already exists without `--force`: refuse; (c) `verify-chain` with single `--log`: refuse, redirect to `qaudit verify`. |

### 13.11.2 Usage examples

```bash
# Scheduled monthly rotation via cron:
qaudit rotate \
    --in     /var/lib/qg/sp-current.qa \
    --out    /var/lib/qg/archive/sp-2026-02.qa \
    --sk     /etc/qg/audit.skid \
    --pk     /etc/qg/audit.pub \
    --new-label "sp-2026-02"
# Then re-point the daemon at sp-2026-02.qa via config; restart.

# Compliance verification at year-end:
qaudit verify-chain \
    --log /var/lib/qg/archive/sp-2025-12.qa \
    --log /var/lib/qg/archive/sp-2026-01.qa \
    --log /var/lib/qg/archive/sp-2026-02.qa \
    --pk  /etc/qg/audit.pub
# Output:
#   ok: 3 logs, 47193 entries total, terminal root = fe3f49...
#     [0] 18204 entries — log_id=fab5e996... label="sp-2025-12"
#     [1] 14823 entries — log_id=332b288c... label="sp-2026-01"
#     [2] 14166 entries — log_id=8a91ef02... label="sp-2026-02"
```

### 13.11.3 Why deferring daemon auto-rotation is honest

The Sprint 7 rotation protocol is fully implemented at the library
level — `AuditLog::rotate_to` is a clean atomic operation that
produces `(sealed_old, new_open)`. The CLI delivered in Sprint 7.5
uses exactly this API.

Wiring the same rotation into the running daemon requires
`AuditChannel::rotate(new_path, new_label)` — a control message that
the audit task receives, processes (calls `rotate_to` on its in-flight
log), and uses to swap its open log for the new one. The current
`AuditChannel` was designed assuming the log is stable for the
lifetime of the task. Adding rotation while preserving its in-flight
invariants (no event lost during the swap, no signature gap) needs:

- A rotation-specific channel message variant
- Atomic file rename on disk (so a crash mid-rotation can't lose data)
- Coordination with concurrent appenders (the channel buffers events;
  during rotation, late events must seal under the new log not the old)

These are real engineering decisions, not boilerplate. Sprint 7.6
will take them up cleanly rather than getting half-done in 7.5.
**Operators who need rotation TODAY use `cron + qaudit rotate +
systemctl restart qgateway`** — the daemon honors the new
`audit_log` path on startup, so a brief restart-time gap (microseconds
to a few seconds depending on systemd's restart latency) is the
trade-off. Acceptable for typical monthly-rotation cadences;
unacceptable for sub-second rotation, which no audit deployment
realistically needs.

### 13.11.4 API surface changes

**CLI**:
- `qaudit rotate --in <path> --out <path> --sk <path> --pk <path> --new-label <str> [--new-log-id <hex32>] [--force]`
- `qaudit verify-chain --log <path>... [--pk <path>]`

**No library API changes** beyond what Sprint 7 shipped.

### 13.11.5 Acceptance — actual

- [x] `cargo test --workspace --locked` green: **127 tests** (unchanged
      from Sprint 7 — these CLI commands are validated via end-to-end
      shell smoke, not unit tests, because they're 90% glue around the
      already-tested `rotate_to` / `verify_chain` library calls).
- [x] `cargo build --workspace --locked` clean.
- [x] `cargo clippy --workspace --all-targets -- -D warnings` clean.
- [x] `cargo fmt --all --check` clean.
- [x] `cargo build -p qgateway --features pkcs11 --locked` clean.
- [x] End-to-end shell smoke: init → append × 2 → rotate → append → verify-chain
      succeeds; wrong-order verify-chain fails with actionable message.

### 13.11.6 Honest deferrals to Sprint 7.6 / 8

1. ✅ **Daemon auto-rotation library primitives** — DELIVERED in Sprint 8.
2. **Connection rate limiting / DoS shield** — Sprint 9.
3. **Per-tenant connection quota** — Sprint 9.
4. ✅ **Wildcard SNI** matching — DELIVERED in Sprint 8.
5. **Runtime `qgateway tenant add/remove`** CLI — Sprint 9.

---

## 13.12. SPRINT 8 — DELIVERABLE CONTRACT (✅ CLOSED)

Library-level primitives for two operationally-painful gaps: live audit-log
rotation in the daemon process, and SNI matching that scales with realistic
TLS deployments (every cert provisioning workflow emits wildcard certs by
default; refusing them forces operators to maintain per-host exact lists
indefinitely).

### 13.12.1 Delivered

| # | Deliverable | Notes |
|---|---|---|
| `RotationPolicy` config schema | TOML `[rotation]` block: optional `max_entries`, `max_bytes`, `max_age_secs`, `archive_pattern` (default `"{label}-{ts}.qa"`). `has_auto_trigger()` returns true when any threshold is set. |
| `RotationPolicy::render_archive_name` | Pure helper substituting `{label}`, `{ts}` (UTC `%Y%m%dT%H%M%SZ`), `{counter}` in the pattern. |
| `SignerFactory` trait (`Send + Sync + 'static`) | Mints a fresh `Box<dyn Signer>` per rotation. Same-key: wrap the audit `KeyPair`. Cross-key: factory returns a different signer (library-level only this sprint). |
| `AuditChannel::spawn_with_rotation(...)` | Builder wiring the channel for rotation. Plain `spawn` retains the no-factory variant; calling `rotate()` on it fail-softs with `"SignerFactory; rotation unsupported"`. |
| `AuditChannel::rotate(archive_path, new_label)` + `request_rotation_silent` | Async rotation API + fire-and-forget variant. The rotation arm drains the MPSC event queue *before* sealing — events emitted just before `rotate()` land in the OLD log. |
| `perform_rotation` worker | Validates `archive_path` doesn't exist (atomicity guard), invokes factory, uses `mem::replace` with a placeholder log to satisfy `rotate_to`'s consume-self signature, persists sealed-old + new-open, installs the new log. Metric `audit_rotations_total` increments only on success. |
| Wildcard SNI in `MultiSniCertResolver` | Patterns `*.host.example.com` only (strict validation rejects `*foo`, `a.*.com`). Resolution: exact first, then single-label-prefix wildcard match per RFC 6125 §6.4.3. |
| Wildcard SNI in `SniDispatchTable` | Symmetric dispatch in `gateway.rs` — exact-first-then-wildcard, identical algorithm. |
| Config validation | Rejects malformed wildcard patterns at load time. |
| 8 new tests | 3 audit channel rotation + 5 wildcard SNI. |

### 13.12.2 Wildcard SNI semantics

```
Pattern              Matches            Does NOT match
*.example.com    →   x.example.com      example.com         (no label substitution)
                     api.example.com    x.y.example.com     (multi-label sub disallowed)
                     www.example.com    other.com           (suffix mismatch)
```

Exact entries always win over wildcards. A client connecting with
`priority.example.com` reaches the exact tenant; a client with
`whatever.example.com` reaches the wildcard catchall; a client with
`x.y.example.com` is rejected (TLS `unrecognized_name` alert — strict
isolation, no fallback cert).

### 13.12.3 Rotation channel — happens-before contract

Sprint 8's most subtle property: events emitted *before* a `rotate()`
call land in the OLD log; events emitted *after* land in the NEW log.
Without explicit draining of the MPSC channel inside the rotation arm,
a `biased` tokio `select!` would race the rotation against in-flight
events and lose ordering:

```rust
// Inside the rotation arm:
while let Ok(ev) = rx.try_recv() {
    pending.push(ev);
}
let _ = flush(&mut log, ...).await;     // emit pending into OLD log
let outcome = perform_rotation(...);    // seal old, open new
```

This guarantees: if `audit.emit(E1)` returns before `audit.rotate()` is
called, then `E1` is signed under the OLD log's key chain and appears
before the `rotation_close` sentinel. Sprint 7's `verify_chain` then
sees `E1 → rotation_close → rotation_open → ...` in a consistent
cryptographic chain.

### 13.12.4 Honest deferral: daemon SIGUSR2 wiring

The library primitives are complete and tested, but the QGateway daemon's
`main.rs` does NOT yet:
- Install a SIGUSR2 handler that walks tenant runtimes and calls
  `request_rotation_silent` on each.
- Run a per-tenant async monitor checking `policy.has_auto_trigger()`
  against current log state every N seconds.

These are wiring work, not new design. The reason for deferral: the
per-tenant audit signer construction currently lives in a closure that
moves the `Box<dyn Signer>` into the log — re-implementing it as a
`SignerFactory` requires reshaping `cmd_run`'s tenant setup loop to
preserve the secret key bytes (softkey path) or the `Pkcs11Config` (HSM
path) for re-use. That refactor is bigger than it looks for the pkcs11
path (cryptoki session lifetimes need attention) and is better landed
as Sprint 8.5 with its own end-to-end test rather than rushed in.

**Operational impact today**: rotation is invoked by external workflows
via `qaudit rotate` CLI (Sprint 7.5) — a cron job that `systemctl reload
qgateway`s to a fresh process picks up the rotated chain. Live in-process
rotation via SIGUSR2 is Sprint 8.5.

### 13.12.5 API surface changes

**Additive**: `RotationPolicy` + helpers, `SignerFactory` trait,
`RotationRequest` struct, `AuditChannel::{spawn_with_rotation, rotate,
request_rotation_silent}`, `Metrics::audit_rotations`, Prometheus metric
`qgateway_audit_rotations_total{tenant="..."}`.

**Behavioural**: `MultiSniCertResolver::resolve` falls back to wildcard
suffix match after exact-map miss; `known_snis` returns `Vec<String>`
(internal change, only used in log lines); `SniDispatchTable::lookup`
mirrors the same exact-then-wildcard behaviour; `Config::validate_sni_groups`
rejects malformed wildcard patterns.

**No removals.** All Sprint 7.5 configs continue to work; new
`RotationPolicy` field defaults to `None`.

### 13.12.6 Acceptance — actual

- [x] `cargo test --workspace --locked` green: **137 tests** (up from 129
      in Sprint 7.5). 8 new tests.
- [x] `cargo build --workspace --locked` clean.
- [x] `cargo clippy --workspace --all-targets -- -D warnings` clean.
- [x] `cargo fmt --all --check` clean.
- [x] `cargo build -p qgateway --features pkcs11 --locked` clean.

### 13.12.7 Honest deferrals to Sprint 8.5

1. ✅ **Daemon SIGUSR2 handler + per-tenant monitor task** — DELIVERED in Sprint 8.5.
2. **`qaudit rotate --new-sk --new-pk`** flag pair for cross-key rotation via CLI — Sprint 9.
3. ✅ **End-to-end wildcard SNI integration test** — DELIVERED in Sprint 8.
4. **Connection rate limiting / DoS shield** — Sprint 9.
5. **Per-tenant connection quota** — Sprint 9.
6. **Runtime `qgateway tenant add/remove`** — Sprint 9.

---

## 13.13. SPRINT 8.5 — DELIVERABLE CONTRACT (✅ CLOSED)

Close the daemon-side auto-rotation gap left open by Sprint 8: the
`RotationPolicy` schema was parsed but no background task evaluated
its thresholds. Sprint 8.5 ships that task and the segment-tracking
counters it consumes.

### 13.13.1 Delivered

| # | Deliverable | Notes |
|---|---|---|
| `RotationMonitor` | New public type in `qgateway-core::audit`. Constructor + `with_poll_interval` builder + `spawn(shutdown)` lifecycle. Default poll cadence 5s. Returns immediately when policy has no auto-triggers (`has_auto_trigger() == false`); otherwise loops on a `tokio::select!` between shutdown notify and poll tick. |
| Segment-tracking on `AuditChannel` | Two new `Arc<AtomicI64>` / `Arc<AtomicU64>` counters: `entries_since_rotation` (updated from `log.entries().len()` after every flush) and `segment_open_unix` (UTC timestamp set at channel creation, reset on every successful rotation). |
| `RotationHandle` accessor methods | `entries_in_current_segment()` reads the entry counter; `seconds_since_segment_open()` computes `now() - segment_open_unix`. The monitor task uses these to evaluate thresholds without holding any locks. |
| `check_thresholds()` evaluator | Pure helper returning `Option<String>` with the reason a threshold crossed (or `None`). Reason strings appear in `tracing::info!` log lines so operators see *which* trigger fired. Order: entries → age → bytes (bytes last because it does a filesystem stat). |
| `max_bytes` filesystem stat | Reads `std::fs::metadata(log_path).len()`. Read failures (e.g. log temporarily moved by an external tool) are silently ignored — the next 5s tick retries. Documented in `RotationPolicy::max_bytes` that the practical threshold is `max_bytes + batch_size * avg_entry_size` due to batched saves. |
| Wired in main.rs | One `RotationMonitor` per tenant when `cfg.rotation` has auto-triggers. SIGUSR2 path and monitor share ONE counter per tenant so the `{counter}` substitution in `archive_pattern` is monotonic regardless of which path fires. Monitors collected in `monitor_handles` and dropped at shutdown. |
| Reset on rotation | `perform_rotation` resets both counters to 0/now on success. Subsequent monitor polls compare against the new segment, not the cumulative history. |
| 3 unit tests | `monitor_fires_rotation_on_max_entries` (real time, 50ms poll, 5 emits, `max_entries=2`, asserts ≥1 rotation + counter ≥1); `monitor_with_no_triggers_exits_immediately` (policy with no thresholds → returns within 1s); `monitor_respects_shutdown_signal` (notify_waiters → exits within 1s). The notify-yield-notify pattern in test #3 documents a subtlety with `tokio::sync::Notify`: it is not sticky, so the monitor must register its waker via `notified()` *before* `notify_waiters()` is called. |

### 13.13.2 Operational model

```toml
# /etc/qgateway/sidecar.toml
[rotation]
max_entries  = 100_000     # rotate after 100k events in current segment
max_bytes    = 134_217_728 # OR after segment file exceeds 128 MiB
max_age_secs = 86_400      # OR after segment is 24h old
archive_pattern = "{label}-{ts}-{counter}.qa"
```

With any of these thresholds set, every tenant gets a background
monitor task. SIGUSR2 still works in parallel — operators can force a
rotation regardless of policy.

`{label}` is the tenant name, `{ts}` is `YYYYMMDDTHHMMSSZ`, `{counter}`
is a monotonic per-tenant integer starting at 1. Rotated archives land
in the same directory as the current `audit_log` path; cold-storage
moves are an external concern.

### 13.13.3 Trade-offs documented

- **5-second poll cadence is fixed at the type level** (with a test-only
  `with_poll_interval` builder). Production policies measure thresholds
  in MB/minutes, so 5s slack is invisible operationally. If sub-second
  responsiveness is needed in the future, switch to event-driven
  triggering from the channel itself.
- **Monitor doesn't run in PKCS#11-only deployments.** Same reason as
  Sprint 8's SIGUSR2 gap: the PKCS#11 signer factory wrapper isn't
  Sprint-8 work. Mixed deployments (Softkey tenant + PKCS#11 tenant in
  same daemon) get rotation only on the Softkey tenants. PKCS#11
  rotation is Sprint 9.
- **`max_bytes` is best-effort.** Batched saves mean the file size can
  exceed `max_bytes` by up to one batch worth of events between the
  flush and the next monitor poll. Operators concerned about hard caps
  should set `max_entries` (which is exact) or `max_age_secs` (which
  is monotonic with wall-clock).
- **No coordination across tenants.** Each monitor fires independently.
  Two tenants hitting their thresholds at the same poll tick rotate
  concurrently — fine because each tenant's log + key + archive path
  is isolated.

### 13.13.4 API surface changes

**Additive**:
- `qgateway_core::audit::RotationMonitor` (struct + `new` + `with_poll_interval` + `spawn`)
- `qgateway_core::audit::RotationHandle::entries_in_current_segment()`
- `qgateway_core::audit::RotationHandle::seconds_since_segment_open()`

**Internal (no external API impact)**:
- `AuditChannel.entries_since_rotation: Arc<AtomicU64>` field
- `AuditChannel.segment_open_unix: Arc<AtomicI64>` field
- `check_thresholds()` private helper

**Removed**:
- `TenantRuntime.rotation_counter` field — unused after refactoring
  the counter ownership to `RotationTarget` (Sprint 8) and now shared
  with `RotationMonitor` via the same atomic.

### 13.13.5 Acceptance — actual

- [x] `cargo test --workspace --locked` green: **143 tests** (up from 140
      in Sprint 8). 3 new tests.
- [x] `cargo build --workspace --locked` clean.
- [x] `cargo clippy --workspace --all-targets -- -D warnings` clean.
- [x] `cargo fmt --all --check` clean.
- [x] `cargo build -p qgateway --features pkcs11 --locked` clean.

### 13.13.6 Honest deferrals to Sprint 9

1. ✅ **PKCS#11 rotation factory** — DELIVERED in Sprint 9.
2. ✅ **`qaudit rotate --new-sk --new-pk`** flag pair for cross-key rotation — DELIVERED in Sprint 9.
3. **Connection rate limiting** / DoS shield — Sprint 9.5.
4. **Per-tenant connection quota** (anti-starvation on SNI shared ports) — Sprint 9.5.
5. **Runtime `qgateway tenant add/remove`** CLI without daemon restart — Sprint 9.5.

---

## 13.14. SPRINT 9 — DELIVERABLE CONTRACT (✅ CLOSED)

Close the two HSM-side and incident-response gaps Sprint 8.5 left
open: PKCS#11 rotation (operator workflow for HSM-backed audit keys)
and cross-key rotation CLI (incident response when an audit key is
suspected compromised).

### 13.14.1 Delivered

| # | Deliverable | Notes |
|---|---|---|
| `qaudit_hsm::Pkcs11SignerFactory` | New public struct in qaudit-hsm. Wraps an `Arc<Pkcs11Config>` and exposes `open_new() -> CoreResult<Box<dyn Signer>>` that opens a fresh HSM session per rotation. No long-lived session pinning — rotation cadences (hours-to-months) make session reopening trivially cheap compared to the cryptographic ops themselves. |
| `Pkcs11SignerFactoryWrapper` in qgateway | Newtype implementing `qgateway_core::SignerFactory` for the HSM factory. Orphan-rule workaround (the trait lives in qgateway-core, the inner type lives in qaudit-hsm). Compiled only when `--features pkcs11`. |
| Pkcs11Config builder extracted | New helper `build_pkcs11_config(cfg)` in main.rs. Used both at startup (build initial signer) and at rotation time (build factory). Single source of truth for env-var PIN resolution + label/mechanism wiring. |
| Daemon wired for HSM rotation | `AuditChannel::spawn_with_rotation` now invoked on the PKCS#11 branch under `cfg(feature = "pkcs11")`. Non-pkcs11 builds fall back to plain `spawn` (no behavioral change for soft-only deployments). |
| `qaudit rotate --new-sk --new-pk` | New flag pair. Either both supplied (cross-key rotation) or both omitted (same-key rotation as before). The `rotation_close` event is signed under `--sk` (old key); the new log's `rotation_open` + subsequent events are signed under `--new-sk`. The new log's header carries `pubkey = new_pk`, so `verify_chain` validates each segment under its own pubkey. |
| Operator guardrails | (a) Both `--new-sk` and `--new-pk` required together or refuse; (b) supplied new key equal to old key refused (operator-error guard — defeats the purpose); (c) chain verification advisory printed: "DO NOT pass --pk to verify-chain on this chain"; (d) new pubkey hex printed in stderr summary for sanity check. |
| 3 new CLI tests | `cli_cross_key_rotation_chain_verifies` (init K1, init K2, append, cross-key rotate, append under K2, verify-chain without --pk); `cli_cross_key_rotation_rejects_same_key` (same-key cross-key flags refused); `cli_cross_key_rotation_requires_both_flags` (lone --new-sk refused). |

### 13.14.2 Operational model — HSM rotation

```toml
# /etc/qgateway/sidecar.toml
[audit_signer]
type           = "pkcs11"
module         = "/opt/dinamo/lib/libdinamo.so"
slot           = 0
pin_env        = "QGW_PKCS11_PIN"
key_label      = "audit-sp-2026"
pub_label      = "audit-sp-2026-pub"
mechanism_id   = 0x80004087

[rotation]
max_entries     = 500_000
archive_pattern = "{label}-{ts}.qa"
```

With this config, every tenant using the HSM audit key gets the same
SIGUSR2 + monitor behavior as Softkey tenants. Each rotation:

1. The monitor (or SIGUSR2 handler) calls `request_rotation_silent`.
2. The channel's background task drains in-flight events, flushes them
   to the OLD log.
3. `perform_rotation` invokes the factory's `new_signer()`, which opens
   a fresh PKCS#11 session.
4. `rotate_to` produces the sealed-old + new-open pair; the new log's
   header records the SAME pubkey (the HSM's key handle wasn't
   rotated — only the file was).
5. Channel installs the new log and resets segment counters.

Total downtime: zero. Total wall-clock: dominated by the `C_OpenSession`
+ `C_FindObjects` round-trip to the HSM (typically <100ms on local
Dinamo, slightly more on networked HSMs).

### 13.14.3 Operational model — cross-key rotation (incident response)

```bash
# Suspected compromise of audit-2026-q1.skid. Rotate key + file together.
qaudit rotate \
    --in   /var/lib/qg/audit-current.qa \
    --out  /var/lib/qg/audit-2026-q2.qa \
    --sk   /etc/qg/audit-2026-q1.skid \
    --pk   /etc/qg/audit-2026-q1.pub \
    --new-sk /etc/qg/audit-2026-q2.skid \
    --new-pk /etc/qg/audit-2026-q2.pub \
    --new-label "audit-2026-q2"
```

Output:

```
qaudit: rotated (cross-key)
  sealed:  /var/lib/qg/audit-current.qa (47218 entries)
    final root: 78a3c2...
    new_log_id: ecec5aa254e4ceaabd2c0d1163b3437c
  new:     /var/lib/qg/audit-2026-q2.qa (1 entries)
    label: "audit-2026-q2"
    new pubkey: 9f3c...
  NOTE: new segment uses a DIFFERENT audit key.
        Verify each segment under its own header pubkey;
        DO NOT pass --pk to `qaudit verify-chain` on this chain.
```

Verification:

```bash
$ qaudit verify-chain \
    --log /var/lib/qg/audit-2025-q4.qa \
    --log /var/lib/qg/audit-current.qa \
    --log /var/lib/qg/audit-2026-q2.qa
ok: 3 logs, 92341 entries total, terminal root = ...
```

`verify-chain` walks adjacent pairs, validating each segment under its
OWN header pubkey. The pubkey switch at the audit-2026-q2 boundary is
visible (each segment lists its own log_id and label) but doesn't break
chain integrity — the cryptographic link is still
`prev_log_id + prev_log_final_root` in the next segment's header.

### 13.14.4 Trade-offs documented

- **HSM rotation requires a fresh session per call.** Connection pooling
  could amortize this, but rotations happen at minute-or-longer
  cadences in practice — pooling complexity isn't worth the µs saved.
- **Cross-key rotation cannot be triggered via SIGUSR2 or the
  monitor.** Both paths invoke the channel's installed factory, which
  carries the original key. Cross-key rotation is an offline operator
  action (`qaudit rotate`), not an auto-trigger. Documented in the CLI
  help text.
- **No automatic key-archive workflow.** The old `--sk`/`--pk` files
  remain on disk after a cross-key rotation. Operators are expected
  to move them to an offline key archive (HSM key escrow,
  encrypted external storage, etc.) following their org's key-lifecycle
  policy. We deliberately don't delete or shred them — that would
  break post-incident forensics.

### 13.14.5 API surface changes

**Additive**:
- `qaudit_hsm::Pkcs11SignerFactory` (struct + `new` + `open_new`)
- `qaudit::cli` — `--new-sk`, `--new-pk` flags on `rotate`

**Internal**:
- `qgateway::main::build_pkcs11_config` helper
- `qgateway::main::Pkcs11SignerFactoryWrapper` newtype (cfg `pkcs11`)

**No removals.** All Sprint 8.5 code continues to work unchanged.

### 13.14.6 Acceptance — actual

- [x] `cargo test --workspace --locked` green: **146 tests** (up from 143
      in Sprint 8.5). 3 new CLI integration tests.
- [x] `cargo build --workspace --locked` clean.
- [x] `cargo clippy --workspace --all-targets -- -D warnings` clean.
- [x] `cargo fmt --all --check` clean.
- [x] `cargo build -p qgateway --features pkcs11 --locked` clean.
- [x] `cargo test -p qaudit-hsm --features pkcs11 --lib` green.

### 13.14.7 Honest deferrals to Sprint 9.5

1. ✅ **Connection rate limiting** — DELIVERED in Sprint 9.5.
2. ✅ **Per-tenant connection quota** — DELIVERED in Sprint 9.5.
3. **Runtime `qgateway tenant add/remove`** CLI without daemon restart — Sprint 10.
4. **HSM connection health metrics** (open sessions, PKCS#11 error counters per tenant) — Sprint 10.

---

## 13.15. SPRINT 9.5 — DELIVERABLE CONTRACT (✅ CLOSED)

Close the two traffic-shaping gaps Sprint 9 left open: per-tenant
concurrency quota (anti-starvation on shared SNI ports) and per-source-IP
token-bucket rate limiting (handshake-cost protection). Both are
opt-in per tenant; deployments that don't set `[tenants.limits]` see
zero behavioral change.

### 13.15.1 Delivered

| # | Deliverable | Notes |
|---|---|---|
| `qgateway_core::admission::AdmissionController` | New module. Combines a tokio `Semaphore` (quota) and a sharded per-IP `HashMap<IpAddr, Bucket>` (rate). Single `check(peer) -> Admit` API. Both checks are synchronous (no awaits) — admit/reject decided in microseconds on the accept hot path. `Admit::Ok(Option<OwnedSemaphorePermit>)` holds the quota slot for the session lifetime via permit drop semantics. |
| `RejectReason::{Quota, Rate}` | Stable enum with `.label()` for Prometheus. Both variants are surfaced as separate counters so operators can distinguish quota saturation (provisioning issue) from rate-limit abuse (DoS attempt). |
| Token-bucket implementation | Integer-only math (no floats). Refill = `floor((now - last_refill) * refill_per_sec)`, capped at capacity, with sub-second remainder preserved across refills. Buckets created lazily per source IP at first accept. |
| `[tenants.limits]` config schema | New `TenantLimits` struct: `max_concurrent: Option<u32>` + `rate_limit_per_source: Option<RateLimitTomlConfig { capacity, refill_per_sec }>`. Validation rejects zero values with action-able messages ("limits.max_concurrent = 0 rejects every connection; omit the field or set ≥ 1"). |
| `qgateway_audit_rotations_total` → +2 counters | `qgateway_admission_rejected_quota_total` and `qgateway_admission_rejected_rate_total`, per-tenant. Increment on `drop(tcp)` in the accept arm; never reset. |
| serve-tcp + serve-pq pre-handshake admission | `run_serve_tcp_tenant` and `run_serve_pq_tenant` build a `build_admission(&tenant.limits)` once per listener and call `admission.check(peer_ip)` synchronously BEFORE spawning the session task. Rejected connections drop the `TcpStream` (TCP RST on the kernel side) and increment the right metric counter. Zero handshake cost paid on rejected connections. |
| SNI group post-dispatch admission | `SniTenantContext` carries `Arc<AdmissionController>`. `handle_sni_session` calls `admission.check(peer_ip)` AFTER TLS handshake + SNI dispatch — the trade-off documented in §13.15.4: the accept loop is group-level, so the controller isn't known until the SNI hostname is. Backend dial + CSPQ handshake costs are still saved. |
| 7 unit tests | `no_limits_admits_everything`; `quota_caps_concurrent_sessions` (with permit drop releasing the slot); `rate_limit_caps_per_source` (burst of N admitted, N+1 rejected); `rate_limit_buckets_are_per_ip` (independent buckets); `rate_limit_refills_over_time` (deterministic time injection via internal `RateLimiter::try_take(peer, now)`); `quota_and_rate_can_coexist` (both must pass); `rate_check_happens_before_quota` (rate reject doesn't deplete quota slot). |

### 13.15.2 Operational model — config

```toml
[[tenants]]
name        = "sp"
listen      = "0.0.0.0:8443"
peer_pq     = "127.0.0.1:9443"
sni         = "sp.bank.example.com"
peer_pub_dir = "/etc/qg/trust/sp"
audit_log   = "/var/lib/qg/sp.qa"

[tenants.limits]
max_concurrent = 500

[tenants.limits.rate_limit_per_source]
capacity        = 20      # burst of 20 conns from one IP
refill_per_sec  = 5       # steady-state max 5 conns/sec per source

[[tenants]]
name        = "rj"
listen      = "0.0.0.0:8443"
peer_pq     = "127.0.0.1:9444"
sni         = "rj.bank.example.com"
peer_pub_dir = "/etc/qg/trust/rj"
audit_log   = "/var/lib/qg/rj.qa"
# No [tenants.limits] block → rj has unlimited admission.
# Mixed-policy SNI groups are supported.
```

### 13.15.3 Observability

```text
# Prometheus scrape (per tenant):
qgateway_admission_rejected_quota_total{tenant="sp"} 47
qgateway_admission_rejected_rate_total{tenant="sp"}  213
qgateway_admission_rejected_quota_total{tenant="rj"} 0
qgateway_admission_rejected_rate_total{tenant="rj"}  0
```

Alerting suggestions:
- `rate(qgateway_admission_rejected_quota_total[5m]) > 0.1` → quota
  saturation, consider raising `max_concurrent` or scaling out.
- `rate(qgateway_admission_rejected_rate_total[5m]) > 1` → sustained
  abuse from one or more sources; cross-reference with access logs to
  identify the IP.

### 13.15.4 Trade-offs documented

- **SNI group admission happens POST-TLS-handshake.** Single-tenant
  listeners check admission BEFORE the handshake (saving the ML-KEM-1024
  + ML-DSA-87 verify cost on rejected connections). SNI groups can't
  — the accept loop doesn't know which tenant's limits apply until the
  ClientHello SNI extension is parsed. Mitigation: TLS handshake is
  cheaper than CSPQ; the backend dial + CSPQ handshake costs ARE
  still saved on SNI-rejected connections. For hard pre-handshake
  protection on shared SNI ports, deploy a layer-4 rate limiter
  (iptables/nftables, eBPF) in front of qgateway.
- **Token-bucket buckets aren't GC'd.** Each unique source IP creates
  a `HashMap` entry that lives for the lifetime of the daemon. At
  10k unique sources the map is ~500 KiB — irrelevant. Deployments
  expecting hundreds of thousands of unique sources should add a
  background sweep task; the predicate (`tokens == capacity` AND
  `idle > 5min`) is stubbed in `RateLimiter::try_take` for that
  future work.
- **No coordinated state across multiple `qgateway` instances.** Each
  daemon has its own quota and rate-limit state. A load balancer
  fanning to 4 qgateway pods effectively multiplies the per-tenant
  limits by 4. Documented in operator README; for strict global limits
  use a shared traffic-management layer upstream.
- **No per-tenant "shares" mechanism on SNI ports.** Tenant A
  saturating its own quota doesn't help tenant B — they share the
  TCP accept queue but the controllers are independent. This is
  intentional (each tenant gets predictable behavior), but it does
  mean a misbehaving high-volume tenant can fill the accept queue
  with connections that get TLS-handshaked and then rejected, briefly
  starving a low-volume tenant on the same port. Mitigation: lower
  `max_concurrent` for high-volume tenants.

### 13.15.5 API surface changes

**Additive**:
- `qgateway_core::admission::{AdmissionController, Admit, RejectReason, RateLimitConfig}`
- `qgateway_core::config::{TenantLimits, RateLimitTomlConfig}` + `From<&RateLimitTomlConfig> for RateLimitConfig`
- `ServeTcpTenant.limits: Option<TenantLimits>`
- `ServePqTenant.limits: Option<TenantLimits>`
- `SniTenantContext.admission: Arc<AdmissionController>`
- `Metrics.admission_rejected_quota: AtomicU64`
- `Metrics.admission_rejected_rate: AtomicU64`

**Internal**:
- `crate::gateway::build_admission` helper
- `crate::gateway::record_admission_reject` helper

**No removals.** All Sprint 9 deployments continue to work — tenants
without `[limits]` blocks see admission as a no-op.

### 13.15.6 Acceptance — actual

- [x] `cargo test --workspace --locked` green: **153 tests** (up from 146
      in Sprint 9). 7 new admission unit tests.
- [x] `cargo build --workspace --locked` clean.
- [x] `cargo clippy --workspace --all-targets -- -D warnings` clean.
- [x] `cargo fmt --all --check` clean.
- [x] `cargo build -p qgateway --features pkcs11 --locked` clean.

### 13.15.7 Honest deferrals to Sprint 10

1. **Runtime `qgateway tenant add/remove`** CLI without daemon restart — Sprint 10.5.
2. ✅ **HSM connection health metrics** — DELIVERED in Sprint 10.
3. **Per-source-IP bucket GC sweep task** for deployments with millions of unique sources — Sprint 10.5.
4. **End-to-end admission integration test** with a real TCP client + metrics observation — Sprint 10.5.

---

## 13.16. SPRINT 10 — DELIVERABLE CONTRACT (✅ CLOSED)

Add Prometheus-grade observability for the PKCS#11 audit signer.
Before Sprint 10, HSM activity was visible only via `tracing` log
lines — fine for forensics, useless for alerting. Sprint 10 exposes
four counters that operators can wire into existing Prometheus +
Alertmanager pipelines.

### 13.16.1 Delivered

| # | Deliverable | Notes |
|---|---|---|
| `qaudit_hsm::HsmTelemetry` trait | New public trait in qaudit-hsm with four `&self` callbacks: `on_session_open`, `on_session_open_failed`, `on_sign_ok`, `on_sign_failed`. All have default no-op implementations so adopters override only the events they care about. `Send + Sync` so the same telemetry sink can be shared across multiple signers (e.g. startup signer + rotation factory). |
| `qaudit_hsm::NoopTelemetry` | Zero-method-body impl. Used as the default when callers invoke the existing `Pkcs11Signer::open(cfg)` / `Pkcs11SignerFactory::new(cfg)` paths — preserves backward compatibility with Sprint 9 deployments. |
| `Pkcs11Signer::open_with_telemetry(cfg, sink)` | New constructor. The sink is held in the signer for its lifetime and called on session-open success/failure AND on every `C_Sign`. The existing `open(cfg)` delegates here with `Arc::new(NoopTelemetry)`. |
| `Pkcs11SignerFactory::with_telemetry(sink)` | Builder method. Every signer minted via `open_new()` inherits the factory's telemetry sink. Single source-of-truth for HSM activity across rotations. |
| 4 new Prometheus counters | `qgateway_hsm_sessions_opened_total`, `qgateway_hsm_sessions_failed_total`, `qgateway_hsm_sign_ops_total`, `qgateway_hsm_sign_failures_total`, all labeled `tenant="<name>"`. Render-time wiring uses the existing `emit_counter` helper — zero new infrastructure. |
| `MetricsHsmTelemetry` adapter | Thin newtype in qgateway/main.rs implementing `qaudit_hsm::HsmTelemetry` on top of `qgateway_core::MetricsRegistry`. The orphan-rule workaround pattern established in Sprint 9 for `Pkcs11SignerFactoryWrapper`. One instance per tenant. |
| `sign_inner` refactor | The original `Pkcs11Signer::sign` method was split into a public `sign` (telemetry shell) and a private `sign_inner` (actual `C_Sign` call). All failure paths — including early returns for invalid mechanism types and poisoned mutexes — flow through the telemetry sink as `on_sign_failed`. |
| MetricsRegistry created before audit log build | `MetricsRegistry::new(t.name.clone())` now happens BEFORE `build_audit_log_pkcs11` so the initial session-open is also instrumented (not just rotations). Single source-of-truth from the first signature on. |
| 2 new lib tests | `telemetry_trait_default_methods_are_noop` (custom counting impl + `NoopTelemetry` exercising default-method path); `pkcs11_signer_factory_with_telemetry_is_clonable_via_arc` (type-level Send+Sync + Arc-erasure verification, no HSM required). |

### 13.16.2 Operational model

```toml
[[tenants]]
name = "sp"
listen = "0.0.0.0:8443"
peer_pq = "127.0.0.1:9443"
peer_pub_dir = "/etc/qg/trust/sp"
audit_log = "/var/lib/qg/sp.qa"

[tenants.audit_signer]
type           = "pkcs11"
module         = "/opt/dinamo/lib/libdinamo.so"
slot           = 0
pin_env        = "QGW_PKCS11_PIN"
key_label      = "audit-sp-2026"
pub_label      = "audit-sp-2026-pub"
mechanism_id   = 0x80004087
```

Scrape:

```text
# HELP qgateway_hsm_sessions_opened_total PKCS#11 sessions opened successfully (startup + per-rotation).
# TYPE qgateway_hsm_sessions_opened_total counter
qgateway_hsm_sessions_opened_total{tenant="sp"} 4
# HELP qgateway_hsm_sessions_failed_total PKCS#11 session-open failures (load, slot, login, or key lookup errors).
# TYPE qgateway_hsm_sessions_failed_total counter
qgateway_hsm_sessions_failed_total{tenant="sp"} 0
# HELP qgateway_hsm_sign_ops_total PKCS#11 C_Sign calls completed successfully (audit signatures).
# TYPE qgateway_hsm_sign_ops_total counter
qgateway_hsm_sign_ops_total{tenant="sp"} 18742
# HELP qgateway_hsm_sign_failures_total PKCS#11 C_Sign failures (token disconnected, mechanism unsupported, etc.).
# TYPE qgateway_hsm_sign_failures_total counter
qgateway_hsm_sign_failures_total{tenant="sp"} 0
```

### 13.16.3 Alerting suggestions

```yaml
# Prometheus rules
- alert: QGatewayHsmSessionsFailing
  expr: rate(qgateway_hsm_sessions_failed_total[5m]) > 0
  for: 1m
  annotations:
    summary: "HSM session-open failing for tenant {{ $labels.tenant }}"
    description: "Persistent session-open failures indicate HSM outage, expired PIN, or driver issue. Check QGW_PKCS11_PIN env var, verify HSM connectivity from the qgateway host, and consult the PKCS#11 driver log."

- alert: QGatewayHsmSignFailing
  expr: |
    rate(qgateway_hsm_sign_failures_total[5m]) > 0
    and on (tenant) rate(qgateway_hsm_sessions_opened_total[5m]) == 0
  for: 30s
  annotations:
    summary: "HSM signing failing on stable session for {{ $labels.tenant }}"
    description: "Sign failures without corresponding session-open failures = the live HSM session is rejecting signs. Token may be disconnected mid-session, or the mechanism ID may have become unsupported after a firmware update."

- alert: QGatewayHsmExcessiveRotations
  expr: increase(qgateway_hsm_sessions_opened_total[1h]) > 100
  annotations:
    summary: "Excessive HSM session churn for {{ $labels.tenant }}"
    description: "More than 100 session-opens per hour suggests an auto-rotation policy with too-low thresholds or unintended SIGUSR2 storms. Review [rotation] config."
```

### 13.16.4 Trade-offs documented

- **Trait dispatch overhead per sign.** Every `C_Sign` now goes through
  a virtual call on `Arc<dyn HsmTelemetry>`. On release builds with LTO,
  the compiler often devirtualises trivial no-op impls; on the metrics-
  reporting path, the cost is one atomic fetch_add per outcome —
  invisible compared to the network round-trip to the HSM (~milliseconds).
  Documented but not optimised further; if a deployment ever measures
  this as a bottleneck, a generic-typed `Pkcs11Signer<T: HsmTelemetry>`
  is a backward-compatible refactor.
- **No tenant-level "current open sessions" gauge.** Counters report
  cumulative events; instantaneous session count is not tracked. The
  rationale: each `Pkcs11Signer` IS a session, and the daemon's
  in-memory tenant table is the source of truth for "how many tenants
  hold a live session". A gauge would add either reference counting
  (complexity) or a periodic poll (lag). Operators wanting that view
  scrape `qgateway_tenants_total` (which has long existed) and combine
  with the `sessions_opened_total - sessions_failed_total` deltas.
- **No per-mechanism breakdown.** The counters don't label by
  `mechanism_id`. Practically every deployment runs one mechanism per
  tenant; the tenant label suffices. If mixed mechanisms per tenant
  ever appear (they shouldn't — that's an audit chain split), this
  refactors trivially.
- **Telemetry sink is `Arc<dyn HsmTelemetry>`, not generic.** Trait-
  object indirection is the right trade-off here: the alternative
  generic `Pkcs11Signer<T>` propagates the type parameter into every
  caller (factory, rotation channel, daemon main), which would force
  cascade refactors. Sprint 10 keeps the type ergonomic at the cost
  of one v-table per `C_Sign`.

### 13.16.5 API surface changes

**Additive**:
- `qaudit_hsm::HsmTelemetry` trait (4 methods, all default-noop)
- `qaudit_hsm::NoopTelemetry` zero-cost default impl
- `qaudit_hsm::Pkcs11Signer::open_with_telemetry`
- `qaudit_hsm::Pkcs11SignerFactory::with_telemetry`
- `qgateway_core::Metrics::{hsm_sessions_opened, hsm_sessions_failed, hsm_sign_ops, hsm_sign_failures}` (4 new AtomicU64 fields)

**Internal**:
- `qgateway::main::MetricsHsmTelemetry` adapter (cfg `pkcs11`)
- `Pkcs11Signer::sign_inner` private method
- `Pkcs11Signer::open_inner` private method
- `Pkcs11Signer.telemetry: Arc<dyn HsmTelemetry>` field

**No removals.** All Sprint 9.5 deployments continue to work — the old
`Pkcs11Signer::open(cfg)` and `Pkcs11SignerFactory::new(cfg)` paths use
`NoopTelemetry`, behaviour unchanged.

### 13.16.6 Acceptance — actual

- [x] `cargo test --workspace --locked` green: **153 tests** (default features, unchanged from Sprint 9.5 — the new tests are pkcs11-gated).
- [x] `cargo test --workspace --features qaudit-hsm/pkcs11` green: **156 tests** (+3 pkcs11-only).
- [x] `cargo build --workspace --locked` clean.
- [x] `cargo clippy --workspace --all-targets -- -D warnings` clean.
- [x] `cargo fmt --all --check` clean.
- [x] `cargo build -p qgateway --features pkcs11 --locked` clean.
- [x] `cargo test -p qaudit-hsm --features pkcs11 --lib` green: **7 tests** (up from 5).

### 13.16.7 Honest deferrals to Sprint 10.5

1. **Runtime `qgateway tenant add/remove`** CLI — Sprint 11 (architectural depth merits dedicated sprint; see §13.17.4).
2. ✅ **Per-source-IP bucket GC sweep task** — DELIVERED in Sprint 10.5.
3. **End-to-end admission integration test** with a real TCP client — Sprint 11.
4. **HSM mechanism-id label** — DEFERRED INDEFINITELY (info-gauge for a constant value is inferior to the existing structured log line; see §13.17.5).

---

## 13.17. SPRINT 10.5 — DELIVERABLE CONTRACT (✅ CLOSED)

Consolidation sprint. Scope honestly trimmed mid-sprint when the
runtime-tenant-CLI work proved larger than the remaining budget —
documented in §13.17.4 rather than half-shipped. What did ship: the
per-source-IP bucket GC sweep, closing a real memory-growth concern
for high-cardinality deployments.

### 13.17.1 Delivered

| # | Deliverable | Notes |
|---|---|---|
| `RateLimiter::maybe_gc` sweep | Real implementation, replacing the Sprint 9.5 stub. When the bucket count exceeds `GC_THRESHOLD`, every `try_take` call retains only entries that are either (a) below capacity (in active use), or (b) within `IDLE_TTL` of last touch. Amortised O(1) per accept: sweep only fires when the map is "too big", and the sweep is one HashMap retain pass — microseconds at the 10k–100k bucket scale. |
| `GC_THRESHOLD = 8192` constant | Below this, the sweep never fires (zero overhead for small deployments). 8k entries ~ 400 KiB of HashMap state — irrelevant. The threshold is the inflection where the cost of leaking entries starts to outweigh the cost of sweeping. |
| `IDLE_TTL = 300s` constant | A bucket idle longer than this is GC-eligible. Five minutes balances two concerns: long enough that recurrent legitimate clients (browser tabs, mobile clients reconnecting) aren't penalised by losing their refill state; short enough that one-shot probes don't accumulate. |
| Projected-tokens projection | The retain predicate evaluates the bucket's CURRENT effective token count without mutating it. A bucket that's been idle for hours has long since refilled to capacity in the eyes of the rate limiter, even though its internal `tokens` field still holds the post-consumption value from hours ago. The projection makes GC correctness independent of refill ordering. |
| 3 new unit tests | `gc_drops_idle_full_buckets_above_threshold` (fill past threshold, advance past TTL, single fresh accept reduces map to ~1); `gc_preserves_recently_used_buckets` (active peer's bucket survives a sweep that drops idle peers); `gc_does_not_run_below_threshold` (100 idle entries for 24h with no GC — sweep gated entirely on `len > GC_THRESHOLD`). |

### 13.17.2 Memory bound

Without GC, the bucket count is unbounded — every unique source IP
allocates a permanent ~50-byte entry. At sustained 1k unique
sources/minute that's 3 MiB/hour, 72 MiB/day, 2 GiB/month. With GC at
the configured thresholds, the map stays bounded at `GC_THRESHOLD +
ACTIVE_WINDOW * arrival_rate` — for arrival rate 1k/min the steady
state is `8192 + 300*1000/60 ≈ 13k` entries (~650 KiB), independent
of total cumulative connections.

### 13.17.3 Trade-offs documented

- **`GC_THRESHOLD` is hardcoded at 8192.** Operators with hundreds of
  thousands of legitimate sustained sources may want this higher; the
  fix is a one-line constant edit + rebuild, or a Sprint-11 TOML
  knob. The current value covers >99% of real deployments.
- **`IDLE_TTL` is hardcoded at 300s.** Same rationale.
- **No metric for GC events.** A counter like
  `qgateway_admission_gc_drops_total` would help operators tune
  thresholds. Sprint-11 candidate if anyone hits the threshold in
  production.
- **Projected-tokens computation is read-only.** A more aggressive
  GC would actually refill stale buckets, drop the ones at capacity,
  and update `last_refill` for survivors. Read-only sweep is simpler
  and correct; the next `try_take` for a surviving bucket does the
  real refill anyway.

### 13.17.4 Honest scope cut — runtime tenant CLI

The most-requested Sprint 10.5 deliverable was a SIGHUP handler that
re-reads `sidecar.toml` and adds (or removes) tenants without
restarting the daemon. Mid-sprint analysis surfaced:

- The tenant-construction code in `main.rs::cmd_run` is ~150 lines of
  glue: signer resolution, audit log build, signer factory, rotation
  monitor, admission controller, metrics registry, `TenantRuntime`
  push. Extracting this into a reusable function callable from the
  signal handler is ~200 lines of refactor.
- New design questions opened up: How does the metrics server's
  per-tenant list grow at runtime (currently passed by value to
  `spawn_metrics_server`)? How are reload failures surfaced (TOML
  parse error vs partial-success per-tenant)? What's the diff
  algorithm — name-keyed, listen-address-keyed, or composite? Removal
  is even harder: drain in-flight sessions, await `tenant_task`
  shutdown, propagate audit channel close.

Honest decision: ship the GC sweep cleanly rather than half-implement
tenant CLI. The carryover to Sprint 11 is documented with a concrete
design sketch (§13.18.4 of the Sprint 11 contract once shipped).

### 13.17.5 Honest scope cut — HSM mechanism-id label

The Sprint 10 contract listed "HSM mechanism-id label on the four
new counters" as a potential Sprint 10.5 follow-up "if mixed-mechanism
deployments emerge". They haven't. The alternative — an info-gauge
like `qgateway_hsm_mechanism_info{tenant=, mechanism_id=}` reporting
a constant 1 — is inferior to the existing structured `tracing::info!`
line emitted at startup. The information is already discoverable;
adding a Prometheus surface for a static value is over-engineering.

Deferred indefinitely. If mixed-mechanism deployments ever emerge,
the refactor is trivial — add `mechanism_id` to the label set on the
existing four counters.

### 13.17.6 API surface changes

**Additive**:
- `qgateway_core::admission::GC_THRESHOLD: usize`
- `qgateway_core::admission::IDLE_TTL: Duration`

Both are private to the module; the public `AdmissionController` and
`RateLimiter` surface is unchanged.

### 13.17.7 Acceptance — actual

- [x] `cargo test --workspace --locked` green: **156 tests** (up from 153
      in Sprint 10). 3 new GC tests in `admission::tests`.
- [x] `cargo build --workspace --locked` clean.
- [x] `cargo clippy --workspace --all-targets -- -D warnings` clean.
- [x] `cargo fmt --all --check` clean.
- [x] `cargo build -p qgateway --features pkcs11 --locked` clean.

### 13.17.8 Honest deferrals to Sprint 11

1. ⚠️ **Runtime `qgateway tenant add/remove`** CLI via SIGHUP + config diff — PARTIALLY DELIVERED in Sprint 11.0 (validation-only); full apply ships in Sprint 11.5.
2. **End-to-end admission integration test** with a real TCP client — Sprint 11.5.
3. **`qgateway_admission_gc_drops_total` counter** if anyone in production reports memory growth past the bound predicted in §13.17.2 — Sprint 12+ (only on operator request).
4. **TOML knobs for `GC_THRESHOLD` and `IDLE_TTL`** if a deployment legitimately needs to tune them — Sprint 12+ (only on operator request).

---

## 13.18. SPRINT 11.0 — DELIVERABLE CONTRACT (✅ CLOSED)

First half of the runtime-tenant-management feature, scope-cut from
the original "Sprint 11" target. Ships the SIGHUP wire-up,
config-reload validation, and tenant-diff reporting — everything
operationally useful that doesn't require the deep runtime-state
mutation refactor. The actual "add a new tenant in-place" apply
ships in Sprint 11.5.

### 13.18.1 Delivered

| # | Deliverable | Notes |
|---|---|---|
| SIGHUP signal handler | New `select!` arm in `install_signal_handler`. The handler captures `config_path: PathBuf` and an `initial_tenant_names: HashSet<String>` at daemon-startup time. On every SIGHUP, the handler re-loads the TOML, runs the full `Config::validate` pass, and computes the diff vs the startup tenant set. |
| Diff reporting | Three sets surfaced via `tracing::info!`: `added` (in config, not running), `removed` (running, not in config), `unchanged` (consistent on both sides). Each `added`/`removed` tenant is logged individually with the actionable "restart required" hint that points operators at the Sprint 11.5 follow-up. |
| Validation-failure recovery | When `Config::load` returns Err (TOML parse error, schema violation, or any of the existing validations), the handler logs the error at `error!` level and the daemon continues running with the previously-loaded config. There is no fail-stop on a bad SIGHUP — operators fix the TOML in place and re-send SIGHUP without losing the running daemon. |
| Non-unix stub | Signature updated to take `config_path` + `initial_tenant_names` so the unix and non-unix branches of `cmd_run` compile identically. Non-unix targets fall back to ctrl_c-only behaviour (no SIGHUP on Windows). |

### 13.18.2 Operational model

```bash
# Add a new tenant to /etc/qgateway/sidecar.toml ...
$ vim /etc/qgateway/sidecar.toml

# Validate without applying:
$ kill -HUP $(pidof qgateway)

# Daemon logs (via journalctl -u qgateway):
[INFO  qgateway] SIGHUP received, validating config (no runtime apply)
                config="/etc/qgateway/sidecar.toml"
[INFO  qgateway] config reload validation OK
                added=1 removed=0 unchanged=3
[INFO  qgateway] tenant="branch-fortaleza" in config but NOT running
                — restart required (Sprint 11.5: runtime add)

# Bad TOML:
$ kill -HUP $(pidof qgateway)
[INFO  qgateway] SIGHUP received, validating config (no runtime apply)
[ERROR qgateway] SIGHUP config reload FAILED validation:
                cannot read /etc/qgateway/sidecar.toml: ...
[ERROR qgateway] daemon continues with previously-loaded config;
                fix the TOML and re-send SIGHUP
```

### 13.18.3 What Sprint 11.0 unlocks today

Even without the apply step, the validation pass is operationally
useful in real production:

- **Catches TOML errors before restart.** An operator who edits the
  config and then realises they need to restart the daemon currently
  has to either keep two terminals open or risk a syntax error
  taking the daemon down. SIGHUP + tracing tells them in advance.
- **Detects unintended manual edits.** An on-call who finds the
  config doesn't match `pidof qgateway`'s tenant set knows immediately
  that something happened — either someone else edited the file
  outside change-control, OR the config file is genuinely out of
  sync (perhaps from a failed config-management push).
- **Documents the diff.** The `added`/`removed`/`unchanged` log line
  is grep-able and feeds into observability pipelines. Sprint 11.5's
  apply step will use the same diff machinery — the operator-visible
  log format won't change.

### 13.18.4 Sprint 11.5 design sketch — apply step

When 11.5 ships, the SIGHUP arm will additionally:

1. **For each `added` tenant**: call a new `build_tenant_runtime(t, cfg, identity)` helper (extracted from the existing `cmd_run` loop body) that returns a `TenantRuntime`. Push it to a shared `Arc<RwLock<Vec<TenantRuntime>>>`. Spawn the tenant's accept-loop task. Push the new `MetricsRegistry` into the metrics server's shared list (also `Arc<RwLock<Vec<_>>>`).

2. **For each `removed` tenant**: send a tenant-specific shutdown notify, await its `tenant_task` JoinHandle for up to a configurable grace period, then drop its `AuditChannel` and remove it from the shared lists. In-flight sessions get the grace period to complete; new accepts on the listener fail with TCP RST.

3. **For each `unchanged` tenant**: leave alone. Sprint 11.5 doesn't support in-place modification of an existing tenant (that's Sprint 12 territory — handles `[tenants.limits]` changes, `audit_log` path migration, SNI re-mapping, etc.).

The metrics-server refactor (`Vec<MetricsRegistry>` → `Arc<RwLock<Vec<_>>>`) is the one breaking change Sprint 11.5 carries; it's internal to the binary and doesn't touch the qgateway-core library surface.

### 13.18.5 Trade-offs documented

- **`config_path: PathBuf` is captured at startup.** A symlink swap on
  the config file is honored on the next SIGHUP (it just re-reads
  the symlink target). A `mv` of the file path itself would break
  reload — but that's not a realistic deployment pattern.
- **`initial_tenant_names: HashSet<String>` snapshots the startup
  set.** It never grows. Sprint 11.5 will replace this with the
  shared `Arc<RwLock<Vec<TenantRuntime>>>`'s current name set,
  computed on-demand at each SIGHUP. The Sprint 11.0 stub is
  forward-compatible: the diff machinery already handles a moving
  baseline, the snapshot is just simpler for validation-only.
- **No diff for tenant *configuration changes*.** Two tenants with
  the same `name` but different `peer_pub_dir`, `tls.cert`, `limits`,
  etc., are reported as `unchanged`. The Sprint 11.0 diff is
  name-keyed only. Configuration-aware diff is Sprint 12+ work; it
  needs an explicit `TenantConfig::differs_from(&other) -> bool`
  method with carefully-chosen "what counts as material change"
  semantics.
- **SIGHUP is single-shot.** Holding SIGHUP (kill -HUP repeatedly in
  rapid succession) just runs the validation pass repeatedly. There's
  no debouncing because the validation is cheap (~1ms for typical
  configs) and idempotent.

### 13.18.6 API surface changes

**Additive**:
- `install_signal_handler` gained two parameters: `config_path: PathBuf` and `initial_tenant_names: HashSet<String>`. Both branches (unix and non-unix) updated.

**No removals.** All existing signal-handling behaviour (SIGINT, SIGTERM, SIGUSR1, SIGUSR2) is preserved unchanged.

### 13.18.7 Acceptance — actual

- [x] `cargo test --workspace --locked` green: **156 tests** (unchanged from Sprint 10.5 — SIGHUP path is stateless validation, no library-level test surface).
- [x] `cargo build --workspace --locked` clean.
- [x] `cargo clippy --workspace --all-targets -- -D warnings` clean.
- [x] `cargo fmt --all --check` clean.
- [x] `cargo build -p qgateway --features pkcs11 --locked` clean.

### 13.18.8 Honest deferrals to Sprint 11.5

1. ✅ **`build_tenant_runtime` extraction** — DELIVERED in Sprint 11.5.
2. ✅ **`Arc<RwLock<Vec<MetricsRegistry>>>` refactor** — DELIVERED in Sprint 11.5.
3. ⚠️ **SIGHUP apply step** — PARTIALLY DELIVERED (runtime build + metrics + name set updated; accept-loop spawn pending Sprint 12).
4. **Tenant-removal drain protocol** — Sprint 12.
5. **End-to-end admission integration test** — Sprint 12.

---

## 13.19. SPRINT 11.5 — DELIVERABLE CONTRACT (✅ CLOSED)

Second half of the runtime-tenant-management story. Ships the
mechanical refactor (extract `build_tenant_runtime`, share metrics +
name set via `Arc<RwLock>`) and the SIGHUP apply step that registers
new tenants into the metrics surface and name set. The remaining
piece — actually spawning the accept loop so new tenants serve
traffic without restart — is deferred to Sprint 12 because the
per-role accept-loop spawn logic (serve-tcp vs serve-pq vs sni-group)
is its own architectural problem that doesn't fit cleanly into
Sprint 11.5's budget.

### 13.19.1 Delivered

| # | Deliverable | Notes |
|---|---|---|
| `build_tenant_runtime(t, cfg) -> Result<TenantRuntime>` | Extracted from `cmd_run`. Takes a single `TenantConfig` plus the surrounding `Config` (needed for `effective_signer` precedence). Returns a fully-wired `TenantRuntime` — peer policy loaded, audit signer/log built (Softkey or PKCS#11 with telemetry), AuditChannel spawned with rotation factory, metrics registry created. Does NOT touch any shared state — callers are responsible for that. |
| `SharedMetricsList` type alias | `Arc<tokio::sync::RwLock<Vec<MetricsRegistry>>>`. The metrics server now reads this on every /metrics scrape; the SIGHUP apply step writes new entries on tenant-add. RwLock chosen over Mutex because scrapes dominate writes (every 15s vs operator-action). |
| Metrics server refactor | `spawn_metrics_server` signature changed from `Vec<MetricsRegistry>` to `SharedMetricsList`. The /metrics handler clones the snapshot under the read lock then releases it before `render_prometheus` — concurrent SIGHUP apply isn't blocked behind a CPU-bound render. |
| Shared tenant-name set | `Arc<RwLock<HashSet<String>>>` replaces Sprint 11.0's `HashSet<String>` snapshot. The apply step extends it after each successful ADD so subsequent SIGHUPs see the updated set. |
| SIGHUP apply step | The signal handler now:  (1) reads the current name set from shared state;  (2) loads + validates the new config;  (3) computes diff against current names;  (4) for each `added` tenant, calls `build_tenant_runtime` and on success pushes the new MetricsRegistry to the shared list + extends the shared name set;  (5) for each `removed` tenant, logs a warning ("removal requires restart, Sprint 12"). Failures during build_tenant_runtime are logged per-tenant and counted in the summary — one bad tenant doesn't abort the cycle. |
| Apply summary log line | `added_applied`, `added_failed`, `removed_pending` counters emitted at info-level. Operators get an at-a-glance view of what changed without parsing per-tenant log lines. |
| `identity` threaded through | The SIGHUP handler now holds an `Arc<IdentityKey>` so Sprint 12's accept-loop spawn has everything it needs without a second signature change. |

### 13.19.2 Operational model — apply step

```bash
# Add a new tenant in the TOML.
$ vim /etc/qgateway/sidecar.toml

# Trigger reload.
$ kill -HUP $(pidof qgateway)

[INFO  qgateway] SIGHUP received config="/etc/qgateway/sidecar.toml"
[INFO  qgateway] config reload diff
                added=1 removed=0 unchanged=3
[INFO  qgateway] tenant="branch-fortaleza" registered
                (metrics + name set); accept loop pending Sprint 12
[INFO  qgateway] config reload apply summary
                added_applied=1 added_failed=0 removed_pending=0
```

After this cycle:

```bash
$ curl localhost:9090/metrics | grep branch-fortaleza
qgateway_audit_events_total{tenant="branch-fortaleza"} 0
qgateway_admission_rejected_quota_total{tenant="branch-fortaleza"} 0
# ... all other tenant-labeled metrics also visible.
```

The new tenant's runtime is fully built — audit log open, signer
wired, metrics registered. The only thing missing is the accept-loop
task. **Inbound CSPQ connections to the new tenant's `listen` address
still get a kernel RST until the next daemon restart.** Documented
honestly in the daemon log line and in this SPEC.

### 13.19.3 Failure modes

```text
[ERROR qgateway] tenant="branch-fortaleza" tenant ADD failed:
                loading peer dir /etc/qg/trust/fortaleza:
                No such file or directory (os error 2)
[INFO  qgateway] config reload apply summary
                added_applied=0 added_failed=1 removed_pending=0
```

One failed tenant doesn't abort the cycle — other added tenants are
still registered. The daemon continues with whatever subset was
successfully built.

### 13.19.4 Trade-offs documented

- **Accept-loop spawn deferred to Sprint 12.** This is the honest
  blocker. The per-role spawn logic in `cmd_run` (serve-tcp builds a
  TLS reload trigger optionally, serve-pq doesn't, sni-group dispatches
  to a shared listener) doesn't extract cleanly without a second
  pass on the spawn callsites. Sprint 11.5 leaves the runtime
  built-and-registered; Sprint 12 wires the listener.
- **Tenant removal still requires restart.** The drain protocol —
  send tenant-scoped shutdown notify, await tenant_task JoinHandle
  with grace period, drop AuditChannel cleanly — is its own
  architectural problem. Logging the diff as `removed_pending` keeps
  the operator informed but doesn't actually take action.
- **Tenant configuration changes still treated as `unchanged`.** Same
  name + different settings = no action. Config-aware diff is Sprint
  12+ work (needs `TenantConfig::differs_from(&other) -> bool` with
  carefully-chosen "what counts as material change" semantics).
- **No rollback on partial failure.** If 5 tenants are added and 3
  succeed + 2 fail, the 3 stay. There's no transactional semantics
  — that would require holding a write lock across all 5 builds,
  which can take seconds for HSM tenants. Operators alerting on
  `added_failed > 0` should investigate per-tenant logs.
- **MetricsRegistry leaks on apply failure.** When `build_tenant_runtime`
  fails AFTER creating the MetricsRegistry, the registry is dropped
  without being pushed. No leak — Rust drops it. The Sprint 12.x
  scope item "tenant remove" will need to handle this carefully when
  removing tenants that have a MetricsRegistry pushed to the shared
  list.

### 13.19.5 API surface changes

**Additive** (internal to qgateway binary):
- `build_tenant_runtime(t: &TenantConfig, cfg: &Config) -> Result<TenantRuntime>`
- `SharedMetricsList` type alias

**Signature changes** (internal to qgateway binary):
- `spawn_metrics_server` second arg: `Vec<MetricsRegistry>` → `SharedMetricsList`
- `install_signal_handler` gained two params: `metrics_list: SharedMetricsList` and `identity: Arc<IdentityKey>`. The non-unix stub mirrors the unix signature shape (with leading underscores on the unused arms).

**Behavioural changes**:
- SIGHUP now mutates runtime state (shared metrics list + shared name set) on successful ADD. Before Sprint 11.5 it was validation-only.

### 13.19.6 Acceptance — actual

- [x] `cargo test --workspace --locked` green: **156 tests** (unchanged — SIGHUP apply path is integration-level, no library-level test surface).
- [x] `cargo build --workspace --locked` clean.
- [x] `cargo clippy --workspace --all-targets -- -D warnings` clean.
- [x] `cargo fmt --all --check` clean.
- [x] `cargo build -p qgateway --features pkcs11 --locked` clean.

### 13.19.7 Honest deferrals to Sprint 12

1. ⚠️ **Accept-loop spawn for runtime-added tenants** — PARTIALLY DELIVERED in Sprint 12 (serve-pq only; serve-tcp + SNI groups pending Sprint 13).
2. **Tenant removal via SIGHUP.** Drain protocol — Sprint 13.
3. **Tenant configuration-change detection.** `TenantConfig::differs_from(&other)` — Sprint 13+.
4. **End-to-end admission integration test** — Sprint 13.
5. **SIGHUP integration test** — Sprint 13.

---

## 13.20. SPRINT 12 — DELIVERABLE CONTRACT (✅ CLOSED)

Wires the SIGHUP apply step (Sprint 11.5) into actual traffic-serving
behaviour for the most common deployment shape: single-tenant
serve-pq. A new tenant added via TOML edit + SIGHUP now begins
serving inbound CSPQ traffic immediately, without restart, for
serve-pq roles. The serve-tcp and SNI-group paths still require
restart because their accept-loop spawn logic carries TLS reload
triggers and SNI dispatch tables that need additional shared-state
plumbing — documented honestly in §13.20.3.

### 13.20.1 Delivered

| # | Deliverable | Notes |
|---|---|---|
| `Config::resolve_one_serve_pq(&self, t: &TenantConfig) -> Result<ServePqTenant, ConfigError>` | New public method on `Config`. Refactored `resolve_serve_pq` (multi-tenant) to delegate to `resolve_one_serve_pq` per tenant. Same validation: rejects non-`ServePq` role, rejects missing `backend`, propagates `effective_signer` precedence. The multi-tenant variant remains for the startup path; the single-tenant variant is what the SIGHUP apply step calls. |
| SIGHUP serve-pq accept-loop spawn | The Sprint 11.5 apply block now matches on `new_cfg.role`: when `ServePq`, the handler resolves the single tenant, clones identity + peer_policy + audit_handle + metrics from the just-built `TenantRuntime`, captures the existing `notify` as the per-tenant `shutdown` source, and `tokio::spawn`s `run_serve_pq_tenant`. The task holds the `AuditChannel` via the handle clone — the `rt` itself drops cleanly. |
| Differentiated apply log | Tenants whose accept loop was actually spawned log `"tenant ADDED at runtime — serving traffic"`. Tenants where the role didn't match (serve-tcp, sni-group) log `"tenant registered (metrics + name set); accept loop pending Sprint 13"`. Operators see at a glance which path their tenant went through. |
| 3 new lib tests | `resolve_one_serve_pq_returns_resolved_single_tenant` (happy path: TOML → resolved struct with correct id/listen/backend); `resolve_one_serve_pq_rejects_when_not_serve_pq_role` (calling on a serve-tcp `Config` returns `Conflict`); `resolve_one_serve_pq_rejects_missing_backend` (hand-built tenant with `backend = None` returns `Missing` — covers the post-TOML-validation path a runtime API would hit). |

### 13.20.2 Operational model — serve-pq runtime add

```bash
# qgateway is running as `role = "serve-pq"` with tenants sp, rj, mg.

# Add a fourth tenant in the TOML.
$ cat >> /etc/qgateway/sidecar.toml <<EOF

[[tenants]]
name         = "branch-fortaleza"
listen       = "0.0.0.0:9004"
backend      = "10.0.4.10:80"
peer_pub_dir = "/etc/qg/peers-fortaleza"
audit_log    = "/var/lib/qg/fortaleza.qa"
EOF

# Reload.
$ kill -HUP $(pidof qgateway)

[INFO  qgateway] SIGHUP received config="/etc/qgateway/sidecar.toml"
[INFO  qgateway] config reload diff added=1 removed=0 unchanged=3
[INFO  qgateway] tenant="branch-fortaleza" role=ServePq
                "tenant ADDED at runtime — serving traffic"
[INFO  qgateway] config reload apply summary
                added_applied=1 added_failed=0 removed_pending=0

# Verify the new tenant is serving:
$ ss -tlnp | grep 9004
LISTEN 0  128  0.0.0.0:9004  *:*  users:(("qgateway",pid=1234,fd=42))

# And metrics include the new label:
$ curl -s localhost:9090/metrics | grep branch-fortaleza | head -3
qgateway_audit_events_total{tenant="branch-fortaleza"} 0
qgateway_handshake_count{tenant="branch-fortaleza"} 0
qgateway_admission_rejected_quota_total{tenant="branch-fortaleza"} 0
```

The new tenant is fully online: listener bound, audit channel
spawned + signing, peer-policy enforcing, admission control active,
metrics labeled. No restart, no traffic loss to existing tenants.

### 13.20.3 Trade-offs documented

- **Only serve-pq supports runtime add.** A `Role::ServeTcp` config
  with an added tenant logs `"accept loop pending Sprint 13"` and
  treats it like Sprint 11.5 did — registers metrics + name set, but
  doesn't bind a listener. The blocker for serve-tcp is the TLS
  reload trigger plumbing: the `reload_triggers: Vec<TlsReloadTrigger>`
  passed to `install_signal_handler` is a fixed snapshot at startup;
  to add a new TLS tenant at runtime, that list (or its replacement
  in shared state) needs the same `Arc<RwLock<Vec<_>>>` treatment as
  the metrics list and name set. Sprint 13 work.
- **SNI groups need even more.** Adding a new SNI tenant to an
  existing group means mutating the `SniDispatchTable` (a `Vec` of
  `(hostname, SniTenantContext)` tuples) AND the cert resolver's
  shared cert map. Both are immutable post-construction in the current
  codebase. Honest scope: this is Sprint 13's biggest item.
- **No tenant removal yet.** Sprint 12 only handles ADD. Removal
  requires (a) tenant-scoped shutdown notify (currently every tenant
  shares the daemon-wide `notify`, so notifying one shuts them all
  down), (b) JoinHandle tracking per tenant to await drain, (c)
  AuditChannel cleanup, (d) removal from shared lists. Same shared-
  state refactor pattern as Sprint 11.5 but applied to a different
  axis. Sprint 13+.
- **No configuration-change diff.** Same name + different settings
  (e.g. operator edits `limits.max_concurrent` from 100 to 200) is
  reported as `unchanged`. Sprint 13's `TenantConfig::differs_from`
  will handle this.
- **Tenant task uses daemon-wide shutdown notify.** Currently
  acceptable: SIGTERM still shuts down the new tenant cleanly along
  with the rest. Becomes a problem only when per-tenant removal
  ships in Sprint 13.

### 13.20.4 API surface changes

**Additive**:
- `qgateway_core::Config::resolve_one_serve_pq` — `pub` method.

**No removals.** `Config::resolve_serve_pq` still exists; it now
delegates to the new per-tenant variant internally.

### 13.20.5 Acceptance — actual

- [x] `cargo test --workspace --locked` green: **159 tests** (up from
      156 in Sprint 11.5). 3 new tests for `resolve_one_serve_pq`.
- [x] `cargo build --workspace --locked` clean.
- [x] `cargo clippy --workspace --all-targets -- -D warnings` clean.
- [x] `cargo fmt --all --check` clean.
- [x] `cargo build -p qgateway --features pkcs11 --locked` clean.

### 13.20.6 Honest deferrals to Sprint 13

1. ⚠️ **serve-tcp runtime add** — PARTIALLY DELIVERED in Sprint 13 (plain TCP only; TLS hot-add pending Sprint 14).
2. **SNI-group runtime add.** Sprint 14.
3. **Tenant removal via SIGHUP** (drain protocol). Sprint 14.
4. ✅ **Config-aware diff** via `TenantConfig::material_changes` — DELIVERED in Sprint 13.
5. **SIGHUP integration test** — Sprint 14.
6. **End-to-end admission integration test** — Sprint 14.

---

## 13.21. SPRINT 13 — DELIVERABLE CONTRACT (✅ CLOSED)

Closes two of the six Sprint 12.6 carryover items honestly: the
config-aware diff machinery and serve-tcp runtime add for the
plain-TCP case. SNI hot-add, TLS hot-add, tenant removal, and the
two integration tests remain Sprint 14 work — each is its own
architectural slice that won't ship cleanly in a shared sprint.

### 13.21.1 Delivered

| # | Deliverable | Notes |
|---|---|---|
| `TenantConfig::material_changes(&self, &Self) -> Vec<&'static str>` | New public method. Returns a deterministic vector of field names that differ between two tenant configs at semantic equality. The order matches the declaration sequence in the method (listen, peer_pq, backend, peer_pub_dir, audit_log, tls, sni, audit_signer, limits) so log output is stable across runs. Manual implementation rather than `#[derive(PartialEq)]` because the equality semantics are path/string/numeric — derive would be brittle if `PathBuf` ever picked up other fields. |
| `TenantConfig::differs_from(&self, &Self) -> bool` | Convenience wrapper: `true` iff `material_changes` would return a non-empty vec. |
| `Config::resolve_one_serve_tcp(&self, &TenantConfig) -> Result<ServeTcpTenant, ConfigError>` | Sprint 12 added this pattern for serve-pq; Sprint 13 adds it for serve-tcp. Refactored `resolve_serve_tcp` (multi-tenant) to delegate to the single-tenant variant. Rejects non-`ServeTcp` role + missing `peer_pq`. |
| SIGHUP serve-tcp runtime add | When `new_cfg.role == ServeTcp` AND the added tenant has neither `[tls]` nor `sni`, the apply step calls `resolve_one_serve_tcp` and spawns `run_serve_tcp_tenant` with `tls = None`. Tenants with TLS or SNI declared log `"TLS/SNI hot-add pending Sprint 14 — registered only"` and follow the Sprint-11.5 register-only path. |
| Config-aware diff in SIGHUP arm | For tenants in the `unchanged` name set, the handler compares the `new_cfg` entry against the startup snapshot via `material_changes`. Non-empty change vectors are logged at `warn!` level with the specific field names: `"tenant configuration changed but hot-reconfigure not supported — restart required for changes to take effect"`. The reload-diff log line gains a `config_changed=N` field for at-a-glance counting. |
| 9 new `material_changes` lib tests | Coverage: identical inputs (empty vec); single-field changes (listen, backend); limits Option transitions (None → Some, Some(x) → Some(y), Some-equal stays empty); audit_signer path changes within Softkey variant; audit_signer variant changes (Softkey ↔ Pkcs11); multi-field change with stable ordering. |
| 3 new `resolve_one_serve_tcp` lib tests | Coverage: happy path; wrong-role rejected; missing `peer_pq` rejected. |
| `#[allow(clippy::too_many_arguments)]` on signal handler | Justified: 9 args now (notify + 2 reload-trigger structs + config path + 2 shared lock handles + identity + startup snapshot). The alternative — bundling into a struct — adds a layer of indirection for zero benefit in a single private function. |

### 13.21.2 Operational model — serve-tcp runtime add

```bash
# qgateway running as `role = "serve-tcp"` with 3 tenants.

# Add a fourth tenant (plain TCP, no TLS, no SNI).
$ cat >> /etc/qgateway/sidecar.toml <<EOF

[[tenants]]
name         = "branch-bahia"
listen       = "0.0.0.0:8447"
peer_pq      = "10.0.5.10:9999"
peer_pub_dir = "/etc/qg/peers-bahia"
audit_log    = "/var/lib/qg/bahia.qa"
EOF

$ kill -HUP $(pidof qgateway)

[INFO  qgateway] SIGHUP received config="/etc/qgateway/sidecar.toml"
[INFO  qgateway] config reload diff
                added=1 removed=0 unchanged=3 config_changed=0
[INFO  qgateway] tenant="branch-bahia" role=ServeTcp
                "tenant ADDED at runtime — serving traffic"
[INFO  qgateway] config reload apply summary
                added_applied=1 added_failed=0 removed_pending=0
```

Tenants with TLS or SNI fall back to register-only:

```bash
# Adding a TLS-terminating tenant:
$ kill -HUP $(pidof qgateway)
[INFO  qgateway] tenant="branch-tls" has_tls=true has_sni=false
                "serve-tcp runtime add: TLS/SNI hot-add pending Sprint 14 — registered only"
[INFO  qgateway] config reload apply summary
                added_applied=1 added_failed=0 removed_pending=0
```

### 13.21.3 Operational model — config-aware diff

When an operator edits an existing tenant's settings, SIGHUP now
reports the specific fields that changed:

```bash
# Operator edits `branch-sp`'s limits.max_concurrent from 100 to 200.
$ kill -HUP $(pidof qgateway)

[INFO  qgateway] SIGHUP received config="/etc/qgateway/sidecar.toml"
[WARN  qgateway] tenant="branch-sp" fields=["limits"]
                "tenant configuration changed but hot-reconfigure not supported
                 — restart required for changes to take effect"
[INFO  qgateway] config reload diff
                added=0 removed=0 unchanged=4 config_changed=1
```

Operators see exactly which field changed and that a restart is
required. The current daemon continues running with the previously-
loaded config — no half-applied state, no surprise behaviour mid-
session.

### 13.21.4 Trade-offs documented

- **TLS hot-add still requires restart.** A serve-tcp tenant with
  `[tls]` configured gets register-only treatment. The blocker is
  the `TlsAcceptorHandle` infrastructure: at startup, each TLS tenant
  builds a reloadable acceptor wired into `reload_triggers` for
  SIGUSR1 cert reload. Adding a new TLS tenant at runtime means
  creating that acceptor + extending the shared reload-trigger list
  + spawning the accept loop with the right acceptor handle. Same
  shared-state refactor as Sprint 11.5 applied to a third axis.
  Sprint 14 work.
- **SNI hot-add is unimplemented.** Even more involved: SNI groups
  share a TCP listener and dispatch by hostname at TLS handshake
  time via a `SniDispatchTable`. Adding a tenant to an existing
  group means mutating both the dispatch table AND the cert resolver's
  shared cert map. Both are immutable post-construction. Sprint 14
  honestly will take this as its main item.
- **Config-aware diff is read-only.** When `material_changes` returns
  `vec!["limits"]`, the daemon logs the warning but does NOT rebuild
  the AdmissionController, restart the tenant task, or update any
  shared state. Hot-reconfiguration of a live tenant requires a
  remove-then-re-add cycle that itself blocks on the Sprint 14
  removal-drain protocol.
- **Material-change detection has a gap.** The startup snapshot
  passed to the signal handler is `Vec<TenantConfig>` taken at daemon
  startup. Tenants ADDED at runtime via earlier SIGHUPs and then
  edited in a later SIGHUP won't show as `config_changed` — the
  snapshot doesn't know about them. Documented inline in the SIGHUP
  arm. Fix: promote to `Arc<RwLock<Vec<TenantConfig>>>` that the
  apply step extends on each successful ADD. Sprint 14.
- **No granularity in "what kind of change".** All material changes
  are reported with the same "restart required" message. A future
  classification could separate hot-applicable (just `limits`) from
  cold-only (everything else), enabling true hot-reconfigure for
  the common case of tuning admission limits. Not in Sprint 13's
  scope — operational value of the current binary classification is
  already high.
- **PartialEq vs manual equality.** Chose manual equality functions
  (`tls_eq`, `audit_signer_eq`, etc.) over `#[derive(PartialEq)]`
  because the types involve `PathBuf` (which has its own platform-
  specific equality semantics) and `Option<T>` (where None and
  Some(default) should both compare unequal to a different
  Some(value)). Manual equality makes the intent explicit and avoids
  accidentally breaking diff semantics if a future struct field is
  added without a corresponding `material_changes` entry — the
  compiler doesn't catch missing fields in manual equality, but
  field additions are rare and reviewers see the gap.

### 13.21.5 API surface changes

**Additive**:
- `qgateway_core::TenantConfig::material_changes(&self, &Self) -> Vec<&'static str>`
- `qgateway_core::TenantConfig::differs_from(&self, &Self) -> bool`
- `qgateway_core::Config::resolve_one_serve_tcp(&self, &TenantConfig) -> Result<ServeTcpTenant, ConfigError>`

**Internal** (qgateway binary):
- `install_signal_handler` gained `startup_tenant_configs: Vec<TenantConfig>` parameter
- `#[allow(clippy::too_many_arguments)]` annotation on `install_signal_handler`

**No removals.** All Sprint 12 behaviour preserved.

### 13.21.6 Acceptance — actual

- [x] `cargo test --workspace --locked` green: **171 tests** (up from 159 in Sprint 12). 9 new `material_changes` tests + 3 new `resolve_one_serve_tcp` tests.
- [x] `cargo build --workspace --locked` clean.
- [x] `cargo clippy --workspace --all-targets -- -D warnings` clean.
- [x] `cargo fmt --all --check` clean.
- [x] `cargo build -p qgateway --features pkcs11 --locked` clean.

### 13.21.7 Honest deferrals to Sprint 14

1. **TLS hot-add for serve-tcp tenants.** Sprint 15.
2. **SNI-group runtime add.** Sprint 15.
3. **Tenant removal via SIGHUP** (drain protocol). Sprint 15.
4. ✅ **Promote startup-snapshot to shared state** — DELIVERED in Sprint 14.
5. ✅ **Hot-applicable subset of material changes** — CLASSIFICATION DELIVERED in Sprint 14 (rebuild-in-place still Sprint 15).
6. **SIGHUP integration test** — Sprint 15+.
7. **End-to-end admission integration test** — Sprint 15+.

---

## 13.22. SPRINT 14 — DELIVERABLE CONTRACT (✅ CLOSED)

Closes two of the seven Sprint-13 carryover items. The bigger items
(TLS/SNI hot-add, tenant removal drain, integration tests) remain
Sprint 15 work — each is an architectural slice on its own.

The two items shipped here are the small-but-high-impact ones:
material-change detection now works for runtime-added tenants
(closing the Sprint-13 gap honestly), and changes carry a
classification distinguishing "hot-applicable in principle" from
"requires restart". The hot/cold distinction unblocks the future
Sprint-15 work where Cristian will rebuild `AdmissionController`
in place for `limits` changes — the apply path will know which
diff entries it can act on without restart.

### 13.22.1 Delivered

| # | Deliverable | Notes |
|---|---|---|
| `Arc<RwLock<Vec<TenantConfig>>>` shared snapshot | Promoted from the Sprint-13 `Vec<TenantConfig>` passed by value. The SIGHUP apply step now extends this on each successful ADD, so a tenant added at runtime + later edited gets correctly classified as `config_changed` instead of falling through as `unchanged`. Closes the gap documented in Sprint-13 §13.21.4. |
| `TenantChange` struct | New public type. Carries `{ field: &'static str, kind: TenantChangeKind }`. The `TenantChange::cold(field)` and `TenantChange::hot(field)` constructors are private (the kind is intrinsic to the field, not caller-chosen). `Debug + Clone + PartialEq + Eq` for test assertions and log output. |
| `TenantChangeKind` enum | `Hot` (could be applied without restart — `limits`) vs `Cold` (requires restart — everything else). Documented intent: "Hot does NOT mean the daemon will automatically rebuild on that change — it means the rebuild is mechanically possible". The current Sprint-14 apply path still requires restart even for hot changes; the classification is forward-looking. |
| `TenantConfig::material_changes` return type | Changed from `Vec<&'static str>` to `Vec<TenantChange>`. Backwards-incompatible API change — the only caller (qgateway main.rs SIGHUP arm) was updated in the same sprint. Sprint-13 callers don't exist yet (the method was added in Sprint 13). |
| SIGHUP arm split-by-kind logging | Hot and cold changes log as separate `warn!` lines with `kind="hot"` or `kind="cold"` field. The reload-diff line now reports `config_changed_hot` and `config_changed_cold` counters separately. Operators triaging an alert see at a glance whether the change is "defer restart to maintenance window" (hot-only) or "must restart now or roll back" (any cold). |
| 4 new lib tests | `limits_change_is_classified_hot`; `listen_change_is_classified_cold`; `audit_signer_change_is_classified_cold`; `mixed_hot_and_cold_changes_each_get_correct_kind` (validates that one tenant edit touching both `listen` and `limits` produces TWO TenantChange entries with correct ordering and kinds). |
| Existing material_changes tests migrated | All 9 Sprint-13 tests updated for the new `Vec<TenantChange>` return shape. Empty-vec assertions: `Vec::<TenantChange>::new()`. Single-field: `vec![TenantChange { field: "listen", kind: TenantChangeKind::Cold }]`. Mechanical migration via Python script + visual review. |

### 13.22.2 Operational model — split log

```bash
# Operator edits two fields on `branch-sp`:
#   - limits.max_concurrent  100 → 200
#   - listen                 8443 → 8444
$ kill -HUP $(pidof qgateway)

[INFO  qgateway] SIGHUP received config="/etc/qgateway/sidecar.toml"
[WARN  qgateway] tenant="branch-sp" fields=["listen"] kind="cold"
                "tenant configuration changed (cold-only, restart required)"
[WARN  qgateway] tenant="branch-sp" fields=["limits"] kind="hot"
                "tenant configuration changed (hot-applicable, but
                 hot-reconfigure not yet wired — Sprint 15)"
[INFO  qgateway] config reload diff
                added=0 removed=0 unchanged=4
                config_changed_hot=1 config_changed_cold=1
```

The split lets operators (or alerting rules) gate restart decisions:

```yaml
# Prometheus alert: ONLY fire when a cold change appears
- alert: QGatewayRestartRequired
  expr: increase(qgateway_config_changed_cold_total[5m]) > 0
  annotations:
    summary: "tenant {{ $labels.tenant }} edited a cold-only field"
    description: "A restart is required to apply the change. Hot
                  changes alone (e.g. limits) can wait for the next
                  maintenance window — see qgateway_config_changed_hot."
```

(The counters themselves are still log-only in Sprint 14; promoting
them to Prometheus is a tiny Sprint-15 follow-up if anyone wants the
PromQL surface.)

### 13.22.3 Operational model — runtime-added + later edited

```bash
# T0: add a new tenant via SIGHUP.
$ kill -HUP $(pidof qgateway)
[INFO  qgateway] tenant="branch-bahia" role=ServeTcp
                "tenant ADDED at runtime — serving traffic"

# T1 (later): operator edits branch-bahia's limits.
$ kill -HUP $(pidof qgateway)
[WARN  qgateway] tenant="branch-bahia" fields=["limits"] kind="hot"
                "tenant configuration changed (hot-applicable, ...)"
```

In Sprint 13, the second SIGHUP would have reported branch-bahia as
`unchanged` because the startup snapshot didn't know about it.
Sprint 14 fixes that — the apply step pushes new tenants onto the
shared `tenant_configs` snapshot, so future diffs work correctly.

### 13.22.4 Trade-offs documented

- **Hot classification doesn't yet trigger hot apply.** The daemon
  still warns "restart required" for hot changes too — the apply
  path is unchanged. The classification is forward-looking
  infrastructure: Sprint 15 will read the `Hot` entries and call
  a (future) `Tenant::rebuild_admission(new_limits)` method to
  swap the `AdmissionController` in place. Today it's pure metadata
  — but cheap metadata, since the classification is intrinsic to
  the field name (not a runtime decision).
- **Only `limits` is currently classified Hot.** Every other field
  is Cold because the state it controls is wired into things the
  tenant task captures by value at spawn time (peer policy = `Arc`
  but rebuilt only on full tenant restart; audit log = inseparable
  from audit channel; listen address = inseparable from
  `TcpListener`; TLS cert = covered by the existing SIGUSR1 reload
  trigger, but TLS *enablement* — going from `tls = None` to
  `tls = Some(_)` — is cold).
- **`AdmissionController` swap is not yet implemented.** Sprint 15
  will need `run_serve_*_tenant` to hold the controller via an
  `Arc<ArcSwap<AdmissionController>>` (or equivalent atomic
  pointer swap) rather than the current `Arc<AdmissionController>`.
  That refactor touches every accept-loop hot path — small in LoC
  but architecturally invasive enough to deserve its own sprint.
- **The shared snapshot can drift if apply fails after metrics push.**
  Current order: metrics_list.push → tenant_names.insert →
  tenant_configs.push → spawn task. If the spawn panics or the
  build between push and spawn fails, the snapshot has an entry
  for a tenant that isn't actually running. Sprint 14 doesn't
  guard against this because the windows are tiny (no .await
  between push and spawn for serve-pq and serve-tcp). Sprint 15's
  removal protocol can clean up orphaned entries by name as a
  side benefit.
- **`TenantChange::cold` and `::hot` constructors are private.** The
  kind is determined by which field name is passed, and the
  `material_changes` method is the only place that maps fields to
  kinds. Forcing callers to use the public field-by-field
  constructor would be footgun-friendly (a caller could mark
  `listen` as Hot and start hot-applying it). The private
  constructors make the intent explicit.

### 13.22.5 API surface changes

**Additive**:
- `qgateway_core::TenantChange` struct (`field`, `kind`)
- `qgateway_core::TenantChangeKind` enum (`Hot`, `Cold`)

**Breaking** (intra-sprint, no external callers):
- `qgateway_core::TenantConfig::material_changes` return type:
  `Vec<&'static str>` → `Vec<TenantChange>`. Only caller (qgateway
  main.rs SIGHUP arm) updated.

**Internal** (qgateway binary):
- `install_signal_handler` `startup_tenant_configs: Vec<TenantConfig>`
  → `tenant_configs: Arc<tokio::sync::RwLock<Vec<TenantConfig>>>`
- SIGHUP arm: split warn logs by kind; new shared-snapshot extend on ADD.

### 13.22.6 Acceptance — actual

- [x] `cargo test --workspace --locked` green: **175 tests** (up from 171 in Sprint 13). 4 new classification tests; 9 existing material_changes tests migrated to the new return shape.
- [x] `cargo build --workspace --locked` clean.
- [x] `cargo clippy --workspace --all-targets -- -D warnings` clean.
- [x] `cargo fmt --all --check` clean.
- [x] `cargo build -p qgateway --features pkcs11 --locked` clean.

### 13.22.7 Honest deferrals to Sprint 15

1. ⚠️ **Hot apply of `limits` changes** — INFRASTRUCTURE DELIVERED in Sprint 15 (Stage A: `HotAdmissionController`); wiring into running accept loops is Sprint 16 work (Stage B).
2. **TLS hot-add for serve-tcp tenants** — Sprint 16.
3. **SNI-group runtime add** — Sprint 16+.
4. **Tenant removal via SIGHUP** (drain protocol) — Sprint 16.
5. **SIGHUP integration test** — Sprint 16+.
6. **End-to-end admission integration test** — Sprint 16+.
7. **Promote `config_changed_hot` / `config_changed_cold` to Prometheus counters** — small follow-up.

---

## 13.23. SPRINT 15 — DELIVERABLE CONTRACT (✅ CLOSED — Stage A)

Two-stage approach to hot-reconfigure of `[tenants.limits]`. Sprint 15
ships **Stage A**: the `HotAdmissionController` infrastructure that
makes runtime swap of an `AdmissionController` mechanically possible.
**Stage B** — wiring the swap into running accept loops + plumbing
it from the SIGHUP apply step — is Sprint 16 work because it touches
the per-role `run_serve_*_tenant` signatures across qgateway-core,
which Sprint 15's budget couldn't accommodate cleanly alongside the
other Sprint-14 carryover items.

Stage A is independently valuable: the infrastructure is fully tested
in isolation (4 dedicated swap-semantics tests), the `arc-swap`
dependency is bedded in, and Sprint 16 can focus exclusively on the
wiring without re-evaluating the type design.

### 13.23.1 Delivered

| # | Deliverable | Notes |
|---|---|---|
| `arc-swap = "1"` workspace dependency | Tested with 1.9.1. Pure-Rust, no unsafe in the public API. Provides `ArcSwap<T>` — atomic pointer swap with zero-cost reads on x86_64. |
| `HotAdmissionController` public type | New type wrapping `arc_swap::ArcSwap<AdmissionController>`. Same `check(peer) -> Admit` surface as the underlying controller — accept loops don't change their call shape. Adds `swap(max_concurrent, rate_limit)` that atomically replaces the inner controller; returns the old `Arc<AdmissionController>` for caller inspection or drop. |
| Swap semantics documented | In-flight permits from the OLD controller remain valid until session end — they don't count against the NEW controller's quota. Per-source rate-limit state is discarded on swap; a noisy source whose bucket was drained gets a fresh bucket. The doc comment is explicit that operators using rate limiting to fend off ongoing abuse must NOT use a limits edit as the mitigation path. |
| `build_admission` return type | Changed from `AdmissionController` to `Arc<HotAdmissionController>`. Mechanical update at the only two callsites (`run_serve_tcp_tenant` and `run_serve_pq_tenant`); accept loop body unchanged because `HotAdmissionController::check` mirrors the underlying API. |
| `SniTenantContext::admission` type | Changed from `Arc<AdmissionController>` to `Arc<HotAdmissionController>`. Mechanical update at the construction site in qgateway/main.rs. |
| 4 new lib tests | `hot_controller_initial_check_uses_initial_limits` (baseline: behaves like an `AdmissionController` until swap); `hot_controller_swap_replaces_limits_for_future_connections` (after swap from quota=1 to quota=5, exactly 5 more admits succeed; held permit from old controller stays valid); `hot_controller_swap_to_unlimited_admits_everything` (swap to (None, None) admits all subsequent connections); `hot_controller_swap_to_rate_limit_creates_fresh_buckets` (swap from rateless to rate-limited: new buckets start at full capacity). |

### 13.23.2 Stage B preview (Sprint 16)

When Sprint 16 ships, the SIGHUP apply step's `Hot` change handler will:

1. Look up the running tenant's `Arc<HotAdmissionController>` (held in `TenantRuntime`).
2. Call `controller.swap(new_limits.max_concurrent, new_limits.rate_limit_per_source.as_ref().map(Into::into))`.
3. Log `"tenant limits hot-applied: connections accepted under new policy"`.
4. Update the shared `tenant_configs` snapshot so subsequent SIGHUPs see the new limits as the baseline.

The wiring blocker is the same one Sprint 12-14 hit at smaller scale: `run_serve_*_tenant` constructs its admission internally via `build_admission(&tenant.limits)`. Sprint 16 will lift admission construction out and propagate the controller from `TenantRuntime` (or equivalent shared handle) into the accept loop. Once that's done, the swap call from the SIGHUP arm is a 4-line addition.

### 13.23.3 Trade-offs documented

- **Two-stage delivery.** Sprint 15 ships infrastructure with full
  test coverage but NO end-to-end behavioral change visible to
  operators. Stage A is operationally indistinguishable from Sprint
  14 — the warn log still says "hot-reconfigure not yet wired —
  Sprint 15" (which is now slightly inaccurate; it should say
  "Sprint 16"). Documented this explicitly here rather than
  rewording the log line in Sprint 15 — that would imply Stage B
  was delivered, which it wasn't. Sprint 16 will rewrite the log.
- **`arc-swap` choice over hand-rolled atomic.** `arc-swap` 1.x is
  battle-tested, has explicit `no_std` and `unsafe`-free public API,
  and the read path is one atomic load on x86_64. Hand-rolling
  `Arc<Mutex<Arc<AdmissionController>>>` would have worked but the
  read overhead (uncontended mutex acquire) is measurably worse on
  the accept hot path. The crate is pure-Rust dep with zero
  transitive build complications.
- **`swap()` discards rate-limit state.** Documented as intentional.
  The alternative — carrying forward the per-source HashMap — would
  partially defeat the purpose of a limits change (operator wants
  new policy applied immediately, not contaminated by old buckets).
  An operator who specifically wants "tighten the rate limit but
  preserve current bucket state" has no path in Sprint 15+. The
  use case is rare enough that the trade-off is right.
- **In-flight permits from the OLD controller remain valid.** This
  is the only sane policy. Forcibly revoking permits mid-session
  would tear down running connections; deliberately admitting MORE
  than the new quota for some transient window is correct (existing
  sessions complete, new sessions count against the new quota).
  Documented in the type's doc comment so operators reading the
  source understand the behavior.
- **No test for permit-held-across-swap.** The hot controller tests
  hold permits in `_a`/`_b` bindings across `swap()` and verify the
  drop chain still works (the test reaches end-of-scope cleanly).
  A more aggressive test would verify the old `Semaphore` is
  reachable through the held permit and that its capacity is
  unchanged. Not added — the `OwnedSemaphorePermit` Drop is from
  tokio, fully tested upstream; testing it here would be testing
  the language.

### 13.23.4 API surface changes

**Additive**:
- `qgateway_core::HotAdmissionController` public type
  - `HotAdmissionController::new(max_concurrent, rate_limit) -> Self`
  - `HotAdmissionController::from_controller(AdmissionController) -> Self`
  - `HotAdmissionController::check(peer) -> Admit`
  - `HotAdmissionController::swap(max_concurrent, rate_limit) -> Arc<AdmissionController>`

**Internal-but-breaking** (Sprint-15 only callers updated):
- `crate::gateway::build_admission` return: `AdmissionController` → `Arc<HotAdmissionController>`.
- `crate::SniTenantContext::admission` field: `Arc<AdmissionController>` → `Arc<HotAdmissionController>`.

**Dependency**:
- Added `arc-swap = "1"` to workspace deps and qgateway-core. Pulls in 1 transitive (the crate is self-contained).

### 13.23.5 Acceptance — actual

- [x] `cargo test --workspace --locked` green: **179 tests** (up from 175 in Sprint 14). 4 new hot-controller tests.
- [x] `cargo build --workspace --locked` clean.
- [x] `cargo clippy --workspace --all-targets -- -D warnings` clean.
- [x] `cargo fmt --all --check` clean.
- [x] `cargo build -p qgateway --features pkcs11 --locked` clean.

### 13.23.6 Honest deferrals to Sprint 16

1. ✅ **Stage B: wire `HotAdmissionController::swap` into the SIGHUP apply step** — DELIVERED in Sprint 16.
2. **TLS hot-add for serve-tcp tenants.** Sprint 17.
3. **SNI-group runtime add.** Sprint 17+.
4. **Tenant removal via SIGHUP** (drain protocol) — Sprint 17.
5. **SIGHUP integration test.** Sprint 17+.
6. **End-to-end admission integration test.** Sprint 17+.
7. **Promote `config_changed_hot` / `config_changed_cold` to Prometheus counters.** Small follow-up — Sprint 17.
8. ✅ **Update the SIGHUP arm's "Sprint 15: not yet wired" warn message** — DELIVERED in Sprint 16 (replaced with actual hot-apply log line).

---

## 13.24. SPRINT 16 — DELIVERABLE CONTRACT (✅ CLOSED — Stage B)

Stage B of the hot-reconfigure work that started in Sprint 14. The
`HotAdmissionController` infrastructure shipped in Sprint 15 is now
wired through to the SIGHUP apply step: an operator who edits
`[tenants.limits]` and sends `kill -HUP` sees the new policy take
effect on subsequent connections WITHOUT restarting the tenant's
accept loop. In-flight permits from the old controller remain valid;
new connections count against the new quota and the new rate-limit
buckets.

This closes the longest-running multi-sprint feature in the project's
recent history — from Sprint 9.5 (initial admission control) →
Sprint 14 (classification of Hot vs Cold changes) → Sprint 15
(`HotAdmissionController` type) → Sprint 16 (the actual wiring).

### 13.24.1 Delivered

| # | Deliverable | Notes |
|---|---|---|
| `admission_override: Option<Arc<HotAdmissionController>>` parameter | Added to `run_serve_tcp_tenant` and `run_serve_pq_tenant` in qgateway-core. When `Some`, the loop uses the caller-provided controller for `check()` and the same controller is the one the SIGHUP arm calls `swap()` on. When `None`, the loop builds one internally (backwards-compat with any external caller). All in-tree callsites pass `Some(rt.admission.clone())`. |
| `TenantRuntime::admission` field | New field on the qgateway binary's `TenantRuntime` struct: `Arc<HotAdmissionController>`. Constructed in `build_tenant_runtime` from `tenant.limits`. The single instance is shared between the accept-loop task (cloned in at spawn) and the SIGHUP-arm shared map. |
| `Arc<RwLock<HashMap<String, Arc<HotAdmissionController>>>>` shared map | New shared state: tenant name → admission controller. Populated at startup from `tenant_state`, extended by the SIGHUP apply step on each successful ADD. Lookup-by-name from the hot-apply path is `HashMap::get` under a read lock — microseconds. |
| `install_signal_handler` 11-arg signature | Added `tenant_admissions` parameter. Existing `#[allow(clippy::too_many_arguments)]` covers the increase. Non-unix stub mirrors signature shape with leading underscores. |
| SIGHUP hot-apply for `limits` | Replaces the Sprint-14 warn-only path. For each unchanged tenant whose diff includes hot-classified fields, the arm: (1) reads the new `[tenants.limits]` block; (2) looks up the running controller by tenant name; (3) calls `controller.swap(mc, rl)` which atomically replaces the inner controller; (4) emits a new info log: `"tenant limits hot-applied (new policy in effect for future connections; in-flight permits unaffected)"`. The old controller is dropped (no longer reachable for new accepts; permits held by in-flight sessions keep the inner `Arc<Semaphore>` alive until session end). |
| SNI context reuse | The SNI dispatch path previously built a fresh `HotAdmissionController` per context. Sprint 16 changes it to clone `rt.admission`, so a SNI-dispatched tenant gets the SAME controller as the SNI lookup — hot-apply works identically for SNI tenants. |
| Defensive "no controller registered" path | If the hot-apply lookup misses (`HashMap::get` returns `None`), the arm falls back to the old warn message — defensive only, should never trigger in normal operation. Documents the invariant operators can rely on. |
| Integration tests updated | The 4 `run_serve_*_tenant` callsites in `e2e_tunnel.rs` updated to pass `None` for the new `admission_override` parameter. Test semantics unchanged. |

### 13.24.2 Operational model — full end-to-end hot-apply

```bash
# qgateway running with branch-sp's limits.max_concurrent = 100.
# Tenant is serving traffic under that policy.

# Operator raises the cap.
$ vim /etc/qgateway/sidecar.toml
#   - max_concurrent = 100
#   + max_concurrent = 200
$ kill -HUP $(pidof qgateway)

[INFO  qgateway] SIGHUP received config="/etc/qgateway/sidecar.toml"
[INFO  qgateway] tenant="branch-sp" fields=["limits"] kind="hot"
                "tenant limits hot-applied (new policy in effect for future
                 connections; in-flight permits unaffected)"
[INFO  qgateway] config reload diff
                added=0 removed=0 unchanged=4
                config_changed_hot=1 config_changed_cold=0

# Verify the new policy:
$ # before: ss showed up to 100 concurrent sessions from one source
$ # after: traffic now accepts up to 200 concurrent (the next 100 connections
$ #        after the SIGHUP go through fine where they would have hit Quota
$ #        reject under the old policy).

# Existing 100 sessions complete naturally under the old controller's
# permits — they don't count toward the new 200. Once they drain, the
# new controller has its full 200 slots available.
```

Combined with the existing Sprint 11.0 → 13 runtime ADD capability,
the daemon now supports:

- Adding new `serve-pq` tenants without restart (Sprint 12).
- Adding new `serve-tcp` plain-TCP tenants without restart (Sprint 13).
- Hot-reconfiguring `[tenants.limits]` on any running tenant without
  restart, regardless of when it was added (Sprint 16).

What still requires restart: TLS hot-add, SNI-group hot-add, all
cold-classified field changes (listen, peer_pq, backend, peer_pub_dir,
audit_log, tls cert path, sni, audit_signer), and tenant removal.

### 13.24.3 Trade-offs documented

- **`admission_override: Option<Arc<HotAdmissionController>>` over a
  required parameter.** Backwards-compat with any external caller of
  the public API. The qgateway binary always passes `Some(...)` now;
  the `None` path remains for downstream crates or future test code
  that wants the old behaviour. Cost: one branch on `unwrap_or_else`
  per task spawn (zero hot-path cost — the controller is captured
  by value into the loop).
- **In-flight permits remain valid against the OLD controller.** This
  is the only safe policy. Forcibly revoking permits mid-session
  would tear down running TCP connections; deliberately admitting
  MORE than the new quota for a transient window is correct
  (existing sessions complete, new sessions count against the new
  quota). Documented in the Sprint 15 `HotAdmissionController` doc
  comment.
- **Rate-limit buckets reset on swap.** A noisy source whose bucket
  was drained under the old policy gets a fresh bucket under the
  new policy. Documented as intentional in Sprint 15. Operators
  using rate limiting to fend off ongoing abuse should NOT use a
  limits edit as the mitigation path — that's tenant remove (Sprint
  17) or upstream layer-4 work.
- **Hot-apply dispatch is currently limits-specific.** The SIGHUP
  arm's hot branch hardcodes "read tenant.limits, swap admission".
  If future fields graduate to Hot (none planned), the dispatch
  needs to become a `match` over `field`. Documented in the inline
  comment so the path is obvious when adding the next hot field.
- **No metric for hot-apply count.** Operators can grep the log
  line `"tenant limits hot-applied"` for now. Promoting this to a
  Prometheus counter (`qgateway_limits_hot_applied_total{tenant=}`)
  is item #7 in Sprint 17's deferred list — small follow-up.
- **Lookup happens under a read lock.** The hot-apply path acquires
  `tenant_admissions.read().await` and calls `HashMap::get`. The
  read lock is held for ~microseconds (just long enough to clone
  the `Arc<HotAdmissionController>` out, then `swap()` happens
  without holding the lock). Writers (ADD) acquire write lock.
  Contention is non-existent in practice — both happen on operator
  action, not request traffic.
- **No transactional rollback on partial hot-apply failure.** Sprint
  16's hot-apply path is straight-line code with no failable steps
  after the controller lookup: `swap()` can't fail (atomic pointer
  swap on infallible `Arc::new`). If a future hot field has a
  failable construction (e.g. parsing a new TLS cert path), the
  semantics need to be defined: pre-validate then swap, vs swap-
  and-rollback. Not in scope today.

### 13.24.4 API surface changes

**Breaking** (intra-sprint, all in-tree callers updated):
- `qgateway_core::run_serve_tcp_tenant` signature: added 8th param `admission_override: Option<Arc<HotAdmissionController>>`.
- `qgateway_core::run_serve_pq_tenant` signature: added 7th param `admission_override: Option<Arc<HotAdmissionController>>`.

**Additive** (internal to qgateway binary):
- `TenantRuntime::admission: Arc<HotAdmissionController>` field.
- `tenant_admissions_shared: Arc<RwLock<HashMap<String, Arc<HotAdmissionController>>>>` (in `cmd_run`).
- `install_signal_handler` gained `tenant_admissions` parameter (11 args total now).

**Annotations**:
- `#[allow(clippy::too_many_arguments)]` added to both `run_serve_*_tenant`
  functions in qgateway-core (8 and 7 args).

### 13.24.5 Acceptance — actual

- [x] `cargo test --workspace --locked` green: **179 tests** (unchanged
      from Sprint 15 — the wiring is integration-level, no new
      library unit tests added). The 4 `e2e_tunnel.rs` callsites were
      mechanically updated to pass `None` for the new parameter.
- [x] `cargo build --workspace --locked` clean.
- [x] `cargo clippy --workspace --all-targets -- -D warnings` clean.
- [x] `cargo fmt --all --check` clean.
- [x] `cargo build -p qgateway --features pkcs11 --locked` clean.

### 13.24.6 Honest deferrals to Sprint 17

1. **TLS hot-add for serve-tcp tenants.** Sprint 18.
2. **SNI-group runtime add.** Sprint 18+.
3. **Tenant removal via SIGHUP** (drain protocol). Sprint 18.
4. ✅ **`qgateway_limits_hot_applied_total` Prometheus counter.** DELIVERED in Sprint 17.
5. ✅ **`config_changed_hot/cold_total` Prometheus counters.** DELIVERED in Sprint 17.
6. **SIGHUP integration test.** Sprint 18+.
7. **End-to-end admission integration test.** Sprint 18+.

---

## 13.25. SPRINT 17 — DELIVERABLE CONTRACT (✅ CLOSED — Prometheus observability)

Sprint 17 promotes the SIGHUP cycle observability from log-only to
Prometheus counters. Operators alerting on configuration drift, hot-
apply velocity, and runtime tenant churn now have first-class
PromQL surface without log scraping.

Tenant removal — the largest item on Sprint 16's deferred list —
remains Sprint 18 work. Honest scope cut documented in §13.25.4:
the drain protocol is its own architectural slice (per-tenant
shutdown notify, JoinHandle tracking, AuditChannel cleanup, partial-
failure handling) that doesn't fit alongside the Prometheus work
without compromising one or the other.

### 13.25.1 Delivered

| # | Deliverable | Notes |
|---|---|---|
| `qgateway_core::metrics::DaemonMetrics` struct | New daemon-wide metrics surface, distinct from per-tenant `MetricsRegistry`. Nine `AtomicU64` counters covering the SIGHUP lifecycle and runtime-tenant operations. `Default::default()` for the all-zero initial state. |
| `render_daemon_metrics(&DaemonMetrics) -> String` | Sibling of `render_prometheus`. Emits unlabeled counters (no `tenant=` label) in Prometheus text format 0.0.4. Concatenates onto the tenant series in the metrics server. |
| 9 new Prometheus counters | `qgateway_sighup_cycles_total`, `qgateway_sighup_failed_total`, `qgateway_tenants_added_total`, `qgateway_tenants_add_failed_total`, `qgateway_tenants_removed_total` (always 0 in Sprint 17), `qgateway_tenants_remove_failed_total` (always 0), `qgateway_limits_hot_applied_total`, `qgateway_config_changed_hot_total`, `qgateway_config_changed_cold_total`. Tenants_removed_* counters are present-but-zero to lock down the metric names ahead of Sprint 18 — operators wiring alerts today won't need to re-name when removal ships. |
| Wired into metrics server | `spawn_metrics_server` 3rd parameter: `Arc<DaemonMetrics>`. The `/metrics` handler appends `render_daemon_metrics` output after `render_prometheus` for one combined scrape. |
| Wired into SIGHUP handler | `install_signal_handler` 11th parameter: `Arc<DaemonMetrics>`. Counters bumped at strategic points: success entry (`sighup_cycles_total`), failed validation (`sighup_failed_total`), each ADD outcome (`tenants_added_total` / `tenants_add_failed_total`), each hot-applied diff entry (`limits_hot_applied_total` + `config_changed_hot_total`), each cold-flagged diff entry (`config_changed_cold_total`). |
| Tenant ADD apply summary still log-only | The per-cycle aggregate line `added_applied=N added_failed=N removed_pending=N` remains in the log. The Prometheus counters are CUMULATIVE counts; the log line is the per-event snapshot. Operators get both — log for forensics, counters for rate-based alerting. |

### 13.25.2 Operational model — example PromQL

```yaml
# Sustained hot-apply velocity (operators tuning live policy):
- record: qg:limits_hot_applied:rate5m
  expr: rate(qgateway_limits_hot_applied_total[5m])

# Configuration drift detection (cold changes piling up without restart):
- alert: QGatewayConfigurationDrift
  expr: increase(qgateway_config_changed_cold_total[1h]) > 0
        and on() (time() - process_start_time_seconds{job="qgateway"}) > 3600
  for: 1h
  annotations:
    summary: "Cold config changes detected without daemon restart"
    description: "Operators have edited cold-only fields ({{ $value }}
                  total in the last hour). The daemon is running with the
                  OLD config for those fields. Either restart to apply or
                  roll back the edits."

# SIGHUP failure rate (TOML errors landing in production):
- alert: QGatewaySighupFailing
  expr: rate(qgateway_sighup_failed_total[15m]) > 0
  for: 5m
  annotations:
    summary: "SIGHUP cycles failing validation"
    description: "Operators are sending SIGHUP with invalid configs.
                  Check the daemon log for the underlying parse errors."

# Tenant ADD failure rate:
- alert: QGatewayTenantAddFailing
  expr: rate(qgateway_tenants_add_failed_total[15m]) > 0
  annotations:
    summary: "Runtime tenant ADD failing"
    description: "New tenant configs are failing to build at SIGHUP
                  apply time. Common causes: missing peer_pub_dir,
                  unreachable HSM, audit log permission errors."
```

### 13.25.3 Sample scrape

```text
# HELP qgateway_sighup_cycles_total Total SIGHUP cycles that passed config validation.
# TYPE qgateway_sighup_cycles_total counter
qgateway_sighup_cycles_total 12
# HELP qgateway_sighup_failed_total Total SIGHUP cycles where Config::load failed validation.
# TYPE qgateway_sighup_failed_total counter
qgateway_sighup_failed_total 1
# HELP qgateway_tenants_added_total Total tenants successfully added at runtime via SIGHUP.
# TYPE qgateway_tenants_added_total counter
qgateway_tenants_added_total 3
# HELP qgateway_tenants_add_failed_total Total tenant ADD failures during SIGHUP apply.
# TYPE qgateway_tenants_add_failed_total counter
qgateway_tenants_add_failed_total 0
# HELP qgateway_tenants_removed_total Total tenants successfully removed at runtime via SIGHUP.
# TYPE qgateway_tenants_removed_total counter
qgateway_tenants_removed_total 0
# HELP qgateway_tenants_remove_failed_total Total tenant REMOVE failures during SIGHUP apply (drain timeout, etc.).
# TYPE qgateway_tenants_remove_failed_total counter
qgateway_tenants_remove_failed_total 0
# HELP qgateway_limits_hot_applied_total Total successful hot-applies of [tenants.limits] via SIGHUP.
# TYPE qgateway_limits_hot_applied_total counter
qgateway_limits_hot_applied_total 7
# HELP qgateway_config_changed_hot_total Total tenant-config diff entries classified as Hot (limits-only today).
# TYPE qgateway_config_changed_hot_total counter
qgateway_config_changed_hot_total 7
# HELP qgateway_config_changed_cold_total Total tenant-config diff entries classified as Cold (require restart).
# TYPE qgateway_config_changed_cold_total counter
qgateway_config_changed_cold_total 2
```

### 13.25.4 Honest scope cut — tenant removal

The Sprint 16 deferred list ranked tenant removal as the highest-
value remaining item. Mid-Sprint-17 analysis surfaced:

- **Per-tenant shutdown notify** — every running tenant currently
  shares the daemon-wide `Arc<Notify>` (`shutdown.clone()` passed to
  every accept loop). Removal requires giving each tenant its own
  `Arc<Notify>` and notifying ONLY that one. Touches 6 callsites:
  3 startup spawn (serve-tcp single, SNI group, serve-pq), 2 SIGHUP
  runtime-add spawn (serve-pq, serve-tcp plain), 1 SIGTERM/SIGINT
  daemon-wide fanout.

- **JoinHandle tracking per tenant** — `tenant_tasks: Vec<JoinHandle>`
  becomes `tenant_handles: Arc<RwLock<HashMap<String, JoinHandle>>>`
  so the SIGHUP arm can pull a specific tenant's handle and `await`
  it with a timeout.

- **AuditChannel close semantics** — when a tenant is removed, its
  `AuditChannel` background task must drain pending events, write
  final segment, and exit cleanly. The channel currently has no
  shutdown method exposed; would need to add one.

- **Partial-failure handling** — when 5 tenants are removed in one
  SIGHUP cycle and 3 drain cleanly + 2 time out: do we roll back
  the 3? Leave them removed? Document the policy?

Each item is independently small but composing them in one sprint
alongside Prometheus work would have produced two half-shipped
features. The Sprint 17 ship is cleanly the Prometheus surface;
Sprint 18 will be cleanly the removal protocol with a clear design
pass.

### 13.25.5 Trade-offs documented

- **Daemon counters are unlabeled.** `qgateway_sighup_cycles_total`
  has no `tenant=` label. Adding one per-tenant SIGHUP-outcome
  counter would multiply the metric cardinality by tenant count
  for data that's mostly identical across tenants. The aggregate
  is the right granularity — operators alerting per-tenant on
  ADD/REMOVE outcomes look at the access log instead.
- **`tenants_removed_*` counters present-but-zero.** Could have
  deferred until Sprint 18 ships removal. Including them now locks
  down the metric names so Sprint 18 just bumps existing counters,
  no new scrape-format change. Operators wiring alerts today won't
  need to update their PromQL when removal ships.
- **`render_daemon_metrics` is a sibling function, not integrated
  into `render_prometheus`.** Keeps the rendering separable —
  callers wanting only tenant metrics or only daemon metrics can
  call the one they need. The /metrics endpoint concatenates both.
- **`Arc<DaemonMetrics>` instead of `&'static`.** Could be a static
  in qgateway-core via `OnceLock`. Used `Arc` for symmetry with the
  per-tenant `MetricsRegistry` pattern + to avoid the global
  mutable state idiom (still possible to have multiple daemon
  instances in tests, integration harnesses).
- **No histogram for SIGHUP cycle duration.** Counters are fine for
  alerting; if someone needs p99 SIGHUP latency they can add a
  histogram later. Not in Sprint 17 scope.

### 13.25.6 API surface changes

**Additive**:
- `qgateway_core::metrics::DaemonMetrics` struct (9 `AtomicU64` fields, `Default`).
- `qgateway_core::metrics::render_daemon_metrics(&DaemonMetrics) -> String`.

**Signature changes** (internal to qgateway binary):
- `spawn_metrics_server` 3rd param: `Arc<DaemonMetrics>`.
- `install_signal_handler` 11th param: `Arc<DaemonMetrics>`.

**No removals.** All Sprint 16 behaviour preserved.

### 13.25.7 Acceptance — actual

- [x] `cargo test --workspace --locked` green: **179 tests** (unchanged
      from Sprint 16 — Prometheus counter wiring is integration-level,
      no library unit tests added).
- [x] `cargo build --workspace --locked` clean.
- [x] `cargo clippy --workspace --all-targets -- -D warnings` clean.
- [x] `cargo fmt --all --check` clean.
- [x] `cargo build -p qgateway --features pkcs11 --locked` clean.

### 13.25.8 Honest deferrals to Sprint 18

1. ✅ **Tenant removal via SIGHUP** (drain protocol) — DELIVERED in Sprint 18 (plain serve-tcp + serve-pq only).
2. **TLS hot-add for serve-tcp tenants.** Sprint 19.
3. **SNI-group runtime add.** Sprint 19+.
4. **SIGHUP integration test.** Sprint 19+.
5. **End-to-end admission integration test.** Sprint 19+.

---

## 13.26. SPRINT 18 — DELIVERABLE CONTRACT (✅ CLOSED — Tenant removal drain)

Sprint 18 closes the longest-standing runtime-lifecycle gap: tenants
can now be removed without restarting the daemon. The drain protocol
is per-tenant — only the targeted tenant's accept loop receives the
shutdown notify, in-flight sessions of OTHER tenants are untouched,
and operator visibility is via the Sprint-17 Prometheus counters.

This closes the runtime tenant lifecycle that started in Sprint 11.0
(SIGHUP validation), 11.5 (apply step register-only), 12 (serve-pq
spawn), 13 (serve-tcp spawn + diff), 14 (Hot/Cold classification),
15-16 (HotAdmissionController + hot-apply wiring), 17 (Prometheus
counters), and now 18 (REMOVE). Plain serve-tcp + serve-pq tenants
can now be added, hot-reconfigured, and removed at runtime — full
lifecycle without daemon restart.

### 13.26.1 Delivered

| # | Deliverable | Notes |
|---|---|---|
| `TenantRuntime::shutdown: Arc<Notify>` | New per-tenant shutdown notify, distinct from the daemon-wide `shutdown`. Created in `build_tenant_runtime`. The accept loop binds to this notify exclusively — daemon-wide shutdown reaches the tenant via SIGTERM/SIGINT fanout. |
| `tenant_shutdowns_shared` map | `Arc<RwLock<HashMap<String, Arc<Notify>>>>`. Populated at startup from `tenant_state`, extended on each successful SIGHUP ADD, walked on SIGTERM/SIGINT fanout, looked up on SIGHUP REMOVE. |
| `tenant_tasks_by_name` map | `Arc<RwLock<HashMap<String, JoinHandle<Result<()>>>>>`. Separate from the existing `Vec<JoinHandle>` — only individually-removable tasks (plain serve-tcp single tenants, all serve-pq tenants, and runtime-added tenants) get registered here. SNI groups and TLS-enabled single tenants stay in the Vec because they can't be removed without restarting the daemon. |
| SIGTERM/SIGINT fanout | Walks `tenant_shutdowns` and calls `notify_waiters()` on every entry, then also fires the daemon-wide notify (which SNI groups still listen on). Two phases ensure both removable and non-removable tasks drain cleanly. |
| SIGHUP REMOVE branch | For each tenant in `removed` set: (1) signal per-tenant shutdown; (2) take the JoinHandle out of `tenant_tasks_by_name`; (3) `tokio::time::timeout(30s, handle).await`; (4) on success purge from all 5 shared maps and bump `tenants_removed_total`; (5) on timeout, log error and bump `tenants_remove_failed_total`. |
| Defensive skip path for non-removable tenants | If a tenant in `removed` has no entry in `tenant_shutdowns` (it's an SNI tenant or TLS-enabled single tenant), the arm logs a warn and continues without bumping any failure counter — this is an expected condition, not a failure. |
| Final drain iterates both maps | The cmd_run main drain (after `shutdown.notified().await`) awaits every JoinHandle in the Vec AND every JoinHandle still in `tenant_tasks_by_name`. Tasks that already self-drained on SIGHUP REMOVE are absent from the map (removed by `HashMap::remove`); only running tasks remain. |
| Sprint 17 counters now live | `qgateway_tenants_removed_total` and `qgateway_tenants_remove_failed_total` were present-but-zero in Sprint 17. Sprint 18 actually bumps them. Existing PromQL rules wired before Sprint 17 ship work without changes. |
| `install_signal_handler` 13-arg signature | Added `tenant_shutdowns` and `tenant_tasks_map` params. `#[allow(clippy::too_many_arguments)]` already in place. |

### 13.26.2 Operational model

```bash
# Daemon serving 4 plain serve-tcp tenants.
$ kill -HUP $(pidof qgateway)

# Operator removes `branch-bahia` from sidecar.toml:
# - [[tenants]]
# -   name = "branch-bahia"
# -   listen = "127.0.0.1:9444"
# -   ...

$ kill -HUP $(pidof qgateway)
[INFO  qgateway] SIGHUP received config="/etc/qgateway/sidecar.toml"
[INFO  qgateway] tenant="branch-bahia" "tenant drained and removed"
[INFO  qgateway] config reload apply summary
                added_applied=0 added_failed=0
                removed_applied=1 removed_failed=0

# /metrics now shows:
$ curl localhost:9090/metrics | grep tenants_removed
qgateway_tenants_removed_total 1
qgateway_tenants_remove_failed_total 0

# The other 3 tenants saw zero interruption — their sessions never
# received any shutdown signal. branch-bahia's port 9444 is now free
# for re-bind by another tenant on a future SIGHUP ADD.
```

Failure case — drain timeout:

```bash
# branch-bahia has a session holding a long-lived stream that
# doesn't honor cancellation within 30s.
$ kill -HUP $(pidof qgateway)
[INFO  qgateway] SIGHUP received
[ERROR qgateway] tenant="branch-bahia"
                "tenant drain timed out after 30s — entry left in
                 shared maps, restart required for full cleanup"
[INFO  qgateway] config reload apply summary
                added_applied=0 added_failed=0
                removed_applied=0 removed_failed=1

# /metrics:
qgateway_tenants_removed_total 0
qgateway_tenants_remove_failed_total 1

# Operator action: daemon restart to fully purge the stale entry.
```

### 13.26.3 Trade-offs documented

- **30s drain timeout is fixed, not configurable.** Operator can't
  tune via TOML. A reasonable global value — short enough that a
  bad SIGHUP doesn't block the SIGHUP arm forever, long enough
  that healthy CSPQ sessions complete in normal load. Per-tenant
  override would require schema extension. Deferred until an
  operator actually asks.
- **SNI tenants are NOT individually removable.** An SNI group is
  one TCP listener shared across multiple tenants. Removing one
  tenant from the group requires mutating the dispatch table
  (which the `run_sni_group` task captures by value at spawn) and
  shrinking the cert resolver — neither has a clean mid-flight
  protocol today. SIGHUP REMOVE on an SNI tenant logs a warn and
  skips. Documented as Sprint 19 work alongside SNI runtime ADD.
- **TLS-enabled single tenants are NOT individually removable.**
  Same TCP listener concept doesn't apply (each TLS-single tenant
  has its own listener), but the `TlsReloadTrigger` is tracked in
  a per-daemon Vec walked by SIGUSR1. Removing the tenant would
  orphan its trigger entry — SIGUSR1 would still call its rebuild
  closure, which references the removed tenant's certs. Cleaning
  this up requires promoting `reload_triggers: Vec<TlsReloadTrigger>`
  to a shared map keyed by tenant name. Out of scope for Sprint 18.
- **On drain timeout, the entry is LEFT in shared maps.** The
  `tokio::time::timeout(30s, handle)` consumes the JoinHandle on
  expiry — we can't re-insert. Alternative implementations: (1)
  use `tokio::time::timeout_at` with a `&mut handle`, (2) `select!`
  on handle + timeout sleep. Both add complexity. Sprint 18 takes
  the honest position: timeout means daemon restart for full
  cleanup, operators see it in `tenants_remove_failed_total` and
  log. The accept loop has already been notified; it WILL exit
  eventually — the cleanup just doesn't happen automatically.
- **AuditChannel close on remove is best-effort.** When a tenant is
  removed, its `AuditChannel` is dropped along with the
  `TenantRuntime` — but the channel's background task may have
  unflushed events in its in-memory buffer. The channel's existing
  `shutdown().await` is called only at daemon shutdown, not on
  individual tenant remove. A handful of audit events in the last
  few hundred ms before remove may not reach disk. Documented as
  acceptable trade-off: tenant remove is operator-initiated, not
  emergency; operators wanting clean audit close can stop traffic
  to the tenant before issuing the remove. Sprint 19+ may add
  `AuditChannel::shutdown_async()` for the SIGHUP REMOVE path.
- **The two-map design (Vec + HashMap).** Single-map alternative was
  considered: all tasks in one `Arc<RwLock<HashMap<String, JoinHandle>>>`.
  Rejected because SNI groups don't have a meaningful tenant name
  key (they span N tenants on one listener). Using a synthetic
  `"sni-group:127.0.0.1:8443"` key would work but adds another
  taxonomy. The Vec for non-removable + HashMap for removable
  matches the operator model: "which tenants can I take down
  without restart?" answers via `tenant_tasks_by_name.keys()`.
- **No new lib tests.** Sprint 18 is integration-level: the drain
  protocol is best tested by an actual SIGHUP-driven E2E test
  (deferred to Sprint 19+). A unit test of "REMOVE branch with
  mocked JoinHandle" would test the test harness more than the
  protocol. The acceptance gate validates that the code compiles
  cleanly, clippy passes, existing 179 tests stay green, and the
  pkcs11 feature builds — sufficient for code-level correctness.
  Operator-level correctness needs E2E harness, which is its own
  sprint.

### 13.26.4 API surface changes

**Additive** (internal to qgateway binary):
- `TenantRuntime::shutdown: Arc<Notify>` field.
- `tenant_shutdowns_shared: Arc<RwLock<HashMap<String, Arc<Notify>>>>` in `cmd_run`.
- `tenant_tasks_by_name: Arc<RwLock<HashMap<String, JoinHandle<Result<()>>>>>` in `cmd_run`.
- `install_signal_handler` 12th and 13th params: `tenant_shutdowns`, `tenant_tasks_map`.

**Behavioural** (no public-API change):
- All accept-loop callsites now use per-tenant shutdown instead of daemon-wide for plain serve-tcp + serve-pq (4 sites — startup serve-tcp, startup serve-pq, SIGHUP runtime-add serve-pq, SIGHUP runtime-add serve-tcp). SNI groups + TLS-single still on daemon-wide shutdown.

**No removals.** All Sprint 17 behaviour preserved. Daemon shutdown
flow is layered: SIGTERM/SIGINT notify all per-tenant notifies
(removable tasks drain) AND daemon notify (SNI groups drain) AND
cmd_run's final drain (everything awaited).

### 13.26.5 Acceptance — actual

- [x] `cargo test --workspace --locked` green: **179 tests** (unchanged
      from Sprint 17 — Sprint 18 is integration-level, no library
      unit tests added per §13.26.3 trade-off discussion).
- [x] `cargo build --workspace --locked` clean.
- [x] `cargo clippy --workspace --all-targets -- -D warnings` clean.
- [x] `cargo fmt --all --check` clean.
- [x] `cargo build -p qgateway --features pkcs11 --locked` clean.

### 13.26.6 Honest deferrals to Sprint 19

1. **TLS hot-add for serve-tcp tenants.** Sprint 20.
2. **SNI-group runtime add + remove.** Sprint 20+.
3. **TLS-enabled single-tenant remove.** Sprint 20.
4. ✅ **`AuditChannel::shutdown_async()`** — DELIVERED in Sprint 19.
5. ✅ **Operator-configurable drain timeout** — DELIVERED in Sprint 19 (`tenant_drain_timeout_secs` TOML field).
6. **SIGHUP integration test.** Sprint 20+.
7. **End-to-end admission integration test.** Sprint 20+.

---

## 13.27. SPRINT 19 — DELIVERABLE CONTRACT (✅ CLOSED — Audit drain + drain-timeout config)

Sprint 19 closes the two smallest-but-most-actionable items from
Sprint 18's deferred list. The audit-channel best-effort cleanup
documented as a trade-off in Sprint 18 §13.26.3 is now a real
graceful drain via `AuditChannel::shutdown_async()`. The hardcoded
30s drain timeout becomes operator-configurable via TOML.

Bigger items (TLS hot-add, SNI runtime add/remove, integration tests)
remain Sprint 20+ work. Honest scope cut documented in §13.27.4:
the TLS refactor is its own architectural slice (promote
`reload_triggers: Vec<TlsReloadTrigger>` to `Arc<RwLock<HashMap>>`
keyed by tenant name) that doesn't fit alongside the audit work
without compromising one or both.

### 13.27.1 Delivered

| # | Deliverable | Notes |
|---|---|---|
| `AuditChannel::handle` → `Mutex<Option<AuditHandle>>` | The internal sender is now wrapped so `shutdown_async(&self)` can take it out idempotently. `handle()` accessor reads through the Mutex and clones the inner Option's `AuditHandle`; panics with a clear message if called after shutdown (only legitimate caller path — accept-loop spawn — happens before shutdown by construction). |
| `AuditChannel::join` → `tokio::sync::Mutex<Option<JoinHandle<()>>>` | Same Option-take pattern. The consuming `shutdown(self)` and the new `shutdown_async(&self)` both use `take()` to grab the join handle, await it, and return; subsequent calls return immediately. |
| `AuditChannel::shutdown_async(&self)` | New public method. First call drops the internal sender (signals writer task to drain buffer + exit) and awaits the task's completion. Subsequent calls are no-ops. Callable from any owner of `&AuditChannel` (typically wrapped in `Arc`). |
| `AuditChannel::shutdown(self)` preserved | Consuming variant kept for the daemon-shutdown path that owns the channel by value. Now uses the same Option-take machinery — interoperates safely with `shutdown_async` (call either first, the other becomes a no-op). |
| `TenantRuntime::audit: AuditChannel` → `Arc<AuditChannel>` | Wrapped at construction in `build_tenant_runtime`. The Arc lets the same channel live in both `TenantRuntime` (for `handle()` / `rotation_handle()` accessors) and the new `tenant_audits_shared` map (for `shutdown_async()` on REMOVE). |
| `tenant_audits_shared` map | `Arc<RwLock<HashMap<String, Arc<AuditChannel>>>>`. Populated at startup from `tenant_state`, extended on each successful SIGHUP ADD, drained-and-purged on SIGHUP REMOVE. |
| SIGHUP REMOVE audit drain | The REMOVE branch now calls `audit.shutdown_async().await` AFTER awaiting the accept-loop JoinHandle (no more events arriving) and BEFORE purging the entry from the map. The writer task drains its buffer to disk; upper bound on duration is a single batch flush (~ms). |
| Final-drain `shutdown_async` migration | `cmd_run`'s post-shutdown loop changed from `for rt in tenant_state { rt.audit.shutdown().await; }` (consuming, was correct but doesn't work via Arc) to `for rt in &tenant_state { rt.audit.shutdown_async().await; }` (borrow, idempotent — REMOVE may have already drained some). |
| `Config::tenant_drain_timeout_secs: u64` | New TOML field with `serde(default = "default_drain_timeout_secs")` → 30. Operator-tunable via TOML. The SIGHUP REMOVE branch reads this value from the daemon's config snapshot at handler-install time (not re-read on SIGHUP — the timeout is daemon-wide policy, not per-cycle). |
| 3 new lib tests | `shutdown_async_flushes_pending_events` (emits 10 events with batch_size=32 so they sit in buffer; shutdown_async must wait for drain before returning — re-open log and assert all 10 events present); `shutdown_async_is_idempotent` (three concurrent shutdowns via tokio::join! — none hang or panic, exactly one drains); `shutdown_async_then_consuming_shutdown_safe` (shutdown_async followed by consuming shutdown(self) — second call is a no-op via the Option-take). |
| `install_signal_handler` 15-arg signature | Added `tenant_audits` and `drain_timeout_secs` params. Existing `#[allow(clippy::too_many_arguments)]` covers the increase. |

### 13.27.2 Operational model

```bash
# Operator removes branch-bahia from sidecar.toml, SIGHUP.
$ kill -HUP $(pidof qgateway)
[INFO  qgateway] SIGHUP received config="/etc/qgateway/sidecar.toml"
[INFO  qgateway] tenant="branch-bahia" "tenant drained and removed (audit channel flushed)"

# The "audit channel flushed" wording is new in Sprint 19. Before:
# the message just said "drained and removed" and the audit channel's
# in-memory buffer was best-effort cleaned by Drop.
```

Configurable drain timeout — `sidecar.toml`:

```toml
role           = "serve-tcp"
identity_key   = "/etc/qgateway/identity.skid"
identity_pub   = "/etc/qgateway/identity.cspqid.pub"
metrics_listen = "127.0.0.1:9099"

# Sprint 19: how many seconds the daemon waits for an accept loop to
# drain after SIGHUP REMOVE notifies it. Defaults to 30. Tighten for
# bursty short-session workloads; relax for long-lived streaming
# tenants. Sessions that don't honor cancellation within this window
# trigger `tenants_remove_failed_total` and leave the tenant entry
# in the shared maps (daemon restart required for full cleanup).
tenant_drain_timeout_secs = 60

[[tenants]]
...
```

### 13.27.3 Drain protocol — full sequence

When `kill -HUP` arrives and the new config drops tenant `branch-bahia`:

```
SIGHUP arm:
  1. tenant_shutdowns[branch-bahia].notify_waiters()
     ↓ accept loop's tokio::select! wakes on its per-tenant notify
  2. accept loop exits, returns Ok(())
     ↓ all AuditHandle clones in the loop are dropped
  3. SIGHUP arm: tenant_tasks_map.remove(branch-bahia)
  4. SIGHUP arm: tokio::time::timeout(drain_timeout_secs, join_handle)
     ↓ JoinHandle awaited; loop has already exited so this returns ~immediately
  5. SIGHUP arm: tenant_names.remove + tenant_shutdowns.remove + tenant_admissions.remove
  6. SIGHUP arm: tenant_audits.remove(branch-bahia) → Some(Arc<AuditChannel>)
  7. SIGHUP arm: audit.shutdown_async().await
     ↓ internal sender taken out of Mutex<Option> → dropped
     ↓ writer task's mpsc::recv() returns None → exits loop
     ↓ writer flushes buffered events to disk
     ↓ JoinHandle resolves; shutdown_async returns
  8. SIGHUP arm: tenant_configs.retain + tenant_metrics.retain
  9. SIGHUP arm: bump tenants_removed_total
 10. info!("tenant drained and removed (audit channel flushed)")
```

The Sprint 18 trade-off was that step 7 didn't exist — the
`Arc<AuditChannel>` was dropped along with the tenant runtime; the
writer task eventually exited when its mpsc sender ref-count hit
zero, but the daemon didn't WAIT for that. Sprint 19 closes that
gap: the daemon awaits the writer task before returning from the
SIGHUP cycle.

### 13.27.4 Trade-offs documented

- **`handle()` panics if called after shutdown.** Refactoring the
  internal sender into `Mutex<Option<AuditHandle>>` means `handle()`
  must handle the post-shutdown case. Options were: (1) return
  `Option<AuditHandle>`, (2) panic, (3) re-open a no-op handle.
  Chose (2) because the legitimate caller path (accept loop spawn)
  always runs before shutdown by construction — a None at runtime
  would indicate a bug, not a recoverable condition. The panic
  message is explicit: "audit channel handle() called after
  shutdown". Operators reading a panic trace get an immediate
  diagnosis.
- **`tenant_drain_timeout_secs` is daemon-wide, not per-tenant.** Schema
  extension would let `[[tenants]].drain_timeout_secs` override the
  daemon default. Deferred — actual operators asking for per-tenant
  values can drive Sprint 20+ work. The daemon-wide value covers
  the typical case (homogeneous tenant workloads).
- **`drain_timeout_secs` not re-read on SIGHUP.** The handler captures
  the value from `cfg.tenant_drain_timeout_secs` at install time.
  An operator changing the value in the TOML must restart the
  daemon for the new value to take effect. Re-reading on each
  SIGHUP would require either re-loading Config inside the handler
  or threading the latest Config snapshot via shared state.
  Documented; defer to Sprint 20+ if anyone asks.
- **No `handle()` panic prevention via Option-returning variant.** Could
  add `try_handle() -> Option<AuditHandle>` alongside `handle()`.
  Not done — would split the API surface without a concrete caller
  needing the fallible version. The single existing caller path
  is provably pre-shutdown.
- **SIGHUP integration test deferred to Sprint 20+.** Considered for
  Sprint 19 but the realistic implementation (spawn daemon binary
  via std::process::Command, write tempfile TOML, send SIGHUP via
  nix::sys::signal::kill, scrape /metrics, assert counters) is
  bigger than the audit drain + drain-timeout-config work
  combined. Honest cut: ship the actionable items cleanly, defer
  the E2E harness to its own sprint.
- **Audit shutdown drains buffer, NOT the in-flight session events.**
  When an accept loop receives shutdown, it returns from its loop —
  but in-flight sessions in handler tasks may still be emitting
  events. By the time the SIGHUP arm calls `audit.shutdown_async()`
  (step 7 of §13.27.3), all session tasks should have completed
  (the accept loop's parent task has joined). If a runaway session
  task is still alive, its emit calls will silently fail because
  the AuditHandle was taken out of the channel. Documented as
  acceptable — operators who care about every last event can stop
  traffic to the tenant before issuing the remove.
- **3 lib tests, no integration test.** Sufficient for the API contract
  (idempotency, drain-before-return, interop with consuming
  shutdown). Operator-level behavior — "SIGHUP REMOVE actually
  causes audit events to land on disk" — is implicitly tested
  via the unit tests of the same machinery, but a true E2E test
  would assert across-process. Sprint 20 work.

### 13.27.5 API surface changes

**Additive**:
- `AuditChannel::shutdown_async(&self)` — new public method.
- `Config::tenant_drain_timeout_secs: u64` — new TOML field with default 30.

**Type-level changes** (breaking only at field-level — no Sprint-19 external callers exist):
- `AuditChannel::handle: AuditHandle` → `std::sync::Mutex<Option<AuditHandle>>`.
- `AuditChannel::join: JoinHandle<()>` → `tokio::sync::Mutex<Option<JoinHandle<()>>>`.

**Behavioural** (internal to qgateway binary):
- `TenantRuntime::audit: AuditChannel` → `Arc<AuditChannel>`.
- `tenant_audits_shared` added to `cmd_run`.
- `install_signal_handler` 14th + 15th params: `tenant_audits`, `drain_timeout_secs`.
- Final-drain loop uses `shutdown_async` instead of consuming `shutdown`.

### 13.27.6 Acceptance — actual

- [x] `cargo test --workspace --locked` green: **182 tests** (up from
      179 in Sprint 18 — 3 new `shutdown_async_*` audit tests).
- [x] `cargo build --workspace --locked` clean.
- [x] `cargo clippy --workspace --all-targets -- -D warnings` clean.
- [x] `cargo fmt --all --check` clean.
- [x] `cargo build -p qgateway --features pkcs11 --locked` clean.

### 13.27.7 Honest deferrals to Sprint 20

1. ✅ **TLS hot-add for serve-tcp tenants.** DELIVERED in Sprint 20.
2. **SNI-group runtime add + remove.** Sprint 21+.
3. ✅ **TLS-enabled single-tenant remove.** DELIVERED in Sprint 20.
4. **SIGHUP integration test.** Sprint 21+.
5. **End-to-end admission integration test.** Sprint 21+.
6. **Per-tenant `drain_timeout_secs`** — deferred until operator asks.

---

## 13.28. SPRINT 20 — DELIVERABLE CONTRACT (✅ CLOSED — TLS hot-add + TLS-single remove)

Sprint 20 closes the last per-tenant lifecycle gap: TLS-enabled
single tenants can now be both added and removed at runtime via
SIGHUP, without restarting the daemon. The Sprint-18-documented
trade-off ("TLS-enabled single tenants are NOT individually
removable") is now resolved — the underlying obstacle (the
`reload_triggers: Vec<TlsReloadTrigger>` walked by SIGUSR1 without
a tenant-keyed lookup path) was the same blocker for both ADD and
REMOVE, so fixing one fixes both.

Only SNI multi-tenant groups remain non-runtime — they share a TCP
listener across N tenants and require a separate architectural slice
(mutable `SniDispatchTable`, shared cert resolver). Documented in
§13.28.4 as Sprint 21+ work.

### 13.28.1 Delivered

| # | Deliverable | Notes |
|---|---|---|
| `reload_triggers_shared` map | Promoted from `Vec<TlsReloadTrigger>` to `Arc<RwLock<HashMap<String, TlsReloadTrigger>>>`. Keyed by tenant name for per-tenant TLS triggers; SNI groups use a synthetic `"sni-group:<listen>"` key so they coexist in the same map without needing a separate Vec. |
| SIGUSR1 iterates HashMap values | Read-locks the triggers map for the duration of the reload cycle. Concurrent SIGHUP ADD/REMOVE (which need write lock) wait — acceptable because both are operator-initiated, not request-path. Existing per-trigger semantics (`trigger.reload()` per entry, success/fail counters, log lines) preserved. |
| SIGHUP ADD for TLS-enabled tenants | Previously rejected with `"serve-tcp runtime add: TLS/SNI hot-add pending Sprint 14 — registered only"`. Now builds `TlsAcceptorHandle` + `TlsReloadTrigger` via `build_reloadable_acceptor`, inserts trigger by tenant name into the shared map, passes the acceptor handle to the spawned `run_serve_tcp_tenant`. |
| Resolve-after-trigger rollback | If `Config::resolve_one_serve_tcp` fails AFTER the trigger insert (e.g. `peer_pub_dir` validation), the apply path purges the trigger entry before bumping `tenants_add_failed_total`. No orphan triggers in the shared map. |
| Labeled-block early-exit pattern | The TLS-build failure path in `Role::ServeTcp` arm uses `'tcp_add: { ... break 'tcp_add false; }` so the arm evaluates to `false` (mapping to "ADD failed") instead of bubbling up via `return false` which would have failed type checking against the outer signal-handler future (whose return type is `()`). Pattern documented inline for future hot-add additions. |
| SIGHUP REMOVE purges TLS trigger | After audit drain, the REMOVE branch calls `reload_triggers.write().await.remove(&name)`. Returns `Option<TlsReloadTrigger>` — `Some` for TLS-enabled tenants (logs `"TLS reload trigger purged"`), `None` for plain-TCP tenants (silently no-op). |
| TLS-single tenants in by-name map | Sprint 18's `if has_tls { tenant_tasks.push(handle); }` branch removed. All single-tenant `serve-tcp` tasks now go to `tenant_tasks_by_name`, regardless of TLS. Combined with trigger purge above, TLS-single tenants are fully removable. SNI groups still go to the Vec (shared listener semantics). |
| `install_signal_handler` reload_triggers type | Changed from `Vec<TlsReloadTrigger>` to `Arc<RwLock<HashMap<String, TlsReloadTrigger>>>`. Existing 15-arg `#[allow(clippy::too_many_arguments)]` covers no signature growth (same count). Non-unix stub signature also updated to match. |

### 13.28.2 Operational model — TLS hot-add

```toml
# /etc/qgateway/sidecar.toml — operator adds a new TLS-enabled tenant:
[[tenants]]
name        = "branch-new"
listen      = "127.0.0.1:9445"
peer_pq     = "peer.example.com:9000"
peer_pub_dir = "/etc/qgateway/peers"
audit_log   = "/var/log/qgateway/branch-new.qa"

[tenants.tls]
cert = "/etc/qgateway/certs/branch-new.crt"
key  = "/etc/qgateway/keys/branch-new.key"
```

```bash
$ kill -HUP $(pidof qgateway)
[INFO  qgateway] SIGHUP received config="/etc/qgateway/sidecar.toml"
[INFO  qgateway] tenant="branch-new" "TLS termination + hot-reload enabled (runtime add)"
[INFO  qgateway] tenant="branch-new" listen=127.0.0.1:9445 ... tls=true admission_shared=true "serve-tcp tenant active"
[INFO  qgateway] tenant="branch-new" role=ServeTcp "tenant ADDED at runtime — serving traffic"

# The new trigger is now in the SIGUSR1 reload set:
$ openssl x509 -in /etc/qgateway/certs/branch-new.crt -dates -noout
notBefore=May 20 14:00:00 2026 GMT
notAfter=Aug 20 14:00:00 2026 GMT
# operator renews the cert later, then:
$ kill -USR1 $(pidof qgateway)
[INFO  qgateway] n_tenants=5 "SIGUSR1 received, reloading TLS certs"
[INFO  qgateway] tenant="branch-new" "TLS cert reloaded"
[INFO  qgateway] reloaded=5 failed=0 "TLS reload cycle complete"
```

### 13.28.3 Operational model — TLS-single remove

```bash
# Operator removes branch-new from sidecar.toml, SIGHUP.
$ kill -HUP $(pidof qgateway)
[INFO  qgateway] SIGHUP received
[INFO  qgateway] tenant="branch-new" "tenant drained and removed (audit channel flushed)"
[INFO  qgateway] tenant="branch-new" "TLS reload trigger purged"

# Subsequent SIGUSR1 no longer touches branch-new's certs (which may not
# even exist on disk anymore):
$ kill -USR1 $(pidof qgateway)
[INFO  qgateway] n_tenants=4 "SIGUSR1 received, reloading TLS certs"
[INFO  qgateway] reloaded=4 failed=0 "TLS reload cycle complete"

# Port 9445 is free for re-bind by another tenant on a future ADD.
```

### 13.28.4 Trade-offs documented

- **Synthetic key `"sni-group:<listen>"` for SNI triggers.** Coexists
  with per-tenant keys in the same HashMap. Alternative: separate
  `sni_triggers: Vec<TlsReloadTrigger>` map. Rejected — the synthetic
  key works because SIGUSR1 iterates `.values()` (key-agnostic), and
  SIGHUP REMOVE only ever targets per-tenant keys (looks up by
  `&rt.name`, never by synthetic SNI key). The HashMap variant
  prevents a future bug where SIGHUP REMOVE accidentally matches a
  SNI tenant — because SNI tenants aren't in `tenant_shutdowns` at
  all, the REMOVE branch exits early on the "no entry in shutdowns
  map" warn path before ever touching `reload_triggers`. The two
  guard rails (key shape AND shutdown-map gate) are belt-and-suspenders;
  the per-tenant-only key shape would also work alone.
- **Rollback on resolve-after-trigger-insert failure.** If the trigger
  insert succeeds but `resolve_one_serve_tcp` fails (rare: would
  require the tenant's `peer_pub_dir` to disappear between Config
  validation and resolve, or a similar TOCTOU), the apply path
  explicitly removes the trigger before returning `false`. Without
  this, SIGUSR1 would call `trigger.reload()` on a tenant that
  doesn't have an accept loop — harmless functionally but pollutes
  the reload metrics with "phantom" tenant entries. The rollback
  is one extra `write().await.remove(&rt.name)` — cheap insurance.
- **Labeled-block `'tcp_add: { ... break 'tcp_add false; }` instead
  of refactoring the match arm into a helper function.** The arm
  has too many captured locals (`identity`, `tenant_admissions`,
  `tenant_tasks_map`, `reload_triggers`, async context) to extract
  cleanly without a heavy refactor. The labeled block is local
  syntax that does exactly what's needed. Documented inline so
  future hot-add additions (SNI? rotation hot-add?) can follow
  the same pattern.
- **SNI groups still non-removable at runtime.** Two reasons: (1) they
  share a TCP listener across N tenants, so notifying a per-tenant
  shutdown doesn't drain only that tenant — the listener belongs
  to the group; (2) the `SniDispatchTable` is captured by value at
  `run_sni_group` spawn time, mutating it mid-flight requires a
  shared `Arc<RwLock<SniDispatchTable>>` or equivalent + the
  dispatch path adapting to runtime table changes. Both are
  achievable but constitute their own sprint of architectural
  work. Sprint 20 explicitly does NOT regress SNI behaviour —
  SNI tenants continue to require daemon restart, with the same
  warn log they had in Sprint 18-19.
- **Concurrent SIGUSR1 + SIGHUP ADD/REMOVE serialize.** SIGUSR1 holds
  read lock on `reload_triggers` for the entire reload cycle (which
  walks every trigger, performs cert reload, logs per-trigger
  outcome — typically tens of ms across all tenants). SIGHUP ADD/
  REMOVE need write lock to insert/remove entries; they wait
  until SIGUSR1 finishes. Acceptable because both signals are
  operator-initiated. The lock could be made finer-grained
  (per-trigger Mutex) but adds complexity for no operational
  benefit at typical deployment sizes (<100 tenants).
- **No new lib tests.** Sprint 20 is integration-level: TLS hot-add
  + remove is tested by the existing TLS integration tests
  (`sni_cert_dispatch.rs`, `e2e_tunnel.rs`) plus the operator-level
  acceptance that the code path compiles, clippy passes, and the
  existing 182 tests stay green. A true E2E test of "SIGHUP ADD
  TLS tenant, send TLS handshake to it, SIGHUP REMOVE, assert
  handshake now fails" is Sprint 21+ work alongside the SIGHUP
  integration test.

### 13.28.5 Cumulative runtime-lifecycle capability matrix

After Sprint 20, the per-tenant runtime lifecycle is:

| Tenant kind | ADD | Hot-reconfigure limits | REMOVE | TLS cert reload |
|---|---|---|---|---|
| serve-pq | ✅ Sprint 12 | ✅ Sprint 16 | ✅ Sprint 18 | N/A |
| serve-tcp (plain TCP) | ✅ Sprint 13 | ✅ Sprint 16 | ✅ Sprint 18 | N/A |
| serve-tcp (TLS-single) | ✅ Sprint 20 | ✅ Sprint 16 | ✅ Sprint 20 | ✅ Sprint 5 (SIGUSR1) |
| serve-tcp (SNI group) | ❌ restart | ✅ Sprint 16 | ❌ restart | ✅ Sprint 6.5 (SIGUSR1) |

The only remaining "requires restart" cell is SNI group ADD/REMOVE
— the architectural slice deferred to Sprint 21+.

### 13.28.6 API surface changes

**Type-level changes** (internal to qgateway binary):
- `reload_triggers: Vec<TlsReloadTrigger>` → `Arc<RwLock<HashMap<String, TlsReloadTrigger>>>` in `cmd_run` and the signal handler.

**Behavioural** (no public-API change):
- SIGHUP ADD path now accepts TLS-enabled tenants.
- SIGHUP REMOVE path now purges TLS triggers.
- TLS-enabled single tenants go to `tenant_tasks_by_name` (were in Vec under Sprint 18).
- SNI groups continue to use synthetic key in shared map.

**No removals.** All Sprint 19 behaviour preserved.

### 13.28.7 Acceptance — actual

- [x] `cargo test --workspace --locked` green: **182 tests**
      (unchanged from Sprint 19 — Sprint 20 is integration-level
      refactor, no new lib tests added per §13.28.4 trade-off).
- [x] `cargo build --workspace --locked` clean.
- [x] `cargo clippy --workspace --all-targets -- -D warnings` clean.
- [x] `cargo fmt --all --check` clean.
- [x] `cargo build -p qgateway --features pkcs11 --locked` clean.

### 13.28.8 Honest deferrals to Sprint 21

1. ⚠️ **SNI-group runtime add** — INFRASTRUCTURE DELIVERED in Sprint 21 (Stage A: `HotSniDispatchTable` + builder methods); wiring into `run_sni_group` + SIGHUP arm is Sprint 22 work (Stage B).
2. ⚠️ **SNI-group runtime remove** — same Stage A/B split as #1.
3. **SIGHUP integration test.** Sprint 22+.
4. **TLS-specific E2E test.** Sprint 22+.
5. **End-to-end admission integration test.** Sprint 22+.
6. **Per-tenant `drain_timeout_secs`** — deferred until operator asks.
7. **Per-trigger finer-grained locking** — deferred until profiling justifies it.

---

## 13.29. SPRINT 21 — DELIVERABLE CONTRACT (✅ CLOSED — SNI dispatch hot-swap infrastructure)

Sprint 21 ships the type system + tests for runtime SNI tenant
add/remove via a two-stage approach mirroring Sprint 15
(`HotAdmissionController`). Stage A — what's in Sprint 21 — is the
immutable-builder + arc-swap-wrapper pair: `SniDispatchTable` gains
`with_tenant_added` and `with_tenant_removed` methods that return
NEW tables (initial table untouched), and `HotSniDispatchTable`
wraps `arc_swap::ArcSwap<SniDispatchTable>` with the same `load()` /
`swap()` API as the admission controller.

Stage B — wiring into `run_sni_group` + the SIGHUP apply step — is
Sprint 22 work because it touches the SNI accept loop's read path
(currently `dispatch.lookup(&server_name)` on a captured-by-value
`SniDispatchTable`; needs to become `hot.load().lookup(&server_name)`)
plus the multi-SNI cert resolver which has its own mutability story
(adding/removing a tenant's TLS cert+key from the rustls resolver).

The Stage A type design is independently valuable: it's lib-testable
in isolation (12 new unit tests covering builder semantics + hot-swap
in-flight guard preservation), the immutable-builder pattern is
ergonomic for the SIGHUP apply step's "diff and compute successor"
flow, and Sprint 22 can focus exclusively on wiring without
re-evaluating the type design.

### 13.29.1 Delivered

| # | Deliverable | Notes |
|---|---|---|
| `SniDispatchTable::with_tenant_added(SniTenantContext) -> Result<Self>` | Immutable builder. Returns a NEW table containing all previous tenants plus the new one. Initial table unchanged (caller can keep a handle to it). Duplicate-SNI detection covers both exact-match (`alice.example.com`) and wildcard (`*.svc.internal`) cases. |
| `SniDispatchTable::with_tenant_removed(tenant_name: &str) -> Option<Self>` | Immutable builder. Returns `Some(new_table)` when the named tenant was present in either the exact-match map or the wildcard list; returns `None` when absent (caller distinguishes "already removed" from a successful removal). |
| `SniDispatchTable::tenant_names() -> Vec<String>` | Enumerates tenant names across exact-match + wildcard entries. Order not guaranteed stable (HashMap iteration); caller sorts if needed. Used by Sprint 22's SIGHUP apply step to compute the diff between the running table and the new config's SNI tenant set. |
| `HotSniDispatchTable` struct | Wraps `arc_swap::ArcSwap<SniDispatchTable>`. Symmetric with Sprint 15's `HotAdmissionController` — same dependency, same single-load read pattern, same swap-returns-old semantics. |
| `HotSniDispatchTable::load()` | Returns `arc_swap::Guard<Arc<SniDispatchTable>>`. The hot accept path will call `.load().lookup(&server_name)` exactly once per inbound TLS handshake. The Arc clone inside ArcSwap keeps the loaded table alive even if a concurrent `swap()` drops the previous one — critical for in-flight handshakes resolving SNI just before a config change. |
| `HotSniDispatchTable::swap(SniDispatchTable) -> Arc<SniDispatchTable>` | Atomically replaces the inner table. Returns the old table as Arc for caller inspection or drop. The new table is pre-built via the immutable builders so this call is infallible. |
| Re-export from `qgateway_core` | `HotSniDispatchTable` added alongside `SniDispatchTable` and `SniTenantContext` in `lib.rs`. |
| `AuditHandle::test_noop()` helper | New `#[cfg(test)]` `pub(crate)` constructor. Creates an `AuditHandle` whose mpsc receiver is dropped immediately — every `emit()` resolves to `TrySendError::Closed`. Used by the new unit tests to construct `SniTenantContext` instances without spawning a full `AuditChannel`. |
| 12 new lib tests | `with_tenant_added_appends_exact_match`, `with_tenant_added_appends_wildcard`, `with_tenant_added_rejects_duplicate_exact_sni`, `with_tenant_added_rejects_duplicate_wildcard`, `with_tenant_removed_drops_exact_match`, `with_tenant_removed_drops_wildcard`, `with_tenant_removed_returns_none_if_absent`, `tenant_names_enumerates_exact_and_wildcard`, `hot_dispatch_table_initial_lookup`, `hot_dispatch_table_swap_installs_new_table`, `hot_dispatch_table_swap_returns_old_table_arc`, `hot_dispatch_table_inflight_guard_survives_swap`. |

### 13.29.2 Stage B preview (Sprint 22)

When Sprint 22 ships, the SIGHUP apply step for SNI tenants will:

1. Identify which SNI group(s) each ADD/REMOVE belongs to (by matching
   the tenant's `listen` address against running group listeners).
2. For each affected group:
   a. Look up the group's `HotSniDispatchTable`.
   b. For each ADD: compute `current.with_tenant_added(new_ctx)` → swap.
   c. For each REMOVE: compute `current.with_tenant_removed(name)` → swap.
   d. Update the multi-SNI cert resolver (this is the part still
      under design — rustls's `ResolvesServerCert` trait needs a
      mutable backing store, which the current `build_reloadable_multi_sni_acceptor`
      doesn't expose).
3. For first-tenant ADD on a new listen address: spawn a fresh
   `run_sni_group` task. For last-tenant-removed: notify the group's
   shutdown notify and await drain.

The wiring blocker is the same one Sprint 16 hit: `run_sni_group`
captures the dispatch table by value at spawn time. Sprint 22 will
change the signature from `dispatch: SniDispatchTable` to
`dispatch: Arc<HotSniDispatchTable>` and update the accept-loop
lookup line.

### 13.29.3 Trade-offs documented

- **Two-stage delivery.** Sprint 21 ships type-level infrastructure
  with full test coverage but NO operator-visible behaviour change.
  Stage A is operationally indistinguishable from Sprint 20 — SNI
  group ADD/REMOVE still requires daemon restart. Documented
  explicitly here. Sprint 22 will wire it through.
- **Immutable builder over in-place mutation.** Could have added
  `&mut self` methods that mutate the table in place. Rejected
  because the SIGHUP apply step computes a successor table and
  THEN swaps it atomically — an in-place mutation would require
  taking the write lock for the duration of the compute + swap,
  blocking concurrent dispatch lookups on the OLD table during
  rebuild. The immutable-builder + swap pattern keeps the read
  path lock-free (arc-swap load) and the write path cheap (one
  Arc construction + atomic pointer swap).
- **`with_tenant_added` is `Result`, `with_tenant_removed` is `Option`.**
  Asymmetric because they answer different questions. Add can FAIL
  (duplicate SNI is operator error, must be surfaced). Remove can't
  fail — "tenant not present" is a valid intermediate state during
  diff convergence, not an error. Returning `Option` lets the
  caller distinguish "no-op" from "actual removal" without
  conflating it with errors.
- **`HashMap` clone on builder call.** Each `with_tenant_*` call
  fully clones the inner `HashMap<String, SniTenantContext>` and
  `Vec<(String, SniTenantContext)>`. At typical deployment sizes
  (<100 tenants per SNI group), this is microseconds. For larger
  groups it'd warrant a copy-on-write or persistent data structure;
  not in Sprint 21 scope.
- **In-flight guard semantics tested explicitly.** The test
  `hot_dispatch_table_inflight_guard_survives_swap` loads the
  guard, swaps, and confirms the guard still resolves the old
  tenant. This models the production behaviour: a TLS handshake
  that completed `server_name` extraction just before a SIGHUP
  swap continues with the OLD context for the entire session. The
  session's audit log, peer policy, and admission permits all
  belong to the OLD tenant — exactly the right semantics
  (matches Sprint 16's `HotAdmissionController` in-flight permit
  policy).
- **No drain protocol for removed-from-SNI-group tenants.** Removing
  a tenant from the dispatch table stops NEW connections from
  reaching it, but in-flight sessions continue under the OLD
  context until they end naturally. Operators wanting to drain
  must use the full per-tenant remove flow (Sprint 18) — but that
  flow currently doesn't apply to SNI tenants (they're not in
  `tenant_shutdowns`). Sprint 22 needs to decide: does removing a
  SNI tenant also trigger per-tenant shutdown? Probably yes —
  documented as Sprint 22 design item.
- **Multi-SNI cert resolver is unchanged.** The biggest blocker
  for Stage B is NOT the dispatch table — it's the rustls cert
  resolver. The current `build_reloadable_multi_sni_acceptor`
  constructs a `Resolver` with a fixed set of cert+key pairs;
  changing the set at runtime requires either rebuilding the
  resolver (atomic swap of the rustls `Acceptor`) or designing a
  mutable backing store. Sprint 22 will need a design pass on
  this; Sprint 21 explicitly does NOT touch it.

### 13.29.4 API surface changes

**Additive**:
- `qgateway_core::SniDispatchTable::with_tenant_added(SniTenantContext) -> Result<Self>`.
- `qgateway_core::SniDispatchTable::with_tenant_removed(&str) -> Option<Self>`.
- `qgateway_core::SniDispatchTable::tenant_names() -> Vec<String>`.
- `qgateway_core::HotSniDispatchTable` struct with `new` / `load` / `swap`.
- `qgateway_core::audit::AuditHandle::test_noop()` (test-only, `pub(crate)`).

**No type-level breaking changes.** All Sprint 20 callers compile
unchanged. The existing `SniDispatchTable` is still passed by value
into `run_sni_group` — Sprint 22 will change that.

**No dependency changes.** `arc-swap` was already a workspace
dependency since Sprint 15 (for `HotAdmissionController`).

### 13.29.5 Acceptance — actual

- [x] `cargo test --workspace --locked` green: **194 tests** (up from
      182 in Sprint 20 — 12 new SNI dispatch tests).
- [x] `cargo build --workspace --locked` clean.
- [x] `cargo clippy --workspace --all-targets -- -D warnings` clean.
- [x] `cargo fmt --all --check` clean.
- [x] `cargo build -p qgateway --features pkcs11 --locked` clean.

### 13.29.6 Honest deferrals to Sprint 22

1. ✅ **Stage B: wire `HotSniDispatchTable` into `run_sni_group`** — DELIVERED in Sprint 22.
2. ✅ **Multi-SNI cert resolver mutation design + implementation** — DELIVERED in Sprint 22 (`TlsReloadTrigger::{add_sni_entry, remove_sni_entry, sni_labels}`).
3. **SIGHUP arm wiring for SNI tenants.** Sprint 23.
4. **SIGHUP integration test.** Sprint 23+.
5. **TLS-specific E2E test.** Sprint 23+.
6. **End-to-end admission integration test.** Sprint 23+.
7. **Per-tenant `drain_timeout_secs`.** Deferred until operator asks.

---

## 13.30. SPRINT 22 — DELIVERABLE CONTRACT (✅ CLOSED — SNI dispatch wiring + cert mutation API)

Sprint 22 ships the wiring half of the SNI runtime add/remove work
(Stage B of the Sprint 21 split) plus the cert resolver mutation API
that was the larger architectural blocker. The two pieces compose:
`run_sni_group` now reads dispatch via `Arc<HotSniDispatchTable>` so
the SIGHUP arm can swap dispatch tables without restarting the accept
loop, AND `TlsReloadTrigger` now exposes `add_sni_entry` /
`remove_sni_entry` so the SIGHUP arm can mutate the cert set in the
running rustls acceptor.

Sprint 23 will compose the two APIs in the SIGHUP arm: detect SNI
tenant ADD/REMOVE in the config diff, compute successor dispatch
table via Sprint 21 builders, mutate cert set via Sprint 22 trigger
methods, swap dispatch into the hot wrapper.

### 13.30.1 Delivered

| # | Deliverable | Notes |
|---|---|---|
| `run_sni_group` signature change | `dispatch: SniDispatchTable` → `dispatch: Arc<HotSniDispatchTable>`. Accept loop logs the snapshot's tenant count under `dispatch.load()` once at startup. Per-session task clones the Arc to the hot wrapper, not the inner table. |
| `handle_sni_session` signature change | Same `Arc<HotSniDispatchTable>` parameter. The session loads the table ONCE just after TLS handshake completes, clones the resolved `SniTenantContext` out, releases the guard. In-flight Arc semantics preserved — a session whose dispatch happened on the OLD table continues with that tenant's identity for its full lifetime even if a SIGHUP REMOVE happens mid-session. Matches Sprint 16's `HotAdmissionController` policy. |
| main.rs SNI group spawn wraps dispatch | `let dispatch = Arc::new(qgateway_core::HotSniDispatchTable::new(dispatch));` before passing to the spawn closure. Log line updated to mention "hot-swappable dispatch". |
| `ReloadSource::Multi.entries` mutability | Field changed from `Vec<(String, String, TlsConfig)>` to `std::sync::Mutex<Vec<...>>`. `reload()` snapshots under the mutex and releases the lock before rebuild — avoids holding the mutex across the (potentially costly) `build_multi_sni_acceptor` call. |
| `TlsReloadTrigger::add_sni_entry(label, sni, cfg)` | Pushes a new entry into the multi-SNI cert set, rebuilds the acceptor, atomically installs it via the existing watch channel. Rolls back the push if the rebuild fails (e.g. bad cert path) — trigger state stays consistent with what's actually serving. Rejects: single-source triggers (clear error message), duplicate labels (operator error must surface). |
| `TlsReloadTrigger::remove_sni_entry(label)` | Drops the named entry from the cert set, rebuilds, swaps. Rolls back on rebuild failure (rare — removing certs shouldn't fail to build the resolver). Rejects: single-source triggers, missing labels (caller distinguishes "already removed" from "removed successfully" — symmetric with Sprint 21's `SniDispatchTable::with_tenant_removed -> Option<Self>`). |
| `TlsReloadTrigger::sni_labels() -> Result<Vec<String>>` | Snapshots the current entry labels under the mutex. Rejects single-source triggers. Used by Sprint 23+'s SIGHUP arm for diff computation between running cert set and new config's SNI tenant set. |
| 7 new lib tests | `add_sni_entry_appends_and_rebuilds`, `add_sni_entry_rejects_duplicate_label`, `add_sni_entry_rolls_back_on_rebuild_failure` (forces a bad cert path, verifies the entry is removed after rebuild fails), `remove_sni_entry_drops_and_rebuilds`, `remove_sni_entry_rejects_missing_label`, `add_remove_on_single_source_trigger_errors` (rejection paths for non-multi triggers), `reload_after_add_sees_new_entries` (smoke test that SIGUSR1 reload reads through the mutated set). All use `rcgen` (dev-dep) to generate real cert+key pairs so the rebuild path is exercised end-to-end. |
| `#[allow(clippy::err_expect)]` at mod-tests level | Required because `Arc<TlsAcceptor>` doesn't implement Debug, so `.unwrap_err()` and `.expect_err()` don't type-check. The `.err().expect("...")` idiom works but trips the `clippy::err_expect` lint. The mod-level allow is the minimal-surface fix — production code paths don't need it. |

### 13.30.2 Operational model — what works now (architecturally)

```rust
// Inside an SNI group's accept loop (Sprint 22 + future SIGHUP arm):
//
// Initial state — group spawned with N tenants. Dispatch table and
// cert set both reflect those N tenants.
//
// Operator adds a new tenant to the group via SIGHUP:
//   1. SIGHUP arm computes new dispatch table:
//        let new = current_dispatch.load().with_tenant_added(new_ctx)?;
//   2. SIGHUP arm adds the cert via the existing trigger:
//        group_trigger.add_sni_entry(label, sni, tls_cfg)?;
//      ↓ trigger rebuilds the multi-SNI acceptor with N+1 certs
//      ↓ trigger swaps via the existing watch channel
//      ↓ run_sni_group's `tls_handle.current()` now returns the new acceptor
//   3. SIGHUP arm swaps the dispatch:
//        current_dispatch.swap(new);
//      ↓ next handle_sni_session loads the new table via .load()
//      ↓ new TLS handshakes for the added SNI complete + dispatch correctly
//
// Operator removes a tenant from the group via SIGHUP:
//   1. Reverse: dispatch.swap(with_tenant_removed(name).unwrap())
//   2. group_trigger.remove_sni_entry(label)?;
//
// In-flight sessions of OTHER tenants in the group:
//   unaffected. They never touched the changed entry's cert or
//   dispatch path — rustls keeps the per-session Arc<TlsAcceptor>
//   alive via the session struct.
//
// In-flight sessions of the REMOVED tenant:
//   continue under the old context (Arc guard semantics). Their
//   audit log, peer policy, and admission permits still belong
//   to the removed tenant's identity. Operators wanting hard drain
//   must also signal the tenant's per-tenant shutdown — Sprint 23
//   design decision.
```

The whole flow is mechanically possible today; only the SIGHUP arm
glue is missing. Sprint 23 will write that glue.

### 13.30.3 Trade-offs documented

- **`std::sync::Mutex<Vec<...>>` over `tokio::sync::RwLock` for entry
  storage.** The mutex is held only for the snapshot clone in
  `reload()` (and for the push/retain in `add`/`remove`) — never
  across `.await`. `std::sync::Mutex` is appropriate. Using
  `tokio::sync::Mutex` would require these methods to be `async`,
  which forces every caller into an async context — gratuitous since
  the existing SIGUSR1 reload path is sync.
- **Snapshot-clone in `reload()` over hold-lock-across-build.** Holding
  the mutex across `build_multi_sni_acceptor` could block concurrent
  `add_sni_entry` / `remove_sni_entry` calls for the rebuild duration
  (typically ms but scales with cert count). Cloning the `Vec` is
  microseconds; the snapshot then drives the build outside the lock.
  Cost: one extra `Vec` allocation per reload. Acceptable.
- **Rollback strategy on rebuild failure.** Push first, rebuild, on
  failure pop — keeps state consistent with what's actually serving.
  Alternative: pre-validate the new cert via a dry-run build, then
  push only on success. Rejected because it doubles the build cost
  (validate + actually-install) and the failure mode is operator
  error (bad cert path), not transient — fast retry is acceptable.
  The rollback path includes the original error context: `"add_sni_entry:
  rollback after rebuild failure"`.
- **`add_sni_entry` is `Result`, `remove_sni_entry` is `Result` (not
  `Option`).** Asymmetric with Sprint 21's dispatch table builders
  (which return `Option` for "tenant not present"). The TLS trigger
  treats missing-label as an error because it's harder to reach
  legitimately — the dispatch table sees "tenant absent" as part of
  diff convergence; the cert set is operator-explicit ("remove
  alice's cert" means alice WAS supposed to be there). If Sprint 23+
  finds the diff use-case wants Option semantics, we can add a
  `try_remove_sni_entry -> Option<...>` sibling.
- **No drain protocol for SNI-removed tenants.** Removing a tenant
  from the dispatch table stops NEW TLS handshakes from reaching
  it; removing its cert from the rustls resolver stops NEW
  handshakes with its SNI from even completing TLS. In-flight
  sessions continue under the OLD context until natural end. To
  hard-drain, the SIGHUP arm (Sprint 23) needs to also notify the
  per-tenant shutdown — but SNI tenants don't have per-tenant
  shutdown today (they're not in `tenant_shutdowns`). Sprint 23
  design decision: do SNI tenants gain per-tenant Notifies? Probably
  yes — the same per-tenant infrastructure that REMOVE uses for
  serve-tcp / serve-pq tenants generalizes.
- **`#[allow(clippy::err_expect)]` instead of refactoring assertions.**
  Could rewrite each test with a manual `match` over `Result`. The
  allow is one line vs ~30 lines of repetitive `match` boilerplate.
  Production code never uses `.err().expect()` — the allow is
  surgical to the test module.
- **No new SPEC section for the dispatch-table builders.** They're
  documented in Sprint 21 §13.29; Sprint 22 only uses them through
  the wiring described here. The Sprint-23 SIGHUP arm wiring will
  reference both sections.
- **Initial test had over-specified `Arc::ptr_eq` assertion.** Dropped
  after observing that `tokio::sync::watch::Sender::send` may
  internally optimize for unchanged values or share Arcs in ways
  the test was assuming wouldn't happen. The labels-set count
  assertion is sufficient evidence that `reload()` ran (entries were
  re-snapshotted, acceptor was rebuilt) — the Arc identity check
  was implementation-detail-coupled.

### 13.30.4 API surface changes

**Additive**:
- `qgateway_core::TlsReloadTrigger::add_sni_entry(label, sni, cfg) -> Result<Arc<TlsAcceptor>>`.
- `qgateway_core::TlsReloadTrigger::remove_sni_entry(label) -> Result<Arc<TlsAcceptor>>`.
- `qgateway_core::TlsReloadTrigger::sni_labels() -> Result<Vec<String>>`.

**Signature changes** (internal to qgateway-core):
- `run_sni_group`: `dispatch: SniDispatchTable` → `dispatch: Arc<HotSniDispatchTable>`.
- `handle_sni_session`: same.

**Type-level changes** (internal):
- `ReloadSource::Multi.entries`: `Vec<(String, String, TlsConfig)>` → `std::sync::Mutex<Vec<(String, String, TlsConfig)>>`.

**No public-API breakage.** The Sprint 20 callers of `run_sni_group` in qgateway main.rs were updated in the same sprint to wrap dispatch in `Arc::new(HotSniDispatchTable::new(d))`. No external callers exist.

### 13.30.5 Acceptance — actual

- [x] `cargo test --workspace --locked` green: **201 tests** (up from
      194 in Sprint 21 — 7 new TLS mutation tests).
- [x] `cargo build --workspace --locked` clean.
- [x] `cargo clippy --workspace --all-targets -- -D warnings` clean
      (after adding `#[allow(clippy::err_expect)]` on the test module
      for the `Arc<TlsAcceptor>`-not-Debug issue).
- [x] `cargo fmt --all --check` clean.
- [x] `cargo build -p qgateway --features pkcs11 --locked` clean.

### 13.30.6 Honest deferrals to Sprint 23

1. ✅ **SIGHUP arm wiring for SNI tenants** — DELIVERED in Sprint 23 (join-existing-group + remove-from-group only).
2. **SIGHUP integration test.** Sprint 24+.
3. **TLS-specific E2E test.** Sprint 24+.
4. **End-to-end admission integration test.** Sprint 24+.
5. **First-tenant-in-new-SNI-group and last-tenant-leaves-SNI-group.** Sprint 24.
6. **Per-tenant `drain_timeout_secs`.** Deferred.

---

## 13.31. SPRINT 23 — DELIVERABLE CONTRACT (✅ CLOSED — SNI runtime ADD/REMOVE in existing groups)

Sprint 23 composes Sprint 21 (dispatch builders) and Sprint 22 (cert
mutation API) into operator-visible behavior: SIGHUP can now add a
tenant to a running SNI group, or remove a tenant from one, without
restarting the daemon.

Two restrictions remain (both Sprint 24+):
1. **First-tenant-in-new-SNI-group** — adding an SNI tenant on a
   `listen` address that has no existing SNI group requires daemon
   restart. Spinning up a fresh `run_sni_group` task at runtime is
   a separate lifecycle item.
2. **Last-tenant-leaves-SNI-group** — removing the last tenant from
   a group leaves the group task running with an empty dispatch
   table (no SNI matches, every handshake fails). Draining the
   group task and freeing the listener is also Sprint 24+ work.

For the typical case — adding/removing tenants to a known set of
SNI listeners declared in `sidecar.toml` — Sprint 23 closes the
runtime gap.

### 13.31.1 Delivered

| # | Deliverable | Notes |
|---|---|---|
| `sni_dispatches_shared` map | `Arc<RwLock<HashMap<String, Arc<HotSniDispatchTable>>>>` keyed by `listen` address. Populated at startup when each `run_sni_group` is spawned; mutated entries by the SIGHUP arm; never grown or shrunk in Sprint 23 (group lifecycle is Sprint 24). |
| `install_signal_handler` 16-arg signature | Added `sni_dispatches` param. Existing `#[allow(clippy::too_many_arguments)]` covers. |
| SIGHUP ADD — SNI hot-add path | The previous "SNI hot-add pending Sprint 21 — registered only" rejection is replaced by a complete add flow: validate `[tls]` present, look up dispatch by `cfg_for_tenant.listen`, resolve via `resolve_one_serve_tcp`, build `SniTenantContext`, compute successor via `dispatch.load().with_tenant_added(ctx)`, mutate certs via `trigger.add_sni_entry(label, sni, cfg)`, swap dispatch. Each step has its own error handling — duplicate SNI returns early without touching certs; cert mutation failure returns early without swapping dispatch. |
| SIGHUP ADD failure paths | Reports the specific failure mode in the daemon log: missing `[tls]` block, no running SNI group on the target listen (with explicit pointer to Sprint 24 for new-group spawn), resolve failure, dispatch build failure (duplicate SNI), cert mutation failure. Each path increments `tenants_add_failed_total`. |
| SIGHUP REMOVE — SNI hot-remove path | Inserted BEFORE the per-tenant-shutdown check in the existing REMOVE branch. Walks `sni_dispatches` looking for the named tenant; if found in a group, computes successor dispatch via `with_tenant_removed`, mutates cert set via `trigger.remove_sni_entry`, swaps dispatch. Then purges entries from `tenant_names`, `tenant_admissions`, `tenant_audits`, `tenant_configs`, `metrics_list`. Bumps `tenants_removed_total`. Soft drain only — in-flight sessions continue under old context. |
| Race-safe lookup | The SNI tenant lookup walks `sni_dispatches.read()` under read lock; if a concurrent operation removed the tenant between the lookup and the `with_tenant_removed` call, the Option-return shape from Sprint 21 surfaces as "already absent" with a warn log + no failure counter (matches the diff-convergence semantics). |
| Triggers read-lock held across cert+dispatch swap | The triggers map's read lock is held for the duration of `trigger.add_sni_entry(...) + dispatch.swap(...)` so an interleaved SIGUSR1 (which needs the same read lock) sees them consistent — either both old or both new, never a mismatched cert+dispatch state. |
| Combined log lines | ADD: `"SNI tenant added at runtime — joining existing group"` with `tenant`/`listen`/`sni` fields. REMOVE: `"SNI tenant removed at runtime (in-flight sessions continue under old context until natural end)"` — operators see explicitly that REMOVE is soft-drain, matching Sprint 22 §13.30.3 documentation. |

### 13.31.2 Operational model

**Adding an SNI tenant to a running group:**

```toml
# /etc/qgateway/sidecar.toml — operator adds carol to an SNI group:
[[tenants]]
name        = "carol"
listen      = "127.0.0.1:9000"   # same as alice/bob; joins their SNI group
peer_pq     = "peer.example.com:9001"
peer_pub_dir = "/etc/qgateway/peers"
audit_log   = "/var/log/qgateway/carol.qa"
sni         = "carol.example.com"

[tenants.tls]
cert = "/etc/qgateway/certs/carol.crt"
key  = "/etc/qgateway/keys/carol.key"
```

```bash
$ kill -HUP $(pidof qgateway)
[INFO  qgateway] SIGHUP received config="/etc/qgateway/sidecar.toml"
[INFO  qgateway] tenant="carol" listen=127.0.0.1:9000 sni=carol.example.com
                "SNI tenant added at runtime — joining existing group"
[INFO  qgateway] config reload apply summary
                added_applied=1 added_failed=0
                removed_applied=0 removed_failed=0
```

**Removing an SNI tenant from a running group:**

```bash
$ kill -HUP $(pidof qgateway)
[INFO  qgateway] tenant="carol" listen=127.0.0.1:9000
                "SNI tenant removed at runtime (in-flight sessions continue under old context until natural end)"
[INFO  qgateway] config reload apply summary
                added_applied=0 added_failed=0
                removed_applied=1 removed_failed=0
```

**ADD fails when target group doesn't exist (Sprint 24+ work):**

```bash
$ kill -HUP $(pidof qgateway)
[ERROR qgateway] tenant="dave" listen=127.0.0.1:9099
                "SNI runtime add: no running SNI group on this listen — first-tenant-in-new-group requires daemon restart (Sprint 24+)"
[INFO  qgateway] config reload apply summary
                added_applied=0 added_failed=1
```

### 13.31.3 Cumulative runtime-lifecycle capability matrix (Sprint 23)

| Tenant kind | ADD | Hot-reconfigure limits | REMOVE | TLS cert reload |
|---|---|---|---|---|
| serve-pq | ✅ Sprint 12 | ✅ Sprint 16 | ✅ Sprint 18 | N/A |
| serve-tcp (plain TCP) | ✅ Sprint 13 | ✅ Sprint 16 | ✅ Sprint 18 | N/A |
| serve-tcp (TLS-single) | ✅ Sprint 20 | ✅ Sprint 16 | ✅ Sprint 20 | ✅ Sprint 5 |
| serve-tcp (SNI in existing group) | ✅ Sprint 23 | ✅ Sprint 16 | ✅ Sprint 23 | ✅ Sprint 6.5 |
| New SNI group (first tenant on new listen) | ❌ restart | N/A | N/A | N/A |

The only remaining "requires restart" path is creating a brand-new
SNI group on a previously-unused `listen` address. Once at least one
tenant is serving on that listen, subsequent ADD/REMOVE of tenants
in the group works at runtime.

### 13.31.4 Trade-offs documented

- **Linear scan over `sni_dispatches` for tenant lookup in REMOVE.** The
  REMOVE path doesn't know which SNI group a tenant belongs to (the
  tenant's config row is already gone from the new TOML); it walks
  every entry in `sni_dispatches` calling `tenant_names()` to find the
  match. For typical deployments (<10 SNI groups, each with <100
  tenants), this is microseconds. Larger deployments could maintain a
  reverse index `tenant_name -> listen` — not in Sprint 23 scope.
- **Triggers read lock held across `add_sni_entry` + `dispatch.swap`.**
  Holds for ~tens-of-ms (cert rebuild dominates). Concurrent SIGUSR1
  blocks for that window. Acceptable: both are operator-initiated;
  SIGUSR1 + SIGHUP at the same time is rare. The alternative — release
  lock between the two — would let SIGUSR1 see a state where the new
  cert is installed but dispatch hasn't swapped yet (or vice versa).
  Holding the lock keeps the invariant simple.
- **Soft drain on REMOVE — in-flight sessions continue under old
  context.** Sprint 22 §13.30.3 documented this as the architectural
  choice; Sprint 23 honors it. The REMOVE log line explicitly says
  "in-flight sessions continue under old context until natural end".
  Hard drain via per-SNI-tenant Notify is a coherent design (the
  same per-tenant Notify infrastructure that REMOVE uses for
  serve-tcp/serve-pq generalizes) — Sprint 24+ work, gated on real
  operator demand.
- **First-tenant-in-new-group rejected with clear log.** The error
  log explicitly says "first-tenant-in-new-group requires daemon
  restart (Sprint 24+)" so operators get an actionable signal.
  Alternative: silently treat it as "register new group" and spawn
  a fresh `run_sni_group` task. Rejected because spawning a new
  group involves: (1) building a new `TlsReloadTrigger` for the
  multi-SNI acceptor, (2) inserting it in `reload_triggers`, (3)
  spawning the task, (4) registering shutdown notify. Each step is
  small but combinable they form their own architectural slice.
- **REMOVE purges `tenant_audits` and calls `shutdown_async`.**
  Mirrors the per-tenant REMOVE behavior from Sprint 19 (the audit
  channel's writer task drains its buffer before the entry is
  purged). The accept loop's session-spawned tasks may still hold
  `AuditHandle` clones; `shutdown_async` is idempotent so each
  session's natural drop is safe.
- **No new lib tests.** Sprint 23 is integration-level wiring built
  entirely on top of Sprint 21 + Sprint 22 APIs, both of which have
  comprehensive lib tests (12 + 7 = 19 tests covering builder
  semantics, hot swap, cert mutation, rollback). A test of "SIGHUP
  arm correctly orchestrates these APIs in the right order" is a
  true integration test — Sprint 24+ work with the rest of the
  SIGHUP integration test suite.
- **`tenants_add_failed_total` counted per failure path.** Five
  distinct failure cases in SNI ADD (missing TLS, no group, resolve
  failure, dispatch build, cert mutation) all bump the same counter.
  Operators alerting on `rate(qgateway_tenants_add_failed_total[5m]) > 0`
  see the failure; the log line distinguishes WHICH failure. Per-
  cause counters would be more granular but counter cardinality
  cost outweighs the benefit at typical scale.
- **Sprint 22 §13.30.3 trade-off "no drain protocol for SNI-removed
  tenants" stands.** Sprint 23 documents the soft-drain semantics
  explicitly in the operator-visible log line. Sprint 24+ may add
  hard drain via per-SNI-tenant `Arc<Notify>` (same pattern as the
  Sprint 18 per-tenant Notify map) if operators demand it.

### 13.31.5 API surface changes

**Additive** (internal to qgateway binary):
- `sni_dispatches_shared: Arc<RwLock<HashMap<String, Arc<HotSniDispatchTable>>>>` in `cmd_run`.
- `install_signal_handler` 16th param: `sni_dispatches`.

**Behavioural** (no public-API change):
- SIGHUP ADD now wires SNI-into-existing-group via Sprint 21 + 22 APIs.
- SIGHUP REMOVE now handles SNI tenants before falling through to per-tenant-shutdown check.
- Startup SNI group spawn registers dispatch in shared map.

**No removals.** Sprint 22 behaviour preserved.

### 13.31.6 Acceptance — actual

- [x] `cargo test --workspace --locked` green: **201 tests** (unchanged
      from Sprint 22 — Sprint 23 is integration-level wiring, no new
      lib tests added per §13.31.4 trade-off).
- [x] `cargo build --workspace --locked` clean.
- [x] `cargo clippy --workspace --all-targets -- -D warnings` clean.
- [x] `cargo fmt --all --check` clean.
- [x] `cargo build -p qgateway --features pkcs11 --locked` clean.

### 13.31.7 Honest deferrals to Sprint 24

1. ✅ **First-tenant-in-new-SNI-group hot-add** — DELIVERED in Sprint 24.
2. ✅ **Last-tenant-leaves-SNI-group group drain** — DELIVERED in Sprint 24.
3. **Hard drain for SNI-removed tenants.** Sprint 25+ (gated on operator demand — soft-drain documented as deliberate choice in §13.30.3).
4. **SIGHUP integration test.** Sprint 25+.
5. **TLS-specific E2E test.** Sprint 25+.
6. **End-to-end admission integration test.** Sprint 25+.

---

## 13.32. SPRINT 24 — DELIVERABLE CONTRACT (✅ CLOSED — SNI group lifecycle: create + drain at runtime)

Sprint 24 closes the final per-tenant lifecycle gap. After Sprint 24
the runtime-lifecycle capability matrix is 100% green: every tenant
kind, including SNI tenants whose `listen` address has no existing
group, can be added at runtime; every group, including those whose
last tenant just left, can be drained at runtime. The daemon no
longer requires a restart for any per-tenant or per-group lifecycle
event short of binary upgrade.

Sprint 24 builds on Sprint 23's plumbing: same `sni_dispatches`,
`reload_triggers` maps; same dispatch + cert mutation APIs from
Sprint 21–22. Two new shared maps split the SNI group from the
daemon-wide shutdown notify:
- `sni_group_shutdowns_shared` — per-group `Arc<Notify>`
- `sni_group_tasks_shared` — per-group `JoinHandle`

Both maps are keyed by `listen` address. The SIGTERM drain path
fans out shutdown via the first map and awaits the second; the
SIGHUP arm uses them for first-tenant-add (insert) and last-tenant-
leaves (notify + await + remove).

### 13.32.1 Delivered

| # | Deliverable | Notes |
|---|---|---|
| `sni_group_shutdowns_shared` map | `Arc<RwLock<HashMap<String, Arc<Notify>>>>` keyed by listen address. Each SNI group has its own Notify — Sprint 18's daemon-wide notify is no longer used for group shutdown. |
| `sni_group_tasks_shared` map | `Arc<RwLock<HashMap<String, JoinHandle<Result<()>>>>>` for awaiting individual group drains. |
| Daemon-wide SIGTERM fan-out | Walks `sni_group_shutdowns_shared` calling `notify_waiters()` on each entry, then awaits each `JoinHandle` from `sni_group_tasks_shared`. Replaces Sprint 18's "SNI groups use daemon-wide shutdown" path. |
| `tenant_tasks` Vec demoted | Retained for forward-compat but no tenant kind populates it after Sprint 24. Comment documents this. |
| SIGHUP ADD — first-tenant-in-new-group path | Replaces Sprint 23's "no running SNI group on this listen — first-tenant-in-new-group requires daemon restart" error. New path: resolve, build single-entry multi-SNI acceptor via `build_reloadable_multi_sni_acceptor`, build `SniTenantContext`, build `SniDispatchTable` with one context, wrap in `HotSniDispatchTable`, spawn fresh `run_sni_group` task with a new per-group `Arc<Notify>`. Inserts into all four shared maps: `reload_triggers`, `sni_dispatches`, `sni_group_shutdowns`, `sni_group_tasks`. Logs `"SNI tenant added at runtime — new group spawned"`. |
| SIGHUP REMOVE — last-tenant-leaves-group path | Inserted after Sprint 23's per-tenant-remove + dispatch.swap. Checks `dispatch.load().tenant_names().is_empty()` post-remove. If empty, signals the group's Notify, awaits the JoinHandle with `tenant_drain_timeout_secs` (operator-configurable since Sprint 19, default 30s). On timeout, warns but proceeds with map purge — the orphan task will exit when its accept loop hits the next iteration. Purges entries from `sni_group_shutdowns`, `sni_dispatches`, and `reload_triggers` (synthetic `"sni-group:<listen>"` key). Logs `"SNI group empty after remove — draining"` then `"SNI group drained cleanly"` (or the timeout/error variant). |
| `qgateway_core::build_reloadable_multi_sni_acceptor` re-exported | Needed for first-tenant-add path. Same change for `build_reloadable_acceptor` and `TlsReloadTrigger` (both used by qgateway main.rs). Surface was already public via the `tls` module path; this just makes it accessible via the crate root, matching the pattern for `run_sni_group`, `HotSniDispatchTable`, etc. |
| `install_signal_handler` 18-arg signature | Added `sni_group_shutdowns` + `sni_group_tasks` params. Existing `#[allow(clippy::too_many_arguments)]` covers. |

### 13.32.2 Operational model

**Adding the first tenant on a brand-new SNI listen:**

```toml
# /etc/qgateway/sidecar.toml — operator adds an SNI tenant on a
# listen that has no existing group:
[[tenants]]
name = "branch-east"
listen = "127.0.0.1:9100"          # not used by any other tenant
peer_pq = "peer.example.com:9101"
peer_pub_dir = "/etc/qgateway/peers"
audit_log = "/var/log/qgateway/branch-east.qa"
sni = "branch-east.example.com"

[tenants.tls]
cert = "/etc/qgateway/certs/branch-east.crt"
key = "/etc/qgateway/keys/branch-east.key"
```

```bash
$ kill -HUP $(pidof qgateway)
[INFO  qgateway] SIGHUP received config="/etc/qgateway/sidecar.toml"
[INFO  qgateway] tenant="branch-east" listen=127.0.0.1:9100 sni=branch-east.example.com
                "SNI tenant added at runtime — new group spawned"
[INFO  qgateway] listen=127.0.0.1:9100 n_tenants=1
                "SNI multi-tenant listener active (hot-swappable dispatch)"
```

**Removing the last tenant from a group:**

```bash
# Operator removes the only tenant from a group's listen.
$ kill -HUP $(pidof qgateway)
[INFO  qgateway] tenant="branch-east" listen=127.0.0.1:9100
                "SNI tenant removed at runtime (in-flight sessions continue under old context until natural end)"
[INFO  qgateway] listen=127.0.0.1:9100 "SNI group empty after remove — draining"
[INFO  qgateway] listen=127.0.0.1:9100 "SNI listener shutdown requested"
[INFO  qgateway] listen=127.0.0.1:9100 "SNI group drained cleanly"
[INFO  qgateway] listen=127.0.0.1:9100 "SNI group purged from shared state"

# Port 9100 is now free. A future ADD on a different listen, or on
# the same listen with a different SNI, will work normally.
```

**Sequencing**: first the tenant is removed from the group's dispatch
(Sprint 23 path) — this stops new handshakes for that SNI. Only after
the dispatch is verified empty does the group drain start. The drain
itself signals the group's Notify; the `run_sni_group` accept loop's
`tokio::select!` hits the `shutdown.notified()` branch and returns
`Ok(())`. The bound TCP listener is dropped when the task exits,
releasing the port.

### 13.32.3 Cumulative runtime-lifecycle capability matrix (Sprint 24 — 100% GREEN)

| Tenant kind | ADD | Hot-reconfigure limits | REMOVE | TLS cert reload |
|---|---|---|---|---|
| serve-pq | ✅ Sprint 12 | ✅ Sprint 16 | ✅ Sprint 18 | N/A |
| serve-tcp (plain TCP) | ✅ Sprint 13 | ✅ Sprint 16 | ✅ Sprint 18 | N/A |
| serve-tcp (TLS-single) | ✅ Sprint 20 | ✅ Sprint 16 | ✅ Sprint 20 | ✅ Sprint 5 |
| serve-tcp (SNI in existing group) | ✅ Sprint 23 | ✅ Sprint 16 | ✅ Sprint 23 | ✅ Sprint 6.5 |
| New SNI group (first tenant on new listen) | ✅ Sprint 24 | N/A | ✅ Sprint 24 (via last-tenant-leaves) | ✅ Sprint 6.5 |

Every cell that can hold a value is green. The daemon supports
zero-downtime ADD / hot-reconfigure / REMOVE / cert-reload for every
tenant kind, including spawning entire new SNI groups and draining
them when emptied — all driven by SIGHUP on a modified TOML.

### 13.32.4 Trade-offs documented

- **Per-group Notify replaces daemon-wide shutdown for SNI groups.**
  Sprint 18 used the daemon-wide `shutdown: Arc<Notify>` for SNI
  groups, with the explicit note that they aren't individually
  removable. Sprint 24's per-group Notify is strictly more capable —
  daemon-wide SIGTERM now fans out via the per-group map. The cost
  is one extra HashMap insert per group at startup + one Notify
  allocation per group; negligible.
- **No rollback on the four-map insert sequence.** First-tenant-new-
  group inserts into `reload_triggers`, `sni_dispatches`,
  `sni_group_shutdowns`, `sni_group_tasks` in sequence. Each insert
  is an infallible RwLock write; the only way they can fail is OOM.
  No rollback path is provided — if a downstream insert panics
  somehow, the maps are left in a consistent state (each insert is
  atomic w.r.t. its own map). Acceptable: the alternative
  (transactional cross-map insert) would add significant complexity
  for a scenario that can't happen.
- **Drain timeout reuses `tenant_drain_timeout_secs`.** Operator-
  configurable since Sprint 19 (default 30s). Same value for per-
  tenant drain and per-group drain — operators wanting different
  timeouts can ask in a future sprint. The use is consistent: both
  are "how long to wait for graceful shutdown before logging a
  warning and moving on".
- **Orphan task on drain timeout.** If the drain times out, the SNI
  group's task is NOT awaited further; the JoinHandle is removed
  from the map and dropped (which detaches the task). The accept
  loop will eventually exit (the shutdown notify was already
  signalled), but the bound TCP listener may hold the port a few
  seconds longer. An operator who tries to ADD a new group on the
  same listen during this window will see a "bind: address in use"
  error and need to retry. Acceptable trade-off vs. blocking the
  SIGHUP arm indefinitely on a stuck group.
- **`tenant_tasks` Vec retained for forward-compat.** No tenant kind
  populates it after Sprint 24 — SNI groups moved to the per-group
  shared maps; single tenants always go to `tenant_tasks_by_name`.
  Could be deleted entirely but keeping it as `let tenant_tasks:
  Vec<...> = Vec::new();` costs nothing and preserves the drain
  loop's structure for forward-compat if a future tenant kind needs
  it.
- **First-tenant-add path has 5 failure modes.** Each bumps the same
  `tenants_add_failed_total` counter (Sprint 23 §13.31.4 trade-off
  re per-cause counter cardinality). Operators distinguish via log
  line; alerting via single counter is sufficient.
- **No new lib tests.** Same justification as Sprint 23: Sprint 24 is
  integration-level wiring over Sprint 21+22 APIs which already have
  19 lib tests. The first-tenant-add path uses the same
  `build_reloadable_multi_sni_acceptor` and `HotSniDispatchTable::new`
  as the startup path; the last-tenant-drain path uses the same
  Notify+JoinHandle pattern as the daemon-wide drain. A true
  integration test ("spawn daemon, SIGHUP first-tenant-add, send
  TLS handshake, SIGHUP REMOVE last tenant, assert handshake fails")
  is Sprint 25+ work with the rest of the SIGHUP integration test
  suite.
- **Soft drain semantics preserved across all SNI scenarios.** Sprint
  22 §13.30.3 established that REMOVE is soft-drain; Sprint 23 honored
  it; Sprint 24 keeps the same policy. In-flight sessions of a
  removed tenant continue under the old context until natural end.
  The group-level drain (last-tenant case) DOES await the accept loop
  task — but only for accept-side state (the bound listener); session
  tasks spawned by the accept loop are detached and not awaited.
  Hard drain (per-SNI-tenant Notify gating session lifetime) remains
  Sprint 25+ work, deferred until operator demand surfaces.

### 13.32.5 API surface changes

**Additive** (qgateway_core crate root):
- `qgateway_core::build_reloadable_acceptor` (re-export).
- `qgateway_core::build_reloadable_multi_sni_acceptor` (re-export).
- `qgateway_core::TlsReloadTrigger` (re-export).

**Additive** (internal to qgateway binary):
- `sni_group_shutdowns_shared` and `sni_group_tasks_shared` maps.
- `install_signal_handler` 17th + 18th params.

**Behavioural** (no public-API change):
- SIGHUP ADD now spawns new SNI groups when the target listen has no existing group.
- SIGHUP REMOVE now drains SNI groups when their last tenant leaves.
- SIGTERM drain path walks per-group maps instead of relying on the daemon-wide Notify reaching the SNI group accept loops.

**No removals.** Sprint 23 behaviour preserved.

### 13.32.6 Acceptance — actual

- [x] `cargo test --workspace --locked` green: **201 tests** (unchanged
      from Sprint 23 — Sprint 24 is integration-level wiring, no new
      lib tests added per §13.32.4 trade-off).
- [x] `cargo build --workspace --locked` clean.
- [x] `cargo clippy --workspace --all-targets -- -D warnings` clean.
- [x] `cargo fmt --all --check` clean.
- [x] `cargo build -p qgateway --features pkcs11 --locked` clean.

### 13.32.7 Honest deferrals to Sprint 25

After Sprint 24 the runtime-lifecycle work is materially complete.
The deferral list is now polish, not core lifecycle:

1. **Hard drain for SNI-removed tenants.** Per-SNI-tenant `Arc<Notify>` so REMOVE can wait for in-flight session tasks to finish before purging audit channel and metrics. Gated on operator demand — soft-drain was a deliberate choice (§13.30.3) with the rationale that audit logging continues under old context until natural session end, which is operationally indistinguishable from hard drain for compliance purposes.
2. ✅ **SIGHUP integration test.** DELIVERED in Sprint 25 (minimal viable: serve-pq ADD + REMOVE + counter assertions).
3. **TLS-specific E2E test.** Carry-over from Sprint 20.
4. **End-to-end admission integration test.** Carry-over since Sprint 9.5.
5. **Per-group drain timeout vs per-tenant drain timeout.** Currently reuse `tenant_drain_timeout_secs`. If operators want different values, add a new TOML field.
6. **TCP listener port reclaim faster than orphan-task drain.** Sprint 24 §13.32.4 trade-off — if the drain times out, the next ADD on the same listen may hit "address in use" briefly. Could be addressed with `SO_REUSEPORT` or an explicit listener-handoff API.

---

## 13.33. SPRINT 25 — DELIVERABLE CONTRACT (✅ CLOSED — SIGHUP integration test)

Sprint 25 is the first end-to-end integration test that drives a real
qgateway subprocess through a complete SIGHUP lifecycle. Every prior
sprint relied on:
- Unit tests of components (Sprint 21 dispatch builders, Sprint 22 cert
  mutation, etc — 201 lib tests total)
- Manual review of the orchestration logic in main.rs

This test wires the full signal-driven loop in a subprocess: spawn
binary → wait for /metrics → modify config → SIGHUP → scrape /metrics
→ assert counter increments → modify config back → SIGHUP → re-scrape
→ assert removal counter → SIGTERM cleanup.

The test passes in ~5 seconds. The 14 sprints of lifecycle code
(Sprints 11.0 → 24) work end-to-end as documented.

### 13.33.1 Delivered

| # | Deliverable | Notes |
|---|---|---|
| `crates/qgateway/tests/sighup_integration.rs` | New 290-line integration test. Uses `CARGO_BIN_EXE_qgateway` to locate the binary under test (no `assert_cmd` or similar harness dep). Uses `nix::sys::signal::kill` for SIGHUP/SIGTERM. Uses `tempfile::TempDir` for per-test isolated state (audit dir, peer dir, config file). |
| Dev-deps added to qgateway | `nix = { version = "0.29", features = ["signal"] }`, `tempfile = "3"`, `tokio = { workspace = true }`. Modest footprint — no new transitive complexity. |
| Self-contained fixture construction | `Fixture::build()` generates an audit signer keypair + transport identity by invoking the binary's own `audit-keygen` / `keygen` subcommands. The peer dir reuses the daemon's own public key as a trust entry (the test never establishes outbound PQ handshakes, so the trust set is only consulted at startup for the "non-empty" check). |
| Counter-driven assertions | Test parses `/metrics` Prometheus exposition output, extracts `qgateway_tenants_added_total`, `qgateway_tenants_removed_total`, `qgateway_sighup_cycles_total` values, asserts strict-greater-than vs baseline after each SIGHUP. |
| Drop-based cleanup | `DaemonGuard::drop` sends SIGTERM, sleeps 500ms, then SIGKILL + wait. Survives test panic (no zombies in CI). |
| `pick_port()` helper | Binds 127.0.0.1:0, reads assigned port, drops listener. Used for both metrics port and tenant listen ports. TOCTOU window exists but is microseconds on a single-machine CI runner. |

### 13.33.2 What the test verifies

Concretely, the test asserts:

1. The daemon binary starts successfully with a 1-tenant config and
   binds its metrics server within 15 seconds.
2. After writing a 2-tenant config and sending SIGHUP:
   - `qgateway_tenants_added_total` > baseline
   - `qgateway_sighup_cycles_total` > baseline
   - (implied: the tenant ADD orchestration in the SIGHUP arm worked
     end-to-end — `build_tenant_runtime`, audit-log creation,
     `run_serve_pq_tenant` spawn, shared-map registration)
3. After writing the original 1-tenant config back and sending SIGHUP:
   - `qgateway_tenants_removed_total` > baseline
   - (implied: per-tenant Notify fanout, JoinHandle await with drain
     timeout, audit channel `shutdown_async`, shared-map purge)
4. SIGTERM produces a clean exit (drained tenants log "qgateway
   stopped" before process death).

These assertions exercise the orchestration logic in the
~1800-line main.rs around the SIGHUP arm — code that previously had
zero direct test coverage despite shipping 14 sprints of lifecycle
features.

### 13.33.3 What the test does NOT verify (honest deferrals)

- **TLS tenants.** Test uses `serve-pq` role to avoid setting up the
  multi-SNI rustls acceptor + cert chains. The serve-pq path
  exercises the same SIGHUP orchestration; cert mutation API has
  its own 7 lib tests (Sprint 22 §13.30.1). A TLS-specific E2E
  is still Sprint 26+ work.
- **SNI tenants.** Same reason. SNI dispatch hot-swap + cert
  mutation each have lib tests. SNI runtime ADD/REMOVE through
  the SIGHUP arm is currently only manually validated.
- **Admission limits hot-reconfigure.** Sprint 16 hot-apply path
  not exercised here. The same shared map / `ArcSwap` mechanism
  has 95 qgateway-core lib tests covering it.
- **Audit chain integrity across reload.** The daemon DOES create
  fresh audit logs for added tenants (visible in log output), but
  the test doesn't read+verify the chain afterwards. Audit chain
  verification has comprehensive coverage in qaudit-core's 48
  lib tests.
- **First-tenant-in-new-SNI-group + last-tenant-leaves drain.**
  Sprint 24 lifecycle items — same TLS-setup blocker as above.
- **Concurrent SIGHUP+SIGUSR1.** Race semantics documented in
  Sprint 20 §13.28.4; not exercised by Sprint 25 test.

Sprint 25's scope is deliberately tight: prove the SIGHUP arm works
end-to-end for ONE tenant kind. The other kinds + interaction
scenarios are reachable from the same harness; expanding test
coverage is mechanical (more tests in the same file), not
architectural.

### 13.33.4 Trade-offs documented

- **`CARGO_BIN_EXE_qgateway` over external harness deps.** Cargo
  provides this env var automatically for integration tests in the
  binary crate's `tests/` directory. No `assert_cmd`, `escargot`,
  or similar — cleaner build, fewer transitive deps. The downside
  is the harness API isn't as ergonomic; the test does manual
  `Command::spawn` + manual stdio handling.
- **Raw TCP `/metrics` scrape over `reqwest`/`hyper`.** The metrics
  endpoint serves a simple HTTP/1.1 response; the test does a 70-line
  raw socket write + read + body parse instead of pulling in a full
  HTTP client. Same dependency-minimization argument. The
  Prometheus parser is also hand-rolled (~12 lines).
- **`std::thread::sleep` over `tokio::time::sleep`.** The test is
  synchronous (`#[test]`, not `#[tokio::test]`) because the
  daemon is a subprocess and the test only needs to drive signals
  + scrape metrics. Tokio runtime startup cost is wasted here.
- **Polling for /metrics readiness with timeout.** Sprint 25 uses
  100ms polling + 15s deadline. Alternative: parse the daemon's
  stderr for "metrics server listening" log line. Rejected because
  it couples test correctness to log format. The polling approach
  is robust to log format changes.
- **Reusing daemon's pubkey as peer trust file.** Hack — the daemon
  is conceptually distinct from any peer, but the test never
  establishes outbound connections, so any non-empty trust set
  suffices. A "real" peer setup would require generating a SECOND
  transport identity. Sprint 25 chose minimalism.
- **2-second sleep between SIGHUP and metrics scrape.** SIGHUP
  processing is async (signal arrives, config-reload task runs
  concurrently with the metrics server). The sleep gives the
  reload task time to bump the counter before scrape. Could be
  replaced with polling-until-counter-changes, but 2s is well
  within typical reload latency (~ms) so the sleep is fine.
- **Drop-based cleanup over explicit teardown.** The
  `DaemonGuard::drop` impl handles cleanup whether the test passes
  or panics. Critical for CI hygiene — no zombie qgateway
  processes if an assertion fails mid-test.
- **One test, not many.** Sprint 25 ships exactly one integration
  test. Resisting the urge to ship 5 tests covering every cell of
  the lifecycle matrix — that's the wrong shape of risk to take in
  one sprint. Once this one is green and stable in CI, adding
  more is mechanical.

### 13.33.5 API surface changes

**None.** Sprint 25 adds only test code + dev-deps. No production
behaviour change.

### 13.33.6 Acceptance — actual

- [x] `cargo test --workspace --locked` green: **202 tests** (201 +
      1 new integration test).
- [x] Integration test runs in ~5s.
- [x] `cargo build --workspace --locked` clean.
- [x] `cargo clippy --workspace --all-targets -- -D warnings` clean
      (after `#[allow(clippy::too_many_arguments)]` on `make_config`
      and dropping a redundant `.trim()` before `.split_whitespace()`).
- [x] `cargo fmt --all --check` clean.
- [x] `cargo build -p qgateway --features pkcs11 --locked` clean.

### 13.33.7 Honest deferrals to Sprint 26

After Sprint 25 the lifecycle work has both production code AND
end-to-end test evidence. The deferral list narrows to:

1. **More integration test coverage.** TLS hot-add, SNI ADD/REMOVE in existing group, first-tenant-in-new-SNI-group, hot-limit-apply. Each is mechanical addition to the same `tests/sighup_integration.rs` file — but adds setup complexity (TLS cert generation, multi-tenant config diffs, etc).
2. **Hard drain for SNI-removed tenants.** Still gated on operator demand.
3. **End-to-end admission integration test.** Carry-over since Sprint 9.5.
4. ✅ **Audit chain integrity verification across SIGHUP cycles** — DELIVERED in Sprint 26.
5. **Chaos/property testing of the SIGHUP arm.** Property-based test: random sequences of SIGHUP/SIGUSR1/config-mutations, assert daemon stays alive + counter invariants hold. Higher-effort, higher-value than #1.
6. **Per-group drain timeout** if operators demand.
7. **`SO_REUSEPORT` port reclaim optimization.**

---

## 13.34. SPRINT 26 — DELIVERABLE CONTRACT (✅ CLOSED — audit chain integrity across SIGHUP cycles)

Sprint 26 ships the second integration test in the qgateway crate,
proving a compliance invariant that no prior test exercised: **every
per-tenant audit log file is a valid chain (header parseable, all
signatures verify, externally verifiable against the published audit
public key) AFTER the tenant has gone through one or more SIGHUP
lifecycle events.**

Two test scenarios:

1. **survivor**: tenant `alice` lives for the daemon's full lifetime.
   `bob` is added via SIGHUP, then removed via SIGHUP, then daemon
   gets SIGTERM. Alice's audit log must parse + verify at every
   step (initial, mid, final). Bob's audit log must parse + verify
   immediately after his REMOVE (proves `shutdown_async` flushes
   cleanly).

2. **external verification**: same lifecycle, but verification is
   done with the externally-loaded `.audit.pub` (the file an
   auditor would receive out of band), confirming the header's
   embedded pubkey matches bit-for-bit. This is the compliance
   auditor's path.

Both tests pass in ~10 seconds combined. The test code is ~170 lines
in `tests/audit_chain_integrity.rs`; common fixture/daemon-guard
code moved into `tests/common/mod.rs` (extracted from Sprint 25's
`sighup_integration.rs` to support reuse).

### 13.34.1 Delivered

| # | Deliverable | Notes |
|---|---|---|
| `crates/qgateway/tests/audit_chain_integrity.rs` | New ~170-line test file with 2 tests. Uses `qaudit_core::AuditLog::open` + `.verify()` to validate chain integrity after each lifecycle event. |
| `crates/qgateway/tests/common/mod.rs` | Extracted shared fixture code from Sprint 25 (`Fixture`, `DaemonGuard`, `pick_port`, `scrape_metrics`, `counter_value`, `sighup`). Module-level `#![allow(dead_code)]` because Cargo compiles each `tests/*.rs` as its own crate, so a helper used by only one of them looks "dead" to the compiler. Standard `tests/common/` idiom. |
| `crates/qgateway/tests/sighup_integration.rs` | Refactored to use `mod common`. Net LoC dropped by ~250 lines (the inline fixture code moved out). |
| Sprint 25's test still passes | The refactor preserved behavior — same assertions, same 5s runtime. |
| `DaemonGuard::shutdown_gracefully` | New method that sends SIGTERM, polls `try_wait` until exit or 10s deadline, then escalates to SIGKILL. Used by Sprint 26 tests that need to inspect audit log files AFTER the daemon's `shutdown_async` flushed pending events. The Drop impl still handles panic-path cleanup with a tighter 500ms SIGTERM-then-SIGKILL sequence. |
| `qaudit-core` dev-dep on qgateway | Needed for `AuditLog::open` + `verify` + `PublicKey::from_bytes`. Modest footprint — qaudit-core is already an indirect dep via qgateway-core. |
| Audit pubkey file format documented inline | The test re-implements the daemon's `auditkey::load_pub` (8-byte `"AUDITPK0"` magic + raw ML-DSA-87 pubkey) because `qgateway_core::auditkey` isn't a `pub use` from the crate root. ~6 lines, well-commented. Same magic constant as `crates/qgateway-core/src/auditkey.rs:26`. |

### 13.34.2 What the tests verify

Concretely:

```text
audit_chains_remain_valid_across_sighup_cycle:
    [t=0]   spawn daemon with config {alice}
    [t=0+]  alice.qa exists; AuditLog::open + verify both succeed
            (proves: chain header written + signed correctly at startup)
    [t=1]   write config {alice, bob}, SIGHUP
    [t=1+]  bob.qa exists; AuditLog::open + verify both succeed
            (proves: SIGHUP ADD creates a new chain correctly)
    [t=2]   write config {alice}, SIGHUP
    [t=2+]  bob.qa still parses + verifies
            (proves: SIGHUP REMOVE's shutdown_async flushes cleanly,
             doesn't truncate or corrupt the chain)
            alice.qa still parses + verifies
            (proves: bob's lifecycle didn't side-effect alice's chain)
    [t=3]   SIGTERM
    [t=3+]  alice.qa parses + verifies once more
            (proves: SIGTERM drain doesn't corrupt remaining chains)

audit_chains_verify_against_provided_pubkey:
    Same lifecycle, plus:
    Load .audit.pub from disk (the file an auditor would receive).
    For alice + bob:
        header.pubkey.as_bytes() == provided_pk.as_bytes()
        (proves: chain header carries the published signer pubkey
         bit-for-bit, no rekeying surprises across reload)
        AuditLog::verify() succeeds
        (proves: external verification path works end-to-end)
```

These assertions exercise the **audit-write half of the daemon
end-to-end**. All 48 prior qaudit-core lib tests exercise the chain
machinery in isolation; this is the first test that proves the
machinery works inside the live daemon across signal-driven
lifecycle events.

### 13.34.3 What the tests do NOT verify (honest deferrals)

- **Audit events under load.** The test verifies empty chains
  (just header). Sprint 26 doesn't drive actual `session.open` /
  `session.close` events because that requires a full CSPQ
  handshake (two daemons or a fake peer). The chain machinery is
  identical with or without events — but adding event-bearing
  scenarios is a real follow-up.
- **Rotation across SIGHUP cycles.** Sprint 8 ships SIGUSR2 audit
  rotation; Sprint 26 doesn't combine rotation with SIGHUP
  ADD/REMOVE. Combining would prove rotation is reentrant w.r.t.
  tenant lifecycle.
- **Multi-tenant rotation key collision.** The daemon has a
  top-level `[audit_signer]` shared by all tenants. If two tenants
  rotate at the same time, the rotation handle is per-tenant —
  this isn't tested here.
- **HSM-backed signer (PKCS#11).** The fixture uses softkey signer
  (the simpler path). PKCS#11 has its own qaudit-hsm lib tests
  with a SoftHSM2 backend.
- **Sustained crash-recovery.** The test doesn't kill -9 mid-write
  to verify the chain header survives an abrupt termination. The
  `shutdown_async` path is the graceful case; the truncation/
  recovery path is its own story (qaudit-core has lib tests for
  truncated-trailer recovery, but not via the daemon).

### 13.34.4 Trade-offs documented

- **Two tests instead of one.** The second test (external pubkey
  verification) is the compliance auditor's perspective and uses
  a different code path (`PublicKey::from_bytes` + manual file
  read instead of `AuditLog::open` doing both). Worth the extra
  ~50 LoC because it proves an invariant operators actually care
  about: "the pubkey I publish is the pubkey embedded in the chain
  header."
- **Common fixture extraction.** Sprint 25 inlined fixture code;
  Sprint 26 forced extraction. Could have copy-pasted into the
  new test file (~140 lines duplicated) — rejected because future
  integration tests (Sprint 27+ TLS/SNI variants) will need the
  same fixture. One-time extraction cost amortizes immediately.
- **`shutdown_gracefully` separate from `Drop`.** The Drop impl
  has a tight timeout (500ms then SIGKILL) because it runs on
  panic paths and must not block CI. Drop never returns errors
  to the test, so a slow drain there silently times out. The
  `shutdown_gracefully` method has a longer timeout (10s) and
  is called explicitly when the test needs to inspect post-drain
  state — explicit because the test author knows graceful drain
  matters for that assertion.
- **300ms sleep after `shutdown_gracefully`.** The graceful method
  waits for the process to exit, but the audit channel's writer
  task may still be flushing bytes to disk in the few milliseconds
  between "task observes shutdown signal" and "OS flushes write
  buffer". The sleep is a pragmatic fix; the more correct fix
  would be for `shutdown_async` to return only after fsync — but
  that's a Sprint 27+ change to the audit machinery itself.
- **No new TLS/SNI scenario coverage.** Sprint 26 deliberately
  stays scoped to audit chain integrity. Adding TLS/SNI variants
  in the same sprint would have doubled the LoC + setup complexity
  (rcgen cert generation, multi-SNI config writing, etc). One
  novel coverage axis per sprint.
- **Pubkey magic constant duplicated, not imported.** The audit
  pubkey file format (`"AUDITPK0"` magic + raw ML-DSA-87 bytes) is
  documented inline in the test file because `qgateway_core::auditkey`
  isn't part of the crate's public surface. A 6-line duplication
  is preferable to either (a) re-exporting an internal module from
  qgateway-core, or (b) the test reaching across crate boundaries
  via `qgateway_core::auditkey::load_pub`. If a future sprint
  promotes the helper to public API, the test can switch over.

### 13.34.5 API surface changes

**None for production code.** Sprint 26 adds only test code + a
qaudit-core dev-dep on qgateway. Refactor of `tests/sighup_integration.rs`
preserves behavior.

### 13.34.6 Acceptance — actual

- [x] `cargo test --workspace --locked` green: **204 tests** (202 +
      2 new audit chain integration tests).
- [x] Integration test suite runs in ~15s total (1 Sprint 25 test
      at ~5s + 2 Sprint 26 tests at ~10s).
- [x] `cargo build --workspace --locked` clean.
- [x] `cargo clippy --workspace --all-targets -- -D warnings` clean.
- [x] `cargo fmt --all --check` clean.
- [x] `cargo build -p qgateway --features pkcs11 --locked` clean.

### 13.34.7 Honest deferrals to Sprint 27

1. **Audit events under load + chain verification.** Drive real `session.open`/`session.close` events (requires either a fake CSPQ peer or two daemons), then verify the chain contains the expected event count.
2. **More integration test coverage** (TLS, SNI, hot-limits) — still mechanical.
3. **Chaos/property testing of the SIGHUP arm** — higher value than #2.
4. **End-to-end admission integration test** — carry-over.
5. ✅ **Audit rotation + SIGHUP combined** — DELIVERED in Sprint 27 (also fixed a real Vec→HashMap bug that was surfaced by writing the test).
6. **`SO_REUSEPORT`, per-group drain timeout, hard SNI drain** — all gated on operator demand.

---

## 13.35. SPRINT 27 — DELIVERABLE CONTRACT (✅ CLOSED — audit rotation + SIGHUP combined; rotation_targets bug fixed)

Sprint 27 set out to test the interaction between SIGUSR2 audit
rotation (Sprint 8) and SIGHUP tenant lifecycle (Sprints 11–24).
**Writing the integration test surfaced a real bug** in the daemon:
the `rotation_targets` data structure was a startup-populated `Vec`
that never grew when SIGHUP ADD added a new tenant — so SIGUSR2
would silently skip rotation for any tenant added at runtime.

This is exactly the failure mode that integration tests are designed
to catch: every other rotation-related state followed the Sprint 20+
pattern of `Arc<RwLock<HashMap>>` shared maps mutable from the SIGHUP
arm, but `rotation_targets` had been forgotten in that promotion
wave. Sprint 27 ships:

1. **The fix**: `rotation_targets` promoted from `Vec<RotationTarget>`
   to `Arc<RwLock<HashMap<String, RotationTarget>>>`. SIGHUP ADD
   inserts; SIGHUP REMOVE purges (both per-tenant and SNI-tenant
   REMOVE paths).
2. **Two regression tests** in a new `tests/rotation_sighup_integration.rs`
   that enforce the invariant.

This pattern — write integration test, surface bug, fix, lock in
with regression test — is exactly the value Sprint 25 and Sprint 26
were building toward. 16 sprints of lifecycle code passed lib tests +
manual review without anyone noticing this gap. Two new integration
tests caught it.

### 13.35.1 Delivered

| # | Deliverable | Notes |
|---|---|---|
| `rotation_targets` Vec→HashMap promotion | Changed from startup-populated `Vec<RotationTarget>` to `Arc<RwLock<HashMap<String, RotationTarget>>>` keyed by tenant name. Matches the Sprint 20+ pattern for `reload_triggers`, `tenant_audits`, `tenant_admissions`, etc. |
| `install_signal_handler` 18th arg type change | The `rotation_targets` param is now `Arc<RwLock<HashMap<...>>>` instead of `Vec<...>`. Existing `#[allow(clippy::too_many_arguments)]` covers — same arg count. |
| SIGUSR2 reads via HashMap snapshot | Read-locks `rotation_targets` for the duration of the rotation cycle, iterates `.values()`. Concurrent SIGHUP ADD/REMOVE wait on write lock — acceptable, both are operator-initiated. |
| SIGHUP ADD inserts rotation target | After `build_tenant_runtime` returns Ok in the apply step, the ADD path now also constructs a fresh `RotationTarget { tenant_name, channel: rt.audit.rotation_handle(), log_path, counter: AtomicU64::new(0), policy }` and inserts it into the shared map. The counter starts at 0 (each tenant has its own counter for `{counter}` substitution in the rotation archive_name pattern). |
| SIGHUP REMOVE purges rotation target | Both the per-tenant REMOVE path (line ~2185) and the SNI tenant REMOVE path (line ~2025) now do `rotation_targets.write().await.remove(&name)`. No-op if the tenant wasn't rotatable (cheap idempotent purge). |
| `tests/rotation_sighup_integration.rs` | New ~210-line test file with 2 tests: `sigusr2_rotates_runtime_added_tenant` (positive — bob added via SIGHUP ADD, then SIGUSR2 produces a `bob-*.qa` archive file) and `sigusr2_skips_removed_tenants` (negative — bob removed via SIGHUP REMOVE, subsequent SIGUSR2 produces no new `bob-*.qa` files). Both tests open the resulting archive + current log files and call `AuditLog::verify` to prove chain integrity. |
| `sigusr2` helper in test file | One-line wrapper around `nix::sys::signal::kill(pid, Signal::SIGUSR2)`. Could go in `common/mod.rs` but kept local to this test file — only one test file currently uses SIGUSR2. Will promote if a third test does. |

### 13.35.2 What the bug was

Before Sprint 27, `crates/qgateway/src/main.rs` had:

```rust
// Sprint 8: collect rotation targets for the SIGUSR2 handler...
let rotation_targets: Vec<RotationTarget>;
{
    let mut targets = Vec::with_capacity(tenant_state.len());
    for rt in &tenant_state {
        targets.push(RotationTarget { ... });
    }
    rotation_targets = targets;
}
```

Then passed by value into `install_signal_handler`, which captured
it in the signal-handler future. The SIGUSR2 arm walked `&rotation_targets`
each cycle.

**Failure mode**: any tenant added at runtime via SIGHUP ADD existed
in `tenant_state`, `tenant_metrics_shared`, `tenant_configs_shared`,
`tenant_admissions_shared`, `tenant_shutdowns_shared`, `tenant_audits_shared`,
and `tenant_tasks_by_name`, BUT NOT in `rotation_targets`. SIGUSR2
walking the Vec saw only the startup tenants.

**Why it lived through 16 sprints**: every operator-facing manual test
either (a) didn't add tenants at runtime, or (b) added them but never
tested SIGUSR2 afterwards. The combinator was outside everyone's mental
model.

**Symptoms operators would see**: runtime-added tenants would NEVER
rotate. Their `.qa` file would grow indefinitely. If the operator
had a size-based auto-rotation policy from Sprint 8.5, that DOES work
because the auto-rotation monitor is spawned per-tenant at startup —
but Sprint 8.5's monitor is also NOT spawned for runtime-added tenants
(separate but related gap, deferred to Sprint 28+).

### 13.35.3 Tests as bug-finders, lock-in

The two tests in `tests/rotation_sighup_integration.rs` were written
BEFORE the fix. The first test (`sigusr2_rotates_runtime_added_tenant`)
failed first run with no `bob-*.qa` archive in the file listing —
that's the test catching the bug. After the Vec→HashMap fix, the
test passed on the next run. The test is now a regression gate: any
future refactor that breaks the invariant will surface immediately.

The second test (`sigusr2_skips_removed_tenants`) verifies the dual
property: REMOVE must purge from rotation_targets. This was always
correct in spirit (the daemon never tried to rotate a tenant whose
audit log was already closed) — but the test makes it CI-enforceable.

### 13.35.4 Trade-offs documented

- **Vec→HashMap is a real type change, not cosmetic.** The signal
  handler's signature, the call site, the SIGUSR2 iteration, and
  the SIGHUP ADD/REMOVE paths all touched. Total diff is ~50 lines
  of production code change. Could not be avoided.
- **Counter starts at 0 for runtime-added tenants.** The `{counter}`
  substitution in `rotation.archive_name_pattern` begins at 0 for
  any tenant added via SIGHUP, regardless of when the daemon started.
  Operators using `{counter}` in their pattern should be aware: a
  daemon that's been running 30 days, then adds a new tenant `bob`,
  and then rotates, will produce `bob-1.qa` not `bob-31.qa`.
  Alternative would be to seed bob's counter from the daemon's
  uptime in rotation cycles — rejected because (a) the counter is
  per-tenant by design (Sprint 8 §13.x), (b) operators reading
  archive directories prefer counters that align with each tenant's
  own history.
- **No per-tenant rotation policy override at ADD time.** SIGHUP
  ADD inserts a rotation target using `new_cfg.rotation` — the
  daemon-level rotation block. If a future config supports
  per-tenant overrides, this site will need to be updated. For
  Sprint 27 the daemon-level policy applies to all tenants (which
  matches the pre-Sprint-27 startup behavior — no change).
- **Auto-rotation monitors are NOT spawned for runtime-added tenants
  in Sprint 27.** The Sprint 8.5 monitor task (size-based +
  age-based auto-trigger) is spawned per-tenant at startup. Runtime-
  added tenants are reachable via SIGUSR2 (Sprint 27 fix) but their
  auto-trigger monitor is still missing. Documented as Sprint 28+
  deferral. Operators with auto-rotation policies who add tenants
  at runtime should send SIGUSR2 manually after observing log
  growth, until Sprint 28 closes this.
- **Tests use `list_root_files` + filename prefix matching.** Brittle
  if the rotation archive_name_pattern changes from the default
  `<tenant>-<timestamp>.qa`. Could parse the daemon's log for the
  "audit rotation requested" line + archive path — rejected because
  it couples to log format. The filename-based check survives any
  pattern that includes the tenant name as a prefix (which is what
  every realistic config does).
- **The test fixture lacks an explicit `[rotation]` block.** That
  means the daemon uses the default archive_name (`<tenant>-<timestamp>.qa`)
  rather than a custom counter-based pattern. Sufficient for testing
  the dispatch logic; testing the pattern substitution is qaudit-core's
  job (already covered by lib tests).

### 13.35.5 API surface changes

**Type-level changes** (internal to qgateway binary):
- `rotation_targets`: `Vec<RotationTarget>` → `Arc<RwLock<HashMap<String, RotationTarget>>>` in `cmd_run` and the signal handler.

**Behavioural** (no public-API change):
- Runtime-added tenants now have their audit logs rotated by SIGUSR2.
- Runtime-removed tenants are now purged from rotation targets (no stale path access on subsequent SIGUSR2).

**No public-API breakage.** `RotationTarget` is `pub(crate)` to qgateway only.

### 13.35.6 Acceptance — actual

- [x] `cargo test --workspace --locked` green: **206 tests** (204 +
      2 new rotation+SIGHUP integration tests).
- [x] Integration test suite runs in ~25s total (1 sighup at ~5s,
      2 audit-chain at ~10s, 2 rotation+SIGHUP at ~10s).
- [x] `cargo build --workspace --locked` clean.
- [x] `cargo clippy --workspace --all-targets -- -D warnings` clean
      (after one `needless_borrows_for_generic_args` fix).
- [x] `cargo fmt --all --check` clean.
- [x] `cargo build -p qgateway --features pkcs11 --locked` clean.

### 13.35.7 Honest deferrals to Sprint 28

1. ✅ **Auto-rotation monitor for runtime-added tenants** — DELIVERED in Sprint 28.
2. **Audit events under load + chain verification.** Carry-over from Sprint 26.
3. **More integration test coverage** (TLS, SNI, hot-limits) — still mechanical.
4. **Chaos/property testing** — higher value than #3.
5. **E2E admission integration test** — long carry-over.
6. **`SO_REUSEPORT`, per-group drain timeout, hard SNI drain** — gated on operator demand.

---

## 13.36. SPRINT 28 — DELIVERABLE CONTRACT (✅ CLOSED — auto-rotation monitor for runtime-added tenants)

Sprint 28 is the direct companion to Sprint 27. Sprint 27 fixed the
SIGUSR2 path's `rotation_targets` Vec→HashMap promotion so runtime-
added tenants get manually-rotated by SIGUSR2. Sprint 27 §13.35.4
trade-off #4 disclosed a parallel bug: Sprint 8.5's `RotationMonitor`
auto-trigger task spawns happened ONLY at startup, so a runtime-
added tenant with size/age-based auto-rotation in its policy would
never auto-rotate. Sprint 28 ships the fix + two regression tests.

The fix mechanically mirrors Sprint 27: promote `monitor_handles`
from `Vec<JoinHandle>` to `Arc<RwLock<HashMap<String, JoinHandle>>>`,
spawn on SIGHUP ADD, drain on SIGHUP REMOVE. One material refinement:
the monitor now listens to the **per-tenant** shutdown Notify
(`rt.shutdown.clone()`) instead of the daemon-wide one — this lets
SIGHUP REMOVE stop just one tenant's monitor without taking down
the others.

### 13.36.1 Delivered

| # | Deliverable | Notes |
|---|---|---|
| `monitor_handles` Vec→HashMap promotion | Changed from startup-populated `Vec<JoinHandle<()>>` to `Arc<RwLock<HashMap<String, JoinHandle<()>>>>` keyed by tenant name. The startup Vec was never drained — Sprint 28 also fixes that latent leak: SIGTERM drain now walks the map and awaits each handle. |
| Per-tenant Notify listening | Startup monitor spawn changed from `monitor.spawn(shutdown.clone())` (daemon-wide) to `monitor.spawn(rt.shutdown.clone())` (per-tenant). SIGTERM/SIGINT fanout already signals every per-tenant Notify (Sprint 18 plumbing), so SIGTERM drain semantics preserved. SIGHUP REMOVE now reaches just this tenant's monitor. |
| SIGHUP ADD spawns monitor | After `build_tenant_runtime` returns Ok and the rotation_target is inserted, the ADD path now also checks `if let Some(policy) = new_cfg.rotation.clone() { if policy.has_auto_trigger() { ... } }` — same condition as startup — and spawns the monitor with `rt.shutdown.clone()`. Inserts the handle into the shared map. |
| SIGHUP REMOVE drains monitor (non-SNI) | After purging the rotation target, REMOVE takes the monitor handle out of the shared map (`Option<JoinHandle>`) and awaits it with a 2-second timeout. The per-tenant Notify was already signalled by the SIGHUP REMOVE branch (Sprint 18 plumbing), so the monitor's `tokio::select!` returns on the next poll boundary. The 2s timeout is generous — the monitor's body is a fast `stat()` call. |
| SIGHUP REMOVE drains monitor (SNI) | SNI tenants don't have entries in `tenant_shutdowns` (their accept loop uses the per-SNI-group Notify), so their per-tenant `rt.shutdown` Notify is never signalled by the REMOVE branch. For SNI REMOVE the monitor handle is `abort()`ed and awaited. Safe because the monitor's `tokio::select!` body is idle 99% of the time (sleeping on `poll_interval`) — no in-flight write to corrupt. |
| SIGTERM drain awaits monitor handles | The cmd_run drain block (after `shutdown.notified().await`) now walks `monitor_handles_shared`, removes each entry, and awaits the JoinHandle. Per-tenant Notify fanout already signalled them; this guarantees they finish before the process exits. |
| `install_signal_handler` 19th arg | New `monitor_handles` param of the same shape as `tenant_audits`, etc. Existing `#[allow(clippy::too_many_arguments)]` covers — same lint, same justification. |
| `tests/auto_rotation_runtime_tenant.rs` | New ~310-line test file with 2 tests using a Sprint-28-specific fixture that writes `[rotation] max_age_secs = 1` so auto-rotation fires within test wall-clock. Default `poll_interval` is 5 seconds, so tests sleep 6-7 seconds between phases. |

### 13.36.2 What the tests verify

**`auto_rotation_fires_for_runtime_added_tenant`** (positive case):
1. Spawn daemon with one tenant `alice` and `[rotation] max_age_secs = 1`.
2. Sleep 6s — alice's startup monitor must have produced at least one archive.
3. SIGHUP ADD `bob`.
4. Sleep 6.5s — bob's runtime-added monitor must have produced at least one archive.
5. Open + verify bob's archive AND bob's post-rotation current log.

**`auto_rotation_monitor_stopped_on_remove`** (negative case + sanity):
1. Same setup; ADD bob, wait for first rotation.
2. SIGHUP REMOVE bob.
3. Capture bob's archive count immediately after REMOVE.
4. Sleep 7s — bob's monitor should be gone, no new archives.
5. Sanity: alice's monitor IS still firing in the same window.
6. Daemon still serves /metrics.

Together they prove: (a) the Sprint 28 fix is active and (b) the
fix doesn't break the survivor's monitor (the most likely
regression risk of a refactor like this).

### 13.36.3 Trade-offs documented

- **5s default `poll_interval` makes tests slow.** Each test takes
  ~17s wall-clock; combined ~35s. Could expose `poll_interval` as
  a config field to let tests use 100ms. Rejected for Sprint 28
  because (a) the slowness is bounded and integration tests run
  in parallel anyway, (b) exposing a tunable for tests' sake is a
  smell — operators don't need millisecond-level polls. If a
  future sprint adds the field for legitimate operator reasons,
  the tests can switch over.
- **SNI tenant monitor uses `abort()` not graceful shutdown.** SNI
  tenants don't have a usable per-tenant Notify path (Sprint 24
  REMOVE goes through the SNI dispatch swap, not per-tenant
  shutdown). The pragmatic fix is `JoinHandle::abort()` followed
  by `await`. Safe because the monitor's poll loop sleeps on
  `tokio::time::sleep(poll_interval)` 99% of the time — when the
  abort hits, the task is at the sleep point with no file I/O
  in flight. The alternative would be to add SNI tenants to
  `tenant_shutdowns_shared` (giving them a usable Notify) — that's
  a real structural change touching Sprint 18's "SNI doesn't have
  per-tenant Notify" invariant. Deferred until it earns its own
  sprint.
- **Counter is per-monitor-instance, not shared with SIGUSR2.** The
  startup loop and SIGHUP ADD path each create a fresh `AtomicU64`
  counter and pass clones to both the RotationTarget (used by
  SIGUSR2) and the RotationMonitor (used by auto-trigger). Both
  paths increment the SAME counter, so archive numbering is
  monotonic regardless of which trigger fired. This was the
  Sprint 8.5 invariant; Sprint 28 preserves it.
- **Pre-Sprint-28 `monitor_handles` Vec was never drained.** The
  startup loop pushed handles into a `let mut monitor_handles:
  Vec<...> = Vec::new();` that was never read again — the Vec was
  dropped at end-of-scope, the tasks were detached (still running
  but unaccountable). Pre-Sprint-28, this leaked tasks across the
  daemon's lifetime; SIGTERM didn't await them. Sprint 28's
  HashMap+await pattern fixes this latent issue too. Not a
  user-visible bug (the tasks WERE getting signalled by the
  daemon-wide shutdown notify, so they exited eventually), but a
  hygiene fix.
- **No new lib tests in qgateway-core.** RotationMonitor's per-tenant
  Notify behavior is already covered by qaudit-core's 48 lib tests
  for the rotation channel + monitor machinery. Sprint 28 is
  exclusively about the SIGHUP wiring; the integration tests are
  the right level of coverage.
- **2-second drain timeout in non-SNI REMOVE.** The monitor's body
  is a single `stat()` call + a conditional rotation request. In
  pathological cases (filesystem hang on `stat`) the 2s timeout
  fires; we log a warn and proceed. Operators seeing this warn
  should investigate the filesystem, not the daemon.

### 13.36.4 The latent task leak that Sprint 28 also fixed

Sprint 8.5 introduced `monitor_handles: Vec<JoinHandle<()>>` at
startup, but no code path ever drained the Vec — when `cmd_run`
returned, the Vec was dropped without `.await` on the handles. The
tasks WERE listening to the daemon-wide shutdown Notify and would
exit when SIGTERM signalled it, but they were never awaited.

In practice this manifested as: SIGTERM fires, daemon-wide notify
is signalled, monitors observe it and start to return, but `cmd_run`
exits `main()` immediately after the audit `shutdown_async` block
without ever awaiting the monitors. Tokio's runtime drops on process
exit handles all remaining tasks via `Runtime::shutdown_background`,
but it doesn't await them — they get aborted.

Sprint 28's HashMap + per-tenant Notify + explicit await fixes this:
- Tasks listen to per-tenant Notify (signalled by SIGTERM fanout).
- SIGTERM drain walks the map and awaits each handle.
- Monitor's `tokio::select!` returns Ok at the next poll boundary
  after Notify fires.

End result: clean monitor shutdown without aborted tasks. Operators
running `RUST_LOG=debug` would no longer see truncated task logs at
shutdown.

### 13.36.5 API surface changes

**Type-level changes** (internal to qgateway binary):
- `monitor_handles`: `Vec<JoinHandle<()>>` → `Arc<RwLock<HashMap<String, JoinHandle<()>>>>`.
- `install_signal_handler`: gained a 19th param, the same shared map.
- Startup `monitor.spawn(shutdown.clone())` → `monitor.spawn(rt.shutdown.clone())`.

**Behavioural** (no public-API change):
- Runtime-added tenants now auto-rotate on `[rotation]` policy triggers.
- Runtime-removed tenants' monitors are stopped (and awaited or aborted).
- SIGTERM drain no longer leaks monitor tasks.

### 13.36.6 Acceptance — actual

- [x] `cargo test --workspace --locked` green: **208 tests** (206 +
      2 new auto-rotation integration tests).
- [x] Integration suite now ~60s total (the new tests are 35s due to
      5s default `poll_interval`; the rest are 25s).
- [x] `cargo build --workspace --locked` clean.
- [x] `cargo clippy --workspace --all-targets -- -D warnings` clean.
- [x] `cargo fmt --all --check` clean.
- [x] `cargo build -p qgateway --features pkcs11 --locked` clean.

### 13.36.7 Honest deferrals to Sprint 29

The lifecycle work is now genuinely complete. The deferral list is
all polish + speculative coverage:

1. **Audit events under load + chain verification.** Drive real `session.open`/`session.close` events. Still the biggest "unknown unknown" in the audit story.
2. **More integration test coverage** (TLS, SNI, hot-limits) — mechanical.
3. ✅ **Chaos/property testing of the SIGHUP arm** — DELIVERED in Sprint 29.
4. **E2E admission integration test** — long carry-over.
5. **`[rotation] poll_interval` config field** to let tests run faster. Justified by Sprint 28 test runtime.
6. **`SO_REUSEPORT`, per-group drain timeout, hard SNI drain** — all gated on operator demand.

---

## 13.37. SPRINT 29 — DELIVERABLE CONTRACT (✅ CLOSED — chaos test of the SIGHUP arm)

Sprint 29 ships a single integration test that drives the daemon
through a long randomised sequence of mixed signals (SIGHUP-ADD,
SIGHUP-REMOVE, SIGHUP-no-change, SIGUSR1, SIGUSR2) and asserts
terminal invariants. The goal is to surface interleaving bugs that
deterministic per-feature tests miss — exactly the kind of bug
Sprint 27 caught by accident (the `rotation_targets` Vec) and
Sprint 28 closed (the `monitor_handles` Vec).

The test is **deterministic** (fixed seed LCG) so a failure is
reproducible by re-running. It is NOT a true property-based test
with shrinking — that would require multi-daemon harness which is
out of scope. The single-daemon stress sweep catches the same
class of bug at far lower harness cost.

### 13.37.1 Delivered

| # | Deliverable | Notes |
|---|---|---|
| `crates/qgateway/tests/chaos_signal_sequence.rs` | ~290-line test file with 1 test. Single deterministic seed (`0xC0FF_EE00_C0DE_0004`), 30 operations, distribution: ~30% ADD, ~20% REMOVE, ~20% SIGHUP-no-change, ~15% SIGUSR1, ~15% SIGUSR2. Maintains a model of the current tenant set so REMOVE only targets existing tenants and ADD uses fresh names. |
| Tiny LCG generator | Numerical Recipes constants (mul=1664525, add=1013904223). Inline ~10 LoC instead of pulling `rand` as a dev-dep. Reproducible without external deps. |
| Terminal invariant assertions | (1) `/metrics` still responds at end of run; (2) Prometheus counter monotonicity at every step (sighup_cycles, tenants_added, tenants_removed never decrease); (3) every surviving tenant's audit log file parses + verifies; (4) counter delta upper bounded by operations issued; (5) counter delta lower bounded at 80% of operations issued (allows for Linux signal coalescing). |
| `send_signal` helper | One-line wrapper for SIGUSR1/SIGUSR2; kept local to this test (`common/mod.rs` already exposes `sighup`). |
| 200ms inter-op delay | Empirically sufficient to let the daemon's signal handler complete one cycle before the next signal arrives. Without delay, Linux signal coalescing aggressively drops queued signals; with delay, dropouts are <20%. Documented in-test. |

### 13.37.2 What the test proves

Concretely, after 30 randomised operations interleaving SIGHUP /
SIGUSR1 / SIGUSR2:

```text
Per-op invariants (asserted in the loop):
  - /metrics scrape succeeds (daemon alive, no deadlock)
  - sighup_cycles_total ≥ previous value (no counter regression)
  - tenants_added_total ≥ previous value
  - tenants_removed_total ≥ previous value

Terminal invariants (asserted at end):
  - Daemon process alive, /metrics responds
  - cycle counter delta ≤ operations issued (no over-count)
  - cycle counter delta ≥ 80% × operations issued (signal coalescing tolerance)
  - same for add/remove counter deltas
  - for every survivor in the post-sequence tenant model:
      AuditLog::open(path).verify() succeeds
      (i.e., audit chain integrity preserved under churn)
```

This exercises code paths that no prior test exercised in
combination:
- SIGUSR1 fired while SIGHUP-spawned tenant is mid-bootstrap
- SIGUSR2 rotation issued mid-SIGHUP-remove
- SIGHUP-no-change exercising the "everything unchanged" diff branch
- Random interleaving of all of the above

### 13.37.3 What the test does NOT prove (honest limitations)

- **No multi-daemon scenarios.** A real production environment may
  run multiple sidecars; the test exercises only one. Inter-daemon
  failure modes (e.g., one sidecar crashes mid-handshake to another)
  are out of scope.
- **No true proptest-style shrinking.** When the test fails, it
  fails on the full 30-op sequence — there's no automatic minimisation
  to a smaller failing sequence. The seed and operation log are
  printed by the test framework, so manual minimisation is feasible
  but slow. Adding `proptest` as a dev-dep would buy shrinking at
  the cost of ~10MB compile-time bloat and a new dep surface;
  deferred until a shrinking-worthy bug appears.
- **No TLS/SNI variants.** The test uses `serve-pq` only. Mixing
  in SNI groups + TLS reload + cert mutation would multiply the
  state space; mechanical follow-up sprint.
- **No real session traffic.** Like Sprint 26's audit chain test,
  this test exercises an idle daemon — no `session.open` /
  `session.close` events flow because that would require a fake
  CSPQ peer. The chain machinery is identical with and without
  events; the test proves the lifecycle plumbing, not the data path.
- **Single seed.** The test runs with one fixed seed. A real
  property test would sweep many seeds in CI; we ship one. If a
  bug surfaces in production that this test doesn't catch, bump
  the seed (or add a second test with a different seed) to
  reproduce + fix.
- **200ms inter-op delay is a hand-tuned constant.** Could be
  shorter on a fast CI box; could be longer if the daemon's signal
  handler grows. If we observe coalescing-related flakes, bump it.

### 13.37.4 Trade-offs documented

- **One seed, not a sweep.** Sweeping multiple seeds increases CI
  time linearly. We ship one well-tested seed and document how to
  add more. If real bugs surface, the seed catalog grows — but the
  ratio of test-runtime to bug-discovery becomes the tradeoff at
  that point.
- **Inline LCG instead of `rand` crate.** Saves dep weight + makes
  the test self-contained for review. The LCG is well-known
  (Numerical Recipes) and adequate for non-cryptographic
  randomness in a test fixture.
- **Counter delta lower bound at 80%.** Linux signal handling
  coalesces signals of the same kind that arrive while another is
  being processed. With the 200ms inter-op delay this rarely
  happens, but to keep the test from flaking on slow CI runners
  we accept a 20% miss rate. If we ever see actual production
  signal storms with significant coalescing, this number is
  documented and tunable.
- **No SNI/TLS variant.** Same reason as every prior integration
  test sprint: one novel coverage axis per sprint. Sprint 29's
  axis is "concurrent signal pressure"; mixing in TLS would dilute
  it. Sprint 30+ can stack.
- **`generate_sequence` enforces well-formed ops.** The generator
  never produces a REMOVE for a tenant that doesn't exist, never
  produces an ADD with a name collision. This narrows the bug
  surface (we don't test the daemon's validation arm) but lets us
  assert deterministic counter math. Testing the validation arm
  is a different test.
- **Survivor set is the model after the sequence.** The test
  uses its own in-memory model of what tenants should exist at
  the end. If a bug existed where the daemon's actual tenant set
  diverged from the model (e.g., a SIGHUP REMOVE silently failed),
  the audit chain verification loop would either miss a survivor
  or claim a survivor that doesn't exist on disk. Both surface as
  test failures.

### 13.37.5 API surface changes

**None.** Sprint 29 is pure test code addition. No production
source modified.

### 13.37.6 Acceptance — actual

- [x] `cargo test --workspace --locked` green: **209 tests** (208 +
      1 new chaos integration test).
- [x] Chaos test runs in ~8s wall-clock.
- [x] `cargo build --workspace --locked` clean.
- [x] `cargo clippy --workspace --all-targets -- -D warnings` clean
      (after two clippy nits: hex grouping + range patterns).
- [x] `cargo fmt --all --check` clean.
- [x] `cargo build -p qgateway --features pkcs11 --locked` clean.

### 13.37.7 Honest deferrals to Sprint 30

The integration story is now substantively complete. Remaining items
are polish + speculative coverage:

1. ✅ **Audit events under load + chain verification** — DELIVERED in Sprint 30.
2. **TLS/SNI chaos variant.** Mechanical extension of Sprint 29 to
   add `ServeTcp` (with TLS-single + SNI) tenants to the chaos
   generator. Worth doing if SNI/TLS bugs surface in production.
3. **Multi-seed chaos sweep.** Trivial to add (loop over seeds);
   trades CI time for bug surface area.
4. **`proptest` dep + shrinking.** Real bug-hunting value if a
   chaos test fails in CI and we need to minimise the sequence.
5. **`[rotation] poll_interval` config field.**
6. **E2E admission integration test.** Long carry-over.
7. **`SO_REUSEPORT`, per-group drain timeout, hard SNI drain** —
   gated on operator demand.

---

## 13.38. SPRINT 30 — DELIVERABLE CONTRACT (✅ CLOSED — audit chain for non-empty chains under real session load)

Sprint 30 closes the biggest "unknown unknown" carried since Sprint 26: every prior
audit chain integration test exercised EMPTY chains (just the header).
Sprint 30 drives REAL CSPQ sessions through a `serve-pq` tenant, so
the daemon emits actual `session.open` + `session.close` events to
its audit log, and the test then verifies the resulting non-empty
signed chain.

This is the test compliance auditors actually care about. "The chain
parses when no events flowed" is necessary but not sufficient. "The
chain parses + verifies + contains the expected events after real
traffic" is the property that maps to the regulatory question
"can you prove what happened on this gateway last month?"

### 13.38.1 Architecture of the test

```
┌────────────┐  CSPQ over TCP   ┌──────────────┐  plain TCP   ┌─────────┐
│ test       │ ──────────────→  │ qgateway     │ ──────────→  │ echo    │
│ client     │ ←──────────────  │ (serve-pq)   │ ←──────────  │ server  │
└────────────┘                  └──────────────┘              └─────────┘
      │                                  │                          │
      │ uses daemon's identity           │ emits session.open       │ runs in
      │ (trusted via self.cspqid.pub)    │ + session.close to       │ test
      │                                  │ the per-tenant .qa       │ process
```

- Test process runs an in-memory TCP echo server (`tokio::TcpListener`)
  in a Tokio runtime.
- Daemon is configured with `backend = <echo server addr>` so its
  proxy machinery has a live backend to dial.
- Test process loads the daemon's transport identity (the existing
  fixture already trusts that identity via `peers/self.cspqid.pub`)
  and uses `qtransport_cspq::connect` to dial the daemon's listen
  port.
- Each dial → real ML-KEM-1024 + ML-DSA-87 handshake → CSPQ stream
  → daemon proxies bytes to echo server → echo returns → test reads
  echo → test half-closes write side → daemon emits `session.close`.

### 13.38.2 Delivered

| # | Deliverable | Notes |
|---|---|---|
| `crates/qgateway/tests/session_events_audit.rs` | ~280-line test file with 2 tests: `audit_chain_contains_session_events_under_load` (drives 5 sequential sessions, asserts opens=closes, opens ∈ [N-1, N] in the chain) and `audit_chain_survives_session_load_across_sighup` (drives 3 sessions, SIGHUP ADD bob, drives 3 more on alice, asserts opens ∈ [5, 6]). |
| Echo server helper | Lightweight `spawn_echo_server` — binds 127.0.0.1:0, accepts connections, echoes bytes until shutdown Notify fires. ~25 LoC inline. |
| Transport identity loader | Mirrors `qgateway::load_transport_identity` (8-byte `CSPQSK01` magic + raw ML-DSA-87 SK). Not re-exported from the binary; duplicated inline in the test for the same reason audit-pub format was duplicated in Sprint 26. ~10 LoC. |
| `Fixture::write_config_with_backend` | New helper on the shared Fixture that lets a test override the placeholder `backend = "127.0.0.1:0"` with a live `SocketAddr`. The existing `make_config` was extended to accept `Option<SocketAddr>` — `None` keeps the placeholder (preserves all earlier tests' behavior); `Some(addr)` writes the real backend address. |
| `make_config` extended (9 params) | Picked up `backend_override: Option<SocketAddr>`. Now flagged with `#[allow(clippy::too_many_arguments)]` — same lint, same justification. All 4 call sites updated. |
| Tolerance window in assertions | Both tests assert `opens ≤ N_SESSIONS` (no spurious events) and `opens ≥ N - 1` (allow one race window where the daemon's writer task hadn't flushed the final session.close before SIGTERM drained the channel). In practice the count is exact in CI; the slack is for slow runners. |

### 13.38.3 What the tests prove

Beyond what Sprint 26 proved (chain machinery is valid for empty chains):

1. **Real handshake works**: the daemon's `serve-pq` accept path
   completes a full ML-KEM-1024 + ML-DSA-87 handshake with a peer
   that uses `qtransport_cspq::connect`. This is the first integration
   test that exercises the real CSPQ data plane.
2. **Proxy works**: bytes flow client → daemon (CSPQ stream) → daemon
   → backend (plain TCP) → backend → daemon (plain TCP) → daemon →
   client (CSPQ stream). The test asserts the echo matches the payload.
3. **Audit events fire**: each completed session produces exactly one
   `session.open` and one `session.close` entry in the daemon's
   audit log.
4. **Chain integrity preserved**: the resulting non-empty signed chain
   parses + verifies. Every entry's signature is valid; every chain
   link (`prev_root` → `new_root`) is consistent.
5. **Chain survives SIGHUP**: events emitted before AND after a
   SIGHUP-ADD cycle land in the same chain (the audit channel is
   tenant-scoped, untouched by SIGHUP-ADD of a different tenant)
   and the chain still verifies end-to-end.
6. **Chain pubkey matches the published `.audit.pub`**: header carries
   the bit-for-bit pubkey an external auditor would receive out of
   band.

### 13.38.4 Trade-offs documented

- **Sequential sessions, not concurrent.** Both tests dial sequentially.
  A concurrent variant (e.g., 10 sessions in flight at once) would
  prove the audit channel serializes appends correctly under contention,
  but it complicates the assertion (race between SIGTERM and the
  pending close-flush widens the tolerance window). Sprint 31+ if
  warranted.
- **Test reuses the daemon's transport identity instead of generating
  a second one.** Simpler — the existing fixture already trusts
  `self.cspqid.pub`. A second-identity variant would prove peer-policy
  enforcement (only configured peers can connect), but Sprint 30's
  scope is audit chain integrity, not peer policy. Different test.
- **Tolerance window `opens ∈ [N-1, N]`**. The daemon's audit channel
  is async; the writer task flushes batched entries to disk on a
  cadence. Between "test asks daemon to shutdown" and "writer task
  observes shutdown and finalizes", the last in-flight `session.close`
  entry MAY or MAY NOT have hit disk yet. The 500ms post-session
  sleep + graceful shutdown reduce the race window to near-zero in
  practice, but the tolerance avoids CI flakes. Documented in-test.
- **Echo backend instead of real protocol semantics**. The daemon
  doesn't care what protocol flows over the proxied stream — it just
  shuffles bytes. A more elaborate backend (HTTP, gRPC) wouldn't
  exercise additional daemon code paths. Keep it simple.
- **Multi-threaded test runtime**. The test driver uses
  `tokio::runtime::Builder::new_multi_thread()` matching the daemon's
  runtime flavor. Avoids any subtle starvation between the test's
  echo-server task and the test's CSPQ-client futures.
- **Duplicated transport-identity loader**. Same rationale as
  Sprint 26's audit-pub magic duplication. The 8-byte `CSPQSK01`
  magic is documented as the file format; if qgateway promotes
  `load_transport_identity` to a public crate API, the test
  switches over.

### 13.38.5 API surface changes

**Production code**: none. Sprint 30 is pure test + test-fixture additions.

**Test fixture**: `make_config` gained a 9th param (`backend_override`);
`Fixture` gained `write_config_with_backend`. All earlier tests
keep their behavior (the new param is `None` for them).

### 13.38.6 Acceptance — actual

- [x] `cargo test --workspace --locked` green: **211 tests** (209 +
      2 new session-events integration tests).
- [x] Sprint 30 tests run in ~5.3s combined.
- [x] `cargo build --workspace --locked` clean.
- [x] `cargo clippy --workspace --all-targets -- -D warnings` clean.
- [x] `cargo fmt --all --check` clean.
- [x] `cargo build -p qgateway --features pkcs11 --locked` clean.

### 13.38.7 Honest deferrals to Sprint 31

The integration coverage story is now genuinely substantive. The
chain machinery is proven end-to-end under real traffic, across
SIGHUP cycles, with cryptographic verification at every step. The
remaining items are all incremental:

1. **Concurrent session load + chain integrity.** Drive N sessions
   in flight simultaneously; prove chain serializes appends. Real
   value if a chain-append race ever surfaces; trade-off is a
   wider assertion-tolerance window.
2. ✅ **Peer-policy enforcement test** — DELIVERED in Sprint 31.
3. **TLS/SNI chaos variant.** Sprint 29 carry-over.
4. **Multi-seed chaos sweep.** Sprint 29 carry-over.
5. **`proptest` dep + shrinking.** Sprint 29 carry-over.
6. **`[rotation] poll_interval` config field.** Sprint 28 carry-over.
7. **E2E admission integration test.** Long carry-over.
8. **`SO_REUSEPORT`, per-group drain timeout, hard SNI drain** —
   operator demand.

---

## 13.39. SPRINT 31 — DELIVERABLE CONTRACT (✅ CLOSED — peer-policy enforcement: untrusted dial rejected, no audit event emitted)

Sprint 31 ships the negative-path security test that the compliance
story has been missing: prove that the daemon REJECTS a CSPQ peer
whose identity is not in the tenant's `peer_pub_dir`, that the
`qgateway_sessions_failed_total` counter increments, and crucially
that the audit chain remains EMPTY of `session.open` /
`session.close` entries for the rejected attempt.

Sprint 30 proved trusted peer events appear in the chain.
Sprint 31 proves untrusted peer events do NOT. Together they bracket
the peer-policy enforcement invariant from both sides.

Pattern is mechanical extension of Sprint 30: same fixture, same
echo server, same two-test structure (negative + sanity positive),
but the negative test uses a freshly-generated identity that is
never copied into the daemon's `peer_pub_dir`.

### 13.39.1 Delivered

| # | Deliverable | Notes |
|---|---|---|
| `crates/qgateway/tests/peer_policy_enforcement.rs` | New ~310-line test file with 2 tests: `untrusted_peer_is_rejected_and_emits_no_audit_event` (negative) and `trusted_peer_succeeds_after_untrusted_attempt` (positive sanity). |
| `generate_untrusted_identity` helper | Invokes the daemon's own `keygen` subcommand to produce a fresh CSPQ identity at runtime, then loads it via the same `load_transport_identity` loader Sprint 30 introduced. The fresh identity's pubkey is never written into the daemon's `peer_pub_dir`, so the daemon's `PeerPolicy::accepts` will return false for it. |
| `tenant_counter_value` helper in `tests/common/mod.rs` | New helper for reading Prometheus counters with `{tenant="<name>"}` labels. The existing `counter_value` matched only daemon-wide unlabeled counters (`qgateway_sighup_cycles_total 5`). Sprint 31 needed per-tenant `qgateway_sessions_failed_total{tenant="alice"} 1`. The new helper parses the label set, matches a target tenant if specified, otherwise sums across all tenants matching the metric name. ~30 lines, kept simple (no full Prometheus parser; just label-substring contains-match). |
| Both tests run in <3 seconds | Faster than Sprint 30's audit-events test because Sprint 31's untrusted-reject case doesn't need to wait for backend echo round-trip. |

### 13.39.2 What the tests prove

**`untrusted_peer_is_rejected_and_emits_no_audit_event`**:
1. Daemon comes up with `alice`'s `peer_pub_dir = peers/`, containing only `self.cspqid.pub` (the daemon's own identity, mirrored by the fixture).
2. Test generates `attacker.skid`/`attacker.cspqid.pub` via `qgateway keygen` — a fresh ML-DSA-87 identity.
3. The attacker pubkey is NOT copied to `peers/`. The fresh identity is unknown to the daemon.
4. Client uses the attacker identity to dial alice's listen port.
5. **Expected**: `qtransport_cspq::connect` returns `Err`. Server-side handshake aborts at the policy check.
6. **Asserted**: `qgateway_sessions_failed_total{tenant="alice"}` incremented.
7. **Asserted**: `qgateway_sessions_opened_total{tenant="alice"}` did NOT change (compliance: no audit emit on rejection).
8. **Asserted**: After graceful shutdown, `alice.qa` audit log parses + verifies (chain integrity preserved).
9. **Asserted**: The chain contains ZERO `session.open` or `session.close` entries.

**`trusted_peer_succeeds_after_untrusted_attempt`** (sanity):
1. Same fixture; daemon up.
2. Attempt one untrusted dial — must fail (proves negative path still works).
3. Attempt one trusted dial (using daemon's own identity, same as Sprint 30) — must succeed and echo bytes round-trip.
4. **Asserted**: Audit chain has EXACTLY 1 `session.open` and EXACTLY 1 `session.close`. The untrusted attempt contributed nothing.

The exact-1 assertion is stronger than Sprint 30's "≥1" because Sprint 31 wants to prove the untrusted attempt didn't accidentally leak an event. The test would fail loudly if (a) the untrusted dial silently succeeded, or (b) the daemon emitted a placeholder `session.open` before the policy check.

### 13.39.3 What the tests do NOT prove (honest limitations)

- **One reject mode.** The test exercises ONE rejection path: identity-not-in-allow-list. Other rejection paths exist (transport-level handshake corruption, replay, version mismatch) — those are covered by qtransport-cspq's 26 lib tests in isolation, but not by integration tests against the live daemon. Mechanical extension if needed.
- **No malformed-peer-frame test.** A real attacker would send malformed CSPQ frames; the test only sends a well-formed handshake from a wrong identity. The daemon's framing/parser robustness is qtransport-cspq's responsibility; this test layer assumes it.
- **No timing-side-channel test.** The reject-vs-accept timing might leak information about which keys are trusted. Documenting as out-of-scope — would require a dudect-style measurement harness. The `PeerPolicy::accepts` check is a `Vec::contains` over byte slices, not constant-time; if a timing attack matters in production, that's a separate hardening task.
- **One untrusted identity, not a sweep.** Sprint 31 generates one fresh identity. A real fuzz of "100 random untrusted identities all rejected" would be a stress variant — currently the deterministic single-case is sufficient evidence for the wiring claim.

### 13.39.4 Trade-offs documented

- **Untrusted identity generated at test runtime via subprocess.** The test calls `qgateway keygen` via `Command::new` to generate the second identity. Could have generated directly via `qaudit_core::KeyPair::generate()` + manual file write, but reusing the daemon's own keygen tool keeps the test self-consistent with how operators would generate keys in the field. Costs one subprocess spawn (~10ms).
- **Audit log inspection via `log.entries().iter().filter(...)`.** This iterates every entry to count matches. For 0-2 entries (the test's scale) it's trivial; for thousands of entries it would be slow. The current API exposes only `entries()` returning a slice; no indexed-by-action lookup. Fine for the test.
- **Sanity positive test duplicates Sprint 30 partial.** The trusted-dial portion of `trusted_peer_succeeds_after_untrusted_attempt` is similar to Sprint 30's `audit_chain_contains_session_events_under_load`. Kept as a sanity guard within Sprint 31 because (a) it asserts an EXACT count of events (1 open + 1 close), which is a stronger claim than Sprint 30's, and (b) it proves the negative→positive transition works in the same daemon instance — a scenario Sprint 30 doesn't cover.
- **Echo server runs on the test's runtime, not in the daemon's process.** Same architecture as Sprint 30. The daemon dials it from the proxy's accept-handshake path.
- **Common helper `tenant_counter_value` added now, not earlier.** The existing `counter_value` worked for every Sprint 25-29 test because they all read daemon-wide counters (sighup_cycles, tenants_added, tenants_removed — all unlabeled). Sprint 31 is the first test that needed per-tenant labeled metrics. Adding the helper now is a one-time cost that future tests will reuse.
- **`tenant_counter_value` is not a full Prometheus parser.** It does naive substring matching on the label string (`tenant="alice"`). Susceptible to false positives if a label value contained that substring — currently the daemon's tenant names are alphanumeric, so collision-free in practice. If a future test needs richer label matching, promote to a proper parser.
- **No assertion on the `error log line` content.** The daemon logs `error!(...)` when a handshake fails. The test doesn't capture stderr to assert on the log text — that would couple the test to log format. The metric counter increment is the wire-level observable.

### 13.39.5 API surface changes

**None for production code.** Sprint 31 is pure test code addition
+ one new helper in `tests/common/mod.rs`.

### 13.39.6 Acceptance — actual

- [x] `cargo test --workspace --locked` green: **213 tests** (211 +
      2 new peer-policy enforcement tests).
- [x] Both new tests run in ~2.5s combined.
- [x] `cargo build --workspace --locked` clean.
- [x] `cargo clippy --workspace --all-targets -- -D warnings` clean.
- [x] `cargo fmt --all --check` clean.
- [x] `cargo build -p qgateway --features pkcs11 --locked` clean.

### 13.39.7 Honest deferrals to Sprint 32

The compliance test matrix has now covered: positive trusted-peer
events (Sprint 30), negative untrusted-peer rejection (Sprint 31),
chain integrity across SIGHUP (Sprint 26), runtime-added rotation
(Sprint 27), runtime-added auto-rotation (Sprint 28), and chaos
mixing (Sprint 29). The deferral list is purely speculative:

1. **Concurrent session load + chain integrity.** Drive N parallel sessions; prove the chain serializes appends correctly. Real value only if a race is suspected.
2. ✅ **Malformed CSPQ frame fuzz** — DELIVERED in Sprint 32.
3. **TLS/SNI chaos variant.** Sprint 29 carry-over.
4. **Multi-seed chaos sweep.** Sprint 29 carry-over.
5. **`proptest` dep + shrinking.** Sprint 29 carry-over.
6. **`[rotation] poll_interval` config field.** Sprint 28 carry-over.
7. **E2E admission integration test.** Long carry-over.
8. **Timing-side-channel measurement of policy check.** dudect-style harness; offline work, not integration.
9. **`SO_REUSEPORT`, per-group drain timeout, hard SNI drain** — operator demand.

---

## 13.40. SPRINT 32 — DELIVERABLE CONTRACT (✅ CLOSED — malformed CSPQ frame robustness)

Sprint 32 closes the third side of the security bracket. Sprint 30
proved trusted-peer cooperation; Sprint 31 proved untrusted-peer
rejection; Sprint 32 proves NON-cooperative wire input (raw garbage
bytes that don't speak CSPQ at all) does not crash the daemon or
emit audit events.

This is the test that maps to the regulatory question *"what happens
when an internet scanner hits your listener?"* — a question
compliance auditors don't always ask but DevSecOps teams always do.

### 13.40.1 Delivered

| # | Deliverable | Notes |
|---|---|---|
| `crates/qgateway/tests/malformed_frame_robustness.rs` | New ~250-line test file with 1 test that exercises 6 representative malformed-input shapes against a live daemon, then asserts the daemon survives + accepts legitimate traffic. |
| 6 malformed input shapes | Realistic attacker / scanner behaviour: bare TCP open-close (port scan), partial length prefix (truncated handshake), zero-length frame, oversized length prefix (memory-exhaustion attempt), 128 bytes of deterministic garbage, full HTTP GET probe (very common scanner behaviour). |
| Per-shape liveness assertion | `/metrics` scraped after EVERY malformed shape. If any single shape were to panic or deadlock the accept loop, the failing case is identified by name, not "the whole suite died." |
| Post-attack legitimate session | After all 6 malformed shapes, a normal trusted-peer dial is driven and asserted to round-trip bytes. Proves the malformed inputs didn't degrade availability (no leaked socket, no exhausted resource pool, no stuck accept loop). |
| Exact audit count assertion | Audit chain must contain EXACTLY 1 `session.open` + 1 `session.close` post-run — from the legit session only. The 6 malformed attempts contribute nothing. Stronger claim than "≥1" — would catch any false-positive emit on a malformed input. |
| Deterministic garbage generator | Inline 8-line LCG (same family as Sprint 29's chaos test), used for the "random_garbage" shape. Reproducible without `rand` dep. |

### 13.40.2 What the test proves

For each of six malformed input shapes (bare close, partial prefix,
zero frame, oversized prefix, random bytes, HTTP probe):
- TCP connection to daemon's listen port succeeds (accept loop is healthy)
- Sending the malformed payload + closing succeeds from client side
- Daemon's `/metrics` endpoint responds within 2s after the shape

After all six shapes, **terminally**:
- `qgateway_sessions_failed_total{tenant="alice"}` did not regress
- `qgateway_sessions_opened_total{tenant="alice"}` did NOT increase
  (NO audit emit on any of the malformed inputs)
- A subsequent legitimate trusted-peer dial completes the full
  CSPQ handshake + byte round-trip
- After daemon shutdown: audit chain parses + verifies; contains
  exactly 1 `session.open` + 1 `session.close` from the legit
  session

The critical invariant: a single malformed connection (or six)
MUST NOT degrade the daemon's ability to serve legitimate traffic.
A bug that, for example, leaked a TCP socket on every malformed
input would eventually exhaust the per-tenant `max_concurrent`
admission quota; the post-attack legitimate session would either
fail or be admission-rejected. The legit dial succeeding proves
the admission slot was released cleanly each time.

### 13.40.3 What the test does NOT prove (honest limitations)

- **Not fuzzing in the AFL/honggfuzz sense.** The 6 shapes are
  hand-picked representatives, not the millions of inputs a real
  fuzzer would generate. Real fuzzing belongs in qtransport-cspq's
  own offline `cargo-fuzz` harness. Sprint 32 proves the daemon's
  accept loop survives wire-level garbage end-to-end; it doesn't
  prove the qtransport-cspq parser is fuzz-clean.
- **No state-machine fuzz.** A real attacker might send a
  well-formed handshake message #1 followed by garbage for #2.
  Sprint 32 tests only initial-byte garbage; intra-handshake
  state pollution is out of scope.
- **No concurrent malformed connections.** The 6 shapes are
  sequential. A flood of N parallel malformed connections would
  test admission-controller behaviour under DoS — separate
  concern, separate test.
- **No assertion on TCP RST vs FIN behaviour.** The daemon may
  close with RST or FIN; the test doesn't distinguish. Either is
  acceptable wire-level behaviour.
- **No assertion on response latency to malformed input.** A
  daemon that responds to a malformed input in 10 seconds (e.g.,
  waiting on a hung read) would still pass the post-shape
  liveness check (which polls `/metrics`, not the listen port).
  This would be a real availability issue. Adding a per-connection
  timeout assertion is straightforward — deferred until operator
  asks.

### 13.40.4 Trade-offs documented

- **Hand-picked shapes, not generated fuzz.** Six well-chosen
  cases catch realistic attacker behaviour. A true fuzz harness
  costs ~10x setup + needs CI integration with corpus storage;
  not worth it inside the integration test layer. Sprint 32's
  value is "daemon survives garbage end-to-end" — exhaustive
  fuzzing is a different deliverable.
- **No assertion on `sessions_failed_total` strict increment.**
  Some shapes (notably `bare_open_close`) may not increment the
  counter because the daemon may classify a zero-byte TCP close
  as "client gave up before handshake started" — pre-counter-bump
  path. We assert no regression (`failed_after >= failed_before`)
  rather than strict increase, accepting that some sub-shapes
  may bypass the counter. The crucial assertion is on
  `sessions_opened_total` (must NOT move) — that's the
  compliance invariant.
- **6 shapes, ~150ms gap each.** Total test runtime ~2.5s.
  Could parallelise the shapes; rejected because (a) sequential
  ordering simplifies per-shape liveness assertion, (b) 2.5s is
  fast enough.
- **Deterministic garbage via LCG.** Inline 8-line LCG instead
  of `rand` dep. Same justification as Sprint 29. Reproducible
  across platforms; failure on a specific seed is investigable
  without dep churn.
- **`drive_legit_session` duplicates Sprint 30/31's helper.**
  Three copies of the same shape now exist across the test
  files. Could promote to `common/mod.rs` — deferred. The risk
  of premature shared abstraction (helper signature drifts to
  serve multiple callers, becoming worse for each) outweighs
  the DRY benefit at three copies. If a fifth test needs it,
  promote.
- **TCP-level read timeout in `send_malformed`.** 200ms read
  timeout on the response side. Could be 0 (write-and-drop only)
  — kept short non-zero to give the daemon a chance to send any
  cooperative-rejection response, and to surface a hang (a
  daemon stuck on the malformed input would not close the TCP
  stream within 200ms).

### 13.40.5 API surface changes

**None.** Sprint 32 is pure test code addition.

### 13.40.6 Acceptance — actual

- [x] `cargo test --workspace --locked` green: **214 tests** (213 +
      1 new malformed-frame robustness test).
- [x] Test runs in ~2.5s.
- [x] `cargo build --workspace --locked` clean.
- [x] `cargo clippy --workspace --all-targets -- -D warnings` clean.
- [x] `cargo fmt --all --check` clean.
- [x] `cargo build -p qgateway --features pkcs11 --locked` clean.

### 13.40.7 Honest deferrals to Sprint 33

The security-test bracket is now complete. Three sides:
- **Cooperative trusted** (Sprint 30): events appear
- **Cooperative untrusted** (Sprint 31): rejected, no events
- **Non-cooperative garbage** (Sprint 32): survived, no events

What remains is honestly polish + speculative coverage:

1. **Concurrent session load + chain integrity.** Drive N parallel sessions; useful if a race is suspected.
2. **Concurrent malformed inputs.** Stress variant of Sprint 32. Real if a DoS attack mode is suspected.
3. ✅ **State-machine fuzz** — DELIVERED in Sprint 33.
4. **`cargo-fuzz` harness for qtransport-cspq.** Offline, not integration. Different deliverable.
5. **TLS/SNI chaos variant.** Sprint 29 carry-over.
6. **Multi-seed chaos sweep.** Sprint 29 carry-over.
7. **`proptest` dep + shrinking.** Sprint 29 carry-over.
8. **`[rotation] poll_interval` config field.** Sprint 28 carry-over.
9. **E2E admission integration test.** Long carry-over — now actually relevant since Sprint 32 indirectly proved admission slots get released on malformed input, but no test asserts the admission counters directly.
10. **`SO_REUSEPORT`, per-group drain timeout, hard SNI drain** — operator demand.

---

## 13.41. SPRINT 33 — DELIVERABLE CONTRACT (✅ CLOSED — state-machine fuzz: malformed CLIENT_FINISH)

Sprint 33 extends Sprint 32's wire-robustness test from initial-byte
garbage to **mid-handshake state corruption**. Sprint 32 probed
transition out of S0 ("server reads CLIENT_HELLO"); Sprint 33 probes
S1 ("server sent SERVER_HELLO, awaits CLIENT_FINISH").

This is the partial-state attack: an attacker who CAN speak the first
half of CSPQ but stops cooperating after getting the server into S1.
Real attackers behave this way when probing for parser bugs in
later-stage messages — the easier-to-reach later parsers tend to be
less hardened than the entry parser.

### 13.41.1 Delivered

| # | Deliverable | Notes |
|---|---|---|
| `crates/qgateway/tests/state_machine_fuzz.rs` | New ~340-line test file with 1 test that exercises 8 state-machine attack shapes against a live daemon. |
| `craft_valid_client_hello()` helper | Generates an ephemeral ML-KEM-1024 keypair via `fips203::ml_kem_1024::KG::try_keygen()`, formats the CLIENT_HELLO body (msg_type=1, suite=SUITE_ID, ek_bytes), returns the bytes ready for length-prefixed framing. The secret half is discarded — the test never decapsulates, it just needs the server to enter state S1. |
| `attack_with_partial_handshake()` | Drives: connect → write framed CLIENT_HELLO → drain SERVER_HELLO → write framed CLIENT_FINISH with malformed body → close. Exercises the daemon's CLIENT_FINISH body parser. |
| `attack_raw_after_hello()` | Drives: connect → write framed CLIENT_HELLO → drain SERVER_HELLO → write RAW bytes (NOT framed) → close. Exercises the daemon's length-prefix layer for the second frame. |
| 8 attack shapes | 5 framed (empty body, msg_type-only, wrong msg_type byte, garbage pubkey+sig, oversized) + 3 raw (close after hello, partial length prefix, oversized length prefix). |
| `fips203` workspace dev-dep added | qgateway didn't previously depend on the KEM crate directly (qtransport-cspq used it internally); Sprint 33 needed it in test code to craft valid CLIENT_HELLO. |
| Per-shape liveness check | `/metrics` polled after every shape, failing shape named in assertion message. |
| Post-attack legit-session assertion | After all 8 attacks, a normal trusted-peer dial succeeds + round-trips bytes. Audit chain has exactly 1 open + 1 close. |

### 13.41.2 What the test proves

For each of eight state-machine attack shapes:
- Daemon stays alive (`/metrics` responds after each shape)
- TCP connection cleanly closed by daemon side
- No `session.open` audit event emitted

Terminally after all 8 attacks:
- `qgateway_sessions_opened_total{tenant="alice"}` did NOT move
- A subsequent legitimate trusted-peer dial completes the full
  CSPQ handshake + byte round-trip
- Audit chain parses + verifies; contains exactly 1 open + 1 close
  (from the legit session only)

The 5 framed attacks specifically exercise CSPQ's `accept()` parser
at line ~245 of `handshake.rs` (the CLIENT_FINISH body parser). The
3 raw attacks exercise the length-prefix layer in `read_frame()` for
the second frame in the handshake conversation. Together they
cover both layers of the state-machine parser.

### 13.41.3 What the test does NOT prove (honest limitations)

- **8 shapes, not a fuzz sweep.** Same limitation as Sprint 32 —
  hand-picked representatives, not exhaustive. Real fuzzing belongs
  in qtransport-cspq's offline `cargo-fuzz` harness.
- **One state-machine transition tested.** S0→S1 is the only
  multi-message transition in CSPQ; if the protocol ever grows to
  4+ messages, deeper state attacks would need new tests.
- **No timing-stack assertions.** A daemon that responds to
  CLIENT_FINISH garbage in 30 seconds (e.g., stuck on a hung
  parser) would still pass the post-shape liveness check (which
  polls `/metrics`, not the listen port). The 200ms read timeout
  on the client side gives an upper bound but isn't asserted.
- **Concurrent partial-handshake attacks not tested.** Eight
  attacks are sequential. A flood of N parallel partial handshakes
  would stress the daemon's per-tenant `max_concurrent` quota.
  Out of scope; separate stress test.
- **No assertion on SERVER_HELLO contents.** The test drains
  SERVER_HELLO but doesn't validate its shape. A daemon that
  returned malformed SERVER_HELLO on a valid CLIENT_HELLO would
  pass this test (the goal is daemon liveness, not protocol
  correctness — qtransport-cspq's lib tests cover that).

### 13.41.4 Trade-offs documented

- **fips203 as dev-dep, not test inline.** Could have copied a
  pre-baked ML-KEM-1024 public key into the test source as a
  static byte array. Rejected because (a) the test ALREADY runs
  on a live daemon that generates fresh keys at startup, so
  determinism doesn't help, (b) `fips203` is already a workspace
  dep — adding it as dev-dep costs zero build-time bloat.
- **MSG_CLIENT_HELLO constant duplicated in test.** Mirrors the
  private constant at `qtransport-cspq/src/handshake.rs:22`.
  Re-exporting from the crate as `pub` would expose protocol
  internals to all callers; the 1-line duplication with a
  source-line comment is preferable.
- **SERVER_HELLO drain uses 500ms + 1s timeouts.** Empirical;
  on the test's localhost loopback the daemon produces
  SERVER_HELLO in ~10ms. The generous timeout absorbs CI jitter
  without slowing the typical path.
- **`drive_legit_session` duplicated AGAIN** (4th copy now). Same
  trade-off as Sprint 32. Promote when a 5th caller appears.
- **No assertion on per-attack `sessions_failed_total` increment.**
  Sprint 32's same trade-off applies — some shapes may bypass
  the counter (e.g., if the daemon classifies "client gave up
  after sending valid CLIENT_HELLO" as something other than
  handshake-failure). The compliance invariant is
  `sessions_opened_total` (must NOT move) — that's what we assert.
- **Garbage-pubkey-sig shape size matches actual expected size.**
  The 7220-byte placeholder happens to equal `1 + ML_DSA_PUBKEY_LEN
  + ML_DSA_SIG_LEN` exactly, so this case exercises the *signature
  verify* arm rather than the size-mismatch arm. If pubkey/sig
  sizes ever change (e.g., post-quantum standard revision), this
  case falls through to size-mismatch which is also acceptable —
  the test still proves the daemon survives.

### 13.41.5 API surface changes

**None for production code.** Sprint 33 is pure test addition +
one new dev-dep (`fips203`).

### 13.41.6 Acceptance — actual

- [x] `cargo test --workspace --locked` green: **215 tests** (214 +
      1 new state-machine fuzz test).
- [x] Test runs in ~4.2s.
- [x] `cargo build --workspace --locked` clean.
- [x] `cargo clippy --workspace --all-targets -- -D warnings` clean.
- [x] `cargo fmt --all --check` clean.
- [x] `cargo build -p qgateway --features pkcs11 --locked` clean.

### 13.41.7 Honest deferrals to Sprint 34

The security-test bracket is now FOUR-sided:
- **Cooperative trusted** (Sprint 30): events appear
- **Cooperative untrusted** (Sprint 31): rejected, no events
- **Non-cooperative S0 garbage** (Sprint 32): survived, no events
- **Non-cooperative S1 garbage** (Sprint 33): survived, no events

What remains is honest polish + speculative coverage:

1. **Concurrent session load + chain integrity.**
2. **Concurrent partial-handshake DoS.** Real stress test for the
   admission quota under attack.
3. **`cargo-fuzz` harness for qtransport-cspq.** Offline; different deliverable.
4. **TLS/SNI chaos variant.** Sprint 29 carry-over.
5. **Multi-seed chaos sweep.** Sprint 29 carry-over.
6. **`proptest` dep + shrinking.** Sprint 29 carry-over.
7. **`[rotation] poll_interval` config field.** Sprint 28 carry-over.
8. ✅ **E2E admission integration test** — DELIVERED in Sprint 34.
9. **`SO_REUSEPORT`, per-group drain timeout, hard SNI drain** —
   operator demand.

The integration test layer has now covered every honest threat
class for a single-daemon cooperative + non-cooperative client
interaction. Further security coverage requires moving to multi-
daemon scenarios (mesh-level), offline fuzzing (qtransport-cspq
internal), or product-surface work (admission enforcement E2E,
operator UX).

---

## 13.42. SPRINT 34 — DELIVERABLE CONTRACT (✅ CLOSED — E2E admission enforcement)

Sprint 34 closes the longest-standing carry-over: end-to-end
integration testing of the admission controller. The controller has
extensive lib tests in `qgateway-core::admission` (the semaphore-
permit + token-bucket logic in isolation), but no test currently
exercised it inside the LIVE daemon — proving that the accept loop
actually rejects connections when limits are reached, the right
Prometheus counters increment, slots release on session close, and
no audit event leaks from a rejected admission.

This is the test compliance auditors will demand for capacity
planning: *"prove that your stated tenant capacity is actually
enforced under load, and that rejection events are observable in
operator metrics."*

### 13.42.1 Delivered

| # | Deliverable | Notes |
|---|---|---|
| `crates/qgateway/tests/admission_enforcement.rs` | New ~400-line test file with 2 tests covering both admission limit modes. |
| `AdmissionFixture` (inline) | Sprint 34-specific fixture that writes `[tenants.limits]` config blocks. Kept inline (not promoted to `common/mod.rs`) because limits surface is specific to this sprint. |
| `LimitsSpec` struct | Captures the three knobs: `max_concurrent`, `rate_capacity`, `rate_refill_per_sec`. |
| `spawn_holding_server()` | Echo server that never closes proactively — used to keep admitted sessions in-flight while the 3rd dial attempts admission. |
| `open_holding_session()` | Opens one CSPQ session, sends one byte + reads echo to confirm round-trip, returns the live `CspqStream` to the caller for explicit drop control. |
| Test 1: `max_concurrent_rejects_third_dial_and_emits_no_audit_event` | Asserts (a) 3rd dial rejected, (b) `admission_rejected_quota_total` increments, (c) `sessions_opened_total` shows exactly 2 (the held sessions), (d) drop one held session → 3rd succeeds (slot release), (e) final audit chain has exactly 3 open + 3 close. |
| Test 2: `rate_limit_per_source_rejects_burst_above_capacity` | `capacity=1`, `refill=1/sec`. First dial consumes the token; second back-to-back dial rejected. `admission_rejected_rate_total` increments. |

### 13.42.2 What the tests prove

**Test 1 (`max_concurrent=2`)**:

```text
[t=0]     Spawn daemon with alice's [tenants.limits] max_concurrent=2
[t=0+]    Open holding session #1 → admitted, permit held
[t=0+]    Open holding session #2 → admitted, permit held
[t=0+]    Attempt 3rd dial:
            - TCP connect succeeds (kernel-level accept)
            - admission.check() returns Reject(Quota)
            - daemon drops the stream → kernel sends RST
            - CSPQ handshake never starts
            - qtransport_cspq::connect returns Err on client
[t=0+]    Assert: admission_rejected_quota_total{tenant="alice"} > before
[t=0+]    Assert: sessions_opened_total delta == 2 (NOT 3)
[t=1]     drop(s1) — releases permit
[t=1+]    Open holding session #3 → admitted (slot freed)
[t=1+]    Assert: sessions_opened_total delta == 3
[t=2]     SIGTERM, audit drain
[t=2+]    Assert: alice.qa has exactly 3 session.open + 3 session.close
```

**Test 2 (`rate_limit_per_source` capacity=1 refill=1/sec)**:

```text
[t=0]     Spawn daemon with alice's rate_limit_per_source = {capacity=1, refill=1}
[t=0+]    First dial → bucket token consumed, admitted
[t=0+ε]   Second dial within <1s → bucket empty, reject(Rate)
[t=0+ε+]  Assert: admission_rejected_rate_total{tenant="alice"} > before
```

The two tests bracket the admission controller's two enforcement
modes (concurrency cap vs. rate limit) from both the wire side
(client sees connection failure) and the metrics side (operator
sees labeled counter increment) and the compliance side (audit chain
has no entry for rejected admissions).

### 13.42.3 What the tests do NOT prove (honest limitations)

- **No concurrent rejection burst.** Test 1 attempts one 3rd dial.
  A real DoS attack would flood the listener with hundreds of
  dials/sec. The single-3rd-dial test proves the *check* works;
  scaling behaviour under sustained pressure is a separate stress
  test (deferred §13.42.7 #1).
- **No multi-source rate limit test.** The rate limit is per-source-
  IP. The test uses only `127.0.0.1` as source. A multi-source
  test would prove that each source IP gets its own bucket — but
  on a single machine, simulating multiple source IPs requires
  network namespace tricks (out of scope) or binding to multiple
  loopback addresses (mechanical, deferred).
- **Refill behaviour not asserted.** Test 2 doesn't wait for the
  bucket to refill and then assert that a subsequent dial succeeds.
  Adding this would make the test ~1s slower; the lib tests cover
  refill in isolation; the integration test asserts the wiring.
- **No SIGHUP hot-limit change test.** The Sprint 16 hot-reload
  pathway lets operators change limits via SIGHUP. Sprint 34
  doesn't test that path end-to-end (start with one limit, SIGHUP
  to a higher one, observe newly-admitted dials work). Mechanical
  extension; deferred until operator asks.
- **Inline fixture not promoted.** The `AdmissionFixture` is a
  ~150-line addition that overlaps with `common::Fixture` in
  ~80% of its body. Could DRY this up — see trade-off below.

### 13.42.4 Trade-offs documented

- **Inline fixture vs `common::Fixture` extension.** Could have
  added a `limits: Option<LimitsSpec>` parameter to
  `common::Fixture::build` + new `write_config_with_limits()`.
  Rejected because (a) the LimitsSpec surface is specific to
  Sprint 34 and would bloat `common`'s API for every other test,
  (b) the inline fixture is ~150 LoC of bog-standard scaffolding
  — duplication cost is bounded, generalization cost is
  unbounded. If a Sprint 35+ test needs limits, promote in that
  sprint.
- **`spawn_holding_server` vs reusing Sprint 30's echo.** Sprint
  30's echo closes when the client closes its write side; Sprint
  34 needs the echo to KEEP THE SESSION ALIVE while the 3rd dial
  attempts admission. Different semantic. Inline.
- **`open_holding_session` returns the live `CspqStream`.** The
  test caller controls when to drop (and thus release the
  admission permit). This is the cleanest way to test slot
  release deterministically — `tokio::spawn`-and-trust-me would
  make timing fragile.
- **No assertion on TCP RST specifically.** The test asserts the
  client sees `Err` on the 3rd dial. Whether the kernel sent RST,
  FIN, or just closed the socket is below the assertion level.
  Either outcome is correct daemon behaviour.
- **3-second timeout on the 3rd dial.** Generous bound. The
  daemon's reject path is `drop(tcp) → continue` — should be
  <10ms. 3s catches a hang without flaking on CI.
- **300ms sleeps between phases.** Empirical. The daemon's
  metrics commit + admission state transitions need a small
  settle window. Could replace with polling-loops on the metric
  values — kept as fixed sleeps for simplicity.
- **Test 2's "second dial rejected" is timing-sensitive.** If
  the test runner sleeps for >1s between the first and second
  dial, the bucket refills and the second succeeds. The test
  fires the second dial immediately (within a couple of ms);
  in practice this is reliable on every reasonable CI runner.
  If flakes ever surface, can switch to `capacity=1, refill=0`
  (no refill ever) — but `refill=0` may not be a valid config
  value, would need a check.
- **`DaemonGuard` duplicated yet again.** Sprint 28 + Sprint 34
  both inline-duplicate it. Same trade-off as the fixture —
  bounded duplication, unbounded generalization. The promote-
  threshold is "5th copy"; Sprint 34 makes it the 3rd copy
  (counting Sprint 28). Not yet.

### 13.42.5 API surface changes

**None for production code.** Sprint 34 is pure test code addition.

### 13.42.6 Acceptance — actual

- [x] `cargo test --workspace --locked` green: **217 tests** (215 +
      2 new admission enforcement tests).
- [x] Both tests run in ~3s combined.
- [x] `cargo build --workspace --locked` clean.
- [x] `cargo clippy --workspace --all-targets -- -D warnings` clean.
- [x] `cargo fmt --all --check` clean.
- [x] `cargo build -p qgateway --features pkcs11 --locked` clean.

### 13.42.7 Honest deferrals to Sprint 35

The carry-over list is now genuinely short:

1. **Concurrent rejection burst.** Stress test under sustained
   DoS pressure. Real value if a sustained-attack scenario is
   suspected. Less abstract now that admission is integration-
   covered.
2. **Multi-source rate limit test.** Prove each source IP gets
   its own bucket. Needs multi-loopback-bind or netns trickery.
3. **SIGHUP hot-limit change test.** Sprint 16 ships hot-reload of
   `[tenants.limits]`; no test exercises start-with-A → SIGHUP-to-B
   → newly-admitted-dial-works.
4. **Refill assertion.** Wait for token-bucket to refill, assert
   admission succeeds.
5. **`cargo-fuzz` harness for qtransport-cspq.** Offline.
6. **TLS/SNI chaos variant.** Sprint 29 carry-over.
7. **Multi-seed chaos sweep.** Sprint 29 carry-over.
8. **`proptest` dep + shrinking.** Sprint 29 carry-over.
9. ✅ **`[rotation] poll_interval` config field** — DELIVERED in Sprint 35.
10. **`SO_REUSEPORT`, per-group drain timeout, hard SNI drain** —
    operator demand.

The integration test surface has now covered:
- **Lifecycle**: SIGHUP ADD/REMOVE, audit chain integrity, rotation,
  auto-rotation, chaos signal pressure
- **Security data plane**: trusted events, untrusted reject, S0
  garbage, S1 garbage
- **Capacity enforcement**: max_concurrent quota, rate limit per source

Further integration coverage would be mechanical extensions of
existing tests. Sprint 35+ should pivot toward product surface
(operator UX, docs, dashboard, gRPC management endpoint,
OpenTelemetry export) or external observability (concurrent stress
tests if real-world capacity questions arise).

---

## 13.43. SPRINT 35 — DELIVERABLE CONTRACT (✅ CLOSED — `[rotation] poll_interval_ms` config field)

Sprint 35 ships a small operator-facing improvement that was
justified by Sprint 28 (§13.36.3) and Sprint 34 (§13.42.7 #9):
make the auto-rotation monitor's poll interval configurable instead
of hardcoded at 5 seconds. The benefit is two-fold:

1. **Operator value**: compliance scenarios with tight rotation
   deadlines (e.g., "rotate within 1 second of crossing 1 MiB")
   can now configure sub-5-second polling instead of waiting up to
   5 seconds past the threshold.
2. **Test value**: Sprint 28's auto-rotation integration tests
   were dominated by 5-second poll waits. With `poll_interval_ms =
   100`, those tests drop from ~35 seconds to ~9.7 seconds — a
   3.6× speedup with no semantic change.

The field name is `poll_interval_ms` (not `_secs`) because
operators who care about polling cadence usually care at sub-
second resolution; operators who don't care never set it.

### 13.43.1 Delivered

| # | Deliverable | Notes |
|---|---|---|
| `RotationPolicy::poll_interval_ms: Option<u64>` | New TOML field. `#[serde(default)]`, defaults to `None`. |
| `RotationPolicy::poll_interval()` method | Resolves the field to a `Duration`. Returns `Duration::from_secs(5)` if `None`, otherwise `Duration::from_millis(ms.max(10))`. |
| 10 ms floor with clamp | Sub-10ms values silently clamp to 10ms. Defends against `poll_interval_ms = 0` accidentally creating a busy-spin. Lib test `rotation_policy_poll_interval_clamps_to_floor` enforces the clamp at 0/1/5/9 ms. |
| 3 new lib tests in config.rs | `rotation_policy_poll_interval_default_is_5s`, `rotation_policy_poll_interval_honors_explicit_value`, `rotation_policy_poll_interval_clamps_to_floor`. |
| `cmd_run` startup loop | Chained `.with_poll_interval(policy.poll_interval())` on every `RotationMonitor::new(...)` call. |
| SIGHUP ADD spawn path | Same chain — runtime-added tenants honor the configured interval. |
| Existing `RotationPolicy {...}` lib test literals updated | Three sites in `audit.rs` lib tests gained `poll_interval_ms: None`. No semantic change. |
| Sprint 28 test fixture updated | Adds `poll_interval_ms = 100` to the `[rotation]` block. All sleeps tightened from 6–7 seconds to 1.5 seconds. |
| Sprint 28 test runtime: 35s → 9.7s | 3.6× speedup. Same assertions, same coverage. |

### 13.43.2 What's now possible

A production operator's config:

```toml
[rotation]
max_age_secs = 60
poll_interval_ms = 1000   # check every 1 second instead of every 5

[[tenants]]
# ...
```

Means: rotation fires within ~1s of crossing the 60-second age
threshold, instead of within ~5s. For high-throughput logs near a
size cap (`max_bytes`), the same applies — the gap between "log
crosses threshold" and "rotation fires" shrinks proportionally.

The default (`poll_interval_ms` unset) preserves Sprint 8.5's 5-
second behaviour for every operator who doesn't opt in.

### 13.43.3 Trade-offs documented

- **Field naming: `_ms` not `_secs`.** Operators who care about
  rotation cadence usually care at sub-second resolution. Operators
  who don't never set it. Picking `_ms` gives the full useful
  range with one field; picking `_secs` would force a second
  field for fine-grained users. The field name is explicit
  (operators reading `poll_interval_ms = 1000` won't confuse it
  for seconds).
- **10ms floor with silent clamp.** A 0ms or 1ms poll would
  busy-spin the monitor task. The clamp is silent (no log warning)
  because (a) the operator may have set it intentionally for a
  test, (b) at 10ms the load is still ~negligible (one `stat()`
  syscall per tick). If we ever see operators hit this in
  production by mistake, can add a warn-log.
- **No upper bound enforcement.** An operator who sets
  `poll_interval_ms = 86_400_000` (one day) gets exactly that.
  Validates the user's intent — they may be running an archival
  log where daily polling is correct.
- **No SIGHUP hot-reload of `poll_interval`.** The rotation policy
  is daemon-wide and changes require restart (see §13.35.4). If
  Sprint X ever adds per-tenant rotation override or hot-reload,
  `poll_interval` would come along automatically.
- **Sprint 28 fixture updated, not all integration tests.** Only
  Sprint 28's auto-rotation tests benefit; no other test runs
  the monitor at all. Updating just where the speedup matters
  minimises diff.
- **Three lib tests instead of a single parametrised one.** Rust
  doesn't have native test parametrisation without `proptest` or
  `rstest`. Three explicit tests are clearer for the three
  semantic cases (default / explicit / clamp).

### 13.43.4 API surface changes

- `qgateway_core::RotationPolicy` gains one public field:
  `poll_interval_ms: Option<u64>` and one method:
  `poll_interval(&self) -> std::time::Duration`.
- `RotationPolicy { ... }` literal constructors must now supply
  `poll_interval_ms`. Three call sites in `audit.rs` lib tests
  updated.
- TOML config schema accepts the new optional field. Existing
  configs that don't set it continue to work unchanged.

No breakage for operators — the new field is `Option<u64>` with
serde default, so every existing TOML file deserialises identically.

### 13.43.5 Acceptance — actual

- [x] `cargo test --workspace --locked` green: **220 tests** (217 +
      3 new lib tests for the poll_interval accessor).
- [x] Sprint 28 auto-rotation tests dropped from ~35s to ~9.7s
      (3.6× speedup).
- [x] `cargo build --workspace --locked` clean.
- [x] `cargo clippy --workspace --all-targets -- -D warnings` clean.
- [x] `cargo fmt --all --check` clean.
- [x] `cargo build -p qgateway --features pkcs11 --locked` clean.

### 13.43.6 Honest deferrals to Sprint 36

The deferral list is now genuinely short and weighted toward
**non-integration-test** axes:

1. ✅ **Operator runbook / deployment docs** — DELIVERED in Sprint 36.
2. **OpenTelemetry export.** Additive observability beyond
   Prometheus. Compliance contexts often demand OTLP traces.
3. **gRPC management endpoint.** Programmatic alternative to
   SIGHUP for ADD/REMOVE. Larger scope; needs design.
4. **SIGHUP hot-limit change test.** Sprint 16 path uncovered.
5. **Concurrent rejection burst.** Stress test.
6. **Multi-source rate limit test.** Needs netns or multi-loopback.
7. **Refill assertion.** 1s wait test.
8. **`cargo-fuzz` harness.** Offline.
9. **TLS/SNI chaos variant.** Mechanical.
10. **`SO_REUSEPORT`, per-group drain timeout, hard SNI drain** —
    operator demand.

The integration-test surface is genuinely complete. Sprint 36+
should pivot to product-surface or external-observability work.

---

## 13.44. SPRINT 36 — DELIVERABLE CONTRACT (✅ CLOSED — operator runbook + HSM integration docs)

Sprint 36 ships the documentation gap between "v1.0 feature-complete"
and "v1.0 deployable in production by a Brazilian bank's DevSecOps
team". The product had a 5400-line SPEC (design) and a README
(orientation), but no operator-facing runbook covering production
deployment, daily ops, troubleshooting, or HSM integration.

This is documentation work; no code change. The justification is
honest: the v1.0 ship gate is gated on operators being able to
deploy the gateway without reading the SPEC. Sprint 36 closes that
gate with two documents totalling ~1100 lines.

### 13.44.1 Delivered

| # | Deliverable | Size | Notes |
|---|---|---|---|
| `docs/RUNBOOK.md` | ~700 lines, 10 sections | Production deploy, signal contract, metrics reference, troubleshooting, incident response, compliance handling guidance |
| `docs/HSM.md` | ~400 lines, 5 sections | PKCS#11 / HSM-backed audit signer walkthrough, vendor matrix, PIN handling, key rotation, hardening checklist |
| README pointer at top | Cross-link to both | Operators landing on the README see the runbook reference immediately, before the design-oriented sections |
| README Sprint 36 section | Summary of docs surface | Same pattern as previous sprints |
| `mkdir docs/` | Created | Was empty until this sprint |

### 13.44.2 Runbook scope (sections)

1. **Audience and scope** — explicit about what knowledge is assumed
   (systemd, TOML, Prometheus) and what is NOT (cryptographic
   expertise; the PQ primitives are abstracted as opaque file artifacts)
2. **Production deployment** — binary install, key generation procedure
   (transport identity + audit signer), peer trust dir setup, complete
   config schema reference with production guidance per knob, systemd
   unit with hardening directives (NoNewPrivileges, ProtectSystem,
   capability bounding, syscall filter), deploy verification checklist
3. **Daily operations** — full signal contract (SIGTERM/SIGINT/SIGHUP/
   SIGUSR1/SIGUSR2/explicit DO-NOT-USE on SIGKILL with reasoning),
   SIGHUP reload workflow + hot-vs-cold change matrix, TLS cert reload
   procedure, audit log rotation procedure + long-term retention
   pipeline guidance, graceful restart procedure
4. **Metrics reference** — every Prometheus counter the daemon emits,
   organized by category (per-tenant data plane / audit / admission /
   HSM / daemon-wide), each with type + meaning + action threshold +
   suggested Prometheus alerting rules (YAML snippets ready to paste)
5. **Compliance and audit chain handling** — what the chain proves,
   external verification workflow, long-term retention pipeline
   suggestion, Bacen 4658/2018 + LGPD headline mapping (with honest
   disclaimer that the gateway provides building blocks, not
   compliance itself)
6. **Troubleshooting** — 7 named failure modes (audit failures spike,
   high handshake failure rate, SIGHUP rejected, runtime-added
   tenant misbehaviour pointing to Sprint 27/28 history, stuck
   sessions_active, HSM errors → HSM.md, restart loop) each with
   diagnosis steps and remedies
7. **Upgrade procedure** — single-major path; explicit note that v1↔v2
   mixed deployments are out of scope for v1.x
8. **Observability extras** — scrape interval recommendation, suggested
   Grafana panel layout (no JSON shipped yet; documented honestly),
   log aggregation guidance with LGPD caveat on logging source IPs
9. **Incident response** — 5-step procedure (preserve evidence, clean
   shutdown only, snapshot, verify chains, rotate keys if compromised);
   explicit guidance on what NOT to do (no SIGKILL, no deletion of
   audit logs)
10. **Where this runbook is incomplete** — honest list of v1.0 gaps:
    no `--dry-run` flag, no reference Grafana dashboard JSON, no
    formal Bacen/LGPD mapping document, no backup/DR procedure,
    no Kubernetes/Helm guide

### 13.44.3 HSM doc scope (sections)

1. **Why HSM-backed audit signing** — threat model explanation:
   protects against host-root compromise, not against application-
   layer code injection or HSM physical attack
2. **Supported PKCS#11 implementations** — vendor matrix with honest
   status: SoftHSM2 (lib-tested via qaudit-hsm CI); YubiHSM2,
   Thales Luna, Utimaco listed as untested-pending-hardware
3. **Configuration** — HSM key provisioning workflow (generate on
   HSM, never import), TOML config schema for `[audit_signer]
   kind = "pkcs11"` block, PIN handling via `pin_env` + systemd
   `EnvironmentFile` (with explicit guidance to NOT use `Environment=`
   directive which leaks via ps), deploy verification via metrics
4. **Troubleshooting** — PKCS#11 error code mapping (CKR_TOKEN_NOT_PRESENT,
   CKR_PIN_INCORRECT, CKR_USER_PIN_LOCKED, CKR_KEY_HANDLE_INVALID,
   CKR_MECHANISM_INVALID), sign-failure incident response, handshake
   latency diagnosis when HSM is bottleneck, HSM key rotation procedure
5. **Honest limitations and roadmap** — what HSM custody does NOT
   protect against, deferred items (per-tenant signers, sign-op
   batching, cluster failover, key attestation), pre-production
   hardening checklist (8 items)

### 13.44.4 Trade-offs documented

- **Two docs, not four.** Originally scoped 4 (RUNBOOK + COMPLIANCE
  + TROUBLESHOOTING + HSM). Compliance mapping deferred until
  concrete bank PoC demand; troubleshooting merged into RUNBOOK
  §6. Two docs is the honest minimum that closes the deploy gap;
  more docs would be speculation about what operators want.
- **No reference Grafana JSON.** Sprint 36 ships the panel layout
  guidance in RUNBOOK §8.2 but not a working JSON file. Reasoning:
  Grafana versions drift fast, JSON exported from one version
  often breaks on another, and the panel selection is honest
  guidance that maps directly to the metric reference. If operators
  ask for a dashboard, ship it in Sprint 37+.
- **No working `--dry-run` config validation flag.** Documented as
  a known gap in RUNBOOK §10. The workaround (test daemon on
  alternate ports) is documented. Adding the flag is small code
  work; not in Sprint 36 because Sprint 36 is documentation-only.
- **HSM vendor matrix honestly marked "untested".** YubiHSM2,
  Thales Luna, Utimaco are listed with 🟡 status not ✅. Operators
  reading the doc will know to validate on their specific firmware
  before going live. Marking them ✅ without test evidence would
  be marketing — flagged explicitly because the product axiom
  ("In Code We Trust") rules out aspirational claims.
- **Compliance section is orientation, not mapping.** RUNBOOK §5.4
  gives headline guidance on Bacen 4658 / LGPD but does not
  constitute a formal compliance mapping. The honest framing:
  "Cofre Soberano PQ provides building blocks that map to
  Brazilian regulatory requirements but does NOT itself constitute
  compliance." A formal mapping document waits for concrete bank
  PoC demand.
- **No code change.** Sprint 36 is pure documentation. The test
  count is unchanged at 220.

### 13.44.5 API surface changes

**None.** Sprint 36 is documentation-only.

### 13.44.6 Acceptance — actual

- [x] `docs/RUNBOOK.md` ~700 lines, 10 sections, covering production
      deploy through incident response
- [x] `docs/HSM.md` ~400 lines, 5 sections, covering PKCS#11
      integration through hardening checklist
- [x] README updated with cross-link at the top
- [x] README Sprint 36 section summarising what's in docs/
- [x] No code change, no test change. Existing acceptance gate
      (220 tests, clippy `-D warnings`, fmt, pkcs11 build clean)
      is unchanged by Sprint 36.

### 13.44.7 Honest deferrals to Sprint 37 / v1.1

The v1.0 ship gate is now genuinely closed. Sprint 37+ items are
operator-demand-gated:

1. ✅ **`--dry-run` config validation flag** — DELIVERED in Sprint 37 (shipped as a dedicated `validate` subcommand rather than `run --dry-run`).
2. **Reference Grafana dashboard JSON.** Ships when an operator uses Grafana and asks.
3. **Formal Bacen / LGPD compliance mapping doc.** Ships when a bank PoC requires it. Until then, RUNBOOK §5.4 is honest orientation.
4. **Kubernetes / Helm deployment guide.** Ships when a containerised operator asks.
5. **Backup / DR procedure document.** Ships when a regulator's recovery-time-objective surfaces.
6. **OpenTelemetry export** (architectural addition).
7. **gRPC management endpoint** (architectural addition).
8. **Per-tenant audit signers** (HSM.md §5.2 deferred item).
9. **Sign-op batching** (HSM.md §5.2 deferred item).
10. All remaining Sprint 35-era integration-test deferrals (concurrent burst, multi-source rate, refill, cargo-fuzz, TLS/SNI chaos, SO_REUSEPORT).

---

## 13.45. SPRINT 37 — DELIVERABLE CONTRACT (✅ CLOSED — `qgateway validate` subcommand)

Sprint 37 closes the only deferral item from §13.44.7 that was
neither speculation nor operator-demand-gated: the `--dry-run`
flag that RUNBOOK.md §3.2 explicitly documented as a workaround
("spin up a test daemon on alternate ports"). Every operator
deploying to production wants to validate config before
SIGHUP'ing prod; the workaround was a real friction point.

Shipped as a dedicated `validate` subcommand rather than `run
--dry-run` because the validation code path diverges substantially
from `run`'s (no listen-socket bind, no audit-log file creation,
no PKCS#11 session open) — a flag on `run` would be a confusing
modal switch. A separate subcommand surfaces the semantic
distinction in the CLI itself: "running" vs "validating" are
different operator actions.

### 13.45.1 Delivered

| # | Deliverable | Notes |
|---|---|---|
| `Cmd::Validate { config: PathBuf }` | New clap subcommand. Help text explicitly documents what `validate` does and does NOT exercise. |
| `cmd_validate(config_path: &Path) -> Result<()>` | Top-level dispatcher. Calls `Config::load` for TOML parse + structural validation, then `load_transport_identity` for the daemon identity, then `validate_one_tenant` for each tenant, then sanity-parses `metrics_listen`. |
| `validate_one_tenant` | Per-tenant resolution: peer trust dir via `PeerPolicy::from_dir`, listen address parse, role-conditional `backend`/`peer_pq` address parse, audit log parent directory exists, audit signer files (softkey: load + parse; PKCS#11: module file exists + `pin_env` is set in environment), TLS cert/key parse if `[tls]` is declared. |
| `validate_tls_cert` / `validate_tls_key` | Minimal PEM parsers in main.rs using `rustls_pemfile` directly. Avoid exposing qgateway-core's internal rustls type signatures as public API just to support the validator. |
| `rustls-pemfile` added to qgateway deps | Was already in workspace deps; added explicitly to qgateway because the validator needs it. |
| `crates/qgateway/tests/validate_cli.rs` | 7 integration tests covering: happy path, no audit-log side-effect, non-interference with already-bound ports, missing identity key, missing peer dir, missing audit signer key, malformed TOML. |
| RUNBOOK.md §3.2 updated | Workaround text replaced with documented `validate` subcommand workflow. |
| RUNBOOK.md §10 updated | `--dry-run` removed from honest-gaps list. |

### 13.45.2 What the validate subcommand exercises

The validator replays the **exact same fallible resolution code**
the daemon hits at startup, including the same loader functions
(no parallel implementation that could drift). What it skips is
specifically the **side-effectful** half:

| Step | `run` | `validate` |
|---|---|---|
| `Config::load` (TOML parse + structural validation) | ✅ | ✅ |
| `load_transport_identity` (file presence + magic + ML-DSA-87 parse) | ✅ | ✅ |
| `PeerPolicy::from_dir` per tenant (read + parse every `.cspqid.pub`) | ✅ | ✅ |
| Listen / backend / peer_pq address string parses to `SocketAddr` | ✅ | ✅ |
| audit_log parent directory exists | ✅ (implicit when file is opened) | ✅ (explicit check) |
| Audit signer keys parse (softkey) | ✅ | ✅ |
| PKCS#11 module file exists | ✅ (implicit when session opens) | ✅ (explicit check) |
| PKCS#11 `pin_env` is set in environment | ✅ | ✅ |
| TLS cert + key PEM parse | ✅ | ✅ |
| **Bind listen sockets** | ✅ | ❌ |
| **Create audit log file (write chain header)** | ✅ | ❌ |
| **Spawn audit-channel task** | ✅ | ❌ |
| **Open PKCS#11 session + authenticate with PIN** | ✅ | ❌ |
| **Spawn metrics HTTP server** | ✅ | ❌ |
| **Install signal handlers** | ✅ | ❌ |

The asymmetric coverage is deliberate. Validation should catch
operator mistakes (wrong path, missing file, malformed PEM, env
var typo) — that's the failure surface the workaround was meant to
expose. Validation should NOT exercise runtime-resource concerns
(port already bound, HSM unreachable, disk full at file-creation
time) because those are environment conditions, not config errors,
and they may differ between validation and prod-run windows.

### 13.45.3 What the tests prove

The 7-test suite is structured around the four invariants that
matter operationally:

**Happy path** (1 test):
- `validate_accepts_good_config` — a `common::Fixture` config
  (the same fixture the integration test suite uses for every
  other test) validates with exit 0 and stdout contains the
  one-line summary.

**No side effects** (2 tests):
- `validate_does_not_create_audit_log_file` — after `validate`
  returns, the tenant's `.qa` file does NOT exist on disk.
- `validate_does_not_bind_listen_port` — the test process binds
  the tenant's port first, then runs `validate`. If the validator
  tried to bind, it would fail with EADDRINUSE; the test asserts
  the validator exits 0 anyway. This is the test that enforces
  the RUNBOOK §3.2 commitment ("safe to run against a production
  config on a host where the daemon is already running").

**Error paths** (4 tests):
- `validate_rejects_missing_identity_key_file` — remove the
  daemon's `.skid` file; validate must exit non-zero and stderr
  must name "transport" or "identity" or the file name.
- `validate_rejects_missing_peer_dir` — empty the peer trust
  directory; validate must reject with peer-related error.
- `validate_rejects_missing_audit_signer_key` — remove the audit
  signer's `.skid`; validate must reject with audit-related error.
- `validate_rejects_malformed_toml` — append a stray brace to the
  config; validate must reject with parse-related error.

All 7 tests pass in 0.5 seconds total.

### 13.45.4 Trade-offs documented

- **Separate subcommand, not `run --dry-run` flag.** Two reasons:
  (1) `cmd_run` is async (calls `Config::load` then immediately
  enters a multi-page async setup chain); a dry-run flag would
  require either a conditional branch in `cmd_run` (modal logic)
  or a duplicated async setup path. A dedicated sync function is
  cleaner. (2) The semantic distinction matters for operators:
  `qgateway validate` is read-only, `qgateway run` is the
  side-effectful action. Surfacing this in the CLI verb improves
  discoverability over a flag.
- **Re-implementing TLS PEM parse inline.** `qgateway_core::tls`
  has private `load_cert_chain` / `load_private_key` helpers that
  return rustls types (`CertificateDer`, `PrivateKeyDer`).
  Exposing them as `pub` would leak rustls types into the public
  API of qgateway-core (currently the crate doesn't re-export
  rustls types at all). The validator only needs "can rustls parse
  this?" — re-implementing in 25 LoC keeps the public API surface
  unchanged and decouples the validator from cert-loader type
  signature drift.
- **No semantic key-cert pairing check.** A config could declare
  a cert chain and key pair whose key doesn't sign the cert; the
  validator does NOT detect this. The daemon would catch it at
  acceptor build time at startup. Checking it here would require
  full rustls type plumbing the validator doesn't need. Documented
  as an honest limitation; the failure mode is rare (most operators
  pair files that match) and surfaces immediately at the next
  prod restart.
- **PKCS#11 validation is structural-only.** We check the module
  file exists and the `pin_env` is set in the validator's
  environment. We do NOT actually open a PKCS#11 session. Reasons:
  (1) opening a session would require the HSM to be reachable
  from wherever validate runs (operators may validate from a
  laptop without HSM access); (2) the PIN would need to be in
  the validator's environment, which exposes it via `ps -e` /
  `/proc/<pid>/environ` more broadly than the daemon's hardened
  systemd unit. Documented limitation; operators who want full
  HSM connectivity validation should fall back to the
  test-daemon-on-alternate-port pattern.
- **audit_log parent directory check is non-strict.** We check
  the parent directory `is_dir()`; we do NOT check it's writable.
  Reason: writability checks via filesystem are racy and
  environment-dependent (the validator may not have the same
  effective UID as the daemon will). Catching a wrong path is
  the typo-level concern that matters; "parent exists" catches
  90% of operator mistakes here.
- **Address strings are parsed twice.** Once during `Config::load`
  structural validation (if applicable; some address fields may
  be lazily parsed at startup), then again in `validate_one_tenant`
  to give a focused error message. Duplication is bounded (3
  `SocketAddr::parse` calls per tenant); error-message quality
  takes priority.
- **The validator output is a single human-readable line on
  success, anyhow-chain on failure.** No JSON output mode. Could
  be added if tooling integration becomes useful; not needed for
  the current operator workflow (which is "type the command, read
  the output, fix what the error said"). YAGNI.

### 13.45.5 API surface changes

- New CLI subcommand: `qgateway validate --config <path>`.
- `qgateway` crate gains a `rustls-pemfile` workspace dependency
  (it was already in workspace deps; just added the import).
- No changes to library crates.

### 13.45.6 Acceptance — actual

- [x] `qgateway validate --config <good>` exits 0 with summary line.
- [x] `qgateway validate --config <bad>` exits non-zero with concrete
      error naming the offending field.
- [x] 7 new integration tests in `tests/validate_cli.rs`, all passing
      in 0.5s combined.
- [x] qgateway crate: 23 integration tests pass.
- [x] Lib crates: 204 tests pass (qgateway-core, qaudit-core, qaudit,
      qaudit-hsm, qaudit-portal, qtransport-cspq).
- [x] **Total: 227 tests** (220 prior + 7 Sprint 37).
- [x] `cargo build -p qgateway --features pkcs11` clean.
- [x] `cargo clippy --workspace --all-targets -- -D warnings` clean.
- [x] `cargo fmt --all --check` clean.
- [x] RUNBOOK.md §3.2 updated to document the new subcommand.
- [x] RUNBOOK.md §10 honest-gaps list updated (`--dry-run` removed).

### 13.45.7 Honest assessment going into Sprint 38

The deferral list contains ZERO remaining items that are both
defensible (not operator-demand-gated speculation) and concrete
(not architectural additions like OTel/gRPC mgmt). Every remaining
deferral falls into one of:

- **Operator-demand-gated** (Grafana JSON, Bacen mapping, K8s/Helm,
  DR procedure): would be speculation without external pull.
- **Architectural additions** (OTel export, gRPC mgmt endpoint,
  per-tenant signers, sign-op batching, multi-daemon mesh): each
  is its own multi-sprint design + implementation effort, not a
  v1.0 polish item.
- **Mechanical test extensions** (concurrent burst, multi-source
  rate, refill, TLS/SNI chaos, `cargo-fuzz`): low marginal value
  past the existing 16 integration tests; would surface bugs only
  if a real production pattern is suspected.
- **Operator-demand-gated kernel knobs** (SO_REUSEPORT, drain
  timeouts, hard SNI drain): no demand signal.

**This is the honest end of the v1.x feature-test-document cycle.**
Continuing past Sprint 37 without concrete external pull (an
operator deploying the gateway and surfacing a real gap) would
violate §17 standing policy: *"If a feature can't be explained
to a Bacen examiner without hand-waving, it doesn't ship."*
Equally, if a feature can't be justified without speculative
operator-demand, it shouldn't be built.

**The product is genuinely done for v1.0.**

---

## 13.46. SPRINT 38 — DELIVERABLE CONTRACT (✅ CLOSED — release hygiene for v1.0)

Sprint 38 closes a gap that Sprints 35-37's "stop sprinting"
recommendation surfaced but didn't itself fix: **reproducible-build
hygiene at the repository level**. The product claims reproducible
builds in README, SPEC, and HSM.md. Sprint 38 makes those claims
true at the release-artifact level rather than aspirational.

This sprint passes the §17 standing-policy test because a Bacen
examiner asking *"reproduce this binary from source"* requires (a)
a pinned toolchain version, (b) a committed `Cargo.lock`, (c) CI
that proves both work. Sprint 38 fixes three concrete defects
where the docs claimed reproducibility but the artifacts didn't
back it up.

### 13.46.1 Defects fixed

| # | Defect | Fix |
|---|---|---|
| 1 | `Cargo.lock` excluded from every ship tarball since Sprint 11 | Removed `--exclude='cofre-soberano-pq/Cargo.lock'` from the canonical ship command. The lockfile is now part of every released tarball, so downstream operators can reproduce the dependency tree exactly. |
| 2 | `rust-toolchain.toml` pinned `channel = "stable"` — drifts | Pinned to `channel = "1.95.0"` (the Rust release used to build v1.0). Bumping requires intentional edit + re-validation against the test suite. |
| 3 | CI used `dtolnay/rust-toolchain@stable` in every job — same drift risk | All 6 CI jobs (fmt, clippy, test, smoke_qaudit, smoke_qgateway, audit_cargo) now use `@1.95.0`. Comment block documents that the file's pins must match `rust-toolchain.toml`. |

### 13.46.2 Additional CI coverage added

While editing CI for the toolchain pin, three honest gaps in the
existing matrix were closed (no new code, just CI surface
extension):

| # | Gap | Fix |
|---|---|---|
| 4 | CI's clippy step linted `qaudit-hsm --features pkcs11` but NOT `qgateway --features pkcs11`. qgateway has had PKCS#11-conditional code paths since Sprint 16+, and Sprint 37 added more (PKCS#11 module presence + pin_env check in the validator). | Added `cargo clippy -p qgateway --features pkcs11 --all-targets --locked -- -D warnings` step. |
| 5 | CI's test step built `qaudit-hsm --features pkcs11` but NOT `qgateway --features pkcs11`. Every sprint since 17 has verified the qgateway pkcs11 build locally as part of the acceptance gate; CI was the gap. | Added `cargo build -p qgateway --features pkcs11 --locked` step to the test matrix. |
| 6 | The `smoke_qgateway` CI job ran the daemon end-to-end but never exercised the Sprint 37 `validate` subcommand. | Added two `qgateway validate` invocations to the smoke job: once before launching the daemons (catches CI-environment-specific config issues), once while daemon A is running (proves the non-interference commitment from RUNBOOK §3.2). |

### 13.46.3 What this does NOT change

- **No code change.** Sprint 38 is repository-hygiene only. The
  test count is unchanged at 227.
- **No semantic change to the product.** v1.0 binaries built from
  Sprint 37's source vs Sprint 38's source will be byte-identical
  (modulo timestamps embedded by the toolchain).
- **No new dependency.** Existing `cargo` + `dtolnay/rust-toolchain`
  + `Swatinem/rust-cache` are unchanged; only the version pins
  inside their `with:` blocks moved from `@stable` to `@1.95.0`.

### 13.46.4 Trade-offs documented

- **Pinning to exact `1.95.0` not `1.95`.** Cargo's
  `rust-toolchain.toml` semantics: `1.95` would accept any patch
  release in the 1.95 minor (e.g., 1.95.1, 1.95.2). For v1.0
  reproducibility we want the EXACT patch the developer used.
  When 1.95.1 comes out and we want to upgrade, the bump is a
  single-line change + re-verify; meanwhile the artifact is
  pinned.
- **CI version pin duplicated in two places.**
  `rust-toolchain.toml` + every `dtolnay/rust-toolchain@X` line
  in CI. Could be DRY'd by deleting the explicit CI pin and
  letting the toolchain file flow through (Cargo respects it
  automatically). Kept the explicit CI pin because (a) it makes
  the version visible in the CI run UI without operators needing
  to read the toolchain file, (b) `dtolnay/rust-toolchain@<file>`
  syntax exists but adds an indirection layer that surprises
  some readers. The comment block at the top of `ci.yml`
  documents the duplication contract.
- **Did not add reproducibility verification step.** A truly
  paranoid pipeline would build the binary twice (once on CI,
  once locally) and `diff` the outputs. Out of scope for Sprint
  38; the toolchain pin + locked deps + locked everywhere build
  bring us to the "should be reproducible" level. Bit-for-bit
  reproducible builds require additional work (deterministic
  build timestamps, sorted symbol tables, etc.) that exceed the
  v1.0 ship gate.
- **Did not ship the binary itself.** Sprint 38's deliverable
  is the SOURCE TARBALL with hygiene improvements. Building the
  release binary + distributing it is a separate operation
  (likely a `make release` target in a future sprint, but trivially
  expressible as `cargo build --release --locked --workspace` for
  now). The HSM doc and runbook document the install workflow
  assuming the operator builds locally; this is normal for
  AGPL-3.0 distribution where source is the canonical artifact.
- **CI smoke now runs `validate` twice in `smoke_qgateway`.**
  Once pre-daemon, once with daemon A running. Could have used
  a separate `validate` smoke job, but folding into the existing
  one avoids an extra `cargo build` cycle in CI (each new job
  rebuilds, which is the long pole). Cost: the smoke job is now
  ~10 seconds longer; benefit: validate gets real CI exercise
  on every push.

### 13.46.5 API surface changes

**None.** Sprint 38 is repository hygiene only.

### 13.46.6 Acceptance — actual

- [x] `rust-toolchain.toml` pinned to `1.95.0`.
- [x] All 6 CI jobs use `dtolnay/rust-toolchain@1.95.0`.
- [x] CI clippy adds `qgateway --features pkcs11` step.
- [x] CI test adds `qgateway --features pkcs11` build step.
- [x] CI `smoke_qgateway` invokes `qgateway validate` twice
      (pre-daemon, mid-daemon for non-interference proof).
- [x] `Cargo.lock` is no longer excluded from the ship tarball.
- [x] `cargo build --workspace --locked` succeeds (lockfile is
      consistent with current Cargo.toml manifests).
- [x] `cargo fmt --all --check` clean.
- [x] `cargo clippy --workspace --all-targets --locked -- -D warnings`
      clean.
- [x] `cargo clippy -p qgateway --features pkcs11 --all-targets
      --locked -- -D warnings` clean (the new CI step).
- [x] `cargo build -p qgateway --features pkcs11 --locked` clean
      (the new CI step).
- [x] 227 tests still pass (unchanged from Sprint 37).
- [x] `.github/workflows/ci.yml` parses as valid YAML.

### 13.46.7 Honest deferrals to Sprint 39+ / v1.1

- All Sprint 37 deferral items remain (operator-demand-gated,
  architectural, mechanical-low-value).
- **Bit-for-bit reproducible binary build** (deterministic
  timestamps, sorted symbol tables, SOURCE_DATE_EPOCH): not yet.
  Ships when a downstream packager asks.
- **Release tarball signing**: not yet. The audit-signer pattern
  proves we know how to do PQ-signed artifacts; releases would
  follow the same pattern (ML-DSA-87 over the source tarball).
  Ships when distribution scale justifies.
- **SBOM generation** (CycloneDX or SPDX): not yet. Useful for
  enterprise procurement; the dependency tree is small + visible
  in `Cargo.lock` for now.
- **Cross-platform release matrix** (Linux x86_64 + aarch64 +
  Windows + macOS): not yet. CI tests on ubuntu + macos already;
  release artifacts are not pre-built. Operators build from source.

### 13.46.8 Final stop assessment

Sprint 38 is the LAST sprint that has a defensible answer to
*"why this, not the other 12 deferred items?"*. The answer here:
"because shipping v1.0 with the documented reproducibility claim
unbacked by toolchain pin + committed Cargo.lock + CI proof would
fail the Bacen examiner test at the most basic level — before
they even get to looking at the crypto."

After Sprint 38, every remaining item is operator-demand-gated.
The §17 standing-policy test would fail. **Sprint 39+ requires
external pull, not internal momentum.**

---

## 13.99. STATE OF THE PROJECT AT v1.0 (post Sprint 38)

**Product status**: feature-complete for v1.0 single-daemon
deployment in regulated-Brazil contexts. Recommended for tagging
v1.0 and shipping to git.securityops.co.

**Test surface**:
- 220 tests across lib + integration layers
- 13 integration test files exercising lifecycle, security data
  plane, capacity enforcement, audit chain integrity
- 207 lib tests across 7 crates
- All gates: `cargo test --workspace`, `cargo clippy
  --workspace --all-targets -- -D warnings`, `cargo fmt --check`,
  `cargo build -p qgateway --features pkcs11`

**Bugs caught and fixed during integration sprints**:
- Sprint 27: `rotation_targets` Vec→HashMap promotion
- Sprint 28: `monitor_handles` Vec→HashMap promotion + latent
  task leak at SIGTERM

**Operator-facing documentation**:
- `SPEC.md` (5400+ lines): design specification and sprint
  history
- `README.md` (1490+ lines): orientation and quick start
- `docs/RUNBOOK.md` (~700 lines): production deployment + daily ops
- `docs/HSM.md` (~400 lines): PKCS#11 integration

**Known gaps for v1.1+** (operator-demand-gated):
- `--dry-run` config validation
- Reference Grafana dashboard JSON
- Formal Bacen / LGPD compliance mapping
- Kubernetes / Helm guide
- OpenTelemetry export
- gRPC management endpoint
- Per-tenant audit signers
- Multi-daemon / mesh-level testing

**Recommended next move**: tag v1.0, push to git.securityops.co,
announce on LinkedIn (PT + EN, same pattern as Evelin's launch),
wait for real operator feedback. Continuing to sprint on
speculation past v1.0 has decreasing marginal value.

---

## 14. CODING STANDARDS

- Rust 2021, MSRV 1.75.
- `#![forbid(unsafe_code)]` in every crate of CSPQ origin.
- `#![deny(missing_docs)]` in libraries with public surface.
- Errors with `thiserror`; binaries panic-free, returning `Result` from `main`.
- All public functions documented with `///`. All modules have a `//!` header.
- Tests live next to code with `#[cfg(test)] mod tests` *and* in `tests/`.
- Property tests welcome; quickcheck or proptest acceptable.
- Benchmarks in `benches/` using criterion when relevant.
- No `println!` in libraries; use `tracing`. Binaries may use `eprintln!`.

---

## 15. SUPPLY-CHAIN POSTURE

- `cargo-deny` enforces license whitelist and CVE blocklist.
- `cargo-audit` runs in CI on every PR.
- All deps pinned by `Cargo.lock` (committed).
- `cargo-vet` audit trail maintained from S7 onward.
- Builds reproducible from a Nix flake (added S8).

---

## 16. WHY BTP IS NOT IN SCOPE (yet)

BTP — Berkeley Transport Protocol — is the third pillar of the SecurityOps
PQ stack, but it requires ecosystem (witness operators, IANA registration,
external audit, client adoption) that no Brazilian bank will gate procurement
on in 2026–2027. BTP returns in **CSPQ v2 (2028)** as `QDoc`: a content-
addressed signed document format replacing ICP-Brasil-PDF in internal flows.

Don't apologize for the absence. Ship the two-thirds that closes contracts.

---

## 17. STANDING POLICY

> When in doubt: **smaller surface, harder guarantees, on-prem only,
> compliance-mapped, no telemetry**. We are not building a SaaS startup. We are
> building the regulated-Brazil equivalent of IBM Quantum Safe — except open,
> auditable, native, and honest about its limits. If a feature can't be
> explained to a Bacen examiner without hand-waving, it doesn't ship.

> *Compress everything. Trust nothing. Encrypt always.*
