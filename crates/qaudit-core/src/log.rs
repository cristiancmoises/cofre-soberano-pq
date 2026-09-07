//! The append-only, ML-DSA-87-signed, Merkle-chained audit log.
//!
//! ## File format (`.qa`)
//!
//! ```text
//!   [8 B]   magic     = "QAUDIT01"
//!   [CBOR]  LogHeader
//!   [CBOR]  LogEntry  (×N, appended)
//! ```
//!
//! The header is read once on open. Entries are streamed and verified one by
//! one, so logs of any size can be checked with O(1) memory plus the MMR
//! frontier (`O(log N)` hashes).
//!
//! ## Per-entry signature
//!
//! The signed message is the canonical CBOR encoding of
//!
//! ```text
//!   SignedPayload {
//!     log_id:    [u8; 16],   // matches header.log_id
//!     index:     u64,
//!     prev_root: [u8; 32],   // chain link
//!     event:     [u8; 32],   // BLAKE3 of canonical event
//!     new_root:  [u8; 32],   // MMR root after appending event
//!   }
//! ```
//!
//! Binding `log_id` defends against splice attacks across logs. Binding both
//! `prev_root` and `new_root` lets a verifier check chain integrity per-entry
//! without recomputing the entire MMR.

use crate::{
    error::{Error, Result},
    event::AuditEvent,
    merkle::{Hash, MerkleTree},
    signing::{verify as verify_sig, KeyPair, PublicKey, Signature, Signer},
    MAGIC, SUITE_ID, WIRE_VERSION,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::io::{BufReader, Read, Seek, SeekFrom, Write};
use std::path::Path;

/// Fixed-size, opaque 16-byte log identifier (UUID-shaped, but we don't depend
/// on a UUID crate; bytes are random from the OS RNG).
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogId(#[serde(with = "serde_bytes_array")] pub [u8; 16]);

impl LogId {
    /// Generate a fresh random log id.
    #[must_use]
    pub fn random() -> Self {
        use rand_core::RngCore;
        let mut b = [0u8; 16];
        rand_core::OsRng.fill_bytes(&mut b);
        Self(b)
    }

    /// Hex-encoded representation (32 lowercase chars).
    #[must_use]
    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }
}

impl std::fmt::Debug for LogId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LogId({})", self.to_hex())
    }
}

impl std::fmt::Display for LogId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

// Serde helper to encode a fixed-size 16-byte array as a CBOR byte string
// (rather than the default CBOR array of u8). This keeps log files compact and
// stable across serializers.
mod serde_bytes_array {
    use serde::{de::Error as _, Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(b: &[u8; 16], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(b)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 16], D::Error> {
        let v = serde_bytes::ByteBuf::deserialize(d)?;
        let slice: &[u8] = v.as_ref();
        slice
            .try_into()
            .map_err(|_| D::Error::custom("expected 16 bytes"))
    }
}

/// Static metadata written once at the head of the log file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LogHeader {
    /// Wire-format version. Currently [`WIRE_VERSION`].
    pub wire_version: u32,
    /// Human-readable suite identifier (e.g. `"cspq-2026"`).
    pub suite: String,
    /// Creation timestamp (UTC).
    pub created_at: DateTime<Utc>,
    /// Stable per-log random identifier; bound into every signature.
    pub log_id: LogId,
    /// ML-DSA-87 public key for verification.
    pub pubkey: PublicKey,
    /// Free-form label set at creation (e.g. `"qvault-prod-saopaulo"`).
    pub label: String,
    /// Sprint 7: previous log in this rotation chain. `None` for root logs
    /// (first in the chain); `Some(id)` for logs created via `rotate_to`.
    /// Backward-compatible: pre-Sprint-7 logs lack this field; readers
    /// default to `None`.
    #[serde(default)]
    pub prev_log_id: Option<LogId>,
    /// Sprint 7: final MMR root of the previous log at the moment of
    /// rotation (i.e. after its `audit.rotation_close` event). Verification
    /// of a multi-file chain checks that this value equals the previous
    /// log's actual computed final root.
    #[serde(default, with = "serde_optional_bytes_32")]
    pub prev_log_final_root: Option<Hash>,
}

fn validate_header(header: &LogHeader) -> Result<()> {
    if header.wire_version != WIRE_VERSION {
        return Err(Error::VersionMismatch {
            found: header.wire_version,
            supported: WIRE_VERSION,
        });
    }
    if header.suite != SUITE_ID {
        return Err(Error::BadHeader(format!(
            "unsupported suite: {}",
            header.suite
        )));
    }
    // Deserialization bypasses PublicKey::from_bytes. Validate even an empty
    // log so malformed keys never reach fingerprint formatting or signing.
    PublicKey::from_bytes(header.pubkey.as_bytes())?;
    Ok(())
}

/// Helper module for serializing `Option<[u8; 32]>` as bytes in CBOR.
/// Without this, `Option<[u8; 32]>` serializes as an array of integers,
/// which breaks the bytes-everywhere convention used elsewhere in the
/// header (PublicKey, LogId).
mod serde_optional_bytes_32 {
    use serde::{de::Error as _, Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Option<[u8; 32]>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(bytes) => s.serialize_some(serde_bytes::Bytes::new(bytes)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<[u8; 32]>, D::Error> {
        let opt: Option<serde_bytes::ByteBuf> = Option::deserialize(d)?;
        match opt {
            Some(bb) => {
                let v = bb.into_vec();
                if v.len() != 32 {
                    return Err(D::Error::custom(format!(
                        "prev_log_final_root: expected 32 bytes, got {}",
                        v.len()
                    )));
                }
                let mut out = [0u8; 32];
                out.copy_from_slice(&v);
                Ok(Some(out))
            }
            None => Ok(None),
        }
    }
}

/// The payload that is signed for each entry.
///
/// Kept private to ensure the canonical encoding stays a library detail.
/// We only ever serialize this — verification reconstructs the bytes from
/// known-typed components and re-runs CBOR encoding.
#[derive(Serialize)]
struct SignedPayload<'a> {
    #[serde(with = "serde_bytes")]
    log_id: &'a [u8; 16],
    index: u64,
    #[serde(with = "serde_bytes")]
    prev_root: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    event_hash: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    new_root: &'a [u8; 32],
}

fn payload_bytes(
    log_id: &[u8; 16],
    index: u64,
    prev_root: &Hash,
    event_hash: &Hash,
    new_root: &Hash,
) -> Vec<u8> {
    let p = SignedPayload {
        log_id,
        index,
        prev_root,
        event_hash,
        new_root,
    };
    let mut buf = Vec::with_capacity(128);
    ciborium::into_writer(&p, &mut buf).expect("payload serialization is infallible");
    buf
}

/// A single signed log entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LogEntry {
    /// Position in the log, starting at 0.
    pub index: u64,
    /// Wall-clock timestamp when the entry was appended (UTC).
    pub appended_at: DateTime<Utc>,
    /// Recorded event.
    pub event: AuditEvent,
    /// MMR root before this entry was appended (32 bytes).
    pub prev_root: Hash,
    /// MMR root after this entry was appended (32 bytes).
    pub new_root: Hash,
    /// ML-DSA-87 signature over [`SignedPayload`].
    pub signature: Signature,
}

/// In-memory mutable representation of an audit log.
///
/// Use [`AuditLog::create`] to start a new log with a software keypair,
/// [`AuditLog::create_with_signer`] to start one with an arbitrary
/// [`Signer`] (e.g. PKCS#11 HSM), [`AuditLog::open`] to load one from disk,
/// and [`AuditLog::append`] / [`AuditLog::save_to`] to write.
/// [`AuditLog::verify`] re-checks every signature and every chain link.
pub struct AuditLog {
    header: LogHeader,
    entries: Vec<LogEntry>,
    tree: MerkleTree,
    /// Present only when the log is open for signing. Verification-only logs
    /// loaded from disk have `signer = None`.
    signer: Option<Box<dyn Signer>>,
}

impl std::fmt::Debug for AuditLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditLog")
            .field("header", &self.header)
            .field("entries", &self.entries.len())
            .field("root", &hex::encode(self.tree.root()))
            .field(
                "signer",
                &self
                    .signer
                    .as_ref()
                    .map(|s| s.provenance())
                    .unwrap_or("<none>"),
            )
            .finish()
    }
}

impl AuditLog {
    /// Create a brand-new log in memory, owned by the given software keypair.
    pub fn create(keypair: KeyPair) -> Result<Self> {
        Self::create_with_label(keypair, "")
    }

    /// Create a new log with a human-readable label (e.g. `"qvault-prod-sp"`),
    /// using a software [`KeyPair`] as the signer.
    pub fn create_with_label(keypair: KeyPair, label: impl Into<String>) -> Result<Self> {
        Self::create_with_signer(keypair, label)
    }

    /// Create a new log signed by any [`Signer`] (software keypair, PKCS#11
    /// HSM session, future remote attester, etc.).
    pub fn create_with_signer<S: Signer + 'static>(
        signer: S,
        label: impl Into<String>,
    ) -> Result<Self> {
        let header = LogHeader {
            wire_version: WIRE_VERSION,
            suite: SUITE_ID.to_string(),
            created_at: Utc::now(),
            log_id: LogId::random(),
            pubkey: signer.public_key().clone(),
            label: label.into(),
            prev_log_id: None,
            prev_log_final_root: None,
        };
        Ok(Self {
            header,
            entries: Vec::new(),
            tree: MerkleTree::new(),
            signer: Some(Box::new(signer)),
        })
    }

    /// Read-only access to the header.
    #[must_use]
    pub fn header(&self) -> &LogHeader {
        &self.header
    }

    /// All entries appended so far, in order.
    #[must_use]
    pub fn entries(&self) -> &[LogEntry] {
        &self.entries
    }

    /// Number of entries.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.entries.len() as u64
    }

    /// `true` if no entries have been appended.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Current MMR root.
    #[must_use]
    pub fn current_root(&self) -> Hash {
        self.tree.root()
    }

    /// Provenance tag of the currently bound signer, or `"<none>"` if the
    /// log was opened in verification-only mode.
    #[must_use]
    pub fn signer_provenance(&self) -> &str {
        self.signer
            .as_ref()
            .map(|s| s.provenance())
            .unwrap_or("<none>")
    }

    /// Attach a software signing keypair to a log that was loaded read-only.
    /// The supplied keypair's public key MUST match the log's header pubkey.
    /// Used by the CLI's `append` path: open file, rebind key, append, save.
    pub fn bind_keypair(&mut self, kp: KeyPair) -> Result<()> {
        self.bind_signer(kp)
    }

    /// Attach an arbitrary [`Signer`] (e.g. PKCS#11 HSM session) to a log
    /// loaded read-only. The signer's public key MUST match the log header's.
    pub fn bind_signer<S: Signer + 'static>(&mut self, signer: S) -> Result<()> {
        if signer.public_key().as_bytes() != self.header.pubkey.as_bytes() {
            return Err(Error::BadKey(
                "signer public key does not match log header pubkey".into(),
            ));
        }
        // Opening a log decodes it; attaching a signing capability must also
        // validate the history before callers can extend a tampered chain.
        self.verify()?;
        self.signer = Some(Box::new(signer));
        Ok(())
    }

    /// Replace the header's public key. Used by `verify --pk` to support
    /// independent verification with an out-of-band key file (the supplied
    /// key must match the one in the header — this is validated by the
    /// caller before invoking this method).
    pub fn override_pubkey(&mut self, pk: PublicKey) {
        self.header.pubkey = pk;
    }

    /// Append a new event, producing a signed entry. Requires the log was
    /// opened with a signer bound (via [`AuditLog::create`],
    /// [`AuditLog::create_with_signer`], or [`AuditLog::bind_signer`]).
    pub fn append(&mut self, event: AuditEvent) -> Result<&LogEntry> {
        let signer = self
            .signer
            .as_ref()
            .ok_or_else(|| Error::Internal("log is read-only; no signer bound".into()))?;

        let prev_root = self.tree.root();
        let event_hash = event.content_hash();
        // Signing can fail (for example, when an HSM is unavailable). Commit
        // the frontier only after signing succeeds so a retry cannot inherit
        // an unsigned leaf. The frontier clone costs O(log N) hashes.
        let mut next_tree = self.tree.clone();
        let new_root = next_tree.append(&event_hash);
        let index = (self.entries.len()) as u64;

        let payload = payload_bytes(
            &self.header.log_id.0,
            index,
            &prev_root,
            &event_hash,
            &new_root,
        );
        let signature = signer.sign(&payload)?;

        let entry = LogEntry {
            index,
            appended_at: Utc::now(),
            event,
            prev_root,
            new_root,
            signature,
        };
        self.tree = next_tree;
        self.entries.push(entry);
        Ok(self.entries.last().expect("just pushed"))
    }

    /// Verify the integrity of the entire log: every signature and every
    /// chain link, replaying the MMR from scratch. Constant memory plus the
    /// frontier; suitable for very large logs.
    pub fn verify(&self) -> Result<()> {
        Self::verify_with_pubkey(&self.header, &self.entries)
    }

    /// Verify against an externally-supplied header (e.g. when reading a log
    /// from disk in verification-only mode).
    fn verify_with_pubkey(header: &LogHeader, entries: &[LogEntry]) -> Result<()> {
        validate_header(header)?;

        let mut tree = MerkleTree::new();
        let mut expected_prev: Hash = [0u8; 32];

        for (i, e) in entries.iter().enumerate() {
            if e.index != i as u64 {
                return Err(Error::InvalidEntry {
                    index: i as u64,
                    reason: format!("declared index {} but position {}", e.index, i),
                });
            }
            if e.prev_root != expected_prev {
                return Err(Error::ChainBroken {
                    index: e.index,
                    expected: hex::encode(expected_prev),
                    got: hex::encode(e.prev_root),
                });
            }
            let event_hash = e.event.content_hash();
            let new_root = tree.append(&event_hash);
            if new_root != e.new_root {
                return Err(Error::ChainBroken {
                    index: e.index,
                    expected: hex::encode(new_root),
                    got: hex::encode(e.new_root),
                });
            }
            let payload = payload_bytes(
                &header.log_id.0,
                e.index,
                &e.prev_root,
                &event_hash,
                &e.new_root,
            );
            verify_sig(&header.pubkey, &payload, &e.signature, e.index)?;
            expected_prev = new_root;
        }
        Ok(())
    }

    /// Write the log to a binary stream in the `.qa` format described in the
    /// module docs.
    pub fn save_to<W: Write>(&self, mut out: W) -> Result<()> {
        out.write_all(MAGIC)?;
        ciborium::into_writer(&self.header, &mut out)?;
        for e in &self.entries {
            ciborium::into_writer(e, &mut out)?;
        }
        out.flush()?;
        Ok(())
    }

    /// Atomically replace a log file after writing and syncing its contents.
    /// Existing regular-file permissions are preserved; new files are private.
    /// Symlinks and other nonregular destinations are rejected.
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let path = path.as_ref();
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let permissions = match std::fs::symlink_metadata(path) {
            Ok(metadata) if metadata.is_file() => Some(metadata.permissions()),
            Ok(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "audit log destination must be a regular file",
                )
                .into())
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.into()),
        };
        let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
        self.save_to(std::io::BufWriter::new(temporary.as_file_mut()))?;
        if let Some(permissions) = permissions {
            temporary.as_file().set_permissions(permissions)?;
        }
        temporary.as_file().sync_all()?;
        temporary.persist(path).map_err(|e| Error::Io(e.error))?;
        #[cfg(unix)]
        std::fs::File::open(parent)?.sync_all()?;
        Ok(())
    }

    /// Open a log from disk in verification-only mode (no signing key bound).
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let f = std::fs::File::open(path)?;
        Self::read_from(BufReader::new(f))
    }

    /// Read a log from any seekable byte stream.
    pub fn read_from<R: Read + Seek>(mut input: R) -> Result<Self> {
        let mut magic = [0u8; MAGIC.len()];
        input.read_exact(&mut magic)?;
        if &magic != MAGIC {
            return Err(Error::BadHeader(format!(
                "bad magic: got {:02x?}, expected {:02x?}",
                magic, MAGIC
            )));
        }

        // ciborium::from_reader stops at end of value; remember position to
        // continue reading entries.
        let header: LogHeader = ciborium::from_reader(&mut input)?;
        validate_header(&header)?;

        let mut entries: Vec<LogEntry> = Vec::new();
        loop {
            // Only EOF before the first byte of an entry is clean. A CBOR
            // decoder's UnexpectedEof may mean a partially written or
            // maliciously truncated entry and must never discard that tail.
            let pos = input.stream_position()?;
            let mut first = [0u8; 1];
            match input.read_exact(&mut first) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e.into()),
            }
            input.seek(SeekFrom::Start(pos))?;
            entries.push(ciborium::from_reader(&mut input)?);
        }

        // Rebuild MMR from entries — needed if the caller wants to append more.
        // (When opened read-only, this is harmless overhead.)
        let mut tree = MerkleTree::new();
        for e in &entries {
            tree.append(&e.event.content_hash());
        }

        Ok(Self {
            header,
            entries,
            tree,
            signer: None,
        })
    }

    // ========================================================================
    //              Sprint 7 — multi-file rotation chain
    // ========================================================================

    /// Sprint 7: rotate this log to a new file. Appends a final
    /// `audit.rotation_close` event to the current log (sealing the chain
    /// at this point), then creates a new log with a header carrying
    /// `prev_log_id` and `prev_log_final_root` references to the current
    /// log. The new log's first event is an `audit.rotation_open` event
    /// re-asserting the same references.
    ///
    /// On success, returns `(old_sealed, new_open)` — the old log is
    /// returned with the rotation_close already appended (operator should
    /// save it and stop appending). The new log is open for writing.
    ///
    /// The current log MUST have a bound signer; the new log uses the
    /// `new_signer` argument. Cross-log signer rotation (different audit
    /// key for the new chain segment) is supported — it's intentional.
    pub fn rotate_to(
        mut self,
        new_signer: Box<dyn Signer>,
        new_label: impl Into<String>,
        new_log_id_hex: impl Into<String>,
    ) -> Result<(Self, Self)> {
        if self.signer.is_none() {
            return Err(Error::Internal(
                "rotate_to: source log is read-only (no signer)".into(),
            ));
        }
        let new_label = new_label.into();
        let new_log_id_hex = new_log_id_hex.into();

        // Generate (or accept caller-provided) new log id.
        // To make rotation reproducible in tests, we accept a pre-computed
        // hex id; pass "" to use a random one.
        let new_log_id = if new_log_id_hex.is_empty() {
            LogId::random()
        } else {
            let bytes = hex::decode(&new_log_id_hex)
                .map_err(|e| Error::Internal(format!("invalid new log id hex: {e}")))?;
            if bytes.len() != 16 {
                return Err(Error::Internal(format!(
                    "new log id hex must decode to 16 bytes, got {}",
                    bytes.len()
                )));
            }
            let mut arr = [0u8; 16];
            arr.copy_from_slice(&bytes);
            LogId(arr)
        };

        // Step 1: append rotation_close event to current log.
        let close_event = crate::AuditEvent::builder()
            .action(ROTATION_CLOSE_ACTION)
            .actor("system:qaudit")
            .resource(format!("log:{}", hex::encode(self.header.log_id.0)))
            .outcome("ok")
            .meta("new_log_id", hex::encode(new_log_id.0))
            .meta("new_log_label", &new_label)
            .build();
        self.append(close_event)?;

        // Step 2: capture old log's final root (includes rotation_close).
        let prev_final_root = self.tree.root();
        let prev_log_id = self.header.log_id;
        let prev_label = self.header.label.clone();

        // Step 3: build new log header with rotation chain references.
        let new_header = LogHeader {
            wire_version: WIRE_VERSION,
            suite: SUITE_ID.to_string(),
            created_at: Utc::now(),
            log_id: new_log_id,
            pubkey: new_signer.public_key().clone(),
            label: new_label,
            prev_log_id: Some(prev_log_id),
            prev_log_final_root: Some(prev_final_root),
        };
        let mut new_log = Self {
            header: new_header,
            entries: Vec::new(),
            tree: MerkleTree::new(),
            signer: Some(new_signer),
        };

        // Step 4: append rotation_open event as first event of new log.
        let open_event = crate::AuditEvent::builder()
            .action(ROTATION_OPEN_ACTION)
            .actor("system:qaudit")
            .resource(format!("log:{}", hex::encode(new_log.header.log_id.0)))
            .outcome("ok")
            .meta("prev_log_id", hex::encode(prev_log_id.0))
            .meta("prev_log_final_root", hex::encode(prev_final_root))
            .meta("prev_log_label", prev_label)
            .build();
        new_log.append(open_event)?;

        // The OLD log is now sealed: drop its signer so accidental appends
        // after rotation are rejected as read-only.
        self.signer = None;

        Ok((self, new_log))
    }

    /// Sprint 7: verify a multi-file rotation chain. Each log's internal
    /// signature chain is verified; adjacent pairs are checked for matching
    /// `prev_log_id` / `prev_log_final_root` linkage. The first log in the
    /// slice MUST be the root of the chain (no prev_log_id); subsequent
    /// logs are linked via the rotation chain references.
    ///
    /// Returns `Err` on any mismatch — a regulator running this on a
    /// suspect chain learns *which* log and *which* property failed.
    pub fn verify_chain(logs: &[&AuditLog]) -> Result<()> {
        if logs.is_empty() {
            return Err(Error::Internal("verify_chain: empty chain".into()));
        }

        // First log: must be a root (no prev_log_id).
        let first = logs[0];
        first.verify().map_err(|e| {
            Error::Internal(format!(
                "verify_chain[0]: log {} internal verification failed: {e}",
                hex::encode(first.header.log_id.0)
            ))
        })?;
        if first.header.prev_log_id.is_some() || first.header.prev_log_final_root.is_some() {
            return Err(Error::Internal(format!(
                "verify_chain[0]: log {} has prev_log_id/prev_log_final_root set                  but is the first in the chain — caller passed logs out of order",
                hex::encode(first.header.log_id.0)
            )));
        }

        // Iterate adjacent pairs.
        for window in logs.windows(2) {
            let prev = window[0];
            let next = window[1];

            // Sprint 7.1 — verify the NEXT log's internal chain.
            next.verify().map_err(|e| {
                Error::Internal(format!(
                    "verify_chain: log {} internal verification failed: {e}",
                    hex::encode(next.header.log_id.0)
                ))
            })?;

            // Sprint 7.2 — the previous log's LAST event must be a
            // rotation_close referencing the next log's id.
            let last = prev.entries.last().ok_or_else(|| {
                Error::Internal(format!(
                    "verify_chain: log {} is empty — cannot have rotated",
                    hex::encode(prev.header.log_id.0)
                ))
            })?;
            if last.event.action != ROTATION_CLOSE_ACTION {
                return Err(Error::Internal(format!(
                    "verify_chain: log {} final event is {:?}, not {:?}",
                    hex::encode(prev.header.log_id.0),
                    last.event.action,
                    ROTATION_CLOSE_ACTION
                )));
            }
            let claimed_next_id_hex = last.event.metadata.get("new_log_id").ok_or_else(|| {
                Error::Internal(format!(
                    "verify_chain: log {} rotation_close lacks new_log_id metadata",
                    hex::encode(prev.header.log_id.0)
                ))
            })?;
            if claimed_next_id_hex != &hex::encode(next.header.log_id.0) {
                return Err(Error::Internal(format!(
                    "verify_chain: log {} rotation_close points to new_log_id={}                      but actual next log has id {}",
                    hex::encode(prev.header.log_id.0),
                    claimed_next_id_hex,
                    hex::encode(next.header.log_id.0)
                )));
            }

            // Sprint 7.3 — the next log's header must link back to prev.
            match next.header.prev_log_id {
                Some(id) if id == prev.header.log_id => {}
                Some(other) => {
                    return Err(Error::Internal(format!(
                        "verify_chain: log {} header.prev_log_id = {} but                          expected {} (the actual previous log's id)",
                        hex::encode(next.header.log_id.0),
                        hex::encode(other.0),
                        hex::encode(prev.header.log_id.0)
                    )));
                }
                None => {
                    return Err(Error::Internal(format!(
                        "verify_chain: log {} has no prev_log_id but is not                          the first in the chain",
                        hex::encode(next.header.log_id.0)
                    )));
                }
            }
            let expected_root = prev.tree.root();
            match next.header.prev_log_final_root {
                Some(root) if root == expected_root => {}
                Some(other) => {
                    return Err(Error::Internal(format!(
                        "verify_chain: log {} header.prev_log_final_root = {} but                          actual previous log's final root is {}",
                        hex::encode(next.header.log_id.0),
                        hex::encode(other),
                        hex::encode(expected_root)
                    )));
                }
                None => {
                    return Err(Error::Internal(format!(
                        "verify_chain: log {} has no prev_log_final_root",
                        hex::encode(next.header.log_id.0)
                    )));
                }
            }

            // Sprint 7.4 — the next log's FIRST event must be a
            // rotation_open referencing prev's id and final root.
            let first_evt = next.entries.first().ok_or_else(|| {
                Error::Internal(format!(
                    "verify_chain: log {} has no entries — rotation_open required",
                    hex::encode(next.header.log_id.0)
                ))
            })?;
            if first_evt.event.action != ROTATION_OPEN_ACTION {
                return Err(Error::Internal(format!(
                    "verify_chain: log {} first event is {:?}, not {:?}",
                    hex::encode(next.header.log_id.0),
                    first_evt.event.action,
                    ROTATION_OPEN_ACTION
                )));
            }
            // The rotation_open metadata also carries prev refs — check
            // they're consistent (defense in depth).
            let meta_prev_id = first_evt.event.metadata.get("prev_log_id").ok_or_else(|| {
                Error::Internal(format!(
                    "verify_chain: log {} rotation_open lacks prev_log_id metadata",
                    hex::encode(next.header.log_id.0)
                ))
            })?;
            if meta_prev_id != &hex::encode(prev.header.log_id.0) {
                return Err(Error::Internal(format!(
                    "verify_chain: log {} rotation_open metadata says prev_log_id={}                      but header says {}",
                    hex::encode(next.header.log_id.0),
                    meta_prev_id,
                    hex::encode(prev.header.log_id.0)
                )));
            }
        }
        Ok(())
    }
}

/// Sprint 7: action string for the sentinel event appended to a log when
/// it is rotated. Carries the new log id in metadata.
pub const ROTATION_CLOSE_ACTION: &str = "audit.rotation_close";

/// Sprint 7: action string for the first event of a rotated log. Carries
/// the previous log id and final root in metadata.
pub const ROTATION_OPEN_ACTION: &str = "audit.rotation_open";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AuditEvent;

    fn make_log() -> (KeyPair, AuditLog) {
        let kp = KeyPair::generate().unwrap();
        let kp2 = KeyPair::from_parts(kp.public().clone(), kp.secret().clone());
        let log = AuditLog::create_with_label(kp, "test-log").unwrap();
        (kp2, log)
    }

    fn evt(action: &str) -> AuditEvent {
        AuditEvent::builder()
            .actor("svc:test")
            .action(action)
            .resource("res://x")
            .outcome("ok")
            .build()
    }

    #[test]
    fn create_empty_log_verifies() {
        let (_kp, log) = make_log();
        log.verify().unwrap();
        assert_eq!(log.len(), 0);
        assert_eq!(log.current_root(), [0u8; 32]);
    }

    #[test]
    fn append_three_and_verify() {
        let (_kp, mut log) = make_log();
        log.append(evt("a")).unwrap();
        log.append(evt("b")).unwrap();
        log.append(evt("c")).unwrap();
        assert_eq!(log.len(), 3);
        log.verify().unwrap();
    }

    #[test]
    fn roundtrip_save_open_verify() {
        let (_kp, mut log) = make_log();
        for i in 0..10 {
            log.append(evt(&format!("action.{i}"))).unwrap();
        }
        let mut bytes = std::io::Cursor::new(Vec::new());
        log.save_to(&mut bytes).unwrap();
        bytes.set_position(0);
        let back = AuditLog::read_from(&mut bytes).unwrap();
        assert_eq!(back.len(), 10);
        back.verify().unwrap();
        assert_eq!(back.header().log_id, log.header().log_id);
        assert_eq!(back.current_root(), log.current_root());
    }

    #[test]
    fn truncated_final_entry_is_rejected_at_every_byte() {
        let (_kp, mut log) = make_log();
        log.append(evt("first")).unwrap();
        let mut prefix = Vec::new();
        log.save_to(&mut prefix).unwrap();
        log.append(evt("second")).unwrap();
        let mut complete = Vec::new();
        log.save_to(&mut complete).unwrap();

        // Complete entries are a valid prefix; detecting removal of whole
        // entries requires a trusted external checkpoint of the final root.
        AuditLog::read_from(std::io::Cursor::new(&prefix)).unwrap();
        for end in prefix.len() + 1..complete.len() {
            assert!(
                AuditLog::read_from(std::io::Cursor::new(&complete[..end])).is_err(),
                "accepted a partially encoded entry ending at byte {end}"
            );
        }
        AuditLog::read_from(std::io::Cursor::new(&complete))
            .unwrap()
            .verify()
            .unwrap();
    }

    #[test]
    fn trailing_malformed_cbor_is_rejected() {
        let (_kp, log) = make_log();
        let mut bytes = Vec::new();
        log.save_to(&mut bytes).unwrap();
        bytes.push(0xff); // CBOR break outside an indefinite-length item.
        assert!(AuditLog::read_from(std::io::Cursor::new(bytes)).is_err());
    }

    #[test]
    fn atomic_save_replaces_file_without_overwriting_hardlink() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log.qa");
        let snapshot = dir.path().join("snapshot.qa");
        let (_kp, mut log) = make_log();
        log.append(evt("before")).unwrap();
        log.save(&path).unwrap();
        std::fs::hard_link(&path, &snapshot).unwrap();
        log.append(evt("after")).unwrap();
        log.save(&path).unwrap();
        assert_eq!(AuditLog::open(&path).unwrap().len(), 2);
        assert_eq!(AuditLog::open(&snapshot).unwrap().len(), 1);
        AuditLog::open(&path).unwrap().verify().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn atomic_save_rejects_symlink_and_preserves_permissions() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log.qa");
        let link = dir.path().join("link.qa");
        let (_kp, log) = make_log();
        log.save(&path).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        log.save(&path).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o640
        );
        symlink(&path, &link).unwrap();
        let before = std::fs::read(&path).unwrap();
        assert!(log.save(&link).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    #[test]
    fn failed_signature_leaves_log_unchanged_and_retry_verifies() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        struct FallibleSigner {
            key: KeyPair,
            fail: Arc<AtomicBool>,
        }

        impl Signer for FallibleSigner {
            fn sign(&self, message: &[u8]) -> Result<Signature> {
                if self.fail.load(Ordering::Relaxed) {
                    Err(Error::Internal("injected signer outage".into()))
                } else {
                    self.key.sign(message)
                }
            }

            fn public_key(&self) -> &PublicKey {
                self.key.public()
            }
        }

        let fail = Arc::new(AtomicBool::new(false));
        let signer = FallibleSigner {
            key: KeyPair::generate().unwrap(),
            fail: fail.clone(),
        };
        let mut log = AuditLog::create_with_signer(signer, "fallible").unwrap();
        log.append(evt("before")).unwrap();
        let original_root = log.current_root();
        fail.store(true, Ordering::Relaxed);
        assert!(log.append(evt("failed")).is_err());
        assert_eq!(log.len(), 1);
        assert_eq!(log.current_root(), original_root);
        log.verify().unwrap();
        fail.store(false, Ordering::Relaxed);
        log.append(evt("retry")).unwrap();
        assert_eq!(log.len(), 2);
        log.verify().unwrap();
    }

    #[test]
    fn binding_signer_rejects_tampered_history() {
        let (kp, mut log) = make_log();
        log.append(evt("original")).unwrap();
        log.entries[0].event = evt("tampered");
        let mut bytes = Vec::new();
        log.save_to(&mut bytes).unwrap();
        let mut reopened = AuditLog::read_from(std::io::Cursor::new(bytes)).unwrap();
        assert!(reopened.bind_keypair(kp).is_err());
        assert!(reopened.append(evt("must not extend")).is_err());
    }

    #[test]
    fn tampered_event_fails_verify() {
        let (_kp, mut log) = make_log();
        for i in 0..5 {
            log.append(evt(&format!("act.{i}"))).unwrap();
        }
        // Tamper: rewrite event action of entry 2.
        log.entries[2].event = evt("HACKED");
        let err = log.verify().unwrap_err();
        match err {
            Error::ChainBroken { index, .. } => assert_eq!(index, 2),
            Error::BadSignature { index } => assert_eq!(index, 2),
            other => panic!("expected ChainBroken or BadSignature at 2, got {other:?}"),
        }
    }

    #[test]
    fn tampered_root_fails_verify() {
        let (_kp, mut log) = make_log();
        for i in 0..3 {
            log.append(evt(&format!("a.{i}"))).unwrap();
        }
        // Flip a byte in entry 1's new_root.
        log.entries[1].new_root[0] ^= 0x01;
        let err = log.verify().unwrap_err();
        assert!(matches!(
            err,
            Error::ChainBroken { index: 1, .. } | Error::BadSignature { index: 1 }
        ));
    }

    #[test]
    fn tampered_signature_fails_verify() {
        let (_kp, mut log) = make_log();
        log.append(evt("x")).unwrap();
        // Replace signature bytes with another valid-sized but wrong sig.
        let kp_other = KeyPair::generate().unwrap();
        let bogus = kp_other.sign(b"other").unwrap();
        log.entries[0].signature = bogus;
        let err = log.verify().unwrap_err();
        assert!(matches!(err, Error::BadSignature { index: 0 }));
    }

    #[test]
    fn wrong_pubkey_fails_verify() {
        let (_kp, mut log) = make_log();
        for i in 0..3 {
            log.append(evt(&format!("a.{i}"))).unwrap();
        }
        // Swap pubkey.
        let other = KeyPair::generate().unwrap();
        log.header.pubkey = other.public().clone();
        let err = log.verify().unwrap_err();
        assert!(matches!(err, Error::BadSignature { .. }));
    }

    #[test]
    fn deleted_entry_detected() {
        let (_kp, mut log) = make_log();
        for i in 0..4 {
            log.append(evt(&format!("a.{i}"))).unwrap();
        }
        log.entries.remove(2);
        let err = log.verify().unwrap_err();
        // After removing index 2, the entry at position 2 will declare index 3.
        match err {
            Error::InvalidEntry { index: 2, .. } => {}
            other => panic!("expected InvalidEntry at 2, got {other:?}"),
        }
    }

    #[test]
    fn reordered_entries_detected() {
        let (_kp, mut log) = make_log();
        for i in 0..4 {
            log.append(evt(&format!("a.{i}"))).unwrap();
        }
        log.entries.swap(1, 2);
        let err = log.verify().unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidEntry { .. } | Error::ChainBroken { .. } | Error::BadSignature { .. }
        ));
    }

    #[test]
    fn opened_log_is_readonly() {
        let (_kp, mut log) = make_log();
        log.append(evt("a")).unwrap();
        let mut bytes = std::io::Cursor::new(Vec::new());
        log.save_to(&mut bytes).unwrap();
        bytes.set_position(0);
        let mut back = AuditLog::read_from(&mut bytes).unwrap();
        let err = back.append(evt("nope")).unwrap_err();
        assert!(matches!(err, Error::Internal(_)));
    }

    #[test]
    fn bad_magic_rejected() {
        let mut bytes = std::io::Cursor::new(vec![0u8; 32]);
        let err = AuditLog::read_from(&mut bytes).unwrap_err();
        assert!(matches!(err, Error::BadHeader(_)));
    }

    #[test]
    fn invalid_empty_log_header_is_rejected() {
        let (_kp, mut log) = make_log();
        log.header.suite = "unsupported-suite".into();
        assert!(log.verify().is_err());
        let mut bytes = Vec::new();
        log.save_to(&mut bytes).unwrap();
        assert!(AuditLog::read_from(std::io::Cursor::new(bytes)).is_err());

        log.header.suite = SUITE_ID.into();
        let malformed =
            std::collections::BTreeMap::from([("bytes", serde_bytes::ByteBuf::from(vec![0u8; 1]))]);
        let mut key_bytes = Vec::new();
        ciborium::into_writer(&malformed, &mut key_bytes).unwrap();
        log.header.pubkey = ciborium::from_reader(key_bytes.as_slice()).unwrap();
        assert!(log.verify().is_err());
        let mut bytes = Vec::new();
        log.save_to(&mut bytes).unwrap();
        assert!(AuditLog::read_from(std::io::Cursor::new(bytes)).is_err());
    }

    #[test]
    fn root_progression_matches_per_entry() {
        // After appending N entries, log.current_root() should equal
        // entries[N-1].new_root.
        let (_kp, mut log) = make_log();
        for i in 0..20 {
            let e = log.append(evt(&format!("a.{i}"))).unwrap().clone();
            assert_eq!(e.new_root, log.current_root());
        }
    }

    #[test]
    fn many_entries_verify() {
        let (_kp, mut log) = make_log();
        for i in 0..50 {
            log.append(evt(&format!("a.{i}"))).unwrap();
        }
        log.verify().unwrap();
    }

    // ========================================================================
    //              Sprint 7 — rotation chain tests
    // ========================================================================

    #[test]
    fn rotation_chain_two_logs_verify_clean() {
        // Build log A, append some events, rotate to log B, append more.
        // Chain verification of [A, B] must pass.
        let (kp_a, mut log_a) = make_log();
        log_a
            .append(
                AuditEvent::builder()
                    .action("test.thing")
                    .actor("u")
                    .build(),
            )
            .unwrap();
        log_a
            .append(
                AuditEvent::builder()
                    .action("test.other")
                    .actor("u")
                    .build(),
            )
            .unwrap();
        // Keep the same key for the new chain segment.
        let kp_b = KeyPair::from_parts(kp_a.public().clone(), kp_a.secret().clone());
        let new_signer = Box::new(kp_b) as Box<dyn Signer>;
        let (log_a_sealed, mut log_b) = log_a.rotate_to(new_signer, "log-b", "").unwrap();
        log_b
            .append(
                AuditEvent::builder()
                    .action("test.after_rotation")
                    .actor("u")
                    .build(),
            )
            .unwrap();

        // Each log verifies on its own.
        log_a_sealed.verify().expect("log A internal");
        log_b.verify().expect("log B internal");

        // Chain verifies.
        AuditLog::verify_chain(&[&log_a_sealed, &log_b]).expect("chain verifies");
    }

    #[test]
    fn rotation_chain_three_logs_verify_clean() {
        let (kp, mut a) = make_log();
        a.append(AuditEvent::builder().action("e1").build())
            .unwrap();
        let kp2 = KeyPair::from_parts(kp.public().clone(), kp.secret().clone());
        let (a, mut b) = a
            .rotate_to(Box::new(kp2) as Box<dyn Signer>, "b", "")
            .unwrap();
        b.append(AuditEvent::builder().action("e2").build())
            .unwrap();
        let kp3 = KeyPair::from_parts(kp.public().clone(), kp.secret().clone());
        let (b, mut c) = b
            .rotate_to(Box::new(kp3) as Box<dyn Signer>, "c", "")
            .unwrap();
        c.append(AuditEvent::builder().action("e3").build())
            .unwrap();

        AuditLog::verify_chain(&[&a, &b, &c]).expect("3-link chain");
    }

    #[test]
    fn rotation_chain_root_with_prev_field_is_rejected() {
        // If the FIRST log in a chain has a prev_log_id set, that's
        // operator-error (e.g. wrong file order). Detect and refuse.
        let (kp, mut a) = make_log();
        a.append(AuditEvent::builder().action("e").build()).unwrap();
        let kp2 = KeyPair::from_parts(kp.public().clone(), kp.secret().clone());
        let (_a, b) = a
            .rotate_to(Box::new(kp2) as Box<dyn Signer>, "b", "")
            .unwrap();
        // `b` has prev_log_id set. Passing [b] alone as "root" must fail.
        let err = AuditLog::verify_chain(&[&b]).unwrap_err();
        assert!(format!("{err}").contains("first in the chain"));
    }

    #[test]
    fn rotation_chain_detects_mismatched_prev_id() {
        // Build two independent chains and try to splice them.
        let (kp1, mut a1) = make_log();
        a1.append(AuditEvent::builder().action("e").build())
            .unwrap();
        let kp1b = KeyPair::from_parts(kp1.public().clone(), kp1.secret().clone());
        let (a1, _b1) = a1
            .rotate_to(Box::new(kp1b) as Box<dyn Signer>, "b1", "")
            .unwrap();
        // Separate chain.
        let (kp2, mut a2) = make_log();
        a2.append(AuditEvent::builder().action("e").build())
            .unwrap();
        let kp2b = KeyPair::from_parts(kp2.public().clone(), kp2.secret().clone());
        let (_a2, b2) = a2
            .rotate_to(Box::new(kp2b) as Box<dyn Signer>, "b2", "")
            .unwrap();
        // Splice: try to chain a1 → b2. b2.prev_log_id points to a2, not a1.
        let err = AuditLog::verify_chain(&[&a1, &b2]).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("prev_log_id") || msg.contains("rotation_close"),
            "got: {msg}"
        );
    }

    #[test]
    fn rotation_chain_detects_tampered_prev_final_root() {
        // Build a valid 2-link chain, then mutate the second log's
        // prev_log_final_root in memory. Re-verify must fail.
        let (kp, mut a) = make_log();
        a.append(AuditEvent::builder().action("e").build()).unwrap();
        let kp2 = KeyPair::from_parts(kp.public().clone(), kp.secret().clone());
        let (a, mut b) = a
            .rotate_to(Box::new(kp2) as Box<dyn Signer>, "b", "")
            .unwrap();
        // Tamper.
        let mut bad_root = a.tree.root();
        bad_root[0] ^= 0xFF;
        b.header.prev_log_final_root = Some(bad_root);
        let err = AuditLog::verify_chain(&[&a, &b]).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("prev_log_final_root"), "got: {msg}");
    }

    #[test]
    fn rotation_old_log_signer_dropped_after_rotation() {
        // After rotate_to, the returned `old` log MUST be read-only — no
        // late appends after the rotation_close sentinel.
        let (kp, mut a) = make_log();
        a.append(AuditEvent::builder().action("e").build()).unwrap();
        let kp2 = KeyPair::from_parts(kp.public().clone(), kp.secret().clone());
        let (mut a, _b) = a
            .rotate_to(Box::new(kp2) as Box<dyn Signer>, "b", "")
            .unwrap();
        let err = a
            .append(AuditEvent::builder().action("late").build())
            .unwrap_err();
        assert!(format!("{err}").contains("read-only"));
    }

    #[test]
    fn rotation_cross_key_chain_verifies() {
        // Rotation supports key change: log A signed by key K1, log B
        // signed by key K2. Each log carries its own pubkey in its header.
        // Verification still works because each log uses its own header
        // pubkey for signature checks.
        let (_kp, mut a) = make_log();
        a.append(AuditEvent::builder().action("e").build()).unwrap();
        // Fresh key for log B.
        let kp2 = KeyPair::generate().unwrap();
        let kp2_for_signer = KeyPair::from_parts(kp2.public().clone(), kp2.secret().clone());
        let (a, b) = a
            .rotate_to(Box::new(kp2_for_signer) as Box<dyn Signer>, "b", "")
            .unwrap();
        // Confirm B's header has a different pubkey.
        assert_ne!(a.header.pubkey, b.header.pubkey);
        AuditLog::verify_chain(&[&a, &b]).expect("cross-key rotation chain verifies");
    }
}
