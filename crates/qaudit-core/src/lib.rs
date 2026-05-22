//! # qaudit-core
//!
//! Post-quantum signed audit log library for the Cofre Soberano PQ stack.
//!
//! Append-only Merkle-chained event log signed entry-by-entry with ML-DSA-87
//! (FIPS 204). Designed for offline verification by regulators (Bacen, CVM,
//! ANPD). No network, no clock dependency for chain validity.
//!
//! ## Quick start
//!
//! ```no_run
//! use qaudit_core::{AuditEvent, AuditLog, KeyPair};
//!
//! let kp = KeyPair::generate().unwrap();
//! let mut log = AuditLog::create(kp).unwrap();
//!
//! let event = AuditEvent::builder()
//!     .actor("svc:qvault")
//!     .action("object.put")
//!     .resource("vault://prod/file.pdf")
//!     .outcome("ok")
//!     .meta("size_bytes", "182734")
//!     .build();
//!
//! log.append(event).unwrap();
//! log.verify().unwrap();
//! ```
//!
//! ## Threat model (Sprint 1)
//!
//! - **Insider editing past entries:** detected (chain breaks).
//! - **Insider appending fake entries with the real key:** **not** prevented;
//!   the key must be kept in an HSM (Sprint 2). Sprint 1 ships software keys
//!   for development only.
//! - **Quantum attacker:** signatures are ML-DSA-87 (NIST L5). Hash chain is
//!   BLAKE3 (Grover gives no useful speedup on 256-bit collision resistance).

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

pub mod error;
pub mod event;
pub mod export;
pub mod log;
pub mod merkle;
pub mod signing;

pub use error::{Error, Result};
pub use event::{AuditEvent, EventBuilder};
pub use export::{export_jsonl, export_xml};
pub use log::{AuditLog, LogEntry, LogHeader};
pub use merkle::{leaf_hash, node_hash, Hash, MerkleTree};
pub use signing::{
    decode_pubkey_any, verify as verify_signature, KeyPair, PublicKey, SecretKey, Signature,
    Signer, QGATEWAY_AUDIT_PK_MAGIC,
};

/// Library version, matching the crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Wire-format version. Bump when `.qa` binary layout changes.
pub const WIRE_VERSION: u32 = 1;

/// Crypto suite identifier emitted into log headers.
pub const SUITE_ID: &str = "cspq-2026";

/// Magic bytes at the start of every `.qa` log file.
pub const MAGIC: &[u8; 8] = b"QAUDIT01";
