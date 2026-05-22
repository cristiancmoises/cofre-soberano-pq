//! # qtransport-cspq
//!
//! Reference post-quantum transport for Cofre Soberano PQ.
//!
//! This crate ships a concrete `PqTransport` implementation built from the
//! same primitives Evelin uses (ML-KEM-1024 + ML-DSA-87 + ChaCha20-Poly1305)
//! so that QGateway has a working, testable wire protocol out of the box.
//! Production deployments can swap this for `evelin-transport` (from
//! `git.securityops.co/cristiancmoises/evelin`) without touching the gateway
//! daemon, by implementing the same trait surface in `qgateway-core`.
//!
//! ## Wire protocol — CSPQ-Transport-v1
//!
//! Mutually authenticated post-quantum handshake (Noise-XK-shape with PQ
//! primitives), followed by length-framed AEAD records:
//!
//! ```text
//!  Client                                                Server
//!   |                                                       |
//!   |  CLIENT_HELLO {                                       |
//!   |    suite,                                             |
//!   |    client_kem_pk (ML-KEM-1024 ephemeral, 1568 B)      |
//!   |  }                                                    |
//!   |------------------------------------------------------>|
//!   |                                                       |
//!   |  SERVER_HELLO {                                       |
//!   |    server_kem_ct (1568 B),                            |
//!   |    server_id_pk  (ML-DSA-87 long-term, 2592 B),       |
//!   |    server_sig    ML-DSA-87 over transcript            |
//!   |  }                                                    |
//!   |<------------------------------------------------------|
//!   |                                                       |
//!   |  CLIENT_FINISH {                                      |
//!   |    client_id_pk (ML-DSA-87 long-term, 2592 B),        |
//!   |    client_sig   ML-DSA-87 over transcript             |
//!   |  }                                                    |
//!   |------------------------------------------------------>|
//!   |                                                       |
//!   |  ===== record layer (AEAD) =====                      |
//! ```
//!
//! - `transcript = BLAKE3(suite || client_kem_pk || server_kem_ct || server_id_pk || client_id_pk)`
//! - `shared_secret` = ML-KEM-1024 decap result (32 B, same on both sides)
//! - `keys = HKDF-SHA3-256(shared_secret, salt = b"cspq-transport-v1", info = transcript)`
//!     - 32 B `key_c2s`, 32 B `key_s2c`
//! - Record-layer nonce = 4 B direction prefix (0 c→s, 1 s→c) || 8 B BE counter
//! - Max frame plaintext = 16 KiB; counter overflow tears the session down
//! - Both peers verify the peer's ML-DSA-87 signature against an
//!   out-of-band-trusted public key (loaded from disk in the gateway daemon).
//!
//! ## Threat model
//!
//! - **Quantum adversary**: KEM is ML-KEM-1024 (NIST L5), signatures
//!   ML-DSA-87 (NIST L5). Both fully post-quantum.
//! - **Active MitM**: detected by ML-DSA-87 transcript signatures. An attacker
//!   without the peers' identity keys cannot forge a handshake.
//! - **Replay**: per-direction nonces start at 0 and never wrap. A captured
//!   record cannot be re-decrypted in a fresh session because keys depend on
//!   `client_kem_pk` (fresh ephemeral per session).
//! - **Long-term-key compromise**: gives the attacker the ability to MitM
//!   future sessions; PAST sessions remain confidential because the KEM
//!   ephemeral was destroyed (forward secrecy).
//!
//! ## Versioning
//!
//! The 2-byte `suite` field in CLIENT_HELLO declares the protocol version.
//! Sprint 3 ships suite `cspq-1024-87-chacha-v1 = 0x0001`. Future suites
//! (e.g. ML-KEM-2048 once standardized) take new IDs without breaking v1.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

pub mod error;
pub mod framing;
pub mod handshake;
pub mod transport;

pub use error::{Error, Result};
pub use handshake::{accept, connect, IdentityKey, PeerPolicy};
pub use transport::{CspqReader, CspqStream, CspqWriter, MAX_PLAINTEXT};

/// Current protocol suite identifier (sent in CLIENT_HELLO).
pub const SUITE_ID: u16 = 0x0001;

/// Human-readable suite name.
pub const SUITE_NAME: &str = "cspq-1024-87-chacha-v1";

/// Magic prefix for `.cspqid` identity-key files (ML-DSA-87 public bytes).
pub const IDENTITY_FILE_MAGIC: &[u8; 8] = b"CSPQID01";
