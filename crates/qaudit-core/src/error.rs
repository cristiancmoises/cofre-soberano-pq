//! Error types for qaudit-core.

use thiserror::Error;

/// Convenience `Result` alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;

/// All errors qaudit-core can produce.
#[derive(Error, Debug)]
pub enum Error {
    /// Underlying I/O error.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization or deserialization failure (CBOR).
    #[error("serialization error: {0}")]
    Cbor(String),

    /// Signature verification failed.
    #[error("invalid signature at entry {index}")]
    BadSignature {
        /// Index of the entry whose signature failed to verify.
        index: u64,
    },

    /// Key material was the wrong size or malformed.
    #[error("invalid key material: {0}")]
    BadKey(String),

    /// Merkle chain integrity broken.
    #[error("merkle chain broken at index {index}: prev_root expected {expected}, got {got}")]
    ChainBroken {
        /// Index where the chain breaks.
        index: u64,
        /// Hex-encoded expected root.
        expected: String,
        /// Hex-encoded observed root.
        got: String,
    },

    /// Entry was malformed or claims wrong root.
    #[error("invalid entry at index {index}: {reason}")]
    InvalidEntry {
        /// Index of the offending entry.
        index: u64,
        /// Human-readable reason.
        reason: String,
    },

    /// Header was missing, corrupt, or wrong magic.
    #[error("invalid header: {0}")]
    BadHeader(String),

    /// Wire-format version mismatch.
    #[error("version mismatch: log is v{found}, library supports v{supported}")]
    VersionMismatch {
        /// Version observed in the log header.
        found: u32,
        /// Version this build supports.
        supported: u32,
    },

    /// Unexpected internal error.
    #[error("internal error: {0}")]
    Internal(String),
}

impl<T: std::fmt::Debug> From<ciborium::ser::Error<T>> for Error {
    fn from(e: ciborium::ser::Error<T>) -> Self {
        Error::Cbor(format!("{e:?}"))
    }
}

impl<T: std::fmt::Debug> From<ciborium::de::Error<T>> for Error {
    fn from(e: ciborium::de::Error<T>) -> Self {
        Error::Cbor(format!("{e:?}"))
    }
}

impl From<quick_xml::Error> for Error {
    fn from(e: quick_xml::Error) -> Self {
        Error::Internal(format!("XML error: {e}"))
    }
}
