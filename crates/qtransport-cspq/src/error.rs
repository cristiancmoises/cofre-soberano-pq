//! Error types for the CSPQ transport.

use thiserror::Error;

/// Convenience `Result` alias.
pub type Result<T> = std::result::Result<T, Error>;

/// All errors produced by the CSPQ transport.
#[derive(Error, Debug)]
pub enum Error {
    /// Underlying I/O error (TCP read/write, EOF, connection reset).
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// Peer sent something we couldn't parse or doesn't satisfy invariants.
    #[error("protocol: {0}")]
    Protocol(String),

    /// Cryptographic verification failed (signature, AEAD tag, KEM decap).
    #[error("crypto: {0}")]
    Crypto(String),

    /// Peer presented an identity key that is not in the allow-list.
    #[error("untrusted peer identity {peer_id}")]
    UntrustedPeer {
        /// Hex-prefix of the peer identity (first 16 B) for human diagnostics.
        peer_id: String,
    },

    /// Session counter overflowed; teardown required.
    #[error("nonce counter overflow")]
    NonceOverflow,

    /// Peer claimed an unknown protocol suite.
    #[error("unsupported suite {0:#06x}")]
    UnsupportedSuite(u16),

    /// Frame exceeded the maximum allowed plaintext size.
    #[error("frame too large: {got} bytes, max {max}")]
    FrameTooLarge {
        /// Bytes claimed by the frame header.
        got: usize,
        /// Configured maximum.
        max: usize,
    },

    /// Identity file malformed.
    #[error("identity file: {0}")]
    Identity(String),

    /// Forwarded from qaudit-core when ML-DSA primitives error.
    #[error("ml-dsa: {0}")]
    MlDsa(String),
}

impl From<qaudit_core::Error> for Error {
    fn from(e: qaudit_core::Error) -> Self {
        Error::MlDsa(e.to_string())
    }
}
