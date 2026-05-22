//! # qaudit-hsm
//!
//! HSM signing substrate for Cofre Soberano PQ.
//!
//! Provides three categories of [`qaudit_core::Signer`] implementations:
//!
//! - [`SoftSigner`]: in-process software key, useful for dev, CI, and tests.
//!   Always available.
//! - [`Pkcs11Signer`]: any PKCS#11 v3 library (Dinamo, YubiHSM 2, Thales,
//!   Entrust nShield, Atos Trustway, SoftHSM2, ...). Behind the `pkcs11`
//!   Cargo feature.
//!
//! All implementations satisfy the same [`qaudit_core::Signer`] trait, so the
//! audit-log crate (`qaudit-core`) is unaware of which backend is producing
//! signatures.
//!
//! ## Threat model assumption
//!
//! Sprint 1 ships software keys only. From Sprint 2 onward, production
//! deployments MUST use a PKCS#11 backend so that the signing key never leaves
//! the HSM, even when the qaudit process is compromised. The verifier-side
//! cryptography is identical in both cases.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

pub mod soft;

#[cfg(feature = "pkcs11")]
pub mod pkcs11;

pub use soft::SoftSigner;

#[cfg(feature = "pkcs11")]
pub use pkcs11::{Pkcs11Config, Pkcs11Signer, Pkcs11SignerFactory};

#[cfg(feature = "pkcs11")]
pub use telemetry::{HsmTelemetry, NoopTelemetry};

#[cfg(feature = "pkcs11")]
mod telemetry {
    //! Sprint 10: lightweight telemetry hook surface for the PKCS#11
    //! signer. Callers wanting HSM activity reported into their metrics
    //! system implement this trait and pass an `Arc<dyn HsmTelemetry>`
    //! into `Pkcs11SignerFactory::with_telemetry` (or
    //! `Pkcs11Signer::open_with_telemetry`).
    //!
    //! The trait lives in qaudit-hsm because qgateway-core, where the
    //! metrics registry lives, depends on qaudit-core (not qaudit-hsm).
    //! qgateway (the daemon) depends on both crates and wires them
    //! together via a thin newtype impl.
    //!
    //! All methods take `&self` and are called from the signing hot
    //! path. Implementations MUST be fast — atomic increment is the
    //! canonical impl. Calls are best-effort: an impl panic or
    //! expensive operation delays signing.

    /// Hooks the PKCS#11 signer fires on session-lifecycle and signing
    /// events. Default methods are no-ops so implementations can override
    /// only the events they care about.
    pub trait HsmTelemetry: Send + Sync {
        /// A new PKCS#11 session was successfully opened (startup or rotation).
        fn on_session_open(&self) {}
        /// A `Pkcs11Signer::open` call failed (load, slot, login, or key lookup).
        fn on_session_open_failed(&self) {}
        /// A `C_Sign` call completed successfully.
        fn on_sign_ok(&self) {}
        /// A `C_Sign` call returned an error.
        fn on_sign_failed(&self) {}
    }

    /// No-op telemetry — every method does nothing. Used when no
    /// telemetry sink is wired (default `Pkcs11Signer::open` path).
    #[derive(Default, Clone, Copy)]
    pub struct NoopTelemetry;
    impl HsmTelemetry for NoopTelemetry {}
}

/// Re-export of the canonical Signer trait so downstream code only needs
/// `qaudit_hsm::Signer`.
pub use qaudit_core::Signer;
