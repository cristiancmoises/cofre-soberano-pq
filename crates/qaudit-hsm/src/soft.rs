//! Software signer (in-process keys).
//!
//! Wraps [`qaudit_core::KeyPair`] and tags signatures with a configurable
//! provenance string so downstream tools can distinguish "soft" from
//! "pkcs11:..." signers at a glance.

use qaudit_core::{KeyPair, PublicKey, Result, Signature, Signer};

/// In-process software signer.
///
/// **Production deployments should use [`crate::pkcs11::Pkcs11Signer`] instead.**
/// SoftSigner exists for development, CI, key migration tooling, and air-
/// gapped verification environments where the signing key is intentionally
/// loaded from a backup.
pub struct SoftSigner {
    kp: KeyPair,
    provenance: String,
}

impl SoftSigner {
    /// Wrap an existing keypair.
    #[must_use]
    pub fn new(kp: KeyPair) -> Self {
        Self {
            kp,
            provenance: "soft:in-memory".to_string(),
        }
    }

    /// Wrap an existing keypair with a custom provenance tag.
    /// Useful when keys originate from a known store (e.g. `"soft:backup-2026-05"`).
    #[must_use]
    pub fn with_provenance(kp: KeyPair, provenance: impl Into<String>) -> Self {
        Self {
            kp,
            provenance: provenance.into(),
        }
    }

    /// Generate a fresh keypair.
    pub fn generate() -> Result<Self> {
        Ok(Self::new(KeyPair::generate()?))
    }

    /// Access the underlying keypair (e.g. for export to a key escrow).
    #[must_use]
    pub fn keypair(&self) -> &KeyPair {
        &self.kp
    }
}

impl Signer for SoftSigner {
    fn sign(&self, m: &[u8]) -> Result<Signature> {
        self.kp.sign(m)
    }

    fn public_key(&self) -> &PublicKey {
        self.kp.public()
    }

    fn provenance(&self) -> &str {
        &self.provenance
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qaudit_core::verify_signature;

    #[test]
    fn default_provenance() {
        let s = SoftSigner::generate().unwrap();
        assert_eq!(s.provenance(), "soft:in-memory");
    }

    #[test]
    fn custom_provenance() {
        let kp = KeyPair::generate().unwrap();
        let s = SoftSigner::with_provenance(kp, "soft:backup-2026-05");
        assert_eq!(s.provenance(), "soft:backup-2026-05");
    }

    #[test]
    fn sign_verify_roundtrip_via_trait() {
        let s = SoftSigner::generate().unwrap();
        let sig = s.sign(b"sprint2 baseline").unwrap();
        verify_signature(s.public_key(), b"sprint2 baseline", &sig, 0).unwrap();
    }

    #[test]
    fn signer_is_object_safe() {
        let s = SoftSigner::generate().unwrap();
        let _b: Box<dyn Signer> = Box::new(s);
    }
}
