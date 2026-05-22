//! ML-DSA-87 (FIPS 204) signing wrapper.
//!
//! Sizes (FIPS 204, ML-DSA-87 parameter set):
//! - Public key:  2592 bytes
//! - Private key: 4896 bytes
//! - Signature:   4627 bytes
//!
//! Security level: NIST PQC Category 5 — strength comparable to AES-256.

use crate::error::{Error, Result};
use fips204::ml_dsa_87;
use fips204::traits::{SerDes, Signer as Fips204Signer, Verifier};
use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

/// Length of an ML-DSA-87 public key in bytes (FIPS 204).
pub const PUBLIC_KEY_LEN: usize = ml_dsa_87::PK_LEN;
/// Length of an ML-DSA-87 secret key in bytes (FIPS 204).
pub const SECRET_KEY_LEN: usize = ml_dsa_87::SK_LEN;
/// Length of an ML-DSA-87 signature in bytes (FIPS 204).
pub const SIGNATURE_LEN: usize = ml_dsa_87::SIG_LEN;

/// Domain separator passed as ML-DSA context byte string. Bound to the project
/// + wire version to harden cross-protocol misuse.
const SIG_CONTEXT: &[u8] = b"cofre-soberano-pq/qaudit/v1";

/// ML-DSA-87 public key.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicKey {
    #[serde(with = "serde_bytes")]
    bytes: Vec<u8>,
}

impl PublicKey {
    /// Construct from raw FIPS-204 bytes. Returns [`Error::BadKey`] if the
    /// length is wrong.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() != PUBLIC_KEY_LEN {
            return Err(Error::BadKey(format!(
                "public key must be {PUBLIC_KEY_LEN} bytes, got {}",
                b.len()
            )));
        }
        Ok(Self { bytes: b.to_vec() })
    }

    /// Return the raw FIPS-204 byte encoding.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "PublicKey({}…)",
            hex::encode(&self.bytes[..8.min(self.bytes.len())])
        )
    }
}

/// 8-byte magic prefix used by `qgateway audit-keygen` to frame the raw
/// ML-DSA-87 public key on disk. The portal and `qaudit verify --pk` accept
/// both raw (2592 B) and framed (2600 B) files so that operators do not have
/// to know which tool wrote the key file they hold.
pub const QGATEWAY_AUDIT_PK_MAGIC: &[u8; 8] = b"AUDITPK0";

/// Decode an ML-DSA-87 public key from either of the two formats produced
/// by the Cofre Soberano PQ tooling:
///
/// - **Raw** (2592 bytes): what `qaudit init` writes for `<log>.pk`.
/// - **Framed** (2600 bytes): what `qgateway audit-keygen` writes for
///   `<host>.audit.pub`. The first 8 bytes are the
///   [`QGATEWAY_AUDIT_PK_MAGIC`] prefix.
///
/// Auto-detection is by length, with the magic verified for the framed case.
/// A 2600-byte file without the magic is rejected (not silently truncated)
/// so that an arbitrary blob cannot pass as a key by accident.
///
/// # Errors
///
/// Returns [`Error::BadKey`] when the length matches neither format, when
/// the framed length lacks the expected magic, or when the underlying raw
/// key bytes are rejected by [`PublicKey::from_bytes`].
pub fn decode_pubkey_any(bytes: &[u8]) -> Result<PublicKey> {
    const FRAMED_LEN: usize = 8 + PUBLIC_KEY_LEN;
    match bytes.len() {
        PUBLIC_KEY_LEN => PublicKey::from_bytes(bytes),
        FRAMED_LEN if &bytes[..8] == QGATEWAY_AUDIT_PK_MAGIC => PublicKey::from_bytes(&bytes[8..]),
        FRAMED_LEN => Err(Error::BadKey(format!(
            "public-key file is {FRAMED_LEN} bytes but does not start with the \
             expected qgateway audit-key magic (\"AUDITPK0\"); refusing to interpret"
        ))),
        n => Err(Error::BadKey(format!(
            "public key must be {PUBLIC_KEY_LEN} bytes (raw ML-DSA-87) or {FRAMED_LEN} bytes \
             (qgateway audit-keygen framed), got {n}"
        ))),
    }
}

/// ML-DSA-87 secret key. Zeroized on drop.
#[derive(Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct SecretKey {
    #[serde(with = "serde_bytes")]
    bytes: Vec<u8>,
}

impl SecretKey {
    /// Construct from raw FIPS-204 bytes. Returns [`Error::BadKey`] if the
    /// length is wrong.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() != SECRET_KEY_LEN {
            return Err(Error::BadKey(format!(
                "secret key must be {SECRET_KEY_LEN} bytes, got {}",
                b.len()
            )));
        }
        Ok(Self { bytes: b.to_vec() })
    }

    /// Return the raw FIPS-204 byte encoding. Callers MUST handle the result
    /// as sensitive material.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Derive the matching public key from this secret key (FIPS 204 §3.5).
    ///
    /// Useful when the only artifact on disk is the secret key file and the
    /// daemon needs to reconstruct the keypair without a separate `.pub` file.
    pub fn derive_public(&self) -> Result<PublicKey> {
        let arr: [u8; SECRET_KEY_LEN] = self
            .bytes
            .as_slice()
            .try_into()
            .map_err(|_| Error::BadKey("secret key wrong length for derive_public".into()))?;
        let sk_obj = ml_dsa_87::PrivateKey::try_from_bytes(arr)
            .map_err(|e| Error::Internal(format!("ML-DSA-87 SK parse: {e}")))?;
        use fips204::traits::Signer as Fips204Signer;
        let pk_obj = sk_obj.get_public_key();
        Ok(PublicKey {
            bytes: pk_obj.into_bytes().to_vec(),
        })
    }
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print key material.
        write!(f, "SecretKey(<redacted, {} B>)", self.bytes.len())
    }
}

/// ML-DSA-87 signature.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Signature {
    #[serde(with = "serde_bytes")]
    bytes: Vec<u8>,
}

impl Signature {
    /// Construct from raw FIPS-204 bytes. Returns
    /// [`Error::BadSignature`] with `index = 0` if the length is wrong;
    /// callers should remap the index when relevant.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() != SIGNATURE_LEN {
            return Err(Error::BadSignature { index: u64::MAX });
        }
        Ok(Self { bytes: b.to_vec() })
    }

    /// Return the raw FIPS-204 byte encoding.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl std::fmt::Debug for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Signature({}…)",
            hex::encode(&self.bytes[..8.min(self.bytes.len())])
        )
    }
}

/// A bound ML-DSA-87 keypair.
#[derive(Clone)]
pub struct KeyPair {
    pk: PublicKey,
    sk: SecretKey,
}

impl KeyPair {
    /// Generate a fresh ML-DSA-87 keypair using the OS RNG.
    pub fn generate() -> Result<Self> {
        let (pk_obj, sk_obj) = ml_dsa_87::try_keygen()
            .map_err(|e| Error::Internal(format!("ML-DSA-87 keygen failed: {e}")))?;
        Ok(Self {
            pk: PublicKey {
                bytes: pk_obj.into_bytes().to_vec(),
            },
            sk: SecretKey {
                bytes: sk_obj.into_bytes().to_vec(),
            },
        })
    }

    /// Reconstruct a keypair from its serialized components.
    pub fn from_parts(pk: PublicKey, sk: SecretKey) -> Self {
        Self { pk, sk }
    }

    /// The public verification key.
    #[must_use]
    pub fn public(&self) -> &PublicKey {
        &self.pk
    }

    /// The secret signing key. Treat as sensitive.
    #[must_use]
    pub fn secret(&self) -> &SecretKey {
        &self.sk
    }

    /// Sign a message with the bound context (`"cofre-soberano-pq/qaudit/v1"`).
    pub fn sign(&self, msg: &[u8]) -> Result<Signature> {
        let arr: [u8; SECRET_KEY_LEN] = self
            .sk
            .bytes
            .as_slice()
            .try_into()
            .map_err(|_| Error::BadKey("secret key wrong length".into()))?;
        let sk_obj = ml_dsa_87::PrivateKey::try_from_bytes(arr)
            .map_err(|e| Error::BadKey(format!("ML-DSA-87 sk decode: {e}")))?;
        let sig = sk_obj
            .try_sign(msg, SIG_CONTEXT)
            .map_err(|e| Error::Internal(format!("ML-DSA-87 sign: {e}")))?;
        Ok(Signature {
            bytes: sig.to_vec(),
        })
    }
}

/// A signing backend that produces ML-DSA-87 signatures bound to the
/// canonical context used by the audit log.
///
/// Implementations in this codebase:
/// - [`KeyPair`] (this crate): in-process software keys, for development.
/// - `qaudit_hsm::Pkcs11Signer`: production HSM backends (Dinamo, YubiHSM 2,
///   Thales, nShield, ...).
///
/// All implementations MUST produce signatures that pass [`verify`] against
/// `self.public_key()` using the project's bound context string.
pub trait Signer: Send + Sync {
    /// Sign `message` with ML-DSA-87 and the project's bound context.
    fn sign(&self, message: &[u8]) -> Result<Signature>;
    /// Public key associated with this signer.
    fn public_key(&self) -> &PublicKey;
    /// Short opaque tag identifying the backend; used in CLI provenance lines
    /// and structured logs. Defaults to `"unknown"`.
    fn provenance(&self) -> &str {
        "unknown"
    }
}

impl Signer for KeyPair {
    fn sign(&self, m: &[u8]) -> Result<Signature> {
        KeyPair::sign(self, m)
    }
    fn public_key(&self) -> &PublicKey {
        self.public()
    }
    fn provenance(&self) -> &str {
        "soft:in-memory"
    }
}

impl<S: Signer + ?Sized> Signer for Box<S> {
    fn sign(&self, m: &[u8]) -> Result<Signature> {
        (**self).sign(m)
    }
    fn public_key(&self) -> &PublicKey {
        (**self).public_key()
    }
    fn provenance(&self) -> &str {
        (**self).provenance()
    }
}

/// Verify a signature against a message and public key with the bound context.
///
/// Returns `Ok(())` on valid; on failure returns [`Error::BadSignature`] with
/// the provided `index` (use `0` if not tied to a log entry).
pub fn verify(pk: &PublicKey, msg: &[u8], sig: &Signature, index: u64) -> Result<()> {
    let pk_arr: [u8; PUBLIC_KEY_LEN] = pk
        .bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::BadKey("public key wrong length".into()))?;
    let sig_arr: [u8; SIGNATURE_LEN] = sig
        .bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::BadSignature { index })?;
    let pk_obj = ml_dsa_87::PublicKey::try_from_bytes(pk_arr)
        .map_err(|e| Error::BadKey(format!("ML-DSA-87 pk decode: {e}")))?;
    if pk_obj.verify(msg, &sig_arr, SIG_CONTEXT) {
        Ok(())
    } else {
        Err(Error::BadSignature { index })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_sizes_match_fips204() {
        assert_eq!(PUBLIC_KEY_LEN, 2592);
        assert_eq!(SECRET_KEY_LEN, 4896);
        assert_eq!(SIGNATURE_LEN, 4627);
    }

    #[test]
    fn keygen_produces_right_sizes() {
        let kp = KeyPair::generate().unwrap();
        assert_eq!(kp.public().as_bytes().len(), PUBLIC_KEY_LEN);
        assert_eq!(kp.secret().as_bytes().len(), SECRET_KEY_LEN);
    }

    #[test]
    fn sign_verify_roundtrip() {
        let kp = KeyPair::generate().unwrap();
        let msg = b"audit log entry 42";
        let sig = kp.sign(msg).unwrap();
        assert_eq!(sig.as_bytes().len(), SIGNATURE_LEN);
        verify(kp.public(), msg, &sig, 42).unwrap();
    }

    #[test]
    fn wrong_message_fails() {
        let kp = KeyPair::generate().unwrap();
        let sig = kp.sign(b"correct").unwrap();
        let err = verify(kp.public(), b"tampered", &sig, 7).unwrap_err();
        match err {
            Error::BadSignature { index } => assert_eq!(index, 7),
            other => panic!("expected BadSignature, got {other:?}"),
        }
    }

    #[test]
    fn wrong_key_fails() {
        let kp1 = KeyPair::generate().unwrap();
        let kp2 = KeyPair::generate().unwrap();
        let sig = kp1.sign(b"msg").unwrap();
        assert!(verify(kp2.public(), b"msg", &sig, 0).is_err());
    }

    #[test]
    fn public_key_serde_roundtrip() {
        let kp = KeyPair::generate().unwrap();
        let mut buf = Vec::new();
        ciborium::into_writer(kp.public(), &mut buf).unwrap();
        let back: PublicKey = ciborium::from_reader(&buf[..]).unwrap();
        assert_eq!(kp.public(), &back);
    }

    #[test]
    fn signature_serde_roundtrip() {
        let kp = KeyPair::generate().unwrap();
        let sig = kp.sign(b"x").unwrap();
        let mut buf = Vec::new();
        ciborium::into_writer(&sig, &mut buf).unwrap();
        let back: Signature = ciborium::from_reader(&buf[..]).unwrap();
        assert_eq!(sig, back);
    }

    #[test]
    fn secret_key_debug_redacts() {
        let kp = KeyPair::generate().unwrap();
        let s = format!("{:?}", kp.secret());
        assert!(s.contains("redacted"));
        assert!(!s.contains(&hex::encode(&kp.secret().as_bytes()[..16])));
    }

    #[test]
    fn bad_lengths_rejected() {
        assert!(PublicKey::from_bytes(&[0u8; 100]).is_err());
        assert!(SecretKey::from_bytes(&[0u8; 100]).is_err());
        assert!(Signature::from_bytes(&[0u8; 100]).is_err());
    }

    #[test]
    fn keypair_implements_signer_trait() {
        // Use the trait via dyn dispatch to exercise the v-table.
        let kp = KeyPair::generate().unwrap();
        let boxed: Box<dyn Signer> = Box::new(kp);
        let sig = boxed.sign(b"hello via trait").unwrap();
        verify(boxed.public_key(), b"hello via trait", &sig, 0).unwrap();
        assert_eq!(boxed.provenance(), "soft:in-memory");
    }

    #[test]
    fn boxed_signer_delegates_provenance() {
        let kp = KeyPair::generate().unwrap();
        let inner: Box<dyn Signer> = Box::new(kp);
        // Box<Box<dyn Signer>> chains via the blanket impl.
        let outer = Box::new(inner);
        let s: &dyn Signer = outer.as_ref().as_ref();
        assert_eq!(s.provenance(), "soft:in-memory");
    }

    #[test]
    fn decode_pubkey_any_accepts_raw() {
        let kp = KeyPair::generate().unwrap();
        let raw = kp.public().as_bytes().to_vec();
        assert_eq!(raw.len(), PUBLIC_KEY_LEN);
        let decoded = decode_pubkey_any(&raw).expect("raw must decode");
        assert_eq!(decoded.as_bytes(), kp.public().as_bytes());
    }

    #[test]
    fn decode_pubkey_any_accepts_framed() {
        let kp = KeyPair::generate().unwrap();
        let raw = kp.public().as_bytes();
        let mut framed = Vec::with_capacity(8 + PUBLIC_KEY_LEN);
        framed.extend_from_slice(QGATEWAY_AUDIT_PK_MAGIC);
        framed.extend_from_slice(raw);
        assert_eq!(framed.len(), 8 + PUBLIC_KEY_LEN);
        let decoded = decode_pubkey_any(&framed).expect("framed must decode");
        assert_eq!(decoded.as_bytes(), kp.public().as_bytes());
    }

    #[test]
    fn decode_pubkey_any_rejects_framed_length_with_wrong_magic() {
        let bogus = vec![0u8; 8 + PUBLIC_KEY_LEN];
        let err = decode_pubkey_any(&bogus).expect_err("must reject");
        assert!(err.to_string().contains("magic"));
    }

    #[test]
    fn decode_pubkey_any_rejects_other_lengths() {
        let too_short = vec![0u8; 100];
        let err = decode_pubkey_any(&too_short).expect_err("must reject");
        let msg = err.to_string();
        assert!(msg.contains(&PUBLIC_KEY_LEN.to_string()));
        assert!(msg.contains(&(8 + PUBLIC_KEY_LEN).to_string()));
    }
}
