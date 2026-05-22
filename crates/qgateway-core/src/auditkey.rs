//! Persistent audit signing key for QGateway.
//!
//! Sprint 3 generated the audit-log signing key in-memory every restart, so
//! each restart effectively started a fresh log. Sprint 4 introduces a
//! persistent `.audit.skid` file (analogous to the transport `.skid` but
//! distinct in magic) plus the option to bind the audit signer to a
//! PKCS#11 HSM key via `qaudit-hsm`.
//!
//! File formats:
//!
//! ```text
//!   .audit.pub  (audit signer public key, world-readable):
//!     magic     = "AUDITPK01"  (8 B)
//!     ml-dsa-87 = 2592 B raw
//!
//!   .audit.skid (audit signer secret key, mode 0600 on unix):
//!     magic     = "AUDITSK01"  (8 B)
//!     ml-dsa-87 = 4896 B raw
//! ```

use anyhow::{anyhow, Context, Result};
use qaudit_core::{KeyPair, PublicKey, SecretKey};
use std::path::Path;

/// Magic for `.audit.pub` files (audit signer public key).
pub const AUDIT_PK_MAGIC: &[u8; 8] = b"AUDITPK0";
/// Magic for `.audit.skid` files (audit signer secret key).
pub const AUDIT_SK_MAGIC: &[u8; 8] = b"AUDITSK0";

/// Generate a fresh audit keypair and persist it.
///
/// `sk_path` is written mode 0600 on unix.
pub fn generate(sk_path: &Path, pk_path: &Path) -> Result<KeyPair> {
    let kp = KeyPair::generate().context("ML-DSA-87 keygen")?;
    save_pub(pk_path, kp.public())?;
    save_secret(sk_path, &kp)?;
    Ok(kp)
}

/// Load an audit keypair previously written by [`generate`].
pub fn load(sk_path: &Path, pk_path: &Path) -> Result<KeyPair> {
    let sk_blob = std::fs::read(sk_path)
        .with_context(|| format!("reading audit secret-key file {}", sk_path.display()))?;
    if sk_blob.len() < 8 + qaudit_core::signing::SECRET_KEY_LEN {
        return Err(anyhow!(
            "audit secret key file too short: {} bytes",
            sk_blob.len()
        ));
    }
    if &sk_blob[..8] != AUDIT_SK_MAGIC {
        return Err(anyhow!("audit secret key file has bad magic"));
    }
    let sk_bytes = &sk_blob[8..8 + qaudit_core::signing::SECRET_KEY_LEN];
    let sk = SecretKey::from_bytes(sk_bytes).context("decoding audit ML-DSA-87 SK")?;
    let pk = load_pub(pk_path)?;
    Ok(KeyPair::from_parts(pk, sk))
}

/// Read just the audit signer public key.
pub fn load_pub(pk_path: &Path) -> Result<PublicKey> {
    let blob = std::fs::read(pk_path)
        .with_context(|| format!("reading audit public-key file {}", pk_path.display()))?;
    if blob.len() < 8 + qaudit_core::signing::PUBLIC_KEY_LEN {
        return Err(anyhow!("audit public-key file too short"));
    }
    if &blob[..8] != AUDIT_PK_MAGIC {
        return Err(anyhow!("audit public-key file has bad magic"));
    }
    PublicKey::from_bytes(&blob[8..8 + qaudit_core::signing::PUBLIC_KEY_LEN])
        .map_err(|e| anyhow!("decoding audit public key: {e}"))
}

fn save_pub(path: &Path, pk: &PublicKey) -> Result<()> {
    let mut blob = Vec::with_capacity(8 + pk.as_bytes().len());
    blob.extend_from_slice(AUDIT_PK_MAGIC);
    blob.extend_from_slice(pk.as_bytes());
    std::fs::write(path, blob).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

fn save_secret(path: &Path, kp: &KeyPair) -> Result<()> {
    let mut blob = Vec::with_capacity(8 + kp.secret().as_bytes().len());
    blob.extend_from_slice(AUDIT_SK_MAGIC);
    blob.extend_from_slice(kp.secret().as_bytes());
    write_secret_file(path, &blob)
}

#[cfg(unix)]
fn write_secret_file(path: &Path, contents: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("opening {} for write", path.display()))?;
    f.write_all(contents)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_secret_file(path: &Path, contents: &[u8]) -> Result<()> {
    std::fs::write(path, contents).with_context(|| format!("writing {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn roundtrip_generate_load() {
        let tmp = TempDir::new().unwrap();
        let sk = tmp.path().join("audit.skid");
        let pk = tmp.path().join("audit.pub");
        let original = generate(&sk, &pk).unwrap();
        let loaded = load(&sk, &pk).unwrap();
        assert_eq!(loaded.public().as_bytes(), original.public().as_bytes());
        // Sanity: signed bytes verify with the loaded keypair.
        let sig = loaded.sign(b"sprint-4-test").unwrap();
        qaudit_core::verify_signature(loaded.public(), b"sprint-4-test", &sig, 0).unwrap();
    }

    #[test]
    fn rejects_bad_magic() {
        let tmp = TempDir::new().unwrap();
        let sk = tmp.path().join("audit.skid");
        let pk = tmp.path().join("audit.pub");
        generate(&sk, &pk).unwrap();
        // Corrupt the SK magic.
        let mut bytes = std::fs::read(&sk).unwrap();
        bytes[0] = 0;
        std::fs::write(&sk, bytes).unwrap();
        let err = load(&sk, &pk).map(|_| ()).unwrap_err();
        assert!(err.to_string().contains("bad magic"));
    }
}
