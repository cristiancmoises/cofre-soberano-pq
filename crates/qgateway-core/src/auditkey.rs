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
//!     magic     = "AUDITPK0"  (8 B)
//!     ml-dsa-87 = 2592 B raw
//!
//!   .audit.skid (audit signer secret key, mode 0600 on unix):
//!     magic     = "AUDITSK0"  (8 B)
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
    let mut public = Vec::from(AUDIT_PK_MAGIC.as_slice());
    public.extend_from_slice(kp.public().as_bytes());
    let mut secret = Vec::from(AUDIT_SK_MAGIC.as_slice());
    secret.extend_from_slice(kp.secret().as_bytes());
    write_keypair_files(sk_path, pk_path, &secret, &public)?;
    Ok(kp)
}

/// Load an audit keypair previously written by [`generate`].
pub fn load(sk_path: &Path, pk_path: &Path) -> Result<KeyPair> {
    let sk_blob = std::fs::read(sk_path)
        .with_context(|| format!("reading audit secret-key file {}", sk_path.display()))?;
    if sk_blob.len() != 8 + qaudit_core::signing::SECRET_KEY_LEN {
        return Err(anyhow!(
            "audit secret key file has invalid length: {} bytes",
            sk_blob.len()
        ));
    }
    if &sk_blob[..8] != AUDIT_SK_MAGIC {
        return Err(anyhow!("audit secret key file has bad magic"));
    }
    let sk_bytes = &sk_blob[8..8 + qaudit_core::signing::SECRET_KEY_LEN];
    let sk = SecretKey::from_bytes(sk_bytes).context("decoding audit ML-DSA-87 SK")?;
    let pk = load_pub(pk_path)?;
    if sk.derive_public()? != pk {
        return Err(anyhow!("audit public key does not match secret key"));
    }
    Ok(KeyPair::from_parts(pk, sk))
}

/// Read just the audit signer public key.
pub fn load_pub(pk_path: &Path) -> Result<PublicKey> {
    let blob = std::fs::read(pk_path)
        .with_context(|| format!("reading audit public-key file {}", pk_path.display()))?;
    if blob.len() != 8 + qaudit_core::signing::PUBLIC_KEY_LEN {
        return Err(anyhow!("audit public-key file has invalid length"));
    }
    if &blob[..8] != AUDIT_PK_MAGIC {
        return Err(anyhow!("audit public-key file has bad magic"));
    }
    PublicKey::from_bytes(&blob[8..8 + qaudit_core::signing::PUBLIC_KEY_LEN])
        .map_err(|e| anyhow!("decoding audit public key: {e}"))
}

/// Persist new key files without replacing existing files, symlinks or devices.
/// Both outputs are staged and synced before publication. If publication of
/// the public key fails after the secret key succeeds, the secret key remains
/// available for recovery; existing key material is never overwritten.
pub fn write_keypair_files(
    sk_path: &Path,
    pk_path: &Path,
    secret: &[u8],
    public: &[u8],
) -> Result<()> {
    use std::io::Write;

    fn parent(path: &Path) -> &Path {
        path.parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."))
    }

    for path in [sk_path, pk_path] {
        match std::fs::symlink_metadata(path) {
            Ok(_) => {
                return Err(anyhow!(
                    "refusing to overwrite existing key file {}",
                    path.display()
                ))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("checking {}", path.display())),
        }
    }
    if sk_path.file_name() == pk_path.file_name()
        && std::fs::canonicalize(parent(sk_path))? == std::fs::canonicalize(parent(pk_path))?
    {
        return Err(anyhow!("secret and public key paths must be different"));
    }
    let mut sk_temp = tempfile::NamedTempFile::new_in(parent(sk_path))?;
    let mut pk_temp = tempfile::NamedTempFile::new_in(parent(pk_path))?;
    sk_temp.write_all(secret)?;
    pk_temp.write_all(public)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        pk_temp
            .as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o644))?;
    }
    sk_temp.as_file().sync_all()?;
    pk_temp.as_file().sync_all()?;
    sk_temp
        .persist_noclobber(sk_path)
        .with_context(|| format!("publishing secret key {}", sk_path.display()))?;
    pk_temp
        .persist_noclobber(pk_path)
        .with_context(|| format!("publishing public key {}", pk_path.display()))?;
    #[cfg(unix)]
    for path in [sk_path, pk_path] {
        std::fs::File::open(parent(path))?.sync_all()?;
    }
    Ok(())
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

    #[test]
    fn key_generation_never_overwrites_existing_outputs() {
        let tmp = TempDir::new().unwrap();
        let sk = tmp.path().join("audit.skid");
        let pk = tmp.path().join("audit.pub");
        std::fs::write(&pk, b"keep existing public key").unwrap();
        assert!(generate(&sk, &pk).is_err());
        assert!(!sk.exists());
        assert_eq!(std::fs::read(&pk).unwrap(), b"keep existing public key");
        std::fs::remove_file(&pk).unwrap();
        generate(&sk, &pk).unwrap();
        let original = std::fs::read(&sk).unwrap();
        assert!(generate(&sk, &pk).is_err());
        assert_eq!(std::fs::read(&sk).unwrap(), original);
    }

    #[test]
    fn key_generation_rejects_aliases_before_publication() {
        let tmp = TempDir::new().unwrap();
        let sk = tmp.path().join("key");
        let pk = tmp.path().join(".").join("key");
        assert!(generate(&sk, &pk).is_err());
        assert!(!sk.exists());
    }

    #[cfg(unix)]
    #[test]
    fn key_generation_rejects_dangling_symlinks_and_creates_private_secret() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let tmp = TempDir::new().unwrap();
        let sk = tmp.path().join("audit.skid");
        let pk = tmp.path().join("audit.pub");
        let target = tmp.path().join("target");
        symlink(&target, &sk).unwrap();
        assert!(generate(&sk, &pk).is_err());
        assert!(!target.exists());
        assert!(!pk.exists());
        std::fs::remove_file(&sk).unwrap();
        generate(&sk, &pk).unwrap();
        assert_eq!(
            std::fs::metadata(&sk).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn loading_rejects_mismatched_pair_and_trailing_bytes() {
        let tmp = TempDir::new().unwrap();
        let sk = tmp.path().join("audit.skid");
        let pk = tmp.path().join("audit.pub");
        generate(&sk, &pk).unwrap();
        let other_sk = tmp.path().join("other.skid");
        let other_pk = tmp.path().join("other.pub");
        generate(&other_sk, &other_pk).unwrap();
        assert!(load(&sk, &other_pk).is_err());
        let mut public = std::fs::read(&pk).unwrap();
        public.push(0);
        std::fs::write(&pk, public).unwrap();
        assert!(load_pub(&pk).is_err());
        let mut secret = std::fs::read(&sk).unwrap();
        secret.push(0);
        std::fs::write(&sk, secret).unwrap();
        assert!(load(&sk, &other_pk).is_err());
    }
}
