//! CSPQ-Transport-v1 handshake.
//!
//! See crate-level docs for the wire diagram. This module implements the three
//! messages plus key schedule derivation.

use crate::error::{Error, Result};
use crate::framing::{read_frame, write_frame};
use crate::transport::{CspqStream, DirectionalKeys};
use crate::{IDENTITY_FILE_MAGIC, SUITE_ID};

use fips203::ml_kem_1024;
use fips203::traits::{Decaps, Encaps, KeyGen, SerDes};
use hkdf::Hkdf;
use qaudit_core::{KeyPair as IdKeyPair, PublicKey as IdPublicKey, Signature};
use sha3::Sha3_256;
use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use zeroize::Zeroizing;

const MSG_CLIENT_HELLO: u8 = 1;
const MSG_SERVER_HELLO: u8 = 2;
const MSG_CLIENT_FINISH: u8 = 3;

/// Long-term ML-DSA-87 identity for a CSPQ peer (server or client).
///
/// Wraps a `qaudit_core::KeyPair` for type clarity — same primitives as the
/// audit log, intentionally so that one keypair can sign both audit entries
/// and transport handshakes if a deployment desires.
pub struct IdentityKey {
    kp: IdKeyPair,
}

impl IdentityKey {
    /// Wrap an existing keypair.
    #[must_use]
    pub fn new(kp: IdKeyPair) -> Self {
        Self { kp }
    }

    /// Generate a fresh identity.
    pub fn generate() -> Result<Self> {
        Ok(Self::new(IdKeyPair::generate()?))
    }

    /// The public part — distribute this to peers via your trust process.
    #[must_use]
    pub fn public(&self) -> &IdPublicKey {
        self.kp.public()
    }

    /// Persist the public part to a `.cspqid.pub` file (8-byte magic +
    /// 2592-byte ML-DSA-87 public key, raw).
    pub fn save_public<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let mut blob = Vec::with_capacity(8 + self.kp.public().as_bytes().len());
        blob.extend_from_slice(IDENTITY_FILE_MAGIC);
        blob.extend_from_slice(self.kp.public().as_bytes());
        std::fs::write(path, blob).map_err(Error::from)?;
        Ok(())
    }

    /// Load a peer public-key file written by [`IdentityKey::save_public`].
    pub fn load_public<P: AsRef<Path>>(path: P) -> Result<IdPublicKey> {
        let blob = std::fs::read(path).map_err(Error::from)?;
        if blob.len() != 8 + qaudit_core::signing::PUBLIC_KEY_LEN {
            return Err(Error::Identity(format!(
                "file has invalid length: {} bytes",
                blob.len()
            )));
        }
        if &blob[..8] != IDENTITY_FILE_MAGIC {
            return Err(Error::Identity("bad magic".into()));
        }
        IdPublicKey::from_bytes(&blob[8..8 + qaudit_core::signing::PUBLIC_KEY_LEN])
            .map_err(Error::from)
    }

    fn sign(&self, msg: &[u8]) -> Result<Signature> {
        Ok(self.kp.sign(msg)?)
    }
}

/// Peer trust policy: which peer ML-DSA-87 public keys are accepted.
///
/// Sprint 3 ships a static allow-list. Sprint 4 will add hot-reload and an
/// admission audit hook.
#[derive(Clone, Default)]
pub struct PeerPolicy {
    allowed: Arc<HashSet<Vec<u8>>>,
}

impl PeerPolicy {
    /// Construct from an explicit list of peer public keys.
    #[must_use]
    pub fn from_keys(keys: impl IntoIterator<Item = IdPublicKey>) -> Self {
        let allowed = keys.into_iter().map(|k| k.as_bytes().to_vec()).collect();
        Self {
            allowed: Arc::new(allowed),
        }
    }

    /// Allow exactly one peer (common single-tenant case).
    #[must_use]
    pub fn single(pk: IdPublicKey) -> Self {
        Self::from_keys(std::iter::once(pk))
    }

    /// Load every `.cspqid.pub` from a directory.
    pub fn from_dir<P: AsRef<Path>>(dir: P) -> Result<Self> {
        let mut keys = Vec::new();
        for entry in std::fs::read_dir(dir.as_ref()).map_err(Error::from)? {
            let entry = entry.map_err(Error::from)?;
            if let Some(name) = entry.file_name().to_str() {
                if name.ends_with(".cspqid.pub") {
                    keys.push(IdentityKey::load_public(entry.path())?);
                }
            }
        }
        Ok(Self::from_keys(keys))
    }

    /// Is this peer in the allow-list?
    #[must_use]
    pub fn accepts(&self, pk: &IdPublicKey) -> bool {
        self.allowed.contains(pk.as_bytes())
    }

    /// Number of admitted peers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.allowed.len()
    }

    /// Whether the policy admits any peers.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.allowed.is_empty()
    }
}

fn transcript(
    suite: u16,
    client_kem_pk: &[u8],
    server_kem_ct: &[u8],
    server_id_pk: &[u8],
    client_id_pk: &[u8],
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(&suite.to_be_bytes());
    h.update(client_kem_pk);
    h.update(server_kem_ct);
    h.update(server_id_pk);
    h.update(client_id_pk);
    h.finalize().into()
}

fn derive_keys(shared_secret: &[u8], transcript: &[u8; 32]) -> DirectionalKeys {
    let hk = Hkdf::<Sha3_256>::new(Some(b"cspq-transport-v1"), shared_secret);
    let mut keys = Zeroizing::new([0u8; 64]);
    hk.expand(transcript, &mut *keys)
        .expect("HKDF expand 64 bytes never fails for SHA3-256");
    let mut c2s = [0u8; 32];
    let mut s2c = [0u8; 32];
    c2s.copy_from_slice(&keys[..32]);
    s2c.copy_from_slice(&keys[32..]);
    DirectionalKeys::new(c2s, s2c)
}

/// Server-side: accept a CSPQ handshake on an already-established byte stream.
pub async fn accept<S>(
    mut stream: S,
    identity: &IdentityKey,
    policy: &PeerPolicy,
) -> Result<CspqStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if policy.is_empty() {
        return Err(Error::Protocol(
            "server peer policy is empty; refusing to accept any client".into(),
        ));
    }

    // --- read CLIENT_HELLO
    let ch = read_frame(&mut stream, 4096).await?;
    if ch.len() != 1 + 2 + ml_kem_1024::EK_LEN {
        return Err(Error::Protocol(format!(
            "CLIENT_HELLO size {} (expected {})",
            ch.len(),
            1 + 2 + ml_kem_1024::EK_LEN
        )));
    }
    if ch[0] != MSG_CLIENT_HELLO {
        return Err(Error::Protocol(format!("bad msg_type {}", ch[0])));
    }
    let suite = u16::from_be_bytes([ch[1], ch[2]]);
    if suite != SUITE_ID {
        return Err(Error::UnsupportedSuite(suite));
    }
    let client_kem_pk_bytes = &ch[3..];
    let client_kem_pk_arr: [u8; ml_kem_1024::EK_LEN] = client_kem_pk_bytes
        .try_into()
        .map_err(|_| Error::Protocol("CLIENT_HELLO KEM size mismatch".into()))?;
    let client_kem_pk = ml_kem_1024::EncapsKey::try_from_bytes(client_kem_pk_arr)
        .map_err(|e| Error::Crypto(format!("ML-KEM-1024 EK parse: {e}")))?;

    // --- KEM encapsulation
    let (shared, ct) = client_kem_pk
        .try_encaps()
        .map_err(|e| Error::Crypto(format!("ML-KEM-1024 encaps: {e}")))?;
    let ct_bytes = ct.into_bytes();
    let shared_bytes: Zeroizing<Vec<u8>> = Zeroizing::new(shared.into_bytes().to_vec());

    // --- sign transcript with server identity (client_id_pk not yet known: fold in later)
    // Server commits to (suite, client_kem_pk, server_kem_ct, server_id_pk, EMPTY).
    // Client will then sign the *full* transcript including its own id_pk; both sides
    // compute the same hash because we keep client_id_pk OUT of the server's signing
    // input and embed it into a SECOND transcript hash used for the record layer.
    //
    // Simpler design: server signs hash(suite || client_kem_pk || ct || server_id_pk).
    // Client signs hash(suite || client_kem_pk || ct || server_id_pk || client_id_pk).
    // Final record-layer key schedule binds both id_pks.
    let server_id_pk_bytes = identity.public().as_bytes();
    let mut h1 = blake3::Hasher::new();
    h1.update(&suite.to_be_bytes());
    h1.update(client_kem_pk_bytes);
    h1.update(&ct_bytes);
    h1.update(server_id_pk_bytes);
    let server_transcript: [u8; 32] = h1.finalize().into();
    let server_sig = identity.sign(&server_transcript)?;

    // --- SERVER_HELLO
    let mut sh = Vec::with_capacity(
        1 + ml_kem_1024::CT_LEN
            + qaudit_core::signing::PUBLIC_KEY_LEN
            + qaudit_core::signing::SIGNATURE_LEN,
    );
    sh.push(MSG_SERVER_HELLO);
    sh.extend_from_slice(&ct_bytes);
    sh.extend_from_slice(server_id_pk_bytes);
    sh.extend_from_slice(server_sig.as_bytes());
    write_frame(&mut stream, &sh).await?;

    // --- CLIENT_FINISH
    let cf = read_frame(&mut stream, 16 * 1024).await?;
    let expected = 1 + qaudit_core::signing::PUBLIC_KEY_LEN + qaudit_core::signing::SIGNATURE_LEN;
    if cf.len() != expected {
        return Err(Error::Protocol(format!(
            "CLIENT_FINISH size {} (expected {})",
            cf.len(),
            expected
        )));
    }
    if cf[0] != MSG_CLIENT_FINISH {
        return Err(Error::Protocol(format!(
            "bad msg_type {} in CLIENT_FINISH",
            cf[0]
        )));
    }
    let mut cur = 1;
    let client_id_pk_bytes = &cf[cur..cur + qaudit_core::signing::PUBLIC_KEY_LEN];
    cur += qaudit_core::signing::PUBLIC_KEY_LEN;
    let client_sig_bytes = &cf[cur..];
    let client_id_pk = IdPublicKey::from_bytes(client_id_pk_bytes).map_err(Error::from)?;
    let client_sig = Signature::from_bytes(client_sig_bytes).map_err(Error::from)?;

    if !policy.accepts(&client_id_pk) {
        return Err(Error::UntrustedPeer {
            peer_id: hex::encode(&client_id_pk_bytes[..16]),
        });
    }

    let final_transcript = transcript(
        suite,
        client_kem_pk_bytes,
        &ct_bytes,
        server_id_pk_bytes,
        client_id_pk_bytes,
    );
    qaudit_core::verify_signature(&client_id_pk, &final_transcript, &client_sig, 0)
        .map_err(|_| Error::Crypto("client signature verify failed".into()))?;

    let keys = derive_keys(&shared_bytes, &final_transcript);
    Ok(CspqStream::new_server(stream, keys, client_id_pk))
}

/// Client-side: initiate a CSPQ handshake over an already-established byte stream.
pub async fn connect<S>(
    mut stream: S,
    identity: &IdentityKey,
    server_policy: &PeerPolicy,
) -> Result<CspqStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if server_policy.is_empty() {
        return Err(Error::Protocol(
            "client server_policy is empty; refusing to dial any server".into(),
        ));
    }

    // --- generate ephemeral KEM keypair
    let (client_kem_pk, client_kem_sk) = ml_kem_1024::KG::try_keygen()
        .map_err(|e| Error::Crypto(format!("ML-KEM-1024 keygen: {e}")))?;
    let client_kem_pk_bytes = client_kem_pk.into_bytes();
    let client_kem_pk_vec = client_kem_pk_bytes.to_vec();

    // --- send CLIENT_HELLO
    let mut ch = Vec::with_capacity(1 + 2 + ml_kem_1024::EK_LEN);
    ch.push(MSG_CLIENT_HELLO);
    ch.extend_from_slice(&SUITE_ID.to_be_bytes());
    ch.extend_from_slice(&client_kem_pk_bytes);
    write_frame(&mut stream, &ch).await?;

    // --- read SERVER_HELLO
    let sh = read_frame(&mut stream, 16 * 1024).await?;
    let expected_sh = 1
        + ml_kem_1024::CT_LEN
        + qaudit_core::signing::PUBLIC_KEY_LEN
        + qaudit_core::signing::SIGNATURE_LEN;
    if sh.len() != expected_sh {
        return Err(Error::Protocol(format!(
            "SERVER_HELLO size {} (expected {})",
            sh.len(),
            expected_sh
        )));
    }
    if sh[0] != MSG_SERVER_HELLO {
        return Err(Error::Protocol(format!(
            "bad msg_type {} in SERVER_HELLO",
            sh[0]
        )));
    }
    let mut cur = 1;
    let ct_bytes = &sh[cur..cur + ml_kem_1024::CT_LEN];
    cur += ml_kem_1024::CT_LEN;
    let server_id_pk_bytes = &sh[cur..cur + qaudit_core::signing::PUBLIC_KEY_LEN];
    cur += qaudit_core::signing::PUBLIC_KEY_LEN;
    let server_sig_bytes = &sh[cur..];
    let server_id_pk = IdPublicKey::from_bytes(server_id_pk_bytes).map_err(Error::from)?;
    let server_sig = Signature::from_bytes(server_sig_bytes).map_err(Error::from)?;

    if !server_policy.accepts(&server_id_pk) {
        return Err(Error::UntrustedPeer {
            peer_id: hex::encode(&server_id_pk_bytes[..16]),
        });
    }

    // --- verify server signature
    let mut h1 = blake3::Hasher::new();
    h1.update(&SUITE_ID.to_be_bytes());
    h1.update(&client_kem_pk_vec);
    h1.update(ct_bytes);
    h1.update(server_id_pk_bytes);
    let server_transcript: [u8; 32] = h1.finalize().into();
    qaudit_core::verify_signature(&server_id_pk, &server_transcript, &server_sig, 0)
        .map_err(|_| Error::Crypto("server signature verify failed".into()))?;

    // --- KEM decapsulation
    let ct_arr: [u8; ml_kem_1024::CT_LEN] = ct_bytes
        .try_into()
        .map_err(|_| Error::Protocol("ciphertext size mismatch".into()))?;
    let ct = ml_kem_1024::CipherText::try_from_bytes(ct_arr)
        .map_err(|e| Error::Crypto(format!("ML-KEM-1024 CT parse: {e}")))?;
    let shared = client_kem_sk
        .try_decaps(&ct)
        .map_err(|e| Error::Crypto(format!("ML-KEM-1024 decaps: {e}")))?;
    let shared_bytes: Zeroizing<Vec<u8>> = Zeroizing::new(shared.into_bytes().to_vec());

    // --- sign final transcript (includes client_id_pk) and send CLIENT_FINISH
    let client_id_pk_bytes = identity.public().as_bytes().to_vec();
    let final_transcript = transcript(
        SUITE_ID,
        &client_kem_pk_vec,
        ct_bytes,
        server_id_pk_bytes,
        &client_id_pk_bytes,
    );
    let client_sig = identity.sign(&final_transcript)?;

    let mut cf = Vec::with_capacity(
        1 + qaudit_core::signing::PUBLIC_KEY_LEN + qaudit_core::signing::SIGNATURE_LEN,
    );
    cf.push(MSG_CLIENT_FINISH);
    cf.extend_from_slice(&client_id_pk_bytes);
    cf.extend_from_slice(client_sig.as_bytes());
    write_frame(&mut stream, &cf).await?;

    let keys = derive_keys(&shared_bytes, &final_transcript);
    Ok(CspqStream::new_client(stream, keys, server_id_pk))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    fn pair() -> (IdentityKey, IdentityKey) {
        (
            IdentityKey::generate().unwrap(),
            IdentityKey::generate().unwrap(),
        )
    }

    #[tokio::test]
    async fn handshake_roundtrip() {
        let client_id = IdentityKey::generate().unwrap();
        let server_id = IdentityKey::generate().unwrap();
        let client_policy = PeerPolicy::single(server_id.public().clone());
        let server_policy = PeerPolicy::single(client_id.public().clone());

        let server_id_pub = server_id.public().clone();
        let client_id_pub = client_id.public().clone();

        let (a, b) = duplex(64 * 1024);

        let server_task = tokio::spawn(async move { accept(b, &server_id, &server_policy).await });
        let client_task = tokio::spawn(async move { connect(a, &client_id, &client_policy).await });

        let server_stream = server_task.await.unwrap().expect("server handshake ok");
        let client_stream = client_task.await.unwrap().expect("client handshake ok");

        assert_eq!(server_stream.peer_id().as_bytes(), client_id_pub.as_bytes());
        assert_eq!(client_stream.peer_id().as_bytes(), server_id_pub.as_bytes());
    }

    #[tokio::test]
    async fn handshake_rejects_unknown_client() {
        let (_unknown, server_id) = pair();
        let intruder = IdentityKey::generate().unwrap();

        // Server only trusts a different key; intruder will not be in policy.
        let trusted_client = IdentityKey::generate().unwrap();
        let server_policy = PeerPolicy::single(trusted_client.public().clone());
        let client_policy = PeerPolicy::single(server_id.public().clone());

        let (a, b) = duplex(64 * 1024);

        let server_task = tokio::spawn(async move { accept(b, &server_id, &server_policy).await });
        let client_task = tokio::spawn(async move { connect(a, &intruder, &client_policy).await });

        let server_err = server_task.await.unwrap().unwrap_err();
        assert!(matches!(server_err, Error::UntrustedPeer { .. }));
        let _ = client_task.await.unwrap();
    }

    #[tokio::test]
    async fn handshake_rejects_wrong_server() {
        let (client_id, real_server) = pair();
        let imposter = IdentityKey::generate().unwrap();
        // Client trusts only the real server. Imposter will be running on the wire.
        let client_policy = PeerPolicy::single(real_server.public().clone());
        let server_policy = PeerPolicy::single(client_id.public().clone());

        let (a, b) = duplex(64 * 1024);
        let server_task = tokio::spawn(async move { accept(b, &imposter, &server_policy).await });
        let client_task = tokio::spawn(async move { connect(a, &client_id, &client_policy).await });

        let client_err = client_task.await.unwrap().unwrap_err();
        assert!(matches!(client_err, Error::UntrustedPeer { .. }));
        let _ = server_task.await.unwrap();
    }
}
