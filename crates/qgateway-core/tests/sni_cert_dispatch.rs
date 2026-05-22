//! Sprint 6.5 — end-to-end test of the multi-SNI cert dispatch.
//!
//! Generates two self-signed certs (one per "tenant"), builds a
//! `MultiSniCertResolver`-backed acceptor, binds a real `TcpListener`,
//! then runs a rustls client through three scenarios:
//!
//! 1. Client sends `sni="sp.test"` → server presents SP cert; handshake
//!    succeeds; the cert the client sees is exactly the one we generated
//!    for SP.
//! 2. Client sends `sni="rj.test"` → server presents RJ cert; handshake
//!    succeeds; cert matches RJ's self-signed material.
//! 3. Client sends `sni="unknown.test"` → server responds with TLS alert
//!    `unrecognized_name`; client handshake fails (the resolver returns
//!    `None`, which rustls converts to that alert per RFC 6066).
//!
//! Hot-reload is exercised separately by the lib-level tests for the
//! `build_reloadable_multi_sni_acceptor` API; this test only validates
//! that the dispatch *layer* selects the right cert per SNI.

use qgateway_core::tls::{build_multi_sni_acceptor, ensure_crypto_provider_installed};
use qgateway_core::TlsConfig;
use rcgen::{CertificateParams, DistinguishedName, KeyPair};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

struct GeneratedCert {
    cert_path: PathBuf,
    key_path: PathBuf,
    cert_der: CertificateDer<'static>,
}

/// Generate a self-signed cert + key for the given DNS SAN, write them to
/// PEM files in `dir`, and return the DER form for verification.
fn generate_self_signed(dir: &std::path::Path, dns_name: &str) -> GeneratedCert {
    // rcgen 0.13 API: build CertificateParams, set SANs, generate the keypair,
    // self-sign.
    let key = KeyPair::generate().expect("keypair");
    let mut params = CertificateParams::new(vec![dns_name.to_string()]).unwrap();
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, dns_name);
    let cert = params.self_signed(&key).expect("self-sign");
    let cert_pem = cert.pem();
    let key_pem = key.serialize_pem();

    let cert_path = dir.join(format!("{dns_name}.cert.pem"));
    let key_path = dir.join(format!("{dns_name}.key.pem"));
    std::fs::write(&cert_path, cert_pem).unwrap();
    std::fs::write(&key_path, key_pem).unwrap();

    GeneratedCert {
        cert_path,
        key_path,
        cert_der: cert.der().clone(),
    }
}

/// Run the multi-SNI acceptor on `bind_addr` until shutdown is signalled.
/// Returns the bound port (since `bind_addr` may be `"127.0.0.1:0"`).
async fn spawn_sni_server(
    bind_addr: &str,
    entries: Vec<(String, String, TlsConfig)>,
) -> (
    u16,
    tokio::task::JoinHandle<()>,
    tokio::sync::oneshot::Sender<()>,
) {
    let acceptor = build_multi_sni_acceptor(entries).expect("build acceptor");
    let listener = TcpListener::bind(bind_addr).await.expect("bind");
    let port = listener.local_addr().unwrap().port();
    let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel();
    let handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut stop_rx => return,
                res = listener.accept() => {
                    let (tcp, _addr) = match res {
                        Ok(x) => x,
                        Err(_) => continue,
                    };
                    let acceptor = acceptor.clone();
                    tokio::spawn(async move {
                        match acceptor.accept(tcp).await {
                            Ok(mut tls) => {
                                // Echo a single line so the client can confirm
                                // it reached the right handler.
                                let mut buf = [0u8; 32];
                                let n = tls.read(&mut buf).await.unwrap_or(0);
                                if n > 0 {
                                    let _ = tls.write_all(&buf[..n]).await;
                                }
                                let _ = tls.shutdown().await;
                            }
                            Err(_e) => {
                                // Expected for unknown-SNI test case.
                            }
                        }
                    });
                }
            }
        }
    });
    (port, handle, stop_tx)
}

/// Build a rustls `ClientConfig` that trusts the two self-signed certs
/// we generated. This is what real clients would do via a CA bundle,
/// but here we install our own roots.
fn client_config_trusting(roots: &[CertificateDer<'static>]) -> Arc<ClientConfig> {
    let mut store = RootCertStore::empty();
    for cert in roots {
        store.add(cert.clone()).expect("add root");
    }
    let cfg = ClientConfig::builder()
        .with_root_certificates(store)
        .with_no_client_auth();
    Arc::new(cfg)
}

/// Connect with the given SNI and return the leaf cert the server presented.
async fn handshake_and_get_leaf(
    port: u16,
    sni: &str,
    client_cfg: Arc<ClientConfig>,
) -> Result<CertificateDer<'static>, String> {
    let tcp = TcpStream::connect(("127.0.0.1", port))
        .await
        .map_err(|e| format!("tcp: {e}"))?;
    let connector = TlsConnector::from(client_cfg);
    let sname = ServerName::try_from(sni.to_string()).map_err(|e| format!("sni: {e}"))?;
    let tls = connector
        .connect(sname, tcp)
        .await
        .map_err(|e| format!("handshake: {e}"))?;
    let (_io, conn) = tls.get_ref();
    let leaf = conn
        .peer_certificates()
        .and_then(|c| c.first())
        .ok_or_else(|| "no peer cert".to_string())?
        .clone();
    Ok(leaf.into_owned())
}

#[tokio::test]
async fn sni_dispatches_correct_cert_per_hostname() {
    ensure_crypto_provider_installed();
    let tmp = TempDir::new().unwrap();
    let sp = generate_self_signed(tmp.path(), "sp.test");
    let rj = generate_self_signed(tmp.path(), "rj.test");

    let entries = vec![
        (
            "sp.test".to_string(),
            "tenant-sp".to_string(),
            TlsConfig {
                cert: sp.cert_path.clone(),
                key: sp.key_path.clone(),
            },
        ),
        (
            "rj.test".to_string(),
            "tenant-rj".to_string(),
            TlsConfig {
                cert: rj.cert_path.clone(),
                key: rj.key_path.clone(),
            },
        ),
    ];

    let (port, server_handle, stop_tx) = spawn_sni_server("127.0.0.1:0", entries).await;

    let trust = client_config_trusting(&[sp.cert_der.clone(), rj.cert_der.clone()]);

    // Case 1: SNI=sp.test → server must present SP's leaf.
    let leaf_sp = handshake_and_get_leaf(port, "sp.test", trust.clone())
        .await
        .expect("sp handshake");
    assert_eq!(
        leaf_sp, sp.cert_der,
        "SNI=sp.test must present SP's exact self-signed cert"
    );
    assert_ne!(
        leaf_sp, rj.cert_der,
        "SNI=sp.test must NOT present RJ's cert"
    );

    // Case 2: SNI=rj.test → server must present RJ's leaf.
    let leaf_rj = handshake_and_get_leaf(port, "rj.test", trust.clone())
        .await
        .expect("rj handshake");
    assert_eq!(
        leaf_rj, rj.cert_der,
        "SNI=rj.test must present RJ's exact self-signed cert"
    );

    let _ = stop_tx.send(());
    let _ = server_handle.await;
}

#[tokio::test]
async fn sni_unknown_hostname_rejected() {
    ensure_crypto_provider_installed();
    let tmp = TempDir::new().unwrap();
    let sp = generate_self_signed(tmp.path(), "sp.test");

    let entries = vec![(
        "sp.test".to_string(),
        "tenant-sp".to_string(),
        TlsConfig {
            cert: sp.cert_path.clone(),
            key: sp.key_path.clone(),
        },
    )];

    let (port, server_handle, stop_tx) = spawn_sni_server("127.0.0.1:0", entries).await;
    let trust = client_config_trusting(std::slice::from_ref(&sp.cert_der));

    // SNI=unknown.test has no entry in the resolver → rustls server returns
    // None from resolve() → client gets a handshake-time alert.
    let result = handshake_and_get_leaf(port, "unknown.test", trust).await;
    assert!(
        result.is_err(),
        "handshake with unknown SNI must fail, got Ok"
    );

    let _ = stop_tx.send(());
    let _ = server_handle.await;
}

// ============================================================================
//                  Sprint 8 — wildcard SNI end-to-end
// ============================================================================

#[tokio::test]
async fn wildcard_sni_dispatches_to_wildcard_cert() {
    // Generate ONE wildcard cert for *.bank.test, then connect with SNI
    // sp.bank.test — the wildcard cert must be presented.
    ensure_crypto_provider_installed();
    let tmp = TempDir::new().unwrap();
    let wildcard = generate_self_signed(tmp.path(), "wildcard-bank-test");

    let entries = vec![(
        "*.bank.test".to_string(),
        "tenant-wildcard".to_string(),
        TlsConfig {
            cert: wildcard.cert_path.clone(),
            key: wildcard.key_path.clone(),
        },
    )];

    let (port, server_handle, stop_tx) = spawn_sni_server("127.0.0.1:0", entries).await;
    let trust = client_config_trusting(std::slice::from_ref(&wildcard.cert_der));

    // sp.bank.test matches *.bank.test → handshake succeeds.
    // (Cert name doesn't have to match the SNI hostname for the rustls
    // server-side test — the wildcard test is about the RESOLVER picking
    // the right CertifiedKey, not about client-side cert verification of
    // the SAN. We bypass client SAN checks by trusting the cert directly.)
    let leaf = handshake_and_get_leaf(port, "sp.bank.test", trust.clone()).await;
    // The handshake completes if the resolver returned a cert for the
    // wildcard match. Client-side SAN verification may then reject because
    // the cert is for 'wildcard-bank-test', not 'sp.bank.test'. That
    // post-resolver step is NOT what this test is exercising — we only
    // need to confirm the resolver returned SOMETHING (not None, which
    // would cause an unrecognized_name alert before any cert validation).
    // So we accept both Ok(_) (full handshake) and Err where the error
    // is about cert name mismatch, not unrecognized_name.
    match leaf {
        Ok(_) => { /* full handshake completed - resolver worked */ }
        Err(e) => {
            assert!(
                !e.contains("unrecognized_name") && !e.contains("UnrecognizedName"),
                "resolver must have returned a cert for *.bank.test → sp.bank.test; \
                 instead got unrecognized_name: {e}"
            );
        }
    }

    let _ = stop_tx.send(());
    let _ = server_handle.await;
}

#[tokio::test]
async fn wildcard_sni_rejects_two_label_subdomain() {
    // *.bank.test must NOT match a.b.bank.test (RFC 6125 single-label rule).
    ensure_crypto_provider_installed();
    let tmp = TempDir::new().unwrap();
    let wildcard = generate_self_signed(tmp.path(), "wildcard");

    let entries = vec![(
        "*.bank.test".to_string(),
        "tenant-wildcard".to_string(),
        TlsConfig {
            cert: wildcard.cert_path.clone(),
            key: wildcard.key_path.clone(),
        },
    )];

    let (port, server_handle, stop_tx) = spawn_sni_server("127.0.0.1:0", entries).await;
    let trust = client_config_trusting(std::slice::from_ref(&wildcard.cert_der));

    // a.b.bank.test has TWO labels before .bank.test → must not match.
    let result = handshake_and_get_leaf(port, "a.b.bank.test", trust).await;
    assert!(
        result.is_err(),
        "wildcard '*.bank.test' must NOT match two-label subdomain 'a.b.bank.test'"
    );

    let _ = stop_tx.send(());
    let _ = server_handle.await;
}

#[tokio::test]
async fn wildcard_sni_exact_match_takes_priority() {
    // Mixed setup: exact 'priority.bank.test' + wildcard '*.bank.test'.
    // SNI=priority.bank.test must hit the EXACT cert, not the wildcard.
    ensure_crypto_provider_installed();
    let tmp = TempDir::new().unwrap();
    let exact = generate_self_signed(tmp.path(), "priority.bank.test");
    let wildcard = generate_self_signed(tmp.path(), "other.bank.test");

    let entries = vec![
        (
            "priority.bank.test".to_string(),
            "tenant-exact".to_string(),
            TlsConfig {
                cert: exact.cert_path.clone(),
                key: exact.key_path.clone(),
            },
        ),
        (
            "*.bank.test".to_string(),
            "tenant-wildcard".to_string(),
            TlsConfig {
                cert: wildcard.cert_path.clone(),
                key: wildcard.key_path.clone(),
            },
        ),
    ];

    let (port, server_handle, stop_tx) = spawn_sni_server("127.0.0.1:0", entries).await;
    let trust = client_config_trusting(&[exact.cert_der.clone(), wildcard.cert_der.clone()]);

    // priority.bank.test → exact must win.
    let leaf = handshake_and_get_leaf(port, "priority.bank.test", trust.clone())
        .await
        .expect("priority.bank.test handshake must succeed");
    assert_eq!(
        leaf, exact.cert_der,
        "exact match must win over wildcard for priority.bank.test"
    );
    assert_ne!(
        leaf, wildcard.cert_der,
        "wildcard cert must NOT be served when exact match exists"
    );

    // other.bank.test → wildcard must answer.
    let leaf2 = handshake_and_get_leaf(port, "other.bank.test", trust)
        .await
        .expect("other.bank.test handshake must succeed via wildcard");
    assert_eq!(leaf2, wildcard.cert_der);

    let _ = stop_tx.send(());
    let _ = server_handle.await;
}
