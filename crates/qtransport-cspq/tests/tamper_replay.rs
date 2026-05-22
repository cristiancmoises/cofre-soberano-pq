//! Network-level tamper / replay tests for CSPQ-Transport-v1.
//!
//! Two tests, each with a frame-aware TCP MitM:
//!
//! - `tampered_record_byte_causes_aead_failure` — MitM flips one byte deep
//!   inside the first record-layer frame; server's AEAD must reject it.
//! - `replayed_record_is_rejected` — MitM forwards two records then replays
//!   the first one; server's nonce counter has advanced, so the duplicate
//!   ciphertext fails AEAD verification.

use qtransport_cspq::{accept, connect, IdentityKey, PeerPolicy};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

async fn pick_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let p = l.local_addr().unwrap().port();
    drop(l);
    p
}

/// Read one length-prefixed CSPQ frame (4-byte BE prefix + body).
async fn read_frame_raw(
    r: &mut tokio::net::tcp::OwnedReadHalf,
) -> std::io::Result<(Vec<u8>, Vec<u8>)> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await?;
    let mut raw = len_buf.to_vec();
    raw.extend_from_slice(&body);
    Ok((body, raw))
}

fn pair() -> (IdentityKey, IdentityKey, PeerPolicy, PeerPolicy) {
    let client = IdentityKey::generate().unwrap();
    let server = IdentityKey::generate().unwrap();
    let client_policy = PeerPolicy::single(server.public().clone());
    let server_policy = PeerPolicy::single(client.public().clone());
    (client, server, client_policy, server_policy)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tampered_record_byte_causes_aead_failure() {
    let (client_id, server_id, client_policy, server_policy) = pair();

    let server_port = pick_port().await;
    let mitm_port = pick_port().await;

    let server_id_arc = Arc::new(server_id);
    let server_policy_arc = Arc::new(server_policy);
    let s_id = server_id_arc.clone();
    let s_pol = server_policy_arc.clone();
    let server_task = tokio::spawn(async move {
        let listener = TcpListener::bind(format!("127.0.0.1:{server_port}"))
            .await
            .unwrap();
        let (sock, _) = listener.accept().await.unwrap();
        accept(sock, &s_id, &s_pol).await
    });

    let listener = TcpListener::bind(format!("127.0.0.1:{mitm_port}"))
        .await
        .unwrap();
    let mitm_handle = tokio::spawn(async move {
        let (inbound, _) = listener.accept().await.unwrap();
        let outbound = TcpStream::connect(format!("127.0.0.1:{server_port}"))
            .await
            .unwrap();
        let (mut ir, mut iw) = inbound.into_split();
        let (mut or, mut ow) = outbound.into_split();

        // c2s: handshake = 2 frames (CLIENT_HELLO, CLIENT_FINISH);
        // record-layer starts at frame index 2. Tamper that one.
        let c2s = tokio::spawn(async move {
            let mut frame_idx = 0;
            loop {
                let (mut body, mut raw) = match read_frame_raw(&mut ir).await {
                    Ok(x) => x,
                    Err(_) => return,
                };
                if frame_idx == 2 && body.len() > 60 {
                    body[40] ^= 0xFF;
                    raw.clear();
                    raw.extend_from_slice(&(body.len() as u32).to_be_bytes());
                    raw.extend_from_slice(&body);
                }
                frame_idx += 1;
                if ow.write_all(&raw).await.is_err() {
                    return;
                }
            }
        });

        let s2c = tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            loop {
                let n = match or.read(&mut buf).await {
                    Ok(0) => return,
                    Ok(n) => n,
                    Err(_) => return,
                };
                if iw.write_all(&buf[..n]).await.is_err() {
                    return;
                }
            }
        });

        let _ = tokio::join!(c2s, s2c);
    });

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let client_id_arc = Arc::new(client_id);
    let client_policy_arc = Arc::new(client_policy);
    let mut client_stream = {
        let tcp = TcpStream::connect(format!("127.0.0.1:{mitm_port}"))
            .await
            .unwrap();
        connect(tcp, &client_id_arc, &client_policy_arc)
            .await
            .expect("handshake succeeds (MitM does not tamper handshake bytes)")
    };
    let mut server_stream = server_task.await.unwrap().expect("server handshake ok");

    for i in 0..4u32 {
        let payload = vec![i as u8; 256];
        client_stream.send_record(&payload).await.unwrap();
    }

    let err = server_stream.recv_record().await.unwrap_err();
    assert!(
        matches!(err, qtransport_cspq::Error::Crypto(_)),
        "tampered first record must produce Crypto error, got {err:?}"
    );

    mitm_handle.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replayed_record_is_rejected() {
    let (client_id, server_id, client_policy, server_policy) = pair();

    let server_port = pick_port().await;
    let mitm_port = pick_port().await;

    let server_id_arc = Arc::new(server_id);
    let server_policy_arc = Arc::new(server_policy);
    let s_id = server_id_arc.clone();
    let s_pol = server_policy_arc.clone();
    let server_task = tokio::spawn(async move {
        let listener = TcpListener::bind(format!("127.0.0.1:{server_port}"))
            .await
            .unwrap();
        let (sock, _) = listener.accept().await.unwrap();
        accept(sock, &s_id, &s_pol).await
    });

    let listener = TcpListener::bind(format!("127.0.0.1:{mitm_port}"))
        .await
        .unwrap();
    let mitm_handle = tokio::spawn(async move {
        let (inbound, _) = listener.accept().await.unwrap();
        let outbound = TcpStream::connect(format!("127.0.0.1:{server_port}"))
            .await
            .unwrap();
        let (mut ir, mut iw) = inbound.into_split();
        let (mut or, mut ow) = outbound.into_split();

        let c2s = tokio::spawn(async move {
            let mut frame_idx = 0;
            let mut captured: Option<Vec<u8>> = None;
            loop {
                let (_, raw) = match read_frame_raw(&mut ir).await {
                    Ok(x) => x,
                    Err(_) => return,
                };
                if ow.write_all(&raw).await.is_err() {
                    return;
                }
                if frame_idx == 2 {
                    captured = Some(raw.clone());
                } else if frame_idx == 3 {
                    if let Some(replay) = captured.as_ref() {
                        if ow.write_all(replay).await.is_err() {
                            return;
                        }
                    }
                }
                frame_idx += 1;
            }
        });

        let s2c = tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            loop {
                let n = match or.read(&mut buf).await {
                    Ok(0) => return,
                    Ok(n) => n,
                    Err(_) => return,
                };
                if iw.write_all(&buf[..n]).await.is_err() {
                    return;
                }
            }
        });

        let _ = tokio::join!(c2s, s2c);
    });

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let client_id_arc = Arc::new(client_id);
    let client_policy_arc = Arc::new(client_policy);
    let mut client_stream = {
        let tcp = TcpStream::connect(format!("127.0.0.1:{mitm_port}"))
            .await
            .unwrap();
        connect(tcp, &client_id_arc, &client_policy_arc)
            .await
            .unwrap()
    };
    let mut server_stream = server_task.await.unwrap().unwrap();

    client_stream
        .send_record(b"first-record-payload")
        .await
        .unwrap();
    client_stream
        .send_record(b"second-record-payload")
        .await
        .unwrap();

    let pt1 = server_stream.recv_record().await.unwrap();
    assert_eq!(&pt1, b"first-record-payload");
    let pt2 = server_stream.recv_record().await.unwrap();
    assert_eq!(&pt2, b"second-record-payload");

    // Third recv = the replayed first record. AEAD verification fails because
    // the server's nonce counter is now 2; the captured ciphertext was sealed
    // with counter 0.
    let err = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        server_stream.recv_record(),
    )
    .await
    .expect("recv timed out — replay should have failed AEAD verification")
    .unwrap_err();
    assert!(
        matches!(err, qtransport_cspq::Error::Crypto(_)),
        "replayed record must produce Crypto error, got {err:?}"
    );

    mitm_handle.abort();
}
