//! Bidirectional proxy pump between a local stream and a CSPQ session
//! (Sprint 4 — graceful-close protocol; generic over the local stream type
//! so TLS-terminated `TlsStream<TcpStream>` and plain `TcpStream` both work).

use crate::audit::AuditHandle;
use crate::metrics::MetricsRegistry;
use qaudit_core::AuditEvent;
use qtransport_cspq::{CspqReader, CspqStream, CspqWriter, MAX_PLAINTEXT};
use std::sync::atomic::Ordering;
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, warn};

/// Which leg of the gateway pair we're running on.
#[derive(Debug, Clone, Copy)]
pub enum Direction {
    /// serve-tcp: the local socket is the client app; CSPQ goes to the peer.
    AppToPeer,
    /// serve-pq: CSPQ comes from the peer gateway; local socket is the backend.
    PeerToBackend,
}

#[derive(Clone, Copy)]
enum Bucket {
    C2s,
    S2c,
}

/// Pump one full session and emit audit events. Returns the byte totals.
///
/// `local` is the application-side stream. It may be a plain [`TcpStream`]
/// (the common case) or a TLS-terminated stream produced by
/// `tokio_rustls::server::TlsStream<TcpStream>` when the tenant configured
/// TLS termination — both implement [`AsyncRead`] + [`AsyncWrite`].
/// Pump one full session and emit audit events. Returns the byte totals.
///
/// `local_peer_addr` is recorded in audit metadata; pass the underlying TCP
/// peer address rather than the TLS wrapper.
#[allow(clippy::too_many_arguments)]
pub async fn run_session<L>(
    local: L,
    cspq: CspqStream<TcpStream>,
    direction: Direction,
    tenant_name: &str,
    local_peer_addr: String,
    audit: &AuditHandle,
    metrics: &MetricsRegistry,
    handshake_elapsed: std::time::Duration,
) -> (u64, u64)
where
    L: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let m = metrics.inner();
    m.sessions_opened.fetch_add(1, Ordering::Relaxed);
    m.sessions_active.fetch_add(1, Ordering::Relaxed);
    m.observe_handshake(handshake_elapsed);

    let peer_id_hex = hex::encode(&cspq.peer_id().as_bytes()[..16]);

    audit.emit(
        AuditEvent::builder()
            .actor("svc:qgateway")
            .action("session.open")
            .resource(format!("cspq://{peer_id_hex}"))
            .meta("tenant", tenant_name)
            .meta("direction", format!("{direction:?}"))
            .meta("tcp_peer", &local_peer_addr)
            .meta("handshake_us", handshake_elapsed.as_micros().to_string())
            .build(),
    );

    let started = Instant::now();
    let (cspq_reader, cspq_writer) = cspq.split();
    let (local_reader, local_writer) = tokio::io::split(local);

    let (a2b_bucket, b2a_bucket) = match direction {
        Direction::AppToPeer => (Bucket::C2s, Bucket::S2c),
        Direction::PeerToBackend => (Bucket::S2c, Bucket::C2s),
    };

    let mut local_to_cspq = tokio::spawn(pump_local_to_cspq(
        local_reader,
        cspq_writer,
        metrics.clone(),
        a2b_bucket,
    ));
    let mut cspq_to_local = tokio::spawn(pump_cspq_to_local(
        cspq_reader,
        local_writer,
        metrics.clone(),
        b2a_bucket,
    ));

    let (mut bytes_up, mut bytes_down) = (0u64, 0u64);
    let mut shutdown_reason: Option<String> = None;
    let mut up_done = false;
    let mut down_done = false;

    while !(up_done && down_done) {
        tokio::select! {
            r = &mut local_to_cspq, if !up_done => {
                match r {
                    Ok(Ok(n)) => { bytes_up = n; }
                    Ok(Err(e)) => { shutdown_reason.get_or_insert(format!("local→cspq: {e}")); }
                    Err(e) if e.is_panic() => { shutdown_reason.get_or_insert(format!("local→cspq panic: {e}")); }
                    Err(_) => { shutdown_reason.get_or_insert("local→cspq cancelled".into()); }
                }
                up_done = true;
                if shutdown_reason.is_some() && !down_done {
                    cspq_to_local.abort();
                }
            }
            r = &mut cspq_to_local, if !down_done => {
                match r {
                    Ok(Ok(n)) => { bytes_down = n; }
                    Ok(Err(e)) => { shutdown_reason.get_or_insert(format!("cspq→local: {e}")); }
                    Err(e) if e.is_panic() => { shutdown_reason.get_or_insert(format!("cspq→local panic: {e}")); }
                    Err(_) => { shutdown_reason.get_or_insert("cspq→local cancelled".into()); }
                }
                down_done = true;
                if shutdown_reason.is_some() && !up_done {
                    local_to_cspq.abort();
                }
            }
        }
    }

    m.sessions_active.fetch_sub(1, Ordering::Relaxed);
    m.sessions_closed.fetch_add(1, Ordering::Relaxed);

    let duration = started.elapsed();
    audit.emit(
        AuditEvent::builder()
            .actor("svc:qgateway")
            .action("session.close")
            .resource(format!("cspq://{peer_id_hex}"))
            .meta("tenant", tenant_name)
            .meta("direction", format!("{direction:?}"))
            .meta("bytes_up", bytes_up.to_string())
            .meta("bytes_down", bytes_down.to_string())
            .meta("duration_ms", duration.as_millis().to_string())
            .meta(
                "shutdown_reason",
                shutdown_reason.unwrap_or_else(|| "clean".into()),
            )
            .build(),
    );

    (bytes_up, bytes_down)
}

fn bump(metrics: &MetricsRegistry, bucket: Bucket, n: u64) {
    match bucket {
        Bucket::C2s => {
            metrics.inner().bytes_c2s.fetch_add(n, Ordering::Relaxed);
        }
        Bucket::S2c => {
            metrics.inner().bytes_s2c.fetch_add(n, Ordering::Relaxed);
        }
    }
}

async fn pump_local_to_cspq<R>(
    mut local_r: R,
    mut cspq_w: CspqWriter<tokio::io::WriteHalf<TcpStream>>,
    metrics: MetricsRegistry,
    bucket: Bucket,
) -> Result<u64, std::io::Error>
where
    R: AsyncRead + Unpin + Send + 'static,
{
    let mut buf = vec![0u8; MAX_PLAINTEXT];
    let mut total = 0u64;
    loop {
        let n = local_r.read(&mut buf).await?;
        if n == 0 {
            debug!("local→cspq EOF after {total} bytes; sending CSPQ EOF marker");
            if let Err(e) = cspq_w.send_eof().await {
                warn!("send_eof failed: {e}");
                return Err(std::io::Error::other(e));
            }
            return Ok(total);
        }
        if let Err(e) = cspq_w.send_record(&buf[..n]).await {
            warn!("send_record failed: {e}");
            return Err(std::io::Error::other(e));
        }
        total = total.saturating_add(n as u64);
        bump(&metrics, bucket, n as u64);
    }
}

async fn pump_cspq_to_local<W>(
    mut cspq_r: CspqReader<tokio::io::ReadHalf<TcpStream>>,
    mut local_w: W,
    metrics: MetricsRegistry,
    bucket: Bucket,
) -> Result<u64, std::io::Error>
where
    W: AsyncWrite + Unpin + Send + 'static,
{
    let mut total = 0u64;
    loop {
        let pt = match cspq_r.recv_record().await {
            Ok(pt) => pt,
            Err(qtransport_cspq::Error::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                debug!("cspq→local peer hard-EOF after {total} bytes");
                let _ = local_w.shutdown().await;
                return Ok(total);
            }
            Err(e) => {
                warn!("recv_record failed: {e}");
                return Err(std::io::Error::other(e));
            }
        };
        if pt.is_empty() {
            debug!("cspq→local received EOF marker after {total} bytes");
            let _ = local_w.shutdown().await;
            return Ok(total);
        }
        local_w.write_all(&pt).await?;
        total = total.saturating_add(pt.len() as u64);
        bump(&metrics, bucket, pt.len() as u64);
    }
}
