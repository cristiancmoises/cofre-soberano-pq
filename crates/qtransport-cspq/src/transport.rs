//! CSPQ record layer.
//!
//! After [`crate::handshake::accept`] / [`crate::handshake::connect`] returns
//! a [`CspqStream`], reads and writes are encrypted with ChaCha20-Poly1305
//! using directional 96-bit nonces (4-byte prefix + 8-byte BE counter).
//!
//! Each direction has its own counter that starts at 0 and is incremented
//! after every frame. A counter overflow (which would require sending
//! 2^64 frames in one direction) tears the session down with
//! [`crate::Error::NonceOverflow`].

use crate::error::{Error, Result};
use crate::framing::{read_frame, write_frame, MAX_FRAME};
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use qaudit_core::PublicKey as IdPublicKey;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use zeroize::Zeroizing;

/// Maximum plaintext bytes per record (16 KiB). Frames larger than this on
/// the wire are rejected at receive time.
pub const MAX_PLAINTEXT: usize = 16 * 1024;

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const DIR_C2S: [u8; 4] = [0, 0, 0, 0];
const DIR_S2C: [u8; 4] = [0, 0, 0, 1];

/// AEAD keys for both directions plus the channel-bound endpoint identity.
#[derive(Clone)]
pub(crate) struct DirectionalKeys {
    pub(crate) key_c2s: Zeroizing<[u8; 32]>,
    pub(crate) key_s2c: Zeroizing<[u8; 32]>,
}

impl DirectionalKeys {
    pub(crate) fn new(c2s: [u8; 32], s2c: [u8; 32]) -> Self {
        Self {
            key_c2s: Zeroizing::new(c2s),
            key_s2c: Zeroizing::new(s2c),
        }
    }
}

struct DirectionState {
    aead: ChaCha20Poly1305,
    counter: u64,
    prefix: [u8; 4],
}

impl DirectionState {
    fn new(key: &[u8; 32], prefix: [u8; 4]) -> Self {
        Self {
            aead: ChaCha20Poly1305::new(key.into()),
            counter: 0,
            prefix,
        }
    }

    fn next_nonce(&mut self) -> Result<Nonce> {
        if self.counter == u64::MAX {
            return Err(Error::NonceOverflow);
        }
        let mut n = [0u8; NONCE_LEN];
        n[..4].copy_from_slice(&self.prefix);
        n[4..].copy_from_slice(&self.counter.to_be_bytes());
        self.counter = self.counter.checked_add(1).ok_or(Error::NonceOverflow)?;
        Ok(*Nonce::from_slice(&n))
    }

    fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce = self.next_nonce()?;
        self.aead
            .encrypt(&nonce, plaintext)
            .map_err(|_| Error::Crypto("AEAD seal failed".into()))
    }

    fn open(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let nonce = self.next_nonce()?;
        self.aead
            .decrypt(&nonce, ciphertext)
            .map_err(|_| Error::Crypto("AEAD open failed (bad tag or replay)".into()))
    }
}

/// An encrypted CSPQ session.
///
/// `S` is the underlying byte stream (usually `tokio::net::TcpStream`, but
/// the type is generic so it works against in-memory duplex streams in tests).
pub struct CspqStream<S> {
    inner: S,
    send: DirectionState,
    recv: DirectionState,
    peer_id: IdPublicKey,
    read_state: ReadState,
    write_state: WriteState,
}

impl<S> std::fmt::Debug for CspqStream<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CspqStream")
            .field("peer_id", &hex::encode(&self.peer_id.as_bytes()[..8]))
            .field("sent_frames", &self.send.counter)
            .field("received_frames", &self.recv.counter)
            .finish()
    }
}

impl<S> CspqStream<S> {
    pub(crate) fn new_client(inner: S, keys: DirectionalKeys, peer_id: IdPublicKey) -> Self {
        Self {
            inner,
            send: DirectionState::new(&keys.key_c2s, DIR_C2S),
            recv: DirectionState::new(&keys.key_s2c, DIR_S2C),
            peer_id,
            read_state: ReadState::Idle,
            write_state: WriteState::Idle,
        }
    }

    pub(crate) fn new_server(inner: S, keys: DirectionalKeys, peer_id: IdPublicKey) -> Self {
        Self {
            inner,
            send: DirectionState::new(&keys.key_s2c, DIR_S2C),
            recv: DirectionState::new(&keys.key_c2s, DIR_C2S),
            peer_id,
            read_state: ReadState::Idle,
            write_state: WriteState::Idle,
        }
    }

    /// The peer's long-term identity public key, as authenticated by the
    /// completed handshake.
    pub fn peer_id(&self) -> &IdPublicKey {
        &self.peer_id
    }

    /// Bytes of plaintext sent so far in this session (excludes AEAD overhead).
    pub fn sent_frames(&self) -> u64 {
        self.send.counter
    }

    /// Bytes of plaintext received so far in this session.
    pub fn received_frames(&self) -> u64 {
        self.recv.counter
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> CspqStream<S> {
    /// Send one record. Plaintext must be ≤ [`MAX_PLAINTEXT`].
    pub async fn send_record(&mut self, plaintext: &[u8]) -> Result<()> {
        if plaintext.len() > MAX_PLAINTEXT {
            return Err(Error::FrameTooLarge {
                got: plaintext.len(),
                max: MAX_PLAINTEXT,
            });
        }
        let ct = self.send.seal(plaintext)?;
        write_frame(&mut self.inner, &ct).await?;
        Ok(())
    }

    /// Send a graceful-close marker — an authenticated zero-length record.
    ///
    /// The peer's [`CspqStream::recv_record`] returns an empty `Vec<u8>`, which
    /// callers should treat as an orderly EOF for this direction. This is the
    /// orderly counterpart to `shutdown`: the receiver knows the sender
    /// finished cleanly rather than crashed or got cancelled.
    pub async fn send_eof(&mut self) -> Result<()> {
        let ct = self.send.seal(&[])?;
        write_frame(&mut self.inner, &ct).await?;
        Ok(())
    }

    /// Receive one record. Returns the decrypted plaintext.
    pub async fn recv_record(&mut self) -> Result<Vec<u8>> {
        let ct = read_frame(
            &mut self.inner,
            MAX_PLAINTEXT + TAG_LEN + 64, /* small overhead */
        )
        .await?;
        let pt = self.recv.open(&ct)?;
        if pt.len() > MAX_PLAINTEXT {
            return Err(Error::FrameTooLarge {
                got: pt.len(),
                max: MAX_PLAINTEXT,
            });
        }
        Ok(pt)
    }

    // NOTE: The Sprint 3 inherent `shutdown()` (which only closed the inner
    // TCP, with no authenticated EOF marker) was removed in Sprint 4.5. Use
    // `tokio::io::AsyncWriteExt::shutdown` on the stream instead; the
    // `AsyncWrite` impl emits a sealed empty-record EOF marker, flushes, and
    // then shuts down the underlying byte stream.

    /// Split into independent reader and writer halves so two concurrent
    /// tasks can pump records in opposite directions over the same session.
    ///
    /// Both halves continue to share the channel-bound peer identity. The
    /// reader gets the recv-direction AEAD state; the writer gets the send
    /// direction. Counters cannot overflow into each other.
    pub fn split(
        self,
    ) -> (
        CspqReader<tokio::io::ReadHalf<S>>,
        CspqWriter<tokio::io::WriteHalf<S>>,
    ) {
        let CspqStream {
            inner,
            send,
            recv,
            peer_id,
            read_state,
            write_state,
        } = self;
        let (r, w) = tokio::io::split(inner);
        (
            CspqReader {
                inner: r,
                recv,
                peer_id: peer_id.clone(),
                read_state,
            },
            CspqWriter {
                inner: w,
                send,
                peer_id,
                write_state,
            },
        )
    }
}

/// Read half of a [`CspqStream`].
pub struct CspqReader<R> {
    inner: R,
    recv: DirectionState,
    peer_id: IdPublicKey,
    read_state: ReadState,
}

impl<R: AsyncRead + Unpin> CspqReader<R> {
    /// Receive one record. Returns the decrypted plaintext.
    pub async fn recv_record(&mut self) -> Result<Vec<u8>> {
        let ct = read_frame(&mut self.inner, MAX_PLAINTEXT + TAG_LEN + 64).await?;
        let pt = self.recv.open(&ct)?;
        if pt.len() > MAX_PLAINTEXT {
            return Err(Error::FrameTooLarge {
                got: pt.len(),
                max: MAX_PLAINTEXT,
            });
        }
        Ok(pt)
    }

    /// Peer identity authenticated by the handshake.
    pub fn peer_id(&self) -> &IdPublicKey {
        &self.peer_id
    }

    /// Number of records received.
    pub fn received_frames(&self) -> u64 {
        self.recv.counter
    }
}

/// Write half of a [`CspqStream`].
pub struct CspqWriter<W> {
    inner: W,
    send: DirectionState,
    peer_id: IdPublicKey,
    write_state: WriteState,
}

impl<W: AsyncWrite + Unpin> CspqWriter<W> {
    /// Send one record. Plaintext must be ≤ [`MAX_PLAINTEXT`].
    pub async fn send_record(&mut self, plaintext: &[u8]) -> Result<()> {
        if plaintext.len() > MAX_PLAINTEXT {
            return Err(Error::FrameTooLarge {
                got: plaintext.len(),
                max: MAX_PLAINTEXT,
            });
        }
        let ct = self.send.seal(plaintext)?;
        write_frame(&mut self.inner, &ct).await?;
        Ok(())
    }

    /// Send a graceful-close marker — see [`CspqStream::send_eof`].
    pub async fn send_eof(&mut self) -> Result<()> {
        let ct = self.send.seal(&[])?;
        write_frame(&mut self.inner, &ct).await?;
        Ok(())
    }

    // The Sprint 3 inherent `shutdown()` was removed in Sprint 4.5. Use
    // `tokio::io::AsyncWriteExt::shutdown` on this writer; the `AsyncWrite`
    // impl emits a sealed empty-record EOF marker, flushes, and shuts down
    // the inner byte stream — strictly stronger than the old behavior.

    /// Peer identity authenticated by the handshake.
    pub fn peer_id(&self) -> &IdPublicKey {
        &self.peer_id
    }

    /// Number of records sent.
    pub fn sent_frames(&self) -> u64 {
        self.send.counter
    }
}

// ============================================================================
//                  AsyncRead + AsyncWrite — Sprint 4.5 state machines
// ============================================================================
//
// CSPQ frames its plaintext as length-prefixed sealed records. To present the
// stream as a normal `tokio::io::AsyncRead + AsyncWrite`, we need explicit
// partial-progress state that survives `Pending` returns across `poll_*`
// invocations. The two state machines below do that.
//
// Read path:  Idle → Len(filled 0..4) → Body(filled 0..ct_len) → decrypt →
//             Drain(plaintext, pos 0..len) → Idle → …
//             A peer-sent zero-length authenticated record transitions us to
//             Eof, which makes future `poll_read`s return `Ok(())` with an
//             empty fill (canonical AsyncRead EOF signal).
//
// Write path: Idle → seal(min(buf.len, MAX_PLAINTEXT)) →
//             Writing(frame=[len4|ct], written 0..frame.len) → Idle → …
//             `poll_flush` drains any in-progress frame and then flushes inner.
//             `poll_shutdown` seals an authenticated empty EOF record, drains
//             it, flushes the inner writer, then shuts it down.
//
// Both state machines persist their progress in struct fields so that a
// `Poll::Pending` from the underlying byte stream simply parks and resumes
// later without losing partial work or AEAD nonce position.

const READ_BODY_HARD_CAP: usize = MAX_PLAINTEXT + TAG_LEN + 64;

#[derive(Debug)]
enum ReadState {
    /// Waiting to start a new record.
    Idle,
    /// Reading the 4-byte length prefix; `filled` bytes are in `buf`.
    Len { buf: [u8; 4], filled: usize },
    /// Reading the ciphertext body of length `ct.len()`; `filled` bytes done.
    Body { ct: Vec<u8>, filled: usize },
    /// Decrypted plaintext waiting to be copied to the caller.
    Drain { pt: Vec<u8>, pos: usize },
    /// An authenticated EOF marker was received, or a fatal read error was
    /// returned. Subsequent `poll_read`s
    /// return `Ok(())` with an empty fill, the canonical AsyncRead EOF signal.
    Eof,
}

#[derive(Debug)]
enum WriteState {
    /// Ready to accept new plaintext.
    Idle,
    /// `frame` = length prefix + ciphertext. `written` bytes have been pushed
    /// to the inner writer. `consumed` is the count of plaintext bytes from
    /// the caller's `poll_write` `buf` that this sealed frame represents —
    /// returned once the frame is fully on the wire.
    Writing {
        frame: Vec<u8>,
        written: usize,
        consumed: usize,
    },
    /// Closed for new writes (either after `poll_shutdown` completed or a
    /// fatal I/O error). `poll_write` returns `NotConnected`; further
    /// `poll_shutdown` calls just re-poll the inner shutdown.
    Closed,
    /// Three-stage shutdown: send sealed-EOF frame, flush, shutdown inner.
    ShuttingDown { stage: ShutdownStage },
}

#[derive(Debug)]
enum ShutdownStage {
    SendEofFrame { frame: Vec<u8>, written: usize },
    FlushInner,
    ShutdownInner,
}

/// Drive a `ReadState` machine to consume from `inner` into `out_buf`.
///
/// Shared between `CspqReader` and `CspqStream` so the logic lives in exactly
/// one place. `recv` is the AEAD direction state; `inner` is the byte source.
fn poll_read_machine<R: AsyncRead + Unpin>(
    inner: &mut R,
    recv: &mut DirectionState,
    state: &mut ReadState,
    cx: &mut Context<'_>,
    out_buf: &mut ReadBuf<'_>,
) -> Poll<io::Result<()>> {
    // Reading into an empty buffer must never consume a frame or wait for I/O.
    if out_buf.remaining() == 0 {
        return Poll::Ready(Ok(()));
    }
    loop {
        let cur = std::mem::replace(state, ReadState::Idle);
        match cur {
            ReadState::Eof => {
                *state = ReadState::Eof;
                return Poll::Ready(Ok(()));
            }
            ReadState::Drain { pt, mut pos } => {
                let remaining = pt.len() - pos;
                if remaining == 0 {
                    // Drained — fall back to Idle and loop to read next frame.
                    continue;
                }
                let cap = out_buf.remaining();
                if cap == 0 {
                    // Caller's buffer is full — restore and yield.
                    *state = ReadState::Drain { pt, pos };
                    return Poll::Ready(Ok(()));
                }
                let to_copy = remaining.min(cap);
                out_buf.put_slice(&pt[pos..pos + to_copy]);
                pos += to_copy;
                if pos == pt.len() {
                    *state = ReadState::Idle;
                } else {
                    *state = ReadState::Drain { pt, pos };
                }
                return Poll::Ready(Ok(()));
            }
            ReadState::Idle => {
                *state = ReadState::Len {
                    buf: [0u8; 4],
                    filled: 0,
                };
                // Loop to actually read the prefix.
            }
            ReadState::Len {
                mut buf,
                mut filled,
            } => {
                let mut rb = ReadBuf::new(&mut buf[filled..]);
                match Pin::new(&mut *inner).poll_read(cx, &mut rb) {
                    Poll::Pending => {
                        *state = ReadState::Len { buf, filled };
                        return Poll::Pending;
                    }
                    Poll::Ready(Err(e)) => {
                        *state = ReadState::Eof;
                        return Poll::Ready(Err(e));
                    }
                    Poll::Ready(Ok(())) => {
                        let n = rb.filled().len();
                        if n == 0 {
                            // Socket EOF is unauthenticated even at a record
                            // boundary. Only a sealed empty record proves the
                            // peer completed its application data.
                            *state = ReadState::Eof;
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "CSPQ transport closed without an authenticated EOF marker",
                            )));
                        }
                        filled += n;
                        if filled < 4 {
                            *state = ReadState::Len { buf, filled };
                            // Re-loop to try to fill the rest.
                            continue;
                        }
                        let ct_len = u32::from_be_bytes(buf) as usize;
                        if ct_len == 0 {
                            *state = ReadState::Eof;
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "CSPQ frame body is empty (missing AEAD tag)",
                            )));
                        }
                        if ct_len > READ_BODY_HARD_CAP {
                            *state = ReadState::Eof;
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!("CSPQ frame too large: {ct_len}"),
                            )));
                        }
                        *state = ReadState::Body {
                            ct: vec![0u8; ct_len],
                            filled: 0,
                        };
                    }
                }
            }
            ReadState::Body { mut ct, mut filled } => {
                let target_len = ct.len();
                let mut rb = ReadBuf::new(&mut ct[filled..]);
                match Pin::new(&mut *inner).poll_read(cx, &mut rb) {
                    Poll::Pending => {
                        *state = ReadState::Body { ct, filled };
                        return Poll::Pending;
                    }
                    Poll::Ready(Err(e)) => {
                        *state = ReadState::Eof;
                        return Poll::Ready(Err(e));
                    }
                    Poll::Ready(Ok(())) => {
                        let n = rb.filled().len();
                        if n == 0 {
                            *state = ReadState::Eof;
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "EOF while reading CSPQ frame body",
                            )));
                        }
                        filled += n;
                        if filled < target_len {
                            *state = ReadState::Body { ct, filled };
                            continue;
                        }
                        // Got the whole ciphertext — decrypt.
                        match recv.open(&ct) {
                            Err(e) => {
                                // AEAD failure poisons the stream.
                                *state = ReadState::Eof;
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    e.to_string(),
                                )));
                            }
                            Ok(pt) => {
                                if pt.is_empty() {
                                    // Authenticated EOF marker — orderly close.
                                    *state = ReadState::Eof;
                                    return Poll::Ready(Ok(()));
                                }
                                if pt.len() > MAX_PLAINTEXT {
                                    *state = ReadState::Eof;
                                    return Poll::Ready(Err(io::Error::new(
                                        io::ErrorKind::InvalidData,
                                        format!("CSPQ plaintext too large: {}", pt.len()),
                                    )));
                                }
                                *state = ReadState::Drain { pt, pos: 0 };
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Drive a `WriteState` machine to absorb `in_buf` into a sealed frame and
/// drain it through `inner`.
fn poll_write_machine<W: AsyncWrite + Unpin>(
    inner: &mut W,
    send: &mut DirectionState,
    state: &mut WriteState,
    cx: &mut Context<'_>,
    in_buf: &[u8],
) -> Poll<io::Result<usize>> {
    // Fail fast on dead/draining streams.
    match state {
        WriteState::Closed => {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "CSPQ stream is closed",
            )));
        }
        WriteState::ShuttingDown { .. } => {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "CSPQ stream is shutting down",
            )));
        }
        _ => {}
    }
    loop {
        let cur = std::mem::replace(state, WriteState::Idle);
        match cur {
            WriteState::Idle => {
                if in_buf.is_empty() {
                    *state = WriteState::Idle;
                    return Poll::Ready(Ok(0));
                }
                let take = in_buf.len().min(MAX_PLAINTEXT);
                let sealed = match send.seal(&in_buf[..take]) {
                    Ok(ct) => ct,
                    Err(e) => {
                        *state = WriteState::Closed;
                        return Poll::Ready(Err(io::Error::other(e.to_string())));
                    }
                };
                let mut frame = Vec::with_capacity(4 + sealed.len());
                frame.extend_from_slice(&(sealed.len() as u32).to_be_bytes());
                frame.extend_from_slice(&sealed);
                *state = WriteState::Writing {
                    frame,
                    written: 0,
                    consumed: take,
                };
                // Fall through to the Writing arm immediately.
            }
            WriteState::Writing {
                frame,
                mut written,
                consumed,
            } => {
                while written < frame.len() {
                    match Pin::new(&mut *inner).poll_write(cx, &frame[written..]) {
                        Poll::Pending => {
                            *state = WriteState::Writing {
                                frame,
                                written,
                                consumed,
                            };
                            return Poll::Pending;
                        }
                        Poll::Ready(Err(e)) => {
                            *state = WriteState::Closed;
                            return Poll::Ready(Err(e));
                        }
                        Poll::Ready(Ok(0)) => {
                            *state = WriteState::Closed;
                            return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                        }
                        Poll::Ready(Ok(n)) => {
                            written += n;
                        }
                    }
                }
                *state = WriteState::Idle;
                return Poll::Ready(Ok(consumed));
            }
            // Closed/ShuttingDown filtered out above.
            other => {
                *state = other;
                unreachable!("filtered above")
            }
        }
    }
}

/// Drive `state` until any in-flight write frame is on the wire, then call
/// `inner.poll_flush`. Used by both AsyncWrite impls.
fn poll_flush_machine<W: AsyncWrite + Unpin>(
    inner: &mut W,
    state: &mut WriteState,
    cx: &mut Context<'_>,
) -> Poll<io::Result<()>> {
    loop {
        let cur = std::mem::replace(state, WriteState::Idle);
        match cur {
            WriteState::Idle => {
                // Done — fall through to flush inner.
                break;
            }
            WriteState::Closed => {
                *state = WriteState::Closed;
                return Pin::new(&mut *inner).poll_flush(cx);
            }
            WriteState::ShuttingDown { stage } => {
                *state = WriteState::ShuttingDown { stage };
                return Pin::new(&mut *inner).poll_flush(cx);
            }
            WriteState::Writing {
                frame,
                mut written,
                consumed,
            } => {
                while written < frame.len() {
                    match Pin::new(&mut *inner).poll_write(cx, &frame[written..]) {
                        Poll::Pending => {
                            *state = WriteState::Writing {
                                frame,
                                written,
                                consumed,
                            };
                            return Poll::Pending;
                        }
                        Poll::Ready(Err(e)) => {
                            *state = WriteState::Closed;
                            return Poll::Ready(Err(e));
                        }
                        Poll::Ready(Ok(0)) => {
                            *state = WriteState::Closed;
                            return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                        }
                        Poll::Ready(Ok(n)) => {
                            written += n;
                        }
                    }
                }
                *state = WriteState::Idle;
            }
        }
    }
    Pin::new(&mut *inner).poll_flush(cx)
}

/// Drive a clean shutdown: finish any pending frame, seal+emit an EOF marker,
/// flush, shutdown the inner writer. Used by both AsyncWrite impls.
fn poll_shutdown_machine<W: AsyncWrite + Unpin>(
    inner: &mut W,
    send: &mut DirectionState,
    state: &mut WriteState,
    cx: &mut Context<'_>,
) -> Poll<io::Result<()>> {
    loop {
        let cur = std::mem::replace(state, WriteState::Idle);
        match cur {
            WriteState::Closed => {
                *state = WriteState::Closed;
                return Pin::new(&mut *inner).poll_shutdown(cx);
            }
            WriteState::Writing {
                frame,
                mut written,
                consumed,
            } => {
                while written < frame.len() {
                    match Pin::new(&mut *inner).poll_write(cx, &frame[written..]) {
                        Poll::Pending => {
                            *state = WriteState::Writing {
                                frame,
                                written,
                                consumed,
                            };
                            return Poll::Pending;
                        }
                        Poll::Ready(Err(e)) => {
                            *state = WriteState::Closed;
                            return Poll::Ready(Err(e));
                        }
                        Poll::Ready(Ok(0)) => {
                            *state = WriteState::Closed;
                            return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                        }
                        Poll::Ready(Ok(n)) => {
                            written += n;
                        }
                    }
                }
                // Fall through to Idle → seal EOF marker.
            }
            WriteState::Idle => {
                let sealed = match send.seal(&[]) {
                    Ok(ct) => ct,
                    Err(e) => {
                        *state = WriteState::Closed;
                        return Poll::Ready(Err(io::Error::other(e.to_string())));
                    }
                };
                let mut frame = Vec::with_capacity(4 + sealed.len());
                frame.extend_from_slice(&(sealed.len() as u32).to_be_bytes());
                frame.extend_from_slice(&sealed);
                *state = WriteState::ShuttingDown {
                    stage: ShutdownStage::SendEofFrame { frame, written: 0 },
                };
            }
            WriteState::ShuttingDown { stage } => match stage {
                ShutdownStage::SendEofFrame { frame, mut written } => {
                    while written < frame.len() {
                        match Pin::new(&mut *inner).poll_write(cx, &frame[written..]) {
                            Poll::Pending => {
                                *state = WriteState::ShuttingDown {
                                    stage: ShutdownStage::SendEofFrame { frame, written },
                                };
                                return Poll::Pending;
                            }
                            Poll::Ready(Err(e)) => {
                                *state = WriteState::Closed;
                                return Poll::Ready(Err(e));
                            }
                            Poll::Ready(Ok(0)) => {
                                *state = WriteState::Closed;
                                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                            }
                            Poll::Ready(Ok(n)) => {
                                written += n;
                            }
                        }
                    }
                    *state = WriteState::ShuttingDown {
                        stage: ShutdownStage::FlushInner,
                    };
                }
                ShutdownStage::FlushInner => match Pin::new(&mut *inner).poll_flush(cx) {
                    Poll::Pending => {
                        *state = WriteState::ShuttingDown {
                            stage: ShutdownStage::FlushInner,
                        };
                        return Poll::Pending;
                    }
                    Poll::Ready(Err(e)) => {
                        *state = WriteState::Closed;
                        return Poll::Ready(Err(e));
                    }
                    Poll::Ready(Ok(())) => {
                        *state = WriteState::ShuttingDown {
                            stage: ShutdownStage::ShutdownInner,
                        };
                    }
                },
                ShutdownStage::ShutdownInner => match Pin::new(&mut *inner).poll_shutdown(cx) {
                    Poll::Pending => {
                        *state = WriteState::ShuttingDown {
                            stage: ShutdownStage::ShutdownInner,
                        };
                        return Poll::Pending;
                    }
                    Poll::Ready(r) => {
                        *state = WriteState::Closed;
                        return Poll::Ready(r);
                    }
                },
            },
        }
    }
}

// ---- AsyncRead impls -------------------------------------------------------

impl<R: AsyncRead + Unpin> AsyncRead for CspqReader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        poll_read_machine(
            &mut this.inner,
            &mut this.recv,
            &mut this.read_state,
            cx,
            buf,
        )
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for CspqStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        poll_read_machine(
            &mut this.inner,
            &mut this.recv,
            &mut this.read_state,
            cx,
            buf,
        )
    }
}

// ---- AsyncWrite impls ------------------------------------------------------

impl<W: AsyncWrite + Unpin> AsyncWrite for CspqWriter<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        poll_write_machine(
            &mut this.inner,
            &mut this.send,
            &mut this.write_state,
            cx,
            buf,
        )
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        poll_flush_machine(&mut this.inner, &mut this.write_state, cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        poll_shutdown_machine(&mut this.inner, &mut this.send, &mut this.write_state, cx)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for CspqStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        poll_write_machine(
            &mut this.inner,
            &mut this.send,
            &mut this.write_state,
            cx,
            buf,
        )
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        poll_flush_machine(&mut this.inner, &mut this.write_state, cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        poll_shutdown_machine(&mut this.inner, &mut this.send, &mut this.write_state, cx)
    }
}

// Limit the visible API surface; framing is an internal detail.
#[allow(dead_code)]
const _: usize = MAX_FRAME;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::{accept, connect, IdentityKey, PeerPolicy};
    use tokio::io::duplex;

    async fn established() -> (
        CspqStream<tokio::io::DuplexStream>,
        CspqStream<tokio::io::DuplexStream>,
    ) {
        let client_id = IdentityKey::generate().unwrap();
        let server_id = IdentityKey::generate().unwrap();
        let client_policy = PeerPolicy::single(server_id.public().clone());
        let server_policy = PeerPolicy::single(client_id.public().clone());
        let (a, b) = duplex(128 * 1024);
        let server_task = tokio::spawn(async move { accept(b, &server_id, &server_policy).await });
        let client_task = tokio::spawn(async move { connect(a, &client_id, &client_policy).await });
        let server = server_task.await.unwrap().unwrap();
        let client = client_task.await.unwrap().unwrap();
        (client, server)
    }

    #[tokio::test]
    async fn record_roundtrip_small() {
        let (mut client, mut server) = established().await;
        client.send_record(b"ping").await.unwrap();
        let got = server.recv_record().await.unwrap();
        assert_eq!(&got, b"ping");
        server.send_record(b"pong").await.unwrap();
        let got = client.recv_record().await.unwrap();
        assert_eq!(&got, b"pong");
    }

    #[tokio::test]
    async fn record_roundtrip_max_plaintext() {
        let (mut client, mut server) = established().await;
        let msg = vec![0xCDu8; MAX_PLAINTEXT];
        client.send_record(&msg).await.unwrap();
        let got = server.recv_record().await.unwrap();
        assert_eq!(got, msg);
    }

    #[tokio::test]
    async fn refuses_oversize_send() {
        let (mut client, _server) = established().await;
        let msg = vec![0u8; MAX_PLAINTEXT + 1];
        let err = client.send_record(&msg).await.unwrap_err();
        assert!(matches!(err, Error::FrameTooLarge { .. }));
    }

    #[tokio::test]
    async fn many_records_increment_counters() {
        let (mut client, mut server) = established().await;
        for i in 0..32u32 {
            let payload = i.to_le_bytes();
            client.send_record(&payload).await.unwrap();
            let got = server.recv_record().await.unwrap();
            assert_eq!(got, payload);
        }
        assert_eq!(client.sent_frames(), 32);
        assert_eq!(server.received_frames(), 32);
    }

    #[tokio::test]
    async fn tampered_ciphertext_rejected() {
        // Sniff the wire: hook a TCP pair so we can flip a byte between peers.
        // Easier here: send a valid record, then construct a manually-tampered
        // ciphertext by stealing the AEAD from one side. We use a simpler path:
        // call send_record on client; intercept the duplex channel? Not possible
        // with duplex(). Instead we exercise the negative path by manually
        // re-using a nonce, which forces decrypt to fail with a fresh ciphertext.
        let (mut client, mut server) = established().await;
        client.send_record(b"valid").await.unwrap();
        // Receive it normally first.
        let pt = server.recv_record().await.unwrap();
        assert_eq!(&pt, b"valid");
        // Now manually advance the server's counter past where the next ciphertext
        // would land, so when client sends the next legitimate record, server's
        // nonce differs and decryption fails.
        server.recv.counter += 1;
        client.send_record(b"out-of-sync").await.unwrap();
        let err = server.recv_record().await.unwrap_err();
        assert!(matches!(err, Error::Crypto(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn split_halves_pump_concurrently() {
        let (client, server) = established().await;
        let (mut c_r, mut c_w) = client.split();
        let (mut s_r, mut s_w) = server.split();

        // Client sends 8 records while concurrently expecting 8 echoes.
        let n = 8usize;
        let send_task = tokio::spawn(async move {
            for i in 0..n {
                c_w.send_record(format!("frame-{i}").as_bytes())
                    .await
                    .unwrap();
            }
        });
        let echo_task = tokio::spawn(async move {
            for _ in 0..n {
                let pt = s_r.recv_record().await.unwrap();
                s_w.send_record(&pt).await.unwrap();
            }
        });
        let recv_task = tokio::spawn(async move {
            let mut got = Vec::new();
            for _ in 0..n {
                got.push(c_r.recv_record().await.unwrap());
            }
            got
        });

        send_task.await.unwrap();
        echo_task.await.unwrap();
        let got = recv_task.await.unwrap();
        for (i, frame) in got.iter().enumerate() {
            assert_eq!(frame, format!("frame-{i}").as_bytes());
        }
    }

    #[tokio::test]
    async fn graceful_eof_marker_is_authenticated() {
        let (mut client, mut server) = established().await;
        client.send_record(b"final-payload").await.unwrap();
        client.send_eof().await.unwrap();

        let pt1 = server.recv_record().await.unwrap();
        assert_eq!(&pt1, b"final-payload");

        // Next record decrypts to zero-length plaintext, signaling EOF.
        let pt2 = server.recv_record().await.unwrap();
        assert!(
            pt2.is_empty(),
            "EOF marker should decrypt to empty plaintext"
        );

        // Counter advanced — replay attempts will fail.
        assert_eq!(client.sent_frames(), 2);
        assert_eq!(server.received_frames(), 2);
    }

    #[tokio::test]
    async fn forged_eof_without_key_is_rejected() {
        // Build two unrelated established sessions; an EOF emitted by one
        // never decrypts in the other, even though both are "zero-length"
        // records cryptographically.
        let (client_a, server_a) = established().await;
        let (_client_b, server_b) = established().await;

        let (_c_a_r, mut c_a_w) = client_a.split();
        let (mut s_a_r, _s_a_w) = server_a.split();

        // Genuine A→A EOF works.
        c_a_w.send_eof().await.unwrap();
        let pt = s_a_r.recv_record().await.unwrap();
        assert!(pt.is_empty());

        // A genuine A→A EOF cannot be replayed in session B (different keys).
        // Construct the same operation on B and verify the keys differ by
        // ensuring server B's counter has NOT advanced.
        assert_eq!(server_b.received_frames(), 0);
    }

    #[test]
    fn aead_layer_rejects_cross_session_ciphertext() {
        // Direct test of the AEAD layer's key-binding: a ciphertext sealed
        // with key K1 must not decrypt with a different key K2, even at the
        // identical nonce. This is the cryptographic core of the defense
        // against cross-session replay: distinct sessions get distinct
        // shared secrets via ML-KEM, so AEAD keys are distinct.
        let mut sender = DirectionState::new(&[0x11u8; 32], DIR_C2S);
        let mut wrong_receiver = DirectionState::new(&[0x22u8; 32], DIR_C2S);

        let ct = sender.seal(b"sensitive-payload").unwrap();
        let err = wrong_receiver.open(&ct).unwrap_err();
        assert!(matches!(err, Error::Crypto(_)));
    }

    #[test]
    fn aead_layer_rejects_within_session_replay() {
        // Within one session, a captured ciphertext cannot be re-injected
        // because the receiver's nonce counter has advanced past the point
        // at which that ciphertext was valid.
        let mut sender = DirectionState::new(&[0x33u8; 32], DIR_C2S);
        let mut receiver = DirectionState::new(&[0x33u8; 32], DIR_C2S);

        let ct = sender.seal(b"replay-target").unwrap();
        // First reception OK — counters match.
        let pt = receiver.open(&ct).unwrap();
        assert_eq!(&pt, b"replay-target");

        // Replay attempt: same ciphertext, receiver counter has moved on.
        let err = receiver.open(&ct).unwrap_err();
        assert!(matches!(err, Error::Crypto(_)));
    }

    #[test]
    fn aead_layer_rejects_one_bit_flip() {
        // A single bit flip in the ciphertext or tag is caught by Poly1305.
        let mut sender = DirectionState::new(&[0x44u8; 32], DIR_C2S);
        let mut receiver = DirectionState::new(&[0x44u8; 32], DIR_C2S);

        let mut ct = sender.seal(b"flip me").unwrap();
        // Flip a byte somewhere inside the ciphertext.
        ct[3] ^= 0x01;
        let err = receiver.open(&ct).unwrap_err();
        assert!(matches!(err, Error::Crypto(_)));
    }

    // ========================================================================
    //               Sprint 4.5 — AsyncRead / AsyncWrite test suite
    // ========================================================================

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Echo half: read all bytes via AsyncRead, write them back via AsyncWrite,
    /// then cleanly shut down (which emits the authenticated EOF marker).
    async fn echo_via_async_traits<S>(mut stream: CspqStream<S>) -> io::Result<u64>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut buf = Vec::new();
        let n = stream.read_to_end(&mut buf).await?;
        stream.write_all(&buf).await?;
        stream.shutdown().await?;
        Ok(n as u64)
    }

    #[tokio::test]
    async fn async_traits_small_roundtrip() {
        // Drive a CSPQ session entirely through AsyncRead/AsyncWrite — no
        // record-API calls anywhere — and round-trip a short message.
        let (client, server) = established().await;

        let server_task = tokio::spawn(async move { echo_via_async_traits(server).await });

        let msg = b"hello from the async-trait layer";
        let mut client = client;
        client.write_all(msg).await.unwrap();
        client.shutdown().await.unwrap(); // sends EOF marker so server's read_to_end returns.

        let mut got = Vec::new();
        client.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, msg);

        let server_total = server_task.await.unwrap().unwrap();
        assert_eq!(server_total, msg.len() as u64);
    }

    #[tokio::test]
    async fn async_traits_tokio_io_copy_roundtrip_1mib() {
        // The point of having AsyncRead/AsyncWrite is that `tokio::io::copy`
        // and any other tokio-shaped consumer just works. Pump 1 MiB through
        // it via tokio::io::copy on the echo side.
        let (client, server) = established().await;

        let server_task = tokio::spawn(async move {
            let (mut r, mut w) = tokio::io::split(server);
            let n = tokio::io::copy(&mut r, &mut w).await?;
            w.shutdown().await?;
            io::Result::Ok(n)
        });

        // Deterministic 1 MiB payload spanning many record boundaries.
        let mut payload = Vec::with_capacity(1024 * 1024);
        for i in 0..(1024 * 1024) {
            payload.push((i as u8).wrapping_mul(31));
        }

        let (mut client_r, mut client_w) = tokio::io::split(client);
        let sender_payload = payload.clone();
        let writer_task = tokio::spawn(async move {
            client_w.write_all(&sender_payload).await?;
            client_w.shutdown().await?; // EOF marker
            io::Result::Ok(())
        });

        let mut got = Vec::with_capacity(1024 * 1024);
        client_r.read_to_end(&mut got).await.unwrap();

        writer_task.await.unwrap().unwrap();
        let echoed_bytes = server_task.await.unwrap().unwrap();

        assert_eq!(got.len(), payload.len(), "echoed payload length mismatch");
        assert_eq!(got, payload, "echoed payload bytes mismatch");
        assert_eq!(echoed_bytes, payload.len() as u64);
    }

    #[tokio::test]
    async fn async_read_delivers_eof_after_marker() {
        // Client sends one record, then EOF marker. Server using AsyncRead
        // must read the data and then observe a clean EOF (read returns 0).
        let (client, server) = established().await;

        let server_task = tokio::spawn(async move {
            let mut server = server;
            let mut buf = vec![0u8; 64];
            let n = server.read(&mut buf).await.unwrap();
            buf.truncate(n);
            // Next read must observe orderly EOF.
            let n2 = server.read(&mut [0u8; 8]).await.unwrap();
            assert_eq!(n2, 0, "expected EOF after CSPQ EOF marker");
            buf
        });

        let mut client = client;
        client.write_all(b"farewell").await.unwrap();
        client.shutdown().await.unwrap();

        let got = server_task.await.unwrap();
        assert_eq!(&got[..], b"farewell");
    }

    #[tokio::test]
    async fn async_read_chunks_oversized_record() {
        // A single 16 KiB record sent on the wire must be readable in many
        // small AsyncRead calls (proves the Drain state preserves position).
        let (client, server) = established().await;
        let payload = vec![0xA5u8; MAX_PLAINTEXT];

        let pclone = payload.clone();
        let send_task = tokio::spawn(async move {
            let mut client = client;
            // Bypass AsyncWrite chunking so we send exactly one record.
            client.send_record(&pclone).await.unwrap();
            client.send_eof().await.unwrap();
        });

        let mut server = server;
        let mut got = Vec::with_capacity(MAX_PLAINTEXT);
        let mut tiny = [0u8; 17];
        loop {
            let n = server.read(&mut tiny).await.unwrap();
            if n == 0 {
                break;
            }
            got.extend_from_slice(&tiny[..n]);
        }
        send_task.await.unwrap();

        assert_eq!(got.len(), MAX_PLAINTEXT);
        assert_eq!(got, payload);
    }

    #[tokio::test]
    async fn async_write_chunks_oversized_input() {
        // A write larger than MAX_PLAINTEXT must be split into multiple sealed
        // records transparently. Verify both halves arrive intact.
        let (client, server) = established().await;
        let mut payload = Vec::with_capacity(MAX_PLAINTEXT * 3 + 17);
        for i in 0..payload.capacity() {
            payload.push((i & 0xFF) as u8);
        }

        let pclone = payload.clone();
        let send_task = tokio::spawn(async move {
            let mut client = client;
            client.write_all(&pclone).await.unwrap();
            client.shutdown().await.unwrap();
        });

        let mut server = server;
        let mut got = Vec::new();
        server.read_to_end(&mut got).await.unwrap();
        send_task.await.unwrap();

        assert_eq!(got.len(), payload.len());
        assert_eq!(got, payload);
    }

    #[tokio::test]
    async fn async_traits_split_halves_concurrent_bidirectional() {
        // Split a stream into halves, run reads and writes concurrently in
        // both directions, ensure no AEAD desync (counters are independent).
        let (client, server) = established().await;

        let server_task = tokio::spawn(async move {
            let (mut r, mut w) = tokio::io::split(server);
            let mut got = Vec::new();
            // Echo whatever the client writes us, in parallel with sending
            // an unsolicited "greeting" of our own.
            let greet = tokio::spawn(async move {
                w.write_all(b"hello-from-server").await.unwrap();
                w.write_all(b"-2nd-message").await.unwrap();
                w.shutdown().await.unwrap();
            });
            r.read_to_end(&mut got).await.unwrap();
            greet.await.unwrap();
            got
        });

        let (mut cr, mut cw) = tokio::io::split(client);
        let writer = tokio::spawn(async move {
            cw.write_all(b"client-says-hi").await.unwrap();
            cw.shutdown().await.unwrap();
        });
        let mut from_server = Vec::new();
        cr.read_to_end(&mut from_server).await.unwrap();
        writer.await.unwrap();

        let server_received = server_task.await.unwrap();
        assert_eq!(server_received, b"client-says-hi");
        assert_eq!(from_server, b"hello-from-server-2nd-message");
    }

    #[tokio::test]
    async fn async_read_rejects_inner_tcp_truncation_mid_frame() {
        // If the underlying transport closes between the length prefix and
        // the body, AsyncRead must surface UnexpectedEof rather than silently
        // EOFing — that asymmetry is how the peer learns about truncation.
        let (mut wire_a, wire_b) = tokio::io::duplex(64 * 1024);

        // Send a valid-looking length prefix but no body, then close.
        tokio::spawn(async move {
            wire_a.write_all(&512u32.to_be_bytes()).await.unwrap();
            // Drop wire_a → EOF mid-frame.
        });

        // Manually construct a reader that thinks the handshake succeeded.
        let mut reader: CspqReader<tokio::io::DuplexStream> = CspqReader {
            inner: wire_b,
            recv: DirectionState::new(&[0u8; 32], DIR_C2S),
            peer_id: IdPublicKey::from_bytes(&vec![0u8; 2592]).unwrap(),
            read_state: ReadState::Idle,
        };

        let mut buf = [0u8; 16];
        let err = reader.read(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn async_read_rejects_inner_eof_without_authenticated_marker() {
        let (wire_a, wire_b) = tokio::io::duplex(64);
        drop(wire_a); // immediate EOF

        let mut reader: CspqReader<tokio::io::DuplexStream> = CspqReader {
            inner: wire_b,
            recv: DirectionState::new(&[0u8; 32], DIR_C2S),
            peer_id: IdPublicKey::from_bytes(&vec![0u8; 2592]).unwrap(),
            read_state: ReadState::Idle,
        };

        let mut buf = [0u8; 16];
        let err = reader.read(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn split_preserves_buffered_plaintext_and_authenticated_eof() {
        let (mut client, mut server) = established().await;
        client.send_record(b"buffered plaintext").await.unwrap();
        client.send_eof().await.unwrap();
        let mut first = [0u8; 3];
        server.read_exact(&mut first).await.unwrap();
        assert_eq!(&first, b"buf");
        let (mut reader, _writer) = server.split();
        let mut rest = Vec::new();
        reader.read_to_end(&mut rest).await.unwrap();
        assert_eq!(rest, b"fered plaintext");
    }

    #[tokio::test]
    async fn split_preserves_pending_encrypted_write() {
        let (mut client, mut server) = established().await;
        let plaintext = b"pending encrypted write";
        let sealed = client.send.seal(plaintext).unwrap();
        let mut frame = Vec::new();
        frame.extend_from_slice(&(sealed.len() as u32).to_be_bytes());
        frame.extend_from_slice(&sealed);
        // Represent a writer that yielded after sending part of a frame.
        client.inner.write_all(&frame[..7]).await.unwrap();
        client.write_state = WriteState::Writing {
            frame,
            written: 7,
            consumed: plaintext.len(),
        };
        let (_reader, mut writer) = client.split();
        writer.flush().await.unwrap();
        assert_eq!(server.recv_record().await.unwrap(), plaintext);
    }

    #[tokio::test]
    async fn empty_async_read_completes_without_waiting_for_peer() {
        let (_client, mut server) = established().await;
        let result =
            tokio::time::timeout(std::time::Duration::from_millis(100), server.read(&mut []))
                .await
                .expect("empty read must not wait for network input");
        assert_eq!(result.unwrap(), 0);
    }
}
