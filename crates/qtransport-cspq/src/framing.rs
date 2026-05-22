//! Length-prefixed framing helpers.
//!
//! All wire messages start with a big-endian 4-byte length prefix. The maximum
//! single frame body is capped to defend against memory exhaustion.

use crate::error::{Error, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Hard cap on any single framed message, including handshake messages.
/// Generous enough for ML-DSA-87 signatures (4627 B) plus public keys.
pub const MAX_FRAME: usize = 64 * 1024;

/// Write a length-prefixed frame.
pub async fn write_frame<W>(w: &mut W, buf: &[u8]) -> Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    if buf.len() > MAX_FRAME {
        return Err(Error::FrameTooLarge {
            got: buf.len(),
            max: MAX_FRAME,
        });
    }
    let len = (buf.len() as u32).to_be_bytes();
    w.write_all(&len).await?;
    w.write_all(buf).await?;
    w.flush().await?;
    Ok(())
}

/// Read a length-prefixed frame. Returns the body bytes (without the prefix).
pub async fn read_frame<R>(r: &mut R, max: usize) -> Result<Vec<u8>>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > max.min(MAX_FRAME) {
        return Err(Error::FrameTooLarge { got: len, max });
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn roundtrip_small() {
        let (mut a, mut b) = duplex(1024);
        let msg = b"hello frame";
        write_frame(&mut a, msg).await.unwrap();
        let got = read_frame(&mut b, MAX_FRAME).await.unwrap();
        assert_eq!(&got[..], msg);
    }

    #[tokio::test]
    async fn roundtrip_8k() {
        let (mut a, mut b) = duplex(16 * 1024);
        let msg = vec![0xABu8; 8192];
        let task = tokio::spawn(async move {
            write_frame(&mut a, &msg).await.unwrap();
        });
        let got = read_frame(&mut b, MAX_FRAME).await.unwrap();
        assert_eq!(got.len(), 8192);
        assert!(got.iter().all(|&b| b == 0xAB));
        task.await.unwrap();
    }

    #[tokio::test]
    async fn rejects_oversized_header() {
        // Inject a length prefix claiming 1 MB while max=4 KB.
        let (mut a, mut b) = duplex(1024);
        let len_bytes = (1_000_000u32).to_be_bytes();
        let task = tokio::spawn(async move {
            a.write_all(&len_bytes).await.unwrap();
        });
        let err = read_frame(&mut b, 4096).await.unwrap_err();
        match err {
            Error::FrameTooLarge { got, max } => {
                assert_eq!(got, 1_000_000);
                assert_eq!(max, 4096);
            }
            other => panic!("expected FrameTooLarge, got {other:?}"),
        }
        task.await.unwrap();
    }

    #[tokio::test]
    async fn refuses_to_write_oversize() {
        let (mut a, _b) = duplex(8);
        let huge = vec![0u8; MAX_FRAME + 1];
        let err = write_frame(&mut a, &huge).await.unwrap_err();
        assert!(matches!(err, Error::FrameTooLarge { .. }));
    }
}
