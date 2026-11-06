// SPDX-License-Identifier: AGPL-3.0-only

//! The VMess response header, consumed lazily on the first read (ADR-0030).
//!
//! # Why lazy, and why an eager read is a deadlock
//!
//! The node's `transferResponse` writes the header into a *buffered* writer and only calls
//! `SetBuffered(false)` **after** it has read the first payload from the target:
//!
//! ```go
//! session.EncodeResponseHeader(response, output)       // buffered
//! data, _ := input.ReadMultiBuffer()                   // ← blocks until the target speaks
//! bodyWriter.WriteMultiBuffer(data)
//! output.SetBuffered(false)                            // ← the header finally leaves
//! ```
//!
//! So a client that sends its request header and then waits for the response header before
//! sending any payload waits forever: the node is waiting for the target, the target is waiting
//! for the client, and the client is waiting for the node. The reference client never hits this
//! because it writes the header and the first payload together, and reads the reply afterwards.
//!
//! daer therefore hands the caller a stream whose first `poll_read` consumes the response header.
//! A caller that writes first — which every caller does — breaks the cycle, and a caller that only
//! ever writes never pays for a read it did not need.
//!
//! # The two seals
//!
//! ```text
//!   [AEAD(length 2) 18] [AEAD(payload) payload+16]
//! ```
//!
//! keyed by KDFs over the *response* body key and IV (the request's, hashed with SHA-256 and
//! truncated — `ServerSession.EncodeResponseHeader`), and the plaintext payload begins with the
//! random byte the request carried. That echo is what proves the reply belongs to this request.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt as _, ReadBuf};

use crate::vmess::header::{self, Session};

/// Where the reader is in the response header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// The header has not been read yet.
    Pending,
    /// The header has been consumed and verified.
    Payload,
    /// The header failed; the error is reported once.
    Failed,
}

/// A stream whose first read consumes the VMess response header.
pub struct ResponseHeaderStream<S> {
    inner: S,
    session: Session,
    phase: Phase,
}

impl<S: std::fmt::Debug> std::fmt::Debug for ResponseHeaderStream<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResponseHeaderStream")
            .field("phase", &self.phase)
            .finish_non_exhaustive()
    }
}

impl<S> ResponseHeaderStream<S> {
    /// Wraps a stream the node's response header is about to arrive on.
    #[must_use]
    pub const fn new(inner: S, session: Session) -> Self {
        Self {
            inner,
            session,
            phase: Phase::Pending,
        }
    }

    /// The stream underneath, for a caller that needs the concrete type back.
    pub fn into_inner(self) -> S {
        self.inner
    }
}

/// Reads and verifies the whole response header.
///
/// The length field is a fixed 18 bytes; the payload is as long as it declares plus its tag, which
/// is why the total is only known after the first seal opens. A wrong key fails on the length,
/// which is the first thing a peer that is not answering this request trips.
async fn read_header<S: AsyncRead + Unpin>(stream: &mut S, session: &Session) -> io::Result<()> {
    let mut prefix = [0u8; 18];
    stream.read_exact(&mut prefix).await.map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("read the VMess response length: {error}"),
        )
    })?;
    let payload_len = header::response_payload_len(&prefix, session).map_err(|reason| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("the VMess response header did not verify: {reason}"),
        )
    })?;
    let mut rest = vec![0u8; payload_len + 16];
    stream.read_exact(&mut rest).await.map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("read the VMess response header body: {error}"),
        )
    })?;
    let mut whole = Vec::with_capacity(prefix.len() + rest.len());
    whole.extend_from_slice(&prefix);
    whole.extend_from_slice(&rest);
    header::decode_response_header(&whole, session).map_err(|reason| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("the VMess response header did not verify: {reason}"),
        )
    })?;
    Ok(())
}

impl<S: AsyncRead + Unpin> AsyncRead for ResponseHeaderStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.phase == Phase::Pending {
            // `read_header` is `async`; polling it as a future keeps the read cancel-safe (a
            // cancelled `read_exact` inside it would lose bytes, so the future is kept whole).
            let mut future = Box::pin(read_header(&mut this.inner, &this.session));
            match future.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => {
                    this.phase = Phase::Failed;
                    return Poll::Ready(Err(error));
                }
                Poll::Ready(Ok(())) => this.phase = Phase::Payload,
            }
        }
        if this.phase == Phase::Failed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the VMess response header already failed on this stream",
            )));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for ResponseHeaderStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes128Gcm, Nonce};

    use crate::vmess::kdf;

    /// Builds the response header a node would write for this session.
    fn encode(session: &Session, echoed: u8, payload: &[u8]) -> Vec<u8> {
        let mut plaintext = vec![echoed, 0x00, 0x00, 0x00];
        plaintext.extend_from_slice(payload);

        let length_key = kdf::kdf16(
            &session.response_body_key,
            &[kdf::SALT_AEAD_RESP_HEADER_LEN_KEY],
        );
        let length_iv = kdf::kdf(
            &session.response_body_iv,
            &[kdf::SALT_AEAD_RESP_HEADER_LEN_IV],
        );
        let cipher = Aes128Gcm::new_from_slice(&length_key).expect("key");
        let sealed_len = cipher
            .encrypt(
                Nonce::from_slice(&length_iv[..12]),
                (plaintext.len() as u16).to_be_bytes().as_slice(),
            )
            .expect("seals");

        let payload_key = kdf::kdf16(
            &session.response_body_key,
            &[kdf::SALT_AEAD_RESP_HEADER_PAYLOAD_KEY],
        );
        let payload_iv = kdf::kdf(
            &session.response_body_iv,
            &[kdf::SALT_AEAD_RESP_HEADER_PAYLOAD_IV],
        );
        let cipher = Aes128Gcm::new_from_slice(&payload_key).expect("key");
        let sealed_payload = cipher
            .encrypt(Nonce::from_slice(&payload_iv[..12]), plaintext.as_slice())
            .expect("seals");

        let mut out = sealed_len;
        out.extend_from_slice(&sealed_payload);
        out
    }

    #[tokio::test]
    async fn the_header_is_consumed_and_the_payload_survives() {
        let session = Session::new();
        let mut wire = encode(&session, session.response_header, b"");
        wire.extend_from_slice(b"the payload");

        let mut stream = ResponseHeaderStream::new(&wire[..], session.clone());
        let mut out = Vec::new();
        stream.read_to_end(&mut out).await.expect("reads");
        assert_eq!(out, b"the payload");
    }

    #[tokio::test]
    async fn a_reply_for_another_session_is_refused() {
        // The echoed byte is what binds a reply to a request; a node answering someone else's
        // request must not be accepted.
        let session = Session::new();
        let wrong = session.response_header.wrapping_add(1);
        let wire = encode(&session, wrong, b"");

        let mut stream = ResponseHeaderStream::new(&wire[..], session);
        let mut out = Vec::new();
        let error = stream.read_to_end(&mut out).await.expect_err("must fail");
        assert!(error.to_string().contains("another session"), "{error}");
    }

    #[tokio::test]
    async fn a_header_sealed_under_another_key_is_refused() {
        let session = Session::new();
        let mut other = Session::new();
        other.response_body_key = session.response_body_key;
        other.response_body_iv = [0xff; 16];
        other.response_header = session.response_header;
        let wire = encode(&other, session.response_header, b"");

        let mut stream = ResponseHeaderStream::new(&wire[..], session);
        let mut out = Vec::new();
        let error = stream.read_to_end(&mut out).await.expect_err("must fail");
        assert!(error.to_string().contains("did not verify"), "{error}");
    }
}
