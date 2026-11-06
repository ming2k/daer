// SPDX-License-Identifier: AGPL-3.0-only

//! The VLESS response header, consumed lazily on the first read.
//!
//! # Why this is a layer and not a two-byte read in `connect`
//!
//! The node answers with
//!
//! ```text
//!   [version 1 = 0] [addon_len 1] [addons…]   then the payload
//! ```
//!
//! and the reference consumes it in `DecodeResponseHeader` before it hands the connection to
//! `DecodeBodyAddons`. daer must do the same, or the caller's first bytes are the response
//! header: `00 00` followed by the real payload, which is what a `vless` node over plain TLS
//! produced before this module existed. The payload then looks shifted by two bytes, and the
//! symptom is a mangled HTTP request rather than an error.
//!
//! It is **lazy** rather than eager for one reason: the node may write the response header and
//! the first payload in one segment, or it may wait for the request payload before answering at
//! all. An eager read in `connect` would block a perfectly good session until its deadline on
//! the second kind of node; consuming it on the first `poll_read` costs nothing and cannot
//! deadlock, because a caller that never reads never needed the answer.
//!
//! # Vision
//!
//! Vision's reader used to special-case this header (`Phase::ResponseHeader { remaining: 2 }`),
//! and it only skipped the version and the addon *length* — an addons body would have been fed
//! to the unpadder as block bytes. With this layer underneath, Vision starts at `Phase::Initial`
//! and the header is somebody else's problem, which is the right division: the header is VLESS's,
//! not the flow's.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// The response header's version byte. VLESS has exactly one.
const VERSION: u8 = 0;

/// Where the reader is in the response header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Waiting for the version byte.
    Version,
    /// Waiting for the addons length.
    AddonLength,
    /// Passing through `remaining` bytes of addons.
    Addons { remaining: usize },
    /// The header is consumed: every remaining byte is payload.
    Payload,
}

/// A stream whose first bytes are the VLESS response header, which it consumes.
pub struct ResponseHeaderStream<S> {
    inner: S,
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
    pub const fn new(inner: S) -> Self {
        Self {
            inner,
            phase: Phase::Version,
        }
    }

    /// Whether the header has been fully consumed.
    #[must_use]
    pub const fn is_consumed(&self) -> bool {
        matches!(self.phase, Phase::Payload)
    }
}

impl<S: AsyncRead + Unpin> ResponseHeaderStream<S> {
    /// Reads exactly one byte, or reports EOF.
    fn read_byte(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Option<u8>>> {
        let mut byte = [0u8; 1];
        let mut buffer = ReadBuf::new(&mut byte);
        match Pin::new(&mut self.inner).poll_read(cx, &mut buffer) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {
                if buffer.filled().is_empty() {
                    Poll::Ready(Ok(None))
                } else {
                    Poll::Ready(Ok(Some(byte[0])))
                }
            }
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ResponseHeaderStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            match this.phase {
                Phase::Version => match this.read_byte(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Ready(Ok(None)) => return Poll::Ready(Ok(())),
                    Poll::Ready(Ok(Some(version))) => {
                        if version != VERSION {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!(
                                    "the VLESS response version is {version}, not {VERSION}: the \
                                     node is not speaking VLESS on this connection"
                                ),
                            )));
                        }
                        this.phase = Phase::AddonLength;
                    }
                },
                Phase::AddonLength => match this.read_byte(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Ready(Ok(None)) => return Poll::Ready(Ok(())),
                    Poll::Ready(Ok(Some(length))) => {
                        this.phase = if length == 0 {
                            Phase::Payload
                        } else {
                            Phase::Addons {
                                remaining: usize::from(length),
                            }
                        };
                    }
                },
                Phase::Addons { remaining } => {
                    let mut byte = [0u8; 1];
                    let mut buffer = ReadBuf::new(&mut byte);
                    match Pin::new(&mut this.inner).poll_read(cx, &mut buffer) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Ready(Ok(())) => {
                            if buffer.filled().is_empty() {
                                return Poll::Ready(Ok(()));
                            }
                            let left = remaining.saturating_sub(1);
                            this.phase = if left == 0 {
                                Phase::Payload
                            } else {
                                Phase::Addons { remaining: left }
                            };
                        }
                    }
                }
                Phase::Payload => return Pin::new(&mut this.inner).poll_read(cx, buf),
            }
        }
    }
}

impl<S> ResponseHeaderStream<S> {
    /// The wrapped stream, for a caller that needs a concrete type back.
    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> AsyncWrite for ResponseHeaderStream<S> {
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
    use tokio::io::AsyncReadExt as _;

    fn stream(bytes: &'static [u8]) -> ResponseHeaderStream<&'static [u8]> {
        ResponseHeaderStream::new(bytes)
    }

    #[tokio::test]
    async fn a_header_with_no_addons_is_consumed_and_the_payload_follows() {
        // `00 00` then the payload: exactly what a `vless` node over plain TLS answered, and
        // exactly what the caller used to receive as its first two bytes.
        let mut stream = stream(b"\x00\x00the payload");
        let mut out = Vec::new();
        stream.read_to_end(&mut out).await.expect("reads");
        assert_eq!(out, b"the payload");
    }

    #[tokio::test]
    async fn an_addons_body_is_skipped_by_its_declared_length() {
        // Vision declares `xtls-rprx-vision` in the response addons, and the old
        // `Phase::ResponseHeader { remaining: 2 }` skipped only the version and the length —
        // leaving the addons to be read as block bytes.
        let mut stream = stream(b"\x00\x0bhello worldpayload");
        let mut out = Vec::new();
        stream.read_to_end(&mut out).await.expect("reads");
        assert_eq!(out, b"payload");
    }

    #[tokio::test]
    async fn a_wrong_version_is_reported_rather_than_passed_through() {
        // A version byte that is not 0 means the peer is not speaking VLESS here. Passing it
        // through would corrupt the stream silently.
        let mut stream = stream(b"\x02\x00payload");
        let mut out = Vec::new();
        let error = stream.read_to_end(&mut out).await.expect_err("must fail");
        assert!(error.to_string().contains("not 0"), "{error}");
    }

    #[tokio::test]
    async fn a_truncated_header_ends_the_stream_instead_of_hanging() {
        // A node that closes after the version byte must produce EOF, not a stuck read.
        let mut stream = stream(b"\x00");
        let mut out = Vec::new();
        stream.read_to_end(&mut out).await.expect("reads");
        assert!(out.is_empty());
    }
}
