// SPDX-License-Identifier: AGPL-3.0-only

//! RFC 6455 framing as a byte stream, over netune's message-oriented `WsStream`.
//!
//! # Why an adapter is needed at all
//!
//! netune's `WsStream` is message-oriented on purpose: `send`/`receive` deal in
//! [`WsMessage`]s, and the heartbeat/close state machine lives in `WsSession`. That is the
//! right shape for an application protocol. A proxy transport is a *byte* stream carried in
//! binary frames, so it needs the opposite: `AsyncWrite::poll_write(&[u8])` becomes one
//! binary message, and inbound binary messages are decoded into a read buffer.
//!
//! This is exactly what Xray's `websocket` transport does, and it is what makes
//! `vless`-over-`ws`-over-TLS work with any panel's node.
//!
//! # What the adapter must not do
//!
//! * **Coalesce reads across frames.** A frame boundary is not a message boundary for this
//!   protocol, but it *is* a flush point for the peer: reading exactly one frame at a time
//!   keeps a `ClientHello` that arrives in one frame from being merged with a later record
//!   the caller is not expecting yet.
//! * **Forward control frames as data.** netune answers pings and completes the close
//!   handshake itself; forwarding a ping's payload as payload would corrupt the stream.
//! * **Fragment on write.** One `poll_write` is one binary frame. Splitting a caller's bytes
//!   across frames is legal on the wire but makes the peer's `Xray` reader re-assemble
//!   something it does not have to.

use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::BytesMut;
use netune::{Transport, WsMessage, WsStream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// A byte stream over WebSocket binary frames.
pub struct WsByteStream<S> {
    inner: WsStream<S>,
    /// Bytes of the current inbound message that the caller has not consumed yet.
    read_buf: BytesMut,
    /// Set once the peer closed the WebSocket.
    closed: bool,
}

impl<S> std::fmt::Debug for WsByteStream<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WsByteStream")
            .field("pending_read", &self.read_buf.len())
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}

impl<S> WsByteStream<S> {
    /// Wraps an upgraded stream and whatever the server sent after its `101`.
    #[must_use]
    pub(crate) fn new(inner: WsStream<S>) -> Self {
        Self {
            inner,
            read_buf: BytesMut::new(),
            closed: false,
        }
    }
}

impl<S: Transport> AsyncRead for WsByteStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        loop {
            if !this.read_buf.is_empty() {
                let take = this.read_buf.len().min(buf.remaining());
                buf.put_slice(&this.read_buf[..take]);
                let _ = this.read_buf.split_to(take);
                return Poll::Ready(Ok(()));
            }
            if buf.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
            if this.closed {
                return Poll::Ready(Ok(()));
            }

            // `receive` is `async`; poll it as a future so the read stays cancel-safe. A
            // message that has been decoded into `read_buf` is never lost: the buffer is
            // checked first on every entry to this loop.
            let mut future = Box::pin(this.inner.receive());
            match future.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => {
                    return Poll::Ready(Err(std::io::Error::other(format!(
                        "WebSocket read failed: {error}"
                    ))));
                }
                Poll::Ready(Ok(None)) => {
                    this.closed = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Ok(Some(message))) => match message {
                    WsMessage::Binary(payload) => {
                        this.read_buf.extend_from_slice(&payload);
                    }
                    // A proxy transport carries binary only. A text message on this stream
                    // is the peer speaking a different protocol — reporting it is better
                    // than appending its bytes to the tunnel.
                    WsMessage::Text(text) => {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!(
                                "the WebSocket peer sent a text message ({:?}) on a transport \
                                 that carries binary frames only",
                                text.chars().take(32).collect::<String>()
                            ),
                        )));
                    }
                    // Control frames were already answered by `WsStream`; a `Close` that
                    // reaches here is the peer's own close and ends the stream.
                    WsMessage::Close(_) => {
                        this.closed = true;
                        return Poll::Ready(Ok(()));
                    }
                    WsMessage::Ping(_) | WsMessage::Pong(_) => {}
                },
            }
        }
    }
}

impl<S: Transport> AsyncWrite for WsByteStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let mut future = Box::pin(this.inner.send_binary(buf.to_vec()));
        match future.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(std::io::Error::other(format!(
                "WebSocket write failed: {error}"
            )))),
            // The report is about the caller's bytes: a caller that asked to write 100 bytes
            // must be told 100, or it retries the remainder of a frame that has already gone
            // out and the peer sees it twice.
            Poll::Ready(Ok(())) => Poll::Ready(Ok(buf.len())),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // `WsStream::send` already writes and flushes the underlying socket, so there is
        // nothing buffered to push. Reporting readiness without a syscall is the honest
        // answer: a flush that wrote nothing is a successful flush.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        // A close frame: `WsStream::close` completes the handshake, which is what stops a node
        // from logging a truncated session.
        let mut future = Box::pin(
            this.inner
                .close(netune::CloseCode::NORMAL, "the proxy session ended"),
        );
        future
            .as_mut()
            .poll(cx)
            .map_err(|error| std::io::Error::other(format!("WebSocket close failed: {error}")))
    }
}

use std::future::Future as _;

#[cfg(test)]
mod tests {
    use super::*;

    /// The trait bounds the composition needs, asserted at compile time.
    ///
    /// `WsByteStream` is what the security layer receives, so it has to be a `Transport`;
    /// a missing `AsyncRead` impl would otherwise surface as a `ws` node that cannot be
    /// built at all.
    const fn _assert_transport<T: Transport>() {}

    #[test]
    fn a_byte_stream_over_websocket_is_a_transport() {
        _assert_transport::<WsByteStream<Box<dyn Transport>>>();
    }
}
