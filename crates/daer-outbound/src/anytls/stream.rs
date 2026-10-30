// SPDX-License-Identifier: AGPL-3.0-only

//! AnyTLS virtual multiplexed stream implementing [`tokio::io::AsyncRead`] and [`tokio::io::AsyncWrite`].

use std::fmt;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, Bytes};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;

use crate::anytls::frame::Frame;

/// Maximum payload size written per single frame chunk (16 KB for low-latency multiplexing).
const STREAM_WRITE_CHUNK_SIZE: usize = 16 * 1024;

/// A virtual bi-directional stream multiplexed over an AnyTLS session.
pub struct AnyTlsStream {
    stream_id: u32,
    inbound_rx: mpsc::Receiver<Bytes>,
    current_chunk: Option<Bytes>,
    outbound_tx: mpsc::UnboundedSender<Frame>,
    fin_sent: bool,
    closed: bool,
}

impl fmt::Debug for AnyTlsStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AnyTlsStream")
            .field("stream_id", &self.stream_id)
            .field("closed", &self.closed)
            .finish()
    }
}

impl AnyTlsStream {
    /// Constructs a new AnyTLS virtual stream.
    pub fn new(
        stream_id: u32,
        inbound_rx: mpsc::Receiver<Bytes>,
        outbound_tx: mpsc::UnboundedSender<Frame>,
    ) -> Self {
        Self {
            stream_id,
            inbound_rx,
            current_chunk: None,
            outbound_tx,
            fin_sent: false,
            closed: false,
        }
    }

    /// The stream ID within this AnyTLS session.
    #[must_use]
    pub fn stream_id(&self) -> u32 {
        self.stream_id
    }
}

impl Drop for AnyTlsStream {
    fn drop(&mut self) {
        if !self.fin_sent && !self.closed {
            let _ = self.outbound_tx.send(Frame::fin(self.stream_id));
            self.fin_sent = true;
        }
    }
}

impl AsyncRead for AnyTlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if let Some(mut chunk) = self.current_chunk.take() {
                if chunk.is_empty() {
                    continue;
                }
                let to_copy = std::cmp::min(chunk.len(), buf.remaining());
                buf.put_slice(&chunk[..to_copy]);
                chunk.advance(to_copy);
                if !chunk.is_empty() {
                    self.current_chunk = Some(chunk);
                }
                return Poll::Ready(Ok(()));
            }

            match self.inbound_rx.poll_recv(cx) {
                Poll::Ready(Some(chunk)) => {
                    if !chunk.is_empty() {
                        self.current_chunk = Some(chunk);
                    }
                }
                Poll::Ready(None) => {
                    self.closed = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for AnyTlsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.fin_sent || self.closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "anytls stream closed",
            )));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let to_send = std::cmp::min(buf.len(), STREAM_WRITE_CHUNK_SIZE);
        let chunk = Bytes::copy_from_slice(&buf[..to_send]);
        if self
            .outbound_tx
            .send(Frame::push(self.stream_id, chunk))
            .is_err()
        {
            self.closed = true;
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "anytls session writer closed",
            )));
        }
        Poll::Ready(Ok(to_send))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.fin_sent && !self.closed {
            let _ = self.outbound_tx.send(Frame::fin(self.stream_id));
            self.fin_sent = true;
        }
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn virtual_stream_read_and_write() {
        let (inbound_tx, inbound_rx) = mpsc::channel(16);
        let (outbound_tx, mut outbound_rx) = mpsc::unbounded_channel();

        let mut stream = AnyTlsStream::new(101, inbound_rx, outbound_tx);

        // Test writing pushes a Push frame
        stream.write_all(b"ping from stream").await.unwrap();
        let frame = outbound_rx.recv().await.unwrap();
        assert_eq!(frame.stream_id, 101);
        assert_eq!(frame.cmd, crate::anytls::frame::Command::Push);
        assert_eq!(frame.data, Bytes::from_static(b"ping from stream"));

        // Test reading from inbound channel
        inbound_tx
            .send(Bytes::from_static(b"pong from server"))
            .await
            .unwrap();
        let mut buf = vec![0u8; 16];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"pong from server");

        // Test shutdown sends Fin
        stream.shutdown().await.unwrap();
        let fin_frame = outbound_rx.recv().await.unwrap();
        assert_eq!(fin_frame.stream_id, 101);
        assert_eq!(fin_frame.cmd, crate::anytls::frame::Command::Fin);
    }
}
