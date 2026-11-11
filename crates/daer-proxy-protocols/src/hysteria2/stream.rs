// SPDX-License-Identifier: AGPL-3.0-only

//! QUIC bidirectional stream wrapper implementing [`tokio::io::AsyncRead`] and
//! [`tokio::io::AsyncWrite`].

use netune_quic::owned::{RecvStream, SendStream};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

/// The application-facing end of one Hysteria 2 bidirectional QUIC stream.
///
/// The owned QUIC engine exposes raw `SendStream`/`RecvStream` halves rather than an
/// `AsyncRead + AsyncWrite` adapter. Two pump tasks bridge them to a duplex pipe, which is
/// the shape every protocol layer above (and netune's `Transport` blanket impl) expects.
/// The pump keeps one buffer per direction and never buffers a whole tunnel.
pub type QuicBiStream = tokio::io::DuplexStream;

/// Wraps a QUIC stream pair as a byte stream.
///
/// The returned value owns the application side. Dropping it closes the pipe; the outbound
/// pump then finishes the QUIC send side.
#[must_use]
pub fn wrap(send: SendStream, recv: RecvStream) -> QuicBiStream {
    const BUFFER: usize = 64 * 1024;
    let (application, tunnel) = tokio::io::duplex(BUFFER);
    let (mut plaintext, mut ciphertext) = tokio::io::split(tunnel);

    // Application → QUIC.
    tokio::spawn(async move {
        let mut send = send;
        let mut buffer = vec![0u8; 16 * 1024];
        loop {
            match plaintext.read(&mut buffer).await {
                Ok(0) | Err(_) => break,
                Ok(read) => {
                    if send.write_all(&buffer[..read]).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = send.finish().await;
    });

    // QUIC → application.
    tokio::spawn(async move {
        let mut recv = recv;
        loop {
            match recv.read(16 * 1024).await {
                Ok(Some(bytes)) => {
                    if ciphertext.write_all(&bytes).await.is_err() {
                        break;
                    }
                }
                Ok(None) | Err(_) => {
                    let _ = ciphertext.shutdown().await;
                    break;
                }
            }
        }
    });

    application
}
