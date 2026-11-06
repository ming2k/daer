// SPDX-License-Identifier: AGPL-3.0-only

//! The two VMess data planes: a byte stream and a datagram stream (ADR-0030).
//!
//! # Why they are separate types
//!
//! `TransferType` is not a hint. A stream flow's payload is chunked and a reader must reassemble
//! arbitrarily split writes across chunk boundaries; a packet flow's payload is **one chunk per
//! datagram**, and coalescing two chunks into one read corrupts both. The reference has two
//! readers for exactly this reason, so daer has two types rather than one with a flag.
//!
//! # The one asymmetry between the two types
//!
//! Both share [`Direction`], so both get the same keys, the same counter discipline and the same
//! keystream ordering. What differs is only the *read* side:
//!
//! * [`ChunkStream`] keeps a byte buffer and hands out as many bytes as the caller asked for,
//!   crossing chunk boundaries freely;
//! * [`PacketStream`] refuses to cross one: a `recv` returns exactly one chunk.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::sync::Mutex;

use netune::{DatagramTransport, Transport};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, ReadBuf};

use crate::vmess::chunk::{Cipher, Direction, MAX_CHUNK, SizeMode, open};
use crate::vmess::header::option;

/// A VMess chunk stream, reassembled into bytes.
pub struct ChunkStream {
    inner: Box<dyn Transport>,
    cipher: Cipher,
    read: Direction,
    write: Direction,
    /// Whether `shutdown` writes the terminating zero-length chunk.
    ///
    /// `no-termination-signal` is the reference's `NoTerminationSignal` account flag: a node
    /// configured with it expects the flow to end without that chunk. It is the one place a
    /// client and a server must agree on *absence*, so getting it wrong shows up as a node that
    /// logs a truncated request rather than as a failed connection.
    termination_signal: bool,
    /// Bytes of the current chunk the caller has not consumed yet.
    ready: Vec<u8>,
    /// Set once a zero-length chunk ends the stream.
    done: bool,
}

impl std::fmt::Debug for ChunkStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChunkStream")
            .field("pending_read", &self.ready.len())
            .field("done", &self.done)
            .finish_non_exhaustive()
    }
}

/// The keys a VMess flow needs in each direction.
///
/// The reference's `NewClientSession`: the uplink uses the request's body key and IV; the downlink
/// uses `SHA-256` of each, truncated to 16 bytes. Sharing them would repeat a GCM nonce, which for
/// these ciphers is not a weakness but a break.
#[must_use]
pub fn direction_material(body_key: &[u8; 16], body_iv: &[u8; 16]) -> ([u8; 16], [u8; 16]) {
    use sha2::{Digest as _, Sha256};

    let response_key: [u8; 16] =
        <[u8; 16]>::try_from(&Sha256::digest(body_key)[..16]).expect("16 bytes");
    let response_iv: [u8; 16] =
        <[u8; 16]>::try_from(&Sha256::digest(body_iv)[..16]).expect("16 bytes");
    (response_key, response_iv)
}

/// Builds both directions from a session's material and the request's options.
fn directions(
    cipher: Cipher,
    body_key: &[u8; 16],
    body_iv: &[u8; 16],
    mode: SizeMode,
    options: u8,
) -> (Direction, Direction) {
    let masking = options & option::CHUNK_MASKING != 0;
    // The downlink's size decoder is seeded from the *response* IV, because that is what the
    // reference's client does: the two directions mask their sizes with different streams.
    let (response_key, response_iv) = direction_material(body_key, body_iv);
    // The length seal is keyed by the *request's* values in both directions, which is why they are
    // passed separately (`chunk::Direction::new`).
    let length = (body_key, *body_iv);
    (
        Direction::new(cipher, &response_key, response_iv, length, mode, masking),
        Direction::new(cipher, body_key, *body_iv, length, mode, masking),
    )
}

impl ChunkStream {
    /// Builds the stream.
    #[must_use]
    pub(crate) fn new(
        inner: Box<dyn Transport>,
        cipher: Cipher,
        body_key: [u8; 16],
        body_iv: [u8; 16],
        mode: SizeMode,
        options: u8,
        termination_signal: bool,
    ) -> Self {
        let (read, write) = directions(cipher, &body_key, &body_iv, mode, options);
        Self {
            inner,
            cipher,
            read,
            write,
            termination_signal,
            ready: Vec::new(),
            done: false,
        }
    }
}

impl AsyncRead for ChunkStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if !this.ready_available() {
                if this.done {
                    return Poll::Ready(Ok(()));
                }
                if buf.remaining() == 0 {
                    return Poll::Ready(Ok(()));
                }
            }
            if this.ready_available() {
                let take = this.ready.len().min(buf.remaining());
                buf.put_slice(&this.ready[..take]);
                this.ready.drain(..take);
                return Poll::Ready(Ok(()));
            }

            // Pull one whole chunk: the size prefix and the tag are part of the framing, so a
            // partial chunk cannot be handed upward.
            let mut future = Box::pin(fill_chunk(&mut this.inner, this.cipher, &mut this.read));
            match future.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(None)) => {
                    this.done = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Ok(Some(payload))) => this.ready = payload,
            }
        }
    }
}

impl ChunkStream {
    /// Whether the current chunk still has payload bytes to hand out.
    ///
    /// A chunk whose payload is legitimately empty (the reference's `mb[0] == nil` case) must not
    /// be mistaken for the end of the stream: `done` is set only by a zero-length *chunk*.
    fn ready_available(&self) -> bool {
        !self.ready.is_empty()
    }
}

impl AsyncWrite for ChunkStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        // One write becomes one chunk, truncated to what a chunk can carry. The report is about
        // the caller's bytes: a caller that asked for 100 must be told 100, or it retries the
        // remainder of a chunk that has already gone out.
        let take = buf.len().min(MAX_CHUNK);
        let payload = buf[..take].to_vec();
        let mut future = Box::pin(write_chunk(
            &mut this.inner,
            this.cipher,
            &mut this.write,
            payload,
        ));
        match future.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => Poll::Ready(Ok(take)),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut future = Box::pin(this.inner.flush());
        future.as_mut().poll(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut future = Box::pin(async move {
            // The terminating zero-length chunk is what tells the node the flow is complete, and a
            // `shutdown` that only closes the socket leaves it waiting for more. A node configured
            // with `no-termination-signal` expects the opposite, so the chunk is conditional.
            if this.termination_signal {
                let end = this.write.seal_chunk(&[]).map_err(io::Error::other)?;
                this.inner.write_all(&end).await?;
                this.inner.flush().await?;
            }
            this.inner.shutdown().await
        });
        future.as_mut().poll(cx)
    }
}

/// Reads one chunk's payload, or `None` for the zero-length terminating chunk.
async fn fill_chunk(
    inner: &mut Box<dyn Transport>,
    cipher: Cipher,
    direction: &mut Direction,
) -> io::Result<Option<Vec<u8>>> {
    let mut field = vec![0u8; direction.size_bytes()];
    inner.read_exact(&mut field).await?;
    let declared = direction
        .decode_size(&field)
        .map_err(|reason| io::Error::new(io::ErrorKind::InvalidData, reason))?;
    if declared == 0 {
        return Ok(None);
    }
    if usize::from(declared) < Cipher::OVERHEAD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("a VMess chunk of {declared} bytes is smaller than its own tag"),
        ));
    }

    // `declared` covers the ciphertext *and* the padding, and the padding length is recovered
    // from the size field: the receiver knows the total but not the split, so it recovers the
    // split by trying the tag. The reference instead recomputes the padding from the keystream;
    // both sides of *this* implementation draw it in `decode_size`, so the value is recovered
    // here from the same place.
    let padding = direction.take_padding();
    let ciphertext_len = usize::from(declared).saturating_sub(usize::from(padding));
    if ciphertext_len < Cipher::OVERHEAD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "a VMess chunk of {declared} bytes declares {padding} of padding, leaving no room \
                 for its tag"
            ),
        ));
    }

    let mut ciphertext = vec![0u8; ciphertext_len];
    inner.read_exact(&mut ciphertext).await?;
    if padding > 0 {
        let mut skip = vec![0u8; usize::from(padding)];
        inner.read_exact(&mut skip).await?;
    }

    let nonce = direction.read_nonce();
    let payload = open(cipher, direction.key(), &nonce, &ciphertext)
        .map_err(|reason| io::Error::new(io::ErrorKind::InvalidData, reason))?;
    direction.advance();
    Ok(Some(payload))
}

/// Writes one chunk.
async fn write_chunk(
    inner: &mut Box<dyn Transport>,
    _cipher: Cipher,
    direction: &mut Direction,
    payload: Vec<u8>,
) -> io::Result<()> {
    let frame = direction.seal_chunk(&payload).map_err(io::Error::other)?;
    inner.write_all(&frame).await?;
    inner.flush().await
}

/// A VMess datagram stream: one chunk per datagram.
pub struct PacketStream {
    state: Mutex<PacketState>,
}

struct PacketState {
    inner: Box<dyn Transport>,
    cipher: Cipher,
    read: Direction,
    write: Direction,
}

impl std::fmt::Debug for PacketStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PacketStream").finish_non_exhaustive()
    }
}

impl PacketStream {
    #[must_use]
    pub(crate) fn new(
        inner: Box<dyn Transport>,
        cipher: Cipher,
        body_key: [u8; 16],
        body_iv: [u8; 16],
        mode: SizeMode,
        options: u8,
    ) -> Self {
        let (read, write) = directions(cipher, &body_key, &body_iv, mode, options);
        Self {
            state: Mutex::new(PacketState {
                inner,
                cipher,
                read,
                write,
            }),
        }
    }
}

impl DatagramTransport for PacketStream {
    fn max_datagram_size(&self) -> usize {
        // One datagram is one chunk, and a chunk's payload is bounded by `buf.Size` minus the tag
        // and the size field.
        MAX_CHUNK
    }

    fn send<'a>(
        &'a self,
        payload: &'a [u8],
    ) -> Pin<Box<dyn std::future::Future<Output = Result<usize, io::Error>> + Send + 'a>> {
        Box::pin(async move {
            if payload.len() > self.max_datagram_size() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "a VMess datagram of {} bytes exceeds the {} a chunk can carry",
                        payload.len(),
                        self.max_datagram_size()
                    ),
                ));
            }
            let mut state = self.state.lock().await;
            let frame = state.write.seal_chunk(payload).map_err(io::Error::other)?;
            state.inner.write_all(&frame).await?;
            state.inner.flush().await?;
            Ok(payload.len())
        })
    }

    fn recv<'a>(
        &'a self,
        buffer: &'a mut [u8],
    ) -> Pin<Box<dyn std::future::Future<Output = Result<usize, io::Error>> + Send + 'a>> {
        Box::pin(async move {
            let mut state = self.state.lock().await;
            // `fill_chunk` borrows the transport and the direction separately, so the state's
            // fields are taken apart here rather than borrowed as a whole.
            let PacketState {
                inner,
                cipher,
                read,
                ..
            } = &mut *state;
            let chunk = fill_chunk(inner, *cipher, read).await?.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "the node ended the VMess datagram stream",
                )
            })?;
            if chunk.len() > buffer.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "a VMess datagram of {} bytes does not fit a {} byte buffer; it was \
                         discarded",
                        chunk.len(),
                        buffer.len()
                    ),
                ));
            }
            buffer[..chunk.len()].copy_from_slice(&chunk);
            Ok(chunk.len())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_two_directions_get_different_keys_and_ivs() {
        // Sharing a key between directions repeats a GCM nonce, which for these ciphers is a
        // break rather than a weakness.
        let body_key = [3u8; 16];
        let body_iv = [4u8; 16];
        let (response_key, response_iv) = direction_material(&body_key, &body_iv);
        assert_ne!(response_key, body_key);
        assert_ne!(response_iv, body_iv);

        use sha2::{Digest as _, Sha256};
        assert_eq!(&response_key[..], &Sha256::digest(body_key)[..16]);
        assert_eq!(&response_iv[..], &Sha256::digest(body_iv)[..16]);
    }

    #[test]
    fn the_two_directions_mask_their_sizes_from_different_streams() {
        // The reference seeds the uplink's size parser from the request IV and the downlink's from
        // the response IV. Using one stream for both makes the second chunk of the reply
        // unreadable.
        let (read, write) = directions(
            Cipher::Aes128Gcm,
            &[1u8; 16],
            &[2u8; 16],
            SizeMode::Masked,
            option::CHUNK_MASKING,
        );
        assert_ne!(read.iv(), write.iv());
    }
}
