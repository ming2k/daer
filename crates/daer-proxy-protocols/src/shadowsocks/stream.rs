// SPDX-License-Identifier: AGPL-3.0-only

//! A shadowsocks stream: an AEAD-framed `AsyncRead`/`AsyncWrite` over a transport.
//!
//! # What "a stream" means here
//!
//! The peer sees a byte stream; the wire carries records. This wrapper is the boundary:
//! [`AsyncWrite::poll_write`] may split a write into records of at most
//! [`Cipher::max_payload`], and [`AsyncRead::poll_read`] refills from records and hands out
//! whatever has been decrypted. Neither side has to know the framing.
//!
//! # The two halves have different keys
//!
//! Each direction has its own salt, its own subkey and its own nonce counter. The client's
//! salt travels first, before any record; the server's salt arrives before the server's first
//! record. Everything below treats them symmetrically, because getting this wrong produces a
//! stream that decrypts garbage after the first response — a failure that looks like a
//! network problem.
//!
//! # Incomplete records are not errors
//!
//! TCP delivers partial data. A read that has half a length record must ask for more, not
//! fail: [`tokio::io::AsyncRead`]'s contract allows a short read at any time, and a decoder
//! that treats "not enough bytes yet" as an error works only on a LAN.

use std::fmt;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use super::crypto::{Cipher, DecryptError, Opener, Sealer};

/// Why a shadowsocks stream failed.
#[derive(Debug)]
pub enum ShadowSocksError {
    /// The AEAD record did not authenticate: the key, the salt or the bytes are wrong.
    Crypto(DecryptError),
    /// The underlying transport failed.
    Io(std::io::Error),
    /// The peer's salt repeats one already seen on this stream.
    Replay,
}

impl fmt::Display for ShadowSocksError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Crypto(error) => write!(f, "shadowsocks: {error}"),
            Self::Io(error) => write!(f, "shadowsocks transport: {error}"),
            Self::Replay => f.write_str("shadowsocks: repeated salt (possible replay)"),
        }
    }
}

impl std::error::Error for ShadowSocksError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Crypto(error) => Some(error),
            Self::Io(error) => Some(error),
            Self::Replay => None,
        }
    }
}

impl From<std::io::Error> for ShadowSocksError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<DecryptError> for ShadowSocksError {
    fn from(error: DecryptError) -> Self {
        Self::Crypto(error)
    }
}

impl From<ShadowSocksError> for std::io::Error {
    /// Maps to `InvalidData`: the stream is unusable and the cause is the peer's bytes.
    fn from(error: ShadowSocksError) -> Self {
        match error {
            ShadowSocksError::Io(error) => error,
            other => std::io::Error::new(std::io::ErrorKind::InvalidData, other.to_string()),
        }
    }
}

/// An AEAD-framed stream.
pub struct ShadowSocksStream<T> {
    inner: T,
    cipher: Cipher,
    sealer: Sealer,
    opener: Opener,
    /// Decrypted bytes not yet handed to the reader.
    plaintext: Vec<u8>,
    plaintext_offset: usize,
    /// Encrypted bytes read but not yet decryptable (a partial record).
    ciphertext: Vec<u8>,
    /// The payload length already decrypted from the current chunk's length record.
    ///
    /// Load-bearing. A record may span several `poll_read` calls, so the length record is
    /// decrypted long before its payload arrives; opening it again would consume a second
    /// nonce and fail authentication on every chunk that arrives in pieces — which on a real
    /// network is every chunk.
    pending_length: Option<usize>,
}

impl<T: fmt::Debug> fmt::Debug for ShadowSocksStream<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShadowSocksStream")
            .field("inner", &self.inner)
            .field("cipher", &self.cipher)
            .finish_non_exhaustive()
    }
}

impl<T> ShadowSocksStream<T> {
    /// Wraps `inner` with the given keys and salts.
    ///
    /// `send_salt` will be written before the first record; `recv_salt` is what the peer
    /// announced. Both are the caller's because they come from the link and from the
    /// handshake, not from here.
    ///
    /// A shadow client should prefer [`ShadowSocksStream::with_sealer`]: the handshake writes
    /// records too, and this constructor would start a *second* nonce sequence at zero.
    #[must_use]
    pub fn new(
        inner: T,
        cipher: Cipher,
        master: &[u8],
        send_salt: &[u8],
        recv_salt: &[u8],
    ) -> Self {
        Self::with_sealer(
            inner,
            cipher,
            Sealer::new(cipher, master, send_salt),
            recv_salt,
        )
    }

    /// Wraps `inner` continuing from an existing sealer.
    ///
    /// This is the constructor a shadow client must use. The handshake already sealed the
    /// address frame, so the sealer's nonce is two records in; a fresh sealer would restart at
    /// zero and every subsequent record would fail the peer's authentication — a failure that
    /// only appears after the first chunk, which is exactly why it is worth a type-level
    /// distinction rather than a comment.
    #[must_use]
    pub fn with_sealer(inner: T, cipher: Cipher, sealer: Sealer, recv_salt: &[u8]) -> Self {
        let master = sealer.master_key().to_vec();
        Self {
            inner,
            cipher,
            sealer,
            // `Subkey` is derived from the master, so the opener needs the master; the sealer
            // keeps it for exactly this reason.
            opener: Opener::new(cipher, &master, recv_salt),
            plaintext: Vec::new(),
            plaintext_offset: 0,
            ciphertext: Vec::new(),
            pending_length: None,
        }
    }

    /// The cipher this stream speaks.
    #[must_use]
    pub const fn cipher(&self) -> Cipher {
        self.cipher
    }

    /// The salt this side sends, for a caller that writes it itself.
    #[must_use]
    pub fn send_salt(&self) -> &[u8] {
        self.sealer.salt()
    }

    /// Borrows the transport.
    #[must_use]
    pub const fn get_ref(&self) -> &T {
        &self.inner
    }

    /// Consumes the wrapper, returning the transport.
    ///
    /// Only safe once both directions are drained: undelivered plaintext is dropped.
    #[must_use]
    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<T: AsyncRead + Unpin> ShadowSocksStream<T> {
    /// Tries to decrypt one more chunk from the buffered ciphertext.
    ///
    /// Returns `Ok(false)` when more bytes are needed. The framing is
    /// `[len][tag][payload][tag]`, so a chunk needs `length_record_len` bytes before its
    /// payload size is even known.
    fn try_decrypt(&mut self) -> Result<bool, ShadowSocksError> {
        let length_len = self.opener.length_record_len();

        // Decrypt the length record at most once per chunk, and only when the whole record is
        // present. Re-opening it would consume a second nonce and break the peer's next one.
        let length = match self.pending_length {
            Some(length) => length,
            None => {
                if self.ciphertext.len() < length_len {
                    return Ok(false);
                }
                let length = self.opener.open_length(&self.ciphertext[..length_len])?;
                self.pending_length = Some(length);
                length
            }
        };

        let total = length_len + length + 16;
        if self.ciphertext.len() < total {
            return Ok(false);
        }

        let payload = self
            .opener
            .open_payload(&self.ciphertext[length_len..total])?;
        // The chunk is complete: retire both the bytes and the remembered length.
        self.ciphertext.drain(..total);
        self.pending_length = None;
        self.plaintext.extend_from_slice(&payload);
        Ok(true)
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for ShadowSocksStream<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        loop {
            // Serve what has already been decrypted before touching the socket.
            if this.plaintext_offset < this.plaintext.len() {
                let available = &this.plaintext[this.plaintext_offset..];
                let take = available.len().min(buf.remaining());
                buf.put_slice(&available[..take]);
                this.plaintext_offset += take;
                if this.plaintext_offset == this.plaintext.len() {
                    this.plaintext.clear();
                    this.plaintext_offset = 0;
                }
                return Poll::Ready(Ok(()));
            }

            match this.try_decrypt() {
                Err(error) => return Poll::Ready(Err(error.into())),
                Ok(true) => continue,
                Ok(false) => {}
            }

            // Need more ciphertext: read once, then loop back to try decrypting again.
            let mut chunk = [0u8; 8192];
            let mut read_buf = ReadBuf::new(&mut chunk);
            match Pin::new(&mut this.inner).poll_read(cx, &mut read_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {
                    let filled = read_buf.filled();
                    if filled.is_empty() {
                        // A clean EOF with a partial record buffered is a truncated stream:
                        // reporting EOF would silently drop data.
                        if this.ciphertext.is_empty() {
                            return Poll::Ready(Ok(()));
                        }
                        return Poll::Ready(Err(ShadowSocksError::Crypto(DecryptError).into()));
                    }
                    this.ciphertext.extend_from_slice(filled);
                }
            }
        }
    }
}

impl<T: AsyncWrite + Unpin> ShadowSocksStream<T> {
    /// Seals `data` into records and writes them.
    ///
    /// Returns how many input bytes were consumed, which may be less than `data.len()`: a
    /// single write larger than one record becomes several, and reporting the whole length
    /// while writing only part of it would silently lose data.
    fn poll_write_records(
        &mut self,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let take = data.len().min(self.cipher.max_payload());
        let sealed = self
            .sealer
            .seal_chunk(&data[..take])
            .map_err(ShadowSocksError::from)?;

        // The inner write may be partial; buffering the remainder is the transport's job, so
        // this retries until the record is accepted.
        let mut written = 0;
        while written < sealed.len() {
            match Pin::new(&mut self.inner).poll_write(cx, &sealed[written..]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::from(std::io::ErrorKind::WriteZero)));
                }
                Poll::Ready(Ok(count)) => written += count,
            }
        }
        Poll::Ready(Ok(take))
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for ShadowSocksStream<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        self.get_mut().poll_write_records(cx, data)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Writes the sending salt, which must precede the first record.
///
/// A separate step rather than part of construction because the write is async and a
/// constructor cannot be. Doing it implicitly on the first `poll_write` would make the
/// first record's framing depend on call order.
///
/// # Errors
///
/// Returns the transport's error, or [`std::io::ErrorKind::WriteZero`] if the transport
/// accepts nothing.
pub async fn write_salt<T: AsyncWrite + Unpin>(stream: &mut T, salt: &[u8]) -> std::io::Result<()> {
    stream.write_all(salt).await?;
    stream.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shadowsocks::crypto::master_key;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const PASSWORD: &str = "hunter2";

    /// Connects two wrapped streams through an in-memory duplex so the framing is
    /// exercised without a socket.
    fn pair(
        cipher: Cipher,
    ) -> (
        ShadowSocksStream<tokio::io::DuplexStream>,
        ShadowSocksStream<tokio::io::DuplexStream>,
    ) {
        let master = master_key(cipher, PASSWORD);
        // Each side's salt is the other's receive salt, as a real handshake establishes.
        let client_salt = vec![0x01u8; cipher.salt_len()];
        let server_salt = vec![0x02u8; cipher.salt_len()];
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);

        (
            ShadowSocksStream::new(client_io, cipher, &master, &client_salt, &server_salt),
            ShadowSocksStream::new(server_io, cipher, &master, &server_salt, &client_salt),
        )
    }

    #[tokio::test]
    async fn data_round_trips_through_the_framing() {
        let (mut client, mut server) = pair(Cipher::Aes256Gcm);
        client.write_all(b"request bytes").await.expect("writes");
        let mut buffer = [0u8; 13];
        server.read_exact(&mut buffer).await.expect("reads");
        assert_eq!(&buffer, b"request bytes");

        server.write_all(b"response").await.expect("writes");
        let mut buffer = [0u8; 8];
        client.read_exact(&mut buffer).await.expect("reads");
        assert_eq!(&buffer, b"response");
    }

    #[tokio::test]
    async fn a_payload_larger_than_one_record_is_split() {
        // 40 KiB is larger than the 0x3FFF record limit, so the write must become several
        // records and the reader must reassemble them.
        let (mut client, mut server) = pair(Cipher::ChaCha20Poly1305);
        let payload: Vec<u8> = (0..40_000u32).map(|i| (i % 251) as u8).collect();

        let writer = tokio::spawn(async move {
            client.write_all(&payload).await.expect("writes");
            client.shutdown().await.expect("shutdown");
            payload
        });

        let mut received = Vec::new();
        server.read_to_end(&mut received).await.expect("reads");
        let expected = writer.await.expect("joins");
        assert_eq!(received.len(), expected.len());
        assert_eq!(received, expected);
    }

    #[tokio::test]
    async fn a_write_may_consume_less_than_it_was_given() {
        // `poll_write` is allowed to accept a prefix; reporting the whole length while
        // writing part would lose data silently.
        let cipher = Cipher::Aes128Gcm;
        let master = master_key(cipher, PASSWORD);
        // Large enough for one sealed record, so the write completes without a reader.
        let (io, _other) = tokio::io::duplex(cipher.max_payload() + 64);
        let mut stream = ShadowSocksStream::new(io, cipher, &master, &[1; 16], &[2; 16]);

        let data = vec![0u8; cipher.max_payload() * 2];
        let written = stream.write(&data).await.expect("writes");
        assert_eq!(
            written,
            cipher.max_payload(),
            "one call writes one record at most"
        );
    }

    #[tokio::test]
    async fn a_partial_record_at_eof_is_an_error_not_a_short_read() {
        // A half record must not be reported as a clean end: that would silently drop the
        // peer's data. Eight bytes is less than one length record.
        let cipher = Cipher::Aes128Gcm;
        let master = master_key(cipher, PASSWORD);
        let (mut feed, reader) = tokio::io::duplex(64);
        feed.write_all(&[0u8; 8]).await.expect("feeds");
        drop(feed);

        let mut stream = ShadowSocksStream::new(reader, cipher, &master, &[1; 16], &[2; 16]);
        let mut buffer = [0u8; 16];
        let error = stream.read(&mut buffer).await.expect_err("must fail");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn an_eof_with_nothing_pending_is_a_clean_end() {
        let cipher = Cipher::Aes128Gcm;
        let master = master_key(cipher, PASSWORD);
        let (feed, reader) = tokio::io::duplex(64);
        drop(feed);

        let mut stream = ShadowSocksStream::new(reader, cipher, &master, &[1; 16], &[2; 16]);
        let mut buffer = [0u8; 4];
        assert_eq!(stream.read(&mut buffer).await.expect("a clean eof"), 0);
    }

    #[tokio::test]
    async fn a_tampered_record_surfaces_as_invalid_data() {
        let cipher = Cipher::Aes128Gcm;
        let master = master_key(cipher, PASSWORD);
        let client_salt = vec![1u8; 16];
        let server_salt = vec![2u8; 16];

        let (raw_client, mut raw_server) = tokio::io::duplex(4096);
        let mut writer =
            ShadowSocksStream::new(raw_client, cipher, &master, &client_salt, &server_salt);
        writer.write_all(b"payload").await.expect("writes");
        // Own the transport, so dropping the writer drops the peer's write end and the
        // `read_to_end` below sees EOF instead of waiting for one.
        drop(writer);

        let mut wire = Vec::new();
        raw_server.read_to_end(&mut wire).await.expect("reads wire");
        // Flip a byte in the payload record.
        let last = wire.len() - 1;
        wire[last] ^= 0xff;

        let (mut feed_writer, feed_reader) = tokio::io::duplex(4096);
        feed_writer.write_all(&wire).await.expect("feeds");
        drop(feed_writer);

        let mut reader =
            ShadowSocksStream::new(feed_reader, cipher, &master, &server_salt, &client_salt);
        let mut sink = Vec::new();
        let error = reader.read_to_end(&mut sink).await.expect_err("must fail");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn the_sending_salt_is_available_to_the_caller() {
        let cipher = Cipher::Aes128Gcm;
        let master = master_key(cipher, PASSWORD);
        let (io, _peer) = tokio::io::duplex(64);
        let salt = [0xabu8; 16];
        let stream = ShadowSocksStream::new(io, cipher, &master, &salt, &[0u8; 16]);
        assert_eq!(stream.send_salt(), &salt);
        assert_eq!(stream.cipher(), Cipher::Aes128Gcm);
    }
}
