// SPDX-License-Identifier: AGPL-3.0-only

//! A shadowsocks 2017 AEAD stream: an AEAD-framed `AsyncRead`/`AsyncWrite` over a transport.

use std::fmt;
use std::pin::Pin;
use std::task::{Context, Poll};

use netune::Transport;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use super::crypto::{Opener, Sealer};
use crate::shadowsocks::{Cipher, ShadowSocksError};

/// An AEAD-framed stream for 2017 AEAD.
pub struct ShadowSocksStream<T> {
    inner: T,
    cipher: Cipher,
    sealer: Sealer,
    opener: Opener,
    plaintext: Vec<u8>,
    plaintext_offset: usize,
    ciphertext: Vec<u8>,
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

    #[must_use]
    pub fn with_sealer(inner: T, cipher: Cipher, sealer: Sealer, recv_salt: &[u8]) -> Self {
        let master = sealer.master_key().to_vec();
        Self {
            inner,
            cipher,
            sealer,
            opener: Opener::new(cipher, &master, recv_salt),
            plaintext: Vec::new(),
            plaintext_offset: 0,
            ciphertext: Vec::new(),
            pending_length: None,
        }
    }

    #[must_use]
    pub const fn cipher(&self) -> Cipher {
        self.cipher
    }

    #[must_use]
    pub fn send_salt(&self) -> &[u8] {
        self.sealer.salt()
    }

    #[must_use]
    pub const fn get_ref(&self) -> &T {
        &self.inner
    }

    #[must_use]
    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<T: AsyncRead + Unpin> ShadowSocksStream<T> {
    fn try_decrypt(&mut self) -> Result<bool, ShadowSocksError> {
        let length_len = self.opener.length_record_len();

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
        self.ciphertext.drain(..total);
        self.pending_length = None;
        self.plaintext = payload;
        self.plaintext_offset = 0;
        Ok(true)
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for ShadowSocksStream<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            if self.plaintext_offset < self.plaintext.len() {
                let available = &self.plaintext[self.plaintext_offset..];
                let take = available.len().min(buf.remaining());
                buf.put_slice(&available[..take]);
                self.plaintext_offset += take;
                if self.plaintext_offset == self.plaintext.len() {
                    self.plaintext.clear();
                    self.plaintext_offset = 0;
                }
                return Poll::Ready(Ok(()));
            }

            match self.try_decrypt() {
                Ok(true) => continue,
                Ok(false) => {}
                Err(error) => return Poll::Ready(Err(error.into())),
            }

            let mut chunk = [0u8; 4096];
            let mut read_buf = ReadBuf::new(&mut chunk);
            match Pin::new(&mut self.inner).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => {
                    let filled = read_buf.filled();
                    if filled.is_empty() {
                        if !self.ciphertext.is_empty() || self.pending_length.is_some() {
                            return Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::UnexpectedEof,
                                "partial shadowsocks record at EOF",
                            )));
                        }
                        return Poll::Ready(Ok(()));
                    }
                    self.ciphertext.extend_from_slice(filled);
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for ShadowSocksStream<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        let max_payload = self.cipher.max_payload();
        let payload = if buf.len() > max_payload {
            &buf[..max_payload]
        } else {
            buf
        };

        let chunk = match self.sealer.seal_chunk(payload) {
            Ok(chunk) => chunk,
            Err(error) => return Poll::Ready(Err(ShadowSocksError::Crypto(error).into())),
        };

        match Pin::new(&mut self.inner).poll_write(cx, &chunk) {
            Poll::Ready(Ok(written)) if written == chunk.len() => Poll::Ready(Ok(payload.len())),
            Poll::Ready(Ok(_)) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "underlying transport accepted only part of a sealed record",
            ))),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Writes `salt` to `stream`.
pub async fn write_salt(
    stream: &mut Box<dyn Transport>,
    salt: &[u8],
) -> Result<(), std::io::Error> {
    stream.write_all(salt).await
}

/// Reads a salt of `length` bytes from `stream`.
pub async fn read_salt(
    stream: &mut Box<dyn Transport>,
    length: usize,
) -> Result<Vec<u8>, std::io::Error> {
    use tokio::io::AsyncReadExt as _;
    let mut salt = vec![0u8; length];
    stream.read_exact(&mut salt).await?;
    Ok(salt)
}
