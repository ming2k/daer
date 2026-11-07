// SPDX-License-Identifier: AGPL-3.0-only

//! A shadowsocks 2022 (SIP022) TCP stream:
//! Non-blocking state machine with bidirectional timestamp validation (±30s),
//! randomized initial handshake padding (1..=900), echoed request salt verification,
//! and lazy response-header processing.

use std::fmt;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};

use netune::Transport;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use super::crypto::{Opener2022, Sealer2022, derive_tcp_session_key};
use crate::shadowsocks::{Cipher, DecryptError, ShadowSocksError};

/// Maximum allowed clock skew between client and server in seconds.
pub const TIMESTAMP_TOLERANCE_SECS: u64 = 30;

/// Returns current Unix timestamp in seconds.
#[inline]
pub fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_secs()
}

/// Handshake details and verification error for Shadowsocks 2022.
#[derive(Debug)]
pub enum Handshake2022Error {
    Crypto(DecryptError),
    Io(std::io::Error),
    InvalidStreamType { expected: u8, got: u8 },
    ClockSkew { client_time: u64, server_time: u64 },
    RequestSaltMismatch,
}

impl fmt::Display for Handshake2022Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Crypto(e) => write!(f, "shadowsocks 2022 handshake: {e}"),
            Self::Io(e) => write!(f, "shadowsocks 2022 handshake transport: {e}"),
            Self::InvalidStreamType { expected, got } => {
                write!(
                    f,
                    "shadowsocks 2022: invalid response stream type {got:#x}, expected {expected:#x}"
                )
            }
            Self::ClockSkew {
                client_time,
                server_time,
            } => {
                write!(
                    f,
                    "shadowsocks 2022: clock skew too large (client={client_time}, server={server_time})"
                )
            }
            Self::RequestSaltMismatch => {
                f.write_str("shadowsocks 2022: server did not echo the client's request salt")
            }
        }
    }
}

impl std::error::Error for Handshake2022Error {}

impl From<DecryptError> for Handshake2022Error {
    fn from(e: DecryptError) -> Self {
        Self::Crypto(e)
    }
}

impl From<std::io::Error> for Handshake2022Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<Handshake2022Error> for std::io::Error {
    fn from(e: Handshake2022Error) -> Self {
        match e {
            Handshake2022Error::Io(err) => err,
            other => std::io::Error::new(std::io::ErrorKind::InvalidData, other.to_string()),
        }
    }
}

/// The receiver state machine for a Shadowsocks 2022 connection.
#[derive(Debug, PartialEq, Eq)]
enum ReadState {
    /// Waiting to read the server's salt (16 or 32 bytes).
    ServerSalt,
    /// Waiting to read the server's response header chunk.
    ResponseHeader,
    /// Waiting to read the initial response payload chunk declared by the header.
    InitialData { data_len: usize },
    /// Waiting to read a 2-byte chunk length record (18 bytes on wire).
    Length,
    /// Waiting to read a payload chunk of `length` bytes (`length + 16` bytes on wire).
    Payload { length: usize },
}

/// A Shadowsocks 2022 framed stream wrapping an underlying transport.
pub struct ShadowSocks2022Stream<T> {
    inner: T,
    cipher: Cipher,
    psk: Vec<u8>,
    client_salt: Vec<u8>,
    sealer: Sealer2022,
    opener: Option<Opener2022>,
    read_state: ReadState,
    plaintext: Vec<u8>,
    plaintext_offset: usize,
    ciphertext: Vec<u8>,
}

impl<T: fmt::Debug> fmt::Debug for ShadowSocks2022Stream<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShadowSocks2022Stream")
            .field("inner", &self.inner)
            .field("cipher", &self.cipher)
            .field("read_state", &self.read_state)
            .finish_non_exhaustive()
    }
}

impl<T> ShadowSocks2022Stream<T> {
    /// Creates a stream whose request header was already sent, and whose response
    /// will be lazily received and authenticated in `poll_read`.
    #[must_use]
    pub fn new(
        inner: T,
        cipher: Cipher,
        psk: Vec<u8>,
        client_salt: Vec<u8>,
        sealer: Sealer2022,
    ) -> Self {
        Self {
            inner,
            cipher,
            psk,
            client_salt,
            sealer,
            opener: None,
            read_state: ReadState::ServerSalt,
            plaintext: Vec::new(),
            plaintext_offset: 0,
            ciphertext: Vec::new(),
        }
    }

    #[must_use]
    pub const fn cipher(&self) -> Cipher {
        self.cipher
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

impl<T: AsyncRead + Unpin> ShadowSocks2022Stream<T> {
    /// Drives the receive state machine from buffered ciphertext.
    ///
    /// Returns `Ok(true)` if plaintext became available, `Ok(false)` if more ciphertext is needed.
    fn try_decrypt(&mut self) -> Result<bool, ShadowSocksError> {
        let salt_len = self.cipher.salt_len();

        loop {
            match self.read_state {
                ReadState::ServerSalt => {
                    if self.ciphertext.len() < salt_len {
                        return Ok(false);
                    }
                    let server_salt: Vec<u8> = self.ciphertext.drain(..salt_len).collect();
                    let recv_subkey = derive_tcp_session_key(self.cipher, &self.psk, &server_salt);
                    self.opener = Some(Opener2022::new(self.cipher, &recv_subkey));
                    self.read_state = ReadState::ResponseHeader;
                }
                ReadState::ResponseHeader => {
                    // Response header plaintext: [TYPE(1B)][TIMESTAMP(8B)][REQUEST_SALT(salt_len B)][DATA_LEN(2B)]
                    let resp_header_plain_len = 1 + 8 + salt_len + 2;
                    let resp_header_cipher_len = resp_header_plain_len + 16;
                    if self.ciphertext.len() < resp_header_cipher_len {
                        return Ok(false);
                    }

                    let mut resp_header_buf: Vec<u8> =
                        self.ciphertext.drain(..resp_header_cipher_len).collect();
                    let opener = self.opener.as_mut().expect("opener initialized");
                    opener
                        .open_record(&mut resp_header_buf)
                        .map_err(ShadowSocksError::Crypto)?;

                    let resp_type = resp_header_buf[0];
                    if resp_type != 0x01 {
                        return Err(ShadowSocksError::Io(
                            Handshake2022Error::InvalidStreamType {
                                expected: 0x01,
                                got: resp_type,
                            }
                            .into(),
                        ));
                    }

                    let server_time = u64::from_be_bytes(resp_header_buf[1..9].try_into().unwrap());
                    let client_now = current_timestamp();
                    if client_now.abs_diff(server_time) > TIMESTAMP_TOLERANCE_SECS {
                        return Err(ShadowSocksError::Io(
                            Handshake2022Error::ClockSkew {
                                client_time: client_now,
                                server_time,
                            }
                            .into(),
                        ));
                    }

                    let echoed_request_salt = &resp_header_buf[9..9 + salt_len];
                    if echoed_request_salt != self.client_salt.as_slice() {
                        return Err(ShadowSocksError::Io(
                            Handshake2022Error::RequestSaltMismatch.into(),
                        ));
                    }

                    let resp_data_len = u16::from_be_bytes(
                        resp_header_buf[9 + salt_len..9 + salt_len + 2]
                            .try_into()
                            .unwrap(),
                    ) as usize;

                    if resp_data_len > 0 {
                        self.read_state = ReadState::InitialData {
                            data_len: resp_data_len,
                        };
                    } else {
                        self.read_state = ReadState::Length;
                    }
                }
                ReadState::InitialData { data_len } => {
                    let total = data_len + 16;
                    if self.ciphertext.len() < total {
                        return Ok(false);
                    }

                    let mut chunk: Vec<u8> = self.ciphertext.drain(..total).collect();
                    let opener = self.opener.as_mut().expect("opener initialized");
                    opener
                        .open_record(&mut chunk)
                        .map_err(ShadowSocksError::Crypto)?;

                    self.read_state = ReadState::Length;
                    self.plaintext = chunk;
                    self.plaintext_offset = 0;
                    return Ok(true);
                }
                ReadState::Length => {
                    let length_len = 2 + 16;
                    if self.ciphertext.len() < length_len {
                        return Ok(false);
                    }

                    let len_record: Vec<u8> = self.ciphertext.drain(..length_len).collect();
                    let opener = self.opener.as_mut().expect("opener initialized");
                    let length = opener.open_length(&len_record)?;
                    self.read_state = ReadState::Payload { length };
                }
                ReadState::Payload { length } => {
                    let total = length + 16;
                    if self.ciphertext.len() < total {
                        return Ok(false);
                    }

                    let mut payload_buf: Vec<u8> = self.ciphertext.drain(..total).collect();
                    let opener = self.opener.as_mut().expect("opener initialized");
                    opener.open_record(&mut payload_buf)?;

                    self.read_state = ReadState::Length;
                    self.plaintext = payload_buf;
                    self.plaintext_offset = 0;
                    return Ok(true);
                }
            }
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for ShadowSocks2022Stream<T> {
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
                        if !self.ciphertext.is_empty() || self.read_state != ReadState::Length {
                            return Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::UnexpectedEof,
                                "partial shadowsocks 2022 record at EOF",
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

impl<T: AsyncWrite + Unpin> AsyncWrite for ShadowSocks2022Stream<T> {
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
                "underlying transport accepted only part of a sealed 2022 record",
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

/// Executes the initial client request transmission for Shadowsocks 2022:
/// writes the client salt, the header chunk, and the first data chunk (with 1..=900 padding
/// when empty), flushes the transport, and returns the stream ready to lazily authenticate
/// the response in `poll_read`.
pub async fn send_client_handshake(
    mut stream: Box<dyn Transport>,
    cipher: Cipher,
    psk: &[u8],
    encoded_target_addr: &[u8],
    initial_payload: &[u8],
) -> Result<ShadowSocks2022Stream<Box<dyn Transport>>, Handshake2022Error> {
    let salt_len = cipher.salt_len();
    let mut client_salt = vec![0u8; salt_len];
    fill_random(&mut client_salt);

    let send_subkey = derive_tcp_session_key(cipher, psk, &client_salt);
    let mut sealer = Sealer2022::new(cipher, &send_subkey);

    let padding_len = if initial_payload.is_empty() {
        fastrand::usize(1..=900)
    } else {
        0
    };

    let mut first_data_chunk =
        Vec::with_capacity(encoded_target_addr.len() + 2 + padding_len + initial_payload.len());
    first_data_chunk.extend_from_slice(encoded_target_addr);
    first_data_chunk.extend_from_slice(&(padding_len as u16).to_be_bytes());
    if padding_len > 0 {
        let mut padding_bytes = vec![0u8; padding_len];
        fill_random(&mut padding_bytes);
        first_data_chunk.extend_from_slice(&padding_bytes);
    }
    first_data_chunk.extend_from_slice(initial_payload);

    let now = current_timestamp();
    let mut header_chunk = Vec::with_capacity(1 + 8 + 2);
    header_chunk.push(0x00); // Client stream type
    header_chunk.extend_from_slice(&now.to_be_bytes());
    header_chunk.extend_from_slice(&(first_data_chunk.len() as u16).to_be_bytes());

    sealer.seal_record(&mut header_chunk)?;
    sealer.seal_record(&mut first_data_chunk)?;

    let mut request_wire =
        Vec::with_capacity(client_salt.len() + header_chunk.len() + first_data_chunk.len());
    request_wire.extend_from_slice(&client_salt);
    request_wire.extend_from_slice(&header_chunk);
    request_wire.extend_from_slice(&first_data_chunk);

    stream.write_all(&request_wire).await?;
    stream.flush().await?;

    Ok(ShadowSocks2022Stream::new(
        stream,
        cipher,
        psk.to_vec(),
        client_salt,
        sealer,
    ))
}

fn fill_random(buffer: &mut [u8]) {
    getrandom::fill(buffer).expect("OS random failure");
}
