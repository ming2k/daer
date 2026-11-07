// SPDX-License-Identifier: AGPL-3.0-only

//! Shadowsocks 2022 (SIP022) UDP datagram implementation:
//! Random 64-bit client session ID, monotonically increasing packet ID,
//! AES-ECB header obfuscation, and per-packet timestamp validation.

use std::fmt;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use netune::DatagramTransport;

use super::crypto::{decrypt_header_block, derive_udp_session_key, encrypt_header_block};
use super::stream::{TIMESTAMP_TOLERANCE_SECS, current_timestamp};
use crate::shadowsocks::Cipher;
use crate::shadowsocks::connector::atyp;

/// A datagram session over Shadowsocks 2022.
pub struct ShadowSocks2022DatagramSession {
    socket: Arc<tokio::net::UdpSocket>,
    cipher: Cipher,
    psk: Vec<u8>,
    client_session_id: u64,
    packet_id: AtomicU64,
    target_addr: Vec<u8>,
}

impl fmt::Debug for ShadowSocks2022DatagramSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShadowSocks2022DatagramSession")
            .field("cipher", &self.cipher)
            .field("client_session_id", &self.client_session_id)
            .finish_non_exhaustive()
    }
}

impl ShadowSocks2022DatagramSession {
    #[must_use]
    pub fn new(
        socket: Arc<tokio::net::UdpSocket>,
        cipher: Cipher,
        psk: Vec<u8>,
        target_addr: Vec<u8>,
    ) -> Self {
        // Generate random 64-bit client session ID
        let mut session_bytes = [0u8; 8];
        getrandom::fill(&mut session_bytes).expect("OS random failure");
        let client_session_id = u64::from_be_bytes(session_bytes);

        Self {
            socket,
            cipher,
            psk,
            client_session_id,
            packet_id: AtomicU64::new(1),
            target_addr,
        }
    }
}

impl DatagramTransport for ShadowSocks2022DatagramSession {
    fn send<'a>(
        &'a self,
        payload: &'a [u8],
    ) -> Pin<Box<dyn std::future::Future<Output = Result<usize, std::io::Error>> + Send + 'a>> {
        Box::pin(async move {
            let pid = self.packet_id.fetch_add(1, Ordering::Relaxed);
            let now = current_timestamp();

            match self.cipher {
                Cipher::Aead2022Blake3Aes128Gcm | Cipher::Aead2022Blake3Aes256Gcm => {
                    // Header plaintext: [Client Session ID (8B)] [Packet ID (8B)]
                    let mut header = [0u8; 16];
                    header[..8].copy_from_slice(&self.client_session_id.to_be_bytes());
                    header[8..16].copy_from_slice(&pid.to_be_bytes());

                    // Nonce is bytes 4..16 of the plaintext header (12 bytes)
                    let nonce = Nonce::from_slice(&header[4..16]);

                    // Derive session subkey for client sending
                    let subkey =
                        derive_udp_session_key(self.cipher, &self.psk, self.client_session_id);

                    // Plaintext message: [TYPE=0 (1B)] [TIMESTAMP (8B)] [PADDING_LEN=0 (2B)] [Address] [Payload]
                    let mut message =
                        Vec::with_capacity(1 + 8 + 2 + self.target_addr.len() + payload.len() + 16);
                    message.push(0x00); // Client socket type
                    message.extend_from_slice(&now.to_be_bytes());
                    message.extend_from_slice(&0u16.to_be_bytes()); // No padding on active client payload
                    message.extend_from_slice(&self.target_addr);
                    message.extend_from_slice(payload);

                    // AEAD seal
                    if self.cipher == Cipher::Aead2022Blake3Aes128Gcm {
                        let cipher = Aes128Gcm::new_from_slice(&subkey).map_err(|_| {
                            std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid key")
                        })?;
                        cipher
                            .encrypt_in_place(nonce, b"", &mut message)
                            .map_err(|_| {
                                std::io::Error::new(std::io::ErrorKind::InvalidData, "crypto error")
                            })?;
                    } else {
                        let cipher = Aes256Gcm::new_from_slice(&subkey).map_err(|_| {
                            std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid key")
                        })?;
                        cipher
                            .encrypt_in_place(nonce, b"", &mut message)
                            .map_err(|_| {
                                std::io::Error::new(std::io::ErrorKind::InvalidData, "crypto error")
                            })?;
                    }

                    // Obfuscate 16-byte header with AES-ECB
                    encrypt_header_block(self.cipher, &self.psk, &mut header);

                    // Send [Encrypted Header (16B)] [Encrypted Message]
                    let mut wire = Vec::with_capacity(16 + message.len());
                    wire.extend_from_slice(&header);
                    wire.extend_from_slice(&message);
                    self.socket.send(&wire).await?;
                }
                Cipher::Aead2022Blake3ChaCha20Poly1305 => {
                    let mut nonce_bytes = [0u8; 24];
                    getrandom::fill(&mut nonce_bytes).expect("OS random failure");
                    let nonce = XNonce::from_slice(&nonce_bytes);

                    // Message plaintext: [Client Session ID (8B)] [Packet ID (8B)] [TYPE=0 (1B)] [TIMESTAMP (8B)] [PADDING_LEN=0 (2B)] [Address] [Payload]
                    let mut message = Vec::with_capacity(
                        8 + 8 + 1 + 8 + 2 + self.target_addr.len() + payload.len() + 16,
                    );
                    message.extend_from_slice(&self.client_session_id.to_be_bytes());
                    message.extend_from_slice(&pid.to_be_bytes());
                    message.push(0x00);
                    message.extend_from_slice(&now.to_be_bytes());
                    message.extend_from_slice(&0u16.to_be_bytes());
                    message.extend_from_slice(&self.target_addr);
                    message.extend_from_slice(payload);

                    let cipher = XChaCha20Poly1305::new_from_slice(&self.psk).map_err(|_| {
                        std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid key")
                    })?;
                    cipher
                        .encrypt_in_place(nonce, b"", &mut message)
                        .map_err(|_| {
                            std::io::Error::new(std::io::ErrorKind::InvalidData, "crypto error")
                        })?;

                    let mut wire = Vec::with_capacity(24 + message.len());
                    wire.extend_from_slice(&nonce_bytes);
                    wire.extend_from_slice(&message);
                    self.socket.send(&wire).await?;
                }
                _ => unreachable!("ShadowSocks2022DatagramSession used for non-2022 cipher"),
            }

            Ok(payload.len())
        })
    }

    fn recv<'a>(
        &'a self,
        buffer: &'a mut [u8],
    ) -> Pin<Box<dyn std::future::Future<Output = Result<usize, std::io::Error>> + Send + 'a>> {
        Box::pin(async move {
            let mut raw = vec![0u8; 65535];
            let read = self.socket.recv(&mut raw).await?;

            let decrypted = match self.cipher {
                Cipher::Aead2022Blake3Aes128Gcm | Cipher::Aead2022Blake3Aes256Gcm => {
                    // Min len: 16 (header) + 1 (type) + 8 (ts) + 8 (client session id) + 2 (pad) + 16 (tag)
                    if read < 16 + 1 + 8 + 8 + 2 + 16 {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "2022 datagram too short",
                        ));
                    }
                    let mut header = [0u8; 16];
                    header.copy_from_slice(&raw[..16]);
                    decrypt_header_block(self.cipher, &self.psk, &mut header);

                    let server_session_id = u64::from_be_bytes(header[0..8].try_into().unwrap());
                    let nonce = Nonce::from_slice(&header[4..16]);
                    let subkey = derive_udp_session_key(self.cipher, &self.psk, server_session_id);

                    let mut ciphertext = raw[16..read].to_vec();
                    if self.cipher == Cipher::Aead2022Blake3Aes128Gcm {
                        let cipher = Aes128Gcm::new_from_slice(&subkey).map_err(|_| {
                            std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid key")
                        })?;
                        cipher
                            .decrypt_in_place(nonce, b"", &mut ciphertext)
                            .map_err(|_| {
                                std::io::Error::new(std::io::ErrorKind::InvalidData, "auth failed")
                            })?;
                    } else {
                        let cipher = Aes256Gcm::new_from_slice(&subkey).map_err(|_| {
                            std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid key")
                        })?;
                        cipher
                            .decrypt_in_place(nonce, b"", &mut ciphertext)
                            .map_err(|_| {
                                std::io::Error::new(std::io::ErrorKind::InvalidData, "auth failed")
                            })?;
                    }

                    // Server message format:
                    // [TYPE=1 (1B)] [TIMESTAMP (8B)] [CLIENT_SESSION_ID (8B)] [PADDING_LEN (2B)] [PADDING] [ADDR] [PAYLOAD]
                    if ciphertext.len() < 1 + 8 + 8 + 2 {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "truncated response",
                        ));
                    }
                    if ciphertext[0] != 0x01 {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "invalid response type",
                        ));
                    }
                    let server_time = u64::from_be_bytes(ciphertext[1..9].try_into().unwrap());
                    if current_timestamp().abs_diff(server_time) > TIMESTAMP_TOLERANCE_SECS {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "clock skew too large",
                        ));
                    }
                    let echoed_client_session_id =
                        u64::from_be_bytes(ciphertext[9..17].try_into().unwrap());
                    if echoed_client_session_id != self.client_session_id {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "client session ID mismatch",
                        ));
                    }
                    let padding_len =
                        u16::from_be_bytes(ciphertext[17..19].try_into().unwrap()) as usize;
                    let offset = 19 + padding_len;
                    if offset > ciphertext.len() {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "padding exceeds buffer",
                        ));
                    }
                    ciphertext[offset..].to_vec()
                }
                Cipher::Aead2022Blake3ChaCha20Poly1305 => {
                    // Min len: 24 (nonce) + 8 (srv session) + 8 (pid) + 1 (type) + 8 (ts) + 8 (client session id) + 2 (pad) + 16 (tag)
                    if read < 24 + 8 + 8 + 1 + 8 + 8 + 2 + 16 {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "2022 datagram too short",
                        ));
                    }
                    let nonce = XNonce::from_slice(&raw[..24]);
                    let mut ciphertext = raw[24..read].to_vec();
                    let cipher = XChaCha20Poly1305::new_from_slice(&self.psk).map_err(|_| {
                        std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid key")
                    })?;
                    cipher
                        .decrypt_in_place(nonce, b"", &mut ciphertext)
                        .map_err(|_| {
                            std::io::Error::new(std::io::ErrorKind::InvalidData, "auth failed")
                        })?;

                    // [Server Session ID (8B)] [Packet ID (8B)] [TYPE=1 (1B)] [TIMESTAMP (8B)] [CLIENT_SESSION_ID (8B)] [PADDING_LEN (2B)] [PADDING] [ADDR] [PAYLOAD]
                    if ciphertext.len() < 8 + 8 + 1 + 8 + 8 + 2 {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "truncated response",
                        ));
                    }
                    if ciphertext[16] != 0x01 {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "invalid response type",
                        ));
                    }
                    let server_time = u64::from_be_bytes(ciphertext[17..25].try_into().unwrap());
                    if current_timestamp().abs_diff(server_time) > TIMESTAMP_TOLERANCE_SECS {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "clock skew too large",
                        ));
                    }
                    let echoed_client_session_id =
                        u64::from_be_bytes(ciphertext[25..33].try_into().unwrap());
                    if echoed_client_session_id != self.client_session_id {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "client session ID mismatch",
                        ));
                    }
                    let padding_len =
                        u16::from_be_bytes(ciphertext[33..35].try_into().unwrap()) as usize;
                    let offset = 35 + padding_len;
                    if offset > ciphertext.len() {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "padding exceeds buffer",
                        ));
                    }
                    ciphertext[offset..].to_vec()
                }
                _ => unreachable!(),
            };

            // Parse address and return payload
            let mut cursor = 0;
            if decrypted.is_empty() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "empty payload",
                ));
            }
            let atyp = decrypted[cursor];
            cursor += 1;
            match atyp {
                atyp::IPV4 => cursor += 4 + 2,
                atyp::IPV6 => cursor += 16 + 2,
                atyp::DOMAIN => {
                    let dlen = decrypted.get(cursor).copied().ok_or_else(|| {
                        std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "bad domain len")
                    })? as usize;
                    cursor += 1 + dlen + 2;
                }
                _ => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "bad atyp in shadowsocks 2022 udp reply",
                    ));
                }
            }
            if cursor > decrypted.len() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "header exceeds payload",
                ));
            }
            let payload = &decrypted[cursor..];
            let to_copy = payload.len().min(buffer.len());
            buffer[..to_copy].copy_from_slice(&payload[..to_copy]);
            Ok(to_copy)
        })
    }

    fn max_datagram_size(&self) -> usize {
        65507
    }
}
