// SPDX-License-Identifier: AGPL-3.0-only

//! Shadowsocks 2017 AEAD UDP datagram session.

use std::fmt;
use std::pin::Pin;
use std::sync::Arc;

use netune::DatagramTransport;

use super::crypto::{Opener, Sealer};
use crate::shadowsocks::Cipher;
use crate::shadowsocks::connector::atyp;

/// A datagram session over Shadowsocks 2017 AEAD.
pub struct ShadowSocksDatagramSession {
    socket: Arc<tokio::net::UdpSocket>,
    cipher: Cipher,
    master: Vec<u8>,
    target_addr: Vec<u8>,
}

impl fmt::Debug for ShadowSocksDatagramSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShadowSocksDatagramSession")
            .field("cipher", &self.cipher)
            .finish_non_exhaustive()
    }
}

impl ShadowSocksDatagramSession {
    #[must_use]
    pub fn new(
        socket: Arc<tokio::net::UdpSocket>,
        cipher: Cipher,
        master: Vec<u8>,
        target_addr: Vec<u8>,
    ) -> Self {
        Self {
            socket,
            cipher,
            master,
            target_addr,
        }
    }
}

impl DatagramTransport for ShadowSocksDatagramSession {
    fn send<'a>(
        &'a self,
        payload: &'a [u8],
    ) -> Pin<Box<dyn std::future::Future<Output = Result<usize, std::io::Error>> + Send + 'a>> {
        Box::pin(async move {
            let mut salt = vec![0u8; self.cipher.salt_len()];
            getrandom::fill(&mut salt).expect("OS random failure");
            let mut sealer = Sealer::new(self.cipher, &self.master, &salt);
            let mut packet =
                Vec::with_capacity(self.target_addr.len() + payload.len() + self.cipher.tag_len());
            packet.extend_from_slice(&self.target_addr);
            packet.extend_from_slice(payload);
            sealer.seal_record(&mut packet).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "crypto error")
            })?;

            let mut wire = Vec::with_capacity(salt.len() + packet.len());
            wire.extend_from_slice(&salt);
            wire.extend_from_slice(&packet);
            self.socket.send(&wire).await?;
            Ok(payload.len())
        })
    }

    fn recv<'a>(
        &'a self,
        buffer: &'a mut [u8],
    ) -> Pin<Box<dyn std::future::Future<Output = Result<usize, std::io::Error>> + Send + 'a>> {
        Box::pin(async move {
            let salt_len = self.cipher.salt_len();
            let tag_len = self.cipher.tag_len();
            let mut raw = vec![0u8; 65535];
            let read = self.socket.recv(&mut raw).await?;
            if read < salt_len + tag_len {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "datagram too short",
                ));
            }
            let salt = &raw[..salt_len];
            let mut ciphertext = raw[salt_len..read].to_vec();
            let mut opener = Opener::new(self.cipher, &self.master, salt);
            opener
                .open_record(&mut ciphertext)
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "auth failed"))?;

            let mut cursor = 0;
            if ciphertext.is_empty() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "empty payload",
                ));
            }
            let atyp = ciphertext[cursor];
            cursor += 1;
            match atyp {
                atyp::IPV4 => cursor += 4 + 2,
                atyp::IPV6 => cursor += 16 + 2,
                atyp::DOMAIN => {
                    let dlen = ciphertext.get(cursor).copied().ok_or_else(|| {
                        std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "bad domain len")
                    })? as usize;
                    cursor += 1 + dlen + 2;
                }
                _ => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "bad atyp in shadowsocks udp reply",
                    ));
                }
            }
            if cursor > ciphertext.len() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "header exceeds payload",
                ));
            }
            let payload = &ciphertext[cursor..];
            let to_copy = payload.len().min(buffer.len());
            buffer[..to_copy].copy_from_slice(&payload[..to_copy]);
            Ok(to_copy)
        })
    }

    fn max_datagram_size(&self) -> usize {
        65507
    }
}
