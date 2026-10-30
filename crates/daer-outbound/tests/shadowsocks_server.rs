// SPDX-License-Identifier: AGPL-3.0-only

//! A shadowsocks server, written from the protocol description rather than by reusing the
//! client's code.
//!
//! # Why a separate server
//!
//! A test that decrypts with the same code that encrypted proves only that the cipher is
//! self-consistent. It cannot catch a wrong nonce order, a wrong little-endian counter, a
//! swapped length/payload framing, or a missing salt — because the same mistake exists on
//! both sides and cancels out.
//!
//! This server therefore shares **only** the primitive AEAD operations from `aes-gcm` and
//! `chacha20poly1305`. It derives its own subkey, keeps its own nonces, and parses the
//! framing itself. If the client deviates from the protocol, this fails — which is the whole
//! point.

use std::net::SocketAddr;
use std::sync::Arc;

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use md5::{Digest, Md5};
use sha1::Sha1;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// The server's own view of a cipher.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl Method {
    fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm | Self::ChaCha20Poly1305 => 32,
        }
    }

    fn open(self, key: &[u8], nonce: &[u8], buffer: &mut Vec<u8>) -> bool {
        match self {
            Self::Aes128Gcm => Aes128Gcm::new_from_slice(key).ok().is_some_and(|cipher| {
                cipher
                    .decrypt_in_place(Nonce::from_slice(nonce), b"", buffer)
                    .is_ok()
            }),
            Self::Aes256Gcm => Aes256Gcm::new_from_slice(key).ok().is_some_and(|cipher| {
                cipher
                    .decrypt_in_place(Nonce::from_slice(nonce), b"", buffer)
                    .is_ok()
            }),
            Self::ChaCha20Poly1305 => {
                ChaCha20Poly1305::new_from_slice(key)
                    .ok()
                    .is_some_and(|cipher| {
                        cipher
                            .decrypt_in_place(Nonce::from_slice(nonce), b"", buffer)
                            .is_ok()
                    })
            }
        }
    }

    fn seal(self, key: &[u8], nonce: &[u8], buffer: &mut Vec<u8>) -> bool {
        match self {
            Self::Aes128Gcm => Aes128Gcm::new_from_slice(key).ok().is_some_and(|cipher| {
                cipher
                    .encrypt_in_place(Nonce::from_slice(nonce), b"", buffer)
                    .is_ok()
            }),
            Self::Aes256Gcm => Aes256Gcm::new_from_slice(key).ok().is_some_and(|cipher| {
                cipher
                    .encrypt_in_place(Nonce::from_slice(nonce), b"", buffer)
                    .is_ok()
            }),
            Self::ChaCha20Poly1305 => {
                ChaCha20Poly1305::new_from_slice(key)
                    .ok()
                    .is_some_and(|cipher| {
                        cipher
                            .encrypt_in_place(Nonce::from_slice(nonce), b"", buffer)
                            .is_ok()
                    })
            }
        }
    }
}

/// `EVP_BytesToKey`, written out again so a bug in the client's KDF shows up here.
fn server_master_key(method: Method, password: &str) -> Vec<u8> {
    let mut key = Vec::new();
    let mut previous: Vec<u8> = Vec::new();
    while key.len() < method.key_len() {
        let mut hasher = Md5::new();
        hasher.update(&previous);
        hasher.update(password.as_bytes());
        previous = hasher.finalize().to_vec();
        key.extend_from_slice(&previous);
    }
    key.truncate(method.key_len());
    key
}

fn server_subkey(method: Method, master: &[u8], salt: &[u8]) -> Vec<u8> {
    let hkdf = Hkdf::<Sha1>::new(Some(salt), master);
    let mut key = vec![0u8; method.key_len()];
    hkdf.expand(b"ss-subkey", &mut key).expect("valid length");
    key
}

/// A little-endian counting nonce.
struct Counter {
    value: [u8; 12],
}

impl Counter {
    fn new() -> Self {
        Self { value: [0; 12] }
    }
    fn increment(&mut self) {
        for byte in &mut self.value {
            let (next, overflow) = byte.overflowing_add(1);
            *byte = next;
            if !overflow {
                return;
            }
        }
    }
}

/// Reads one AEAD record of `plaintext_len` + 16 bytes of tag.
async fn read_record(
    stream: &mut TcpStream,
    method: Method,
    key: &[u8],
    counter: &mut Counter,
    plaintext_len: usize,
) -> Option<Vec<u8>> {
    let mut buffer = vec![0u8; plaintext_len + 16];
    stream.read_exact(&mut buffer).await.ok()?;
    if !method.open(key, &counter.value, &mut buffer) {
        return None;
    }
    counter.increment();
    Some(buffer)
}

async fn write_record(
    stream: &mut TcpStream,
    method: Method,
    key: &[u8],
    counter: &mut Counter,
    plaintext: &[u8],
) -> bool {
    let mut buffer = plaintext.to_vec();
    if !method.seal(key, &counter.value, &mut buffer) {
        return false;
    }
    counter.increment();
    stream.write_all(&buffer).await.is_ok()
}

/// What the server observed, for the test's assertions.
#[derive(Debug, Clone, Default)]
pub struct Observed {
    /// The target the client asked for, `host:port`.
    pub target: String,
    /// The first payload bytes after the address, if the client coalesced them.
    pub first_payload: Vec<u8>,
}

/// A running shadowsocks server that echoes whatever it receives back to the client.
///
/// It also reports the target the client requested, which is the part of the handshake that
/// the client's framing has to get exactly right.
pub async fn serve(
    method: Method,
    password: &'static str,
) -> (SocketAddr, tokio::sync::oneshot::Receiver<Observed>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("binds");
    let address = listener.local_addr().expect("addr");
    let (sender, receiver) = tokio::sync::oneshot::channel();
    let master = Arc::new(server_master_key(method, password));

    tokio::spawn(async move {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };

        // 1. The client's salt arrives before anything else.
        let mut client_salt = vec![0u8; method.key_len()];
        if stream.read_exact(&mut client_salt).await.is_err() {
            return;
        }
        let client_key = server_subkey(method, &master, &client_salt);

        // 2. The first record's length, then the address frame.
        let mut counter = Counter::new();
        let Some(length_record) =
            read_record(&mut stream, method, &client_key, &mut counter, 2).await
        else {
            return;
        };
        let length = usize::from(u16::from_be_bytes([length_record[0], length_record[1]]));
        let Some(address) =
            read_record(&mut stream, method, &client_key, &mut counter, length).await
        else {
            return;
        };
        let Some((target, used)) = decode_address(&address) else {
            return;
        };
        let first_payload = address[used..].to_vec();
        let _ = sender.send(Observed {
            target,
            first_payload: first_payload.clone(),
        });

        // 3. Answer: our salt, then the payload framed.
        let mut server_salt = vec![0u8; method.key_len()];
        for (index, byte) in server_salt.iter_mut().enumerate() {
            *byte = (index as u8).wrapping_mul(7).wrapping_add(1);
        }
        if stream.write_all(&server_salt).await.is_err() {
            return;
        }
        let server_key = server_subkey(method, &master, &server_salt);
        let mut server_counter = Counter::new();

        let echo = if first_payload.is_empty() {
            b"hello".to_vec()
        } else {
            first_payload
        };
        let mut length_frame = (echo.len() as u16).to_be_bytes().to_vec();
        if !write_record(
            &mut stream,
            method,
            &server_key,
            &mut server_counter,
            &length_frame,
        )
        .await
        {
            return;
        }
        length_frame.clear();
        if !write_record(&mut stream, method, &server_key, &mut server_counter, &echo).await {
            return;
        }

        // Drain whatever else the client sends, so a test can prove the stream stays usable.
        loop {
            let Some(length_record) =
                read_record(&mut stream, method, &client_key, &mut counter, 2).await
            else {
                return;
            };
            let length = usize::from(u16::from_be_bytes([length_record[0], length_record[1]]));
            let Some(payload) =
                read_record(&mut stream, method, &client_key, &mut counter, length).await
            else {
                return;
            };
            // Length record, then payload record: two records, two nonce increments.
            let length_record = (payload.len() as u16).to_be_bytes();
            if !write_record(
                &mut stream,
                method,
                &server_key,
                &mut server_counter,
                &length_record,
            )
            .await
            {
                return;
            }
            if !write_record(
                &mut stream,
                method,
                &server_key,
                &mut server_counter,
                &payload,
            )
            .await
            {
                return;
            }
        }
    });

    (address, receiver)
}

/// Decodes the address frame, returning it and how many bytes it used.
fn decode_address(bytes: &[u8]) -> Option<(String, usize)> {
    let atyp = *bytes.first()?;
    match atyp {
        1 => {
            let octets: [u8; 4] = bytes.get(1..5)?.try_into().ok()?;
            let port = u16::from_be_bytes(bytes.get(5..7)?.try_into().ok()?);
            Some((
                format!(
                    "{}.{}.{}.{}:{port}",
                    octets[0], octets[1], octets[2], octets[3]
                ),
                7,
            ))
        }
        3 => {
            let length = usize::from(*bytes.get(1)?);
            let host = std::str::from_utf8(bytes.get(2..2 + length)?).ok()?;
            let port_at = 2 + length;
            let port = u16::from_be_bytes(bytes.get(port_at..port_at + 2)?.try_into().ok()?);
            Some((format!("{host}:{port}"), port_at + 2))
        }
        4 => {
            let octets: [u8; 16] = bytes.get(1..17)?.try_into().ok()?;
            let address = std::net::Ipv6Addr::from(octets);
            let port = u16::from_be_bytes(bytes.get(17..19)?.try_into().ok()?);
            Some((format!("[{address}]:{port}"), 19))
        }
        _ => None,
    }
}

/// Builds a `ss://` link for `method`/`password`/`server`.
pub fn link(method: &str, password: &str, server: SocketAddr) -> String {
    fn encode(text: &str) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let bytes = text.as_bytes();
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let mut buffer = [0u8; 3];
            buffer[..chunk.len()].copy_from_slice(chunk);
            let value =
                (u32::from(buffer[0]) << 16) | (u32::from(buffer[1]) << 8) | u32::from(buffer[2]);
            out.push(ALPHABET[(value >> 18) as usize & 0x3f] as char);
            out.push(ALPHABET[(value >> 12) as usize & 0x3f] as char);
            if chunk.len() > 1 {
                out.push(ALPHABET[(value >> 6) as usize & 0x3f] as char);
            }
            if chunk.len() > 2 {
                out.push(ALPHABET[value as usize & 0x3f] as char);
            }
        }
        out
    }
    format!("ss://{}@{server}", encode(&format!("{method}:{password}")))
}
