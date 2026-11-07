// SPDX-License-Identifier: AGPL-3.0-only

//! An independent Shadowsocks 2022 (SIP022) server implementation used solely for verification.
//! Written strictly from the protocol specification without reusing the client's internal modules.

use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::{Aes128, Aes256, Block};
use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce};
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305, XNonce};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::oneshot;

pub const BLAKE3_CONTEXT: &str = "shadowsocks 2022 session subkey";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method2022 {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl Method2022 {
    pub fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm | Self::ChaCha20Poly1305 => 32,
        }
    }

    pub fn salt_len(self) -> usize {
        self.key_len()
    }
}

pub fn derive_key(method: Method2022, psk: &[u8], salt: &[u8]) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new_derive_key(BLAKE3_CONTEXT);
    hasher.update(psk);
    hasher.update(salt);
    let mut out = hasher.finalize_xof();
    let mut subkey = vec![0u8; method.key_len()];
    out.fill(&mut subkey);
    subkey
}

pub struct Counter12 {
    value: [u8; 12],
}

impl Counter12 {
    pub fn new() -> Self {
        Self { value: [0; 12] }
    }

    pub fn bytes(&self) -> &[u8; 12] {
        &self.value
    }

    pub fn increment(&mut self) {
        for byte in &mut self.value {
            let (next, overflow) = byte.overflowing_add(1);
            *byte = next;
            if !overflow {
                return;
            }
        }
    }
}

pub fn seal(method: Method2022, key: &[u8], nonce: &[u8; 12], buffer: &mut Vec<u8>) {
    match method {
        Method2022::Aes128Gcm => {
            let cipher = Aes128Gcm::new_from_slice(key).unwrap();
            cipher
                .encrypt_in_place(Nonce::from_slice(nonce), b"", buffer)
                .unwrap();
        }
        Method2022::Aes256Gcm => {
            let cipher = Aes256Gcm::new_from_slice(key).unwrap();
            cipher
                .encrypt_in_place(Nonce::from_slice(nonce), b"", buffer)
                .unwrap();
        }
        Method2022::ChaCha20Poly1305 => {
            let cipher = ChaCha20Poly1305::new_from_slice(key).unwrap();
            cipher
                .encrypt_in_place(Nonce::from_slice(nonce), b"", buffer)
                .unwrap();
        }
    }
}

pub fn open(method: Method2022, key: &[u8], nonce: &[u8; 12], buffer: &mut Vec<u8>) -> bool {
    match method {
        Method2022::Aes128Gcm => {
            let Ok(cipher) = Aes128Gcm::new_from_slice(key) else {
                return false;
            };
            cipher
                .decrypt_in_place(Nonce::from_slice(nonce), b"", buffer)
                .is_ok()
        }
        Method2022::Aes256Gcm => {
            let Ok(cipher) = Aes256Gcm::new_from_slice(key) else {
                return false;
            };
            cipher
                .decrypt_in_place(Nonce::from_slice(nonce), b"", buffer)
                .is_ok()
        }
        Method2022::ChaCha20Poly1305 => {
            let Ok(cipher) = ChaCha20Poly1305::new_from_slice(key) else {
                return false;
            };
            cipher
                .decrypt_in_place(Nonce::from_slice(nonce), b"", buffer)
                .is_ok()
        }
    }
}

#[derive(Debug)]
pub struct Observed2022 {
    pub target: String,
    pub padding_len: usize,
    pub payload: Vec<u8>,
}

#[derive(Default)]
pub struct ServerBehavior {
    pub clock_skew_secs: i64,
    pub tamper_request_salt: bool,
}

pub async fn serve_2022(
    method: Method2022,
    psk: Vec<u8>,
    behavior: ServerBehavior,
) -> (SocketAddr, oneshot::Receiver<Observed2022>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("binds");
    let address = listener.local_addr().expect("local address");
    let (tx, rx) = oneshot::channel();

    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accepts");
        let salt_len = method.salt_len();

        let mut client_salt = vec![0u8; salt_len];
        if socket.read_exact(&mut client_salt).await.is_err() {
            return;
        }

        let recv_key = derive_key(method, &psk, &client_salt);
        let mut recv_counter = Counter12::new();

        // 1. Read Header Chunk: 11 bytes plain + 16 bytes tag = 27 bytes
        let mut header_chunk = vec![0u8; 27];
        if socket.read_exact(&mut header_chunk).await.is_err() {
            return;
        }

        if !open(method, &recv_key, recv_counter.bytes(), &mut header_chunk) {
            return;
        }
        recv_counter.increment();

        let stream_type = header_chunk[0];
        assert_eq!(stream_type, 0x00, "client stream type must be 0");
        let client_timestamp = u64::from_be_bytes(header_chunk[1..9].try_into().unwrap());
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(now.abs_diff(client_timestamp) <= 30, "timestamp check");
        let first_data_len = u16::from_be_bytes(header_chunk[9..11].try_into().unwrap()) as usize;

        // 2. Read First Data Chunk
        let mut first_data = vec![0u8; first_data_len + 16];
        if socket.read_exact(&mut first_data).await.is_err() {
            return;
        }
        if !open(method, &recv_key, recv_counter.bytes(), &mut first_data) {
            return;
        }
        recv_counter.increment();

        // Parse address: atyp (1B)
        let atyp = first_data[0];
        let (target, offset) = match atyp {
            1 => {
                let ip = std::net::Ipv4Addr::new(
                    first_data[1],
                    first_data[2],
                    first_data[3],
                    first_data[4],
                );
                let port = u16::from_be_bytes([first_data[5], first_data[6]]);
                (format!("{ip}:{port}"), 7)
            }
            3 => {
                let dlen = first_data[1] as usize;
                let domain = std::str::from_utf8(&first_data[2..2 + dlen]).unwrap();
                let port = u16::from_be_bytes([first_data[2 + dlen], first_data[3 + dlen]]);
                (format!("{domain}:{port}"), 4 + dlen)
            }
            4 => {
                let ip =
                    std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&first_data[1..17]).unwrap());
                let port = u16::from_be_bytes([first_data[17], first_data[18]]);
                (format!("[{ip}]:{port}"), 19)
            }
            _ => panic!("invalid atyp {atyp}"),
        };

        let padding_len = u16::from_be_bytes([first_data[offset], first_data[offset + 1]]) as usize;
        let payload = first_data[offset + 2 + padding_len..first_data_len].to_vec();

        // Assert SIP022 rule: empty payload MUST carry non-zero padding (1..=900)
        if payload.is_empty() {
            assert!(
                (1..=900).contains(&padding_len),
                "SIP022 requires non-zero 1..=900 padding on empty initial payload, got {padding_len}"
            );
        }

        let _ = tx.send(Observed2022 {
            target,
            padding_len,
            payload,
        });

        // 3. Send Server Response
        let server_salt = vec![0x99u8; salt_len];
        if socket.write_all(&server_salt).await.is_err() {
            return;
        }

        let send_key = derive_key(method, &psk, &server_salt);
        let mut send_counter = Counter12::new();

        let resp_time = if behavior.clock_skew_secs != 0 {
            (now as i64 + behavior.clock_skew_secs) as u64
        } else {
            now
        };

        let echoed_salt = if behavior.tamper_request_salt {
            vec![0xEEu8; salt_len]
        } else {
            client_salt
        };

        // Response header chunk: [TYPE=1] [TIMESTAMP (8B)] [REQUEST_SALT] [DATA_LEN=5]
        let mut resp_header = Vec::new();
        resp_header.push(0x01); // Server stream type
        resp_header.extend_from_slice(&resp_time.to_be_bytes());
        resp_header.extend_from_slice(&echoed_salt);
        resp_header.extend_from_slice(&5u16.to_be_bytes()); // "hello" is 5 bytes

        seal(method, &send_key, send_counter.bytes(), &mut resp_header);
        send_counter.increment();
        if socket.write_all(&resp_header).await.is_err() {
            return;
        }

        // Response first data chunk: "hello"
        let mut resp_data = b"hello".to_vec();
        seal(method, &send_key, send_counter.bytes(), &mut resp_data);
        send_counter.increment();
        if socket.write_all(&resp_data).await.is_err() {
            return;
        }

        // Echo loop
        loop {
            // Read 2-byte length frame
            let mut len_record = vec![0u8; 18];
            if socket.read_exact(&mut len_record).await.is_err() {
                break;
            }
            if !open(method, &recv_key, recv_counter.bytes(), &mut len_record) {
                break;
            }
            recv_counter.increment();
            let dlen = u16::from_be_bytes([len_record[0], len_record[1]]) as usize;

            let mut data_record = vec![0u8; dlen + 16];
            if socket.read_exact(&mut data_record).await.is_err() {
                break;
            }
            if !open(method, &recv_key, recv_counter.bytes(), &mut data_record) {
                break;
            }
            recv_counter.increment();

            // Echo back
            let mut out_len = (dlen as u16).to_be_bytes().to_vec();
            seal(method, &send_key, send_counter.bytes(), &mut out_len);
            send_counter.increment();
            let mut out_data = data_record[..dlen].to_vec();
            seal(method, &send_key, send_counter.bytes(), &mut out_data);
            send_counter.increment();

            if socket.write_all(&out_len).await.is_err()
                || socket.write_all(&out_data).await.is_err()
            {
                break;
            }
        }
    });

    (address, rx)
}

/// A standalone UDP echo server for Shadowsocks 2022.
pub async fn serve_2022_udp(
    method: Method2022,
    psk: Vec<u8>,
) -> (SocketAddr, tokio::sync::mpsc::Receiver<Vec<u8>>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("binds udp");
    let addr = socket.local_addr().expect("udp addr");
    let (tx, rx) = tokio::sync::mpsc::channel(16);

    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        while let Ok((len, peer)) = socket.recv_from(&mut buf).await {
            let packet = &mut buf[..len];
            match method {
                Method2022::Aes128Gcm | Method2022::Aes256Gcm => {
                    if packet.len() < 16 + 1 + 8 + 2 + 16 {
                        continue;
                    }
                    let (header, message) = packet.split_at_mut(16);
                    // Decrypt AES-ECB header
                    if method == Method2022::Aes128Gcm {
                        let cipher = Aes128::new_from_slice(&psk).unwrap();
                        cipher.decrypt_block(Block::from_mut_slice(header));
                    } else {
                        let cipher = Aes256::new_from_slice(&psk).unwrap();
                        cipher.decrypt_block(Block::from_mut_slice(header));
                    }
                    let client_session_id = u64::from_be_bytes(header[..8].try_into().unwrap());
                    let _packet_id = u64::from_be_bytes(header[8..16].try_into().unwrap());
                    let nonce = Nonce::from_slice(&header[4..16]);

                    // Derive client sending key
                    let subkey = {
                        let mut h = blake3::Hasher::new_derive_key(BLAKE3_CONTEXT);
                        h.update(&psk);
                        h.update(&client_session_id.to_be_bytes());
                        let mut out = h.finalize_xof();
                        let mut k = vec![0u8; method.key_len()];
                        out.fill(&mut k);
                        k
                    };

                    let mut msg_vec = message.to_vec();
                    let ok = if method == Method2022::Aes128Gcm {
                        Aes128Gcm::new_from_slice(&subkey)
                            .unwrap()
                            .decrypt_in_place(nonce, b"", &mut msg_vec)
                            .is_ok()
                    } else {
                        Aes256Gcm::new_from_slice(&subkey)
                            .unwrap()
                            .decrypt_in_place(nonce, b"", &mut msg_vec)
                            .is_ok()
                    };
                    if !ok {
                        continue;
                    }

                    // Message: [TYPE=0] [TS(8B)] [PAD_LEN(2B)] [Address] [Payload]
                    let pad_len = u16::from_be_bytes([msg_vec[9], msg_vec[10]]) as usize;
                    let payload_offset = 11 + pad_len + 7; // assuming 1.2.3.4:port (7 bytes)
                    let payload = msg_vec[payload_offset..].to_vec();
                    let _ = tx.send(payload.clone()).await;

                    // Send response back:
                    // Server Session ID = 0x1234567890abcdef
                    let server_session_id = 0x1234_5678_90ab_cdefu64;
                    let mut resp_header = [0u8; 16];
                    resp_header[..8].copy_from_slice(&server_session_id.to_be_bytes());
                    resp_header[8..16].copy_from_slice(&1u64.to_be_bytes()); // pid 1
                    let resp_nonce = Nonce::from_slice(&resp_header[4..16]);

                    let resp_subkey = {
                        let mut h = blake3::Hasher::new_derive_key(BLAKE3_CONTEXT);
                        h.update(&psk);
                        h.update(&server_session_id.to_be_bytes());
                        let mut out = h.finalize_xof();
                        let mut k = vec![0u8; method.key_len()];
                        out.fill(&mut k);
                        k
                    };

                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    // Response: [TYPE=1] [TS] [CLIENT_SESSION_ID] [PAD_LEN=0] [Address] [Payload]
                    let mut resp_body = Vec::new();
                    resp_body.push(0x01);
                    resp_body.extend_from_slice(&now.to_be_bytes());
                    resp_body.extend_from_slice(&client_session_id.to_be_bytes());
                    resp_body.extend_from_slice(&0u16.to_be_bytes());
                    resp_body.extend_from_slice(&[1, 1, 2, 3, 4, 1, 187]); // 1.2.3.4:443
                    resp_body.extend_from_slice(&payload);

                    if method == Method2022::Aes128Gcm {
                        Aes128Gcm::new_from_slice(&resp_subkey)
                            .unwrap()
                            .encrypt_in_place(resp_nonce, b"", &mut resp_body)
                            .unwrap();
                    } else {
                        Aes256Gcm::new_from_slice(&resp_subkey)
                            .unwrap()
                            .encrypt_in_place(resp_nonce, b"", &mut resp_body)
                            .unwrap();
                    }

                    if method == Method2022::Aes128Gcm {
                        Aes128::new_from_slice(&psk)
                            .unwrap()
                            .encrypt_block(Block::from_mut_slice(&mut resp_header));
                    } else {
                        Aes256::new_from_slice(&psk)
                            .unwrap()
                            .encrypt_block(Block::from_mut_slice(&mut resp_header));
                    }

                    let mut resp_wire = Vec::new();
                    resp_wire.extend_from_slice(&resp_header);
                    resp_wire.extend_from_slice(&resp_body);
                    let _ = socket.send_to(&resp_wire, peer).await;
                }
                Method2022::ChaCha20Poly1305 => {
                    if packet.len() < 24 + 8 + 8 + 1 + 8 + 2 + 16 {
                        continue;
                    }
                    let (nonce, message) = packet.split_at_mut(24);
                    let xnonce = XNonce::from_slice(nonce);
                    let cipher = XChaCha20Poly1305::new_from_slice(&psk).unwrap();
                    let mut msg_vec = message.to_vec();
                    if cipher.decrypt_in_place(xnonce, b"", &mut msg_vec).is_err() {
                        continue;
                    }

                    let client_session_id = u64::from_be_bytes(msg_vec[..8].try_into().unwrap());
                    let pad_len = u16::from_be_bytes([msg_vec[25], msg_vec[26]]) as usize;
                    let payload_offset = 27 + pad_len + 7;
                    let payload = msg_vec[payload_offset..].to_vec();
                    let _ = tx.send(payload.clone()).await;

                    // Response
                    let resp_nonce_bytes = [0x55u8; 24];
                    let resp_nonce = XNonce::from_slice(&resp_nonce_bytes);
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs();

                    let mut resp_msg = Vec::new();
                    resp_msg.extend_from_slice(&0x9999u64.to_be_bytes()); // server session id
                    resp_msg.extend_from_slice(&1u64.to_be_bytes()); // pid
                    resp_msg.push(0x01); // type
                    resp_msg.extend_from_slice(&now.to_be_bytes());
                    resp_msg.extend_from_slice(&client_session_id.to_be_bytes());
                    resp_msg.extend_from_slice(&0u16.to_be_bytes());
                    resp_msg.extend_from_slice(&[1, 1, 2, 3, 4, 1, 187]);
                    resp_msg.extend_from_slice(&payload);

                    cipher
                        .encrypt_in_place(resp_nonce, b"", &mut resp_msg)
                        .unwrap();
                    let mut resp_wire = Vec::new();
                    resp_wire.extend_from_slice(&resp_nonce_bytes);
                    resp_wire.extend_from_slice(&resp_msg);
                    let _ = socket.send_to(&resp_wire, peer).await;
                }
            }
        }
    });

    (addr, rx)
}
