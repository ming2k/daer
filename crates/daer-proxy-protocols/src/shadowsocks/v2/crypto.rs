// SPDX-License-Identifier: AGPL-3.0-only

//! Shadowsocks 2022 (SIP022) cryptographic primitives:
//! BLAKE3 key derivation, AES-ECB header obfuscation, and per-record AEAD sealing/opening.

use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::{Aes128, Aes256, Block};
use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce};
use chacha20poly1305::ChaCha20Poly1305;

use crate::shadowsocks::{Cipher, DecryptError};

/// Context string for BLAKE3 key derivation as specified in SIP022.
pub const BLAKE3_KEY_DERIVE_CONTEXT: &str = "shadowsocks 2022 session subkey";

/// Derives a TCP session subkey from a PSK and salt via BLAKE3 KDF.
#[must_use]
pub fn derive_tcp_session_key(cipher: Cipher, psk: &[u8], salt: &[u8]) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new_derive_key(BLAKE3_KEY_DERIVE_CONTEXT);
    hasher.update(psk);
    hasher.update(salt);
    let mut output = hasher.finalize_xof();
    let mut subkey = vec![0u8; cipher.key_len()];
    output.fill(&mut subkey);
    subkey
}

/// Derives a UDP session subkey from a PSK and 64-bit session ID via BLAKE3 KDF.
#[must_use]
pub fn derive_udp_session_key(cipher: Cipher, psk: &[u8], session_id: u64) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new_derive_key(BLAKE3_KEY_DERIVE_CONTEXT);
    hasher.update(psk);
    hasher.update(&session_id.to_be_bytes());
    let mut output = hasher.finalize_xof();
    let mut subkey = vec![0u8; cipher.key_len()];
    output.fill(&mut subkey);
    subkey
}

/// Obfuscates a 16-byte UDP header [SessionID || PacketID] with PSK using AES-ECB.
pub fn encrypt_header_block(cipher: Cipher, psk: &[u8], block: &mut [u8; 16]) {
    match cipher {
        Cipher::Aead2022Blake3Aes128Gcm => {
            let aes = Aes128::new_from_slice(psk).expect("AES-128 key length 16");
            let b = Block::from_mut_slice(block);
            aes.encrypt_block(b);
        }
        Cipher::Aead2022Blake3Aes256Gcm => {
            let aes = Aes256::new_from_slice(psk).expect("AES-256 key length 32");
            let b = Block::from_mut_slice(block);
            aes.encrypt_block(b);
        }
        _ => panic!("encrypt_header_block only applies to AES-GCM 2022 ciphers"),
    }
}

/// De-obfuscates a 16-byte UDP header [SessionID || PacketID] with PSK using AES-ECB.
pub fn decrypt_header_block(cipher: Cipher, psk: &[u8], block: &mut [u8; 16]) {
    match cipher {
        Cipher::Aead2022Blake3Aes128Gcm => {
            let aes = Aes128::new_from_slice(psk).expect("AES-128 key length 16");
            let b = Block::from_mut_slice(block);
            aes.decrypt_block(b);
        }
        Cipher::Aead2022Blake3Aes256Gcm => {
            let aes = Aes256::new_from_slice(psk).expect("AES-256 key length 32");
            let b = Block::from_mut_slice(block);
            aes.decrypt_block(b);
        }
        _ => panic!("decrypt_header_block only applies to AES-GCM 2022 ciphers"),
    }
}

/// A 12-byte nonce counter incremented per AEAD record in little-endian order.
#[derive(Debug, Clone)]
pub struct Nonce12 {
    value: [u8; 12],
}

impl Nonce12 {
    #[must_use]
    pub const fn new() -> Self {
        Self { value: [0; 12] }
    }

    #[must_use]
    pub const fn bytes(&self) -> &[u8; 12] {
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

impl Default for Nonce12 {
    fn default() -> Self {
        Self::new()
    }
}

/// The sealing half of a Shadowsocks 2022 AEAD stream.
#[derive(Debug)]
pub struct Sealer2022 {
    cipher: Cipher,
    key: Vec<u8>,
    nonce12: Nonce12,
}

impl Sealer2022 {
    #[must_use]
    pub fn new(cipher: Cipher, session_key: &[u8]) -> Self {
        Self {
            cipher,
            key: session_key.to_vec(),
            nonce12: Nonce12::new(),
        }
    }

    pub fn seal_record(&mut self, buffer: &mut Vec<u8>) -> Result<(), DecryptError> {
        match self.cipher {
            Cipher::Aead2022Blake3Aes128Gcm => {
                let cipher = Aes128Gcm::new_from_slice(&self.key).map_err(|_| DecryptError)?;
                cipher
                    .encrypt_in_place(Nonce::from_slice(self.nonce12.bytes()), b"", buffer)
                    .map_err(|_| DecryptError)?;
                self.nonce12.increment();
            }
            Cipher::Aead2022Blake3Aes256Gcm => {
                let cipher = Aes256Gcm::new_from_slice(&self.key).map_err(|_| DecryptError)?;
                cipher
                    .encrypt_in_place(Nonce::from_slice(self.nonce12.bytes()), b"", buffer)
                    .map_err(|_| DecryptError)?;
                self.nonce12.increment();
            }
            Cipher::Aead2022Blake3ChaCha20Poly1305 => {
                let cipher =
                    ChaCha20Poly1305::new_from_slice(&self.key).map_err(|_| DecryptError)?;
                cipher
                    .encrypt_in_place(Nonce::from_slice(self.nonce12.bytes()), b"", buffer)
                    .map_err(|_| DecryptError)?;
                self.nonce12.increment();
            }
            _ => unreachable!("Sealer2022 invoked for non-2022 cipher"),
        }
        Ok(())
    }

    pub fn seal_chunk(&mut self, payload: &[u8]) -> Result<Vec<u8>, DecryptError> {
        debug_assert!(payload.len() <= self.cipher.max_payload());
        let mut length_record = Vec::with_capacity(2 + 16);
        length_record.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        self.seal_record(&mut length_record)?;

        let mut payload_record = payload.to_vec();
        self.seal_record(&mut payload_record)?;

        length_record.extend_from_slice(&payload_record);
        Ok(length_record)
    }
}

/// The opening half of a Shadowsocks 2022 AEAD stream.
#[derive(Debug)]
pub struct Opener2022 {
    cipher: Cipher,
    key: Vec<u8>,
    nonce12: Nonce12,
}

impl Opener2022 {
    #[must_use]
    pub fn new(cipher: Cipher, session_key: &[u8]) -> Self {
        Self {
            cipher,
            key: session_key.to_vec(),
            nonce12: Nonce12::new(),
        }
    }

    pub fn open_record(&mut self, buffer: &mut Vec<u8>) -> Result<(), DecryptError> {
        match self.cipher {
            Cipher::Aead2022Blake3Aes128Gcm => {
                let cipher = Aes128Gcm::new_from_slice(&self.key).map_err(|_| DecryptError)?;
                cipher
                    .decrypt_in_place(Nonce::from_slice(self.nonce12.bytes()), b"", buffer)
                    .map_err(|_| DecryptError)?;
                self.nonce12.increment();
            }
            Cipher::Aead2022Blake3Aes256Gcm => {
                let cipher = Aes256Gcm::new_from_slice(&self.key).map_err(|_| DecryptError)?;
                cipher
                    .decrypt_in_place(Nonce::from_slice(self.nonce12.bytes()), b"", buffer)
                    .map_err(|_| DecryptError)?;
                self.nonce12.increment();
            }
            Cipher::Aead2022Blake3ChaCha20Poly1305 => {
                let cipher =
                    ChaCha20Poly1305::new_from_slice(&self.key).map_err(|_| DecryptError)?;
                cipher
                    .decrypt_in_place(Nonce::from_slice(self.nonce12.bytes()), b"", buffer)
                    .map_err(|_| DecryptError)?;
                self.nonce12.increment();
            }
            _ => unreachable!("Opener2022 invoked for non-2022 cipher"),
        }
        Ok(())
    }

    #[must_use]
    pub const fn length_record_len(&self) -> usize {
        2 + 16
    }

    pub fn open_length(&mut self, record: &[u8]) -> Result<usize, DecryptError> {
        if record.len() != self.length_record_len() {
            return Err(DecryptError);
        }
        let mut buffer = record.to_vec();
        self.open_record(&mut buffer)?;
        let length = usize::from(u16::from_be_bytes([buffer[0], buffer[1]]));
        if length > self.cipher.max_payload() {
            return Err(DecryptError);
        }
        Ok(length)
    }

    pub fn open_payload(&mut self, record: &[u8]) -> Result<Vec<u8>, DecryptError> {
        let mut buffer = record.to_vec();
        self.open_record(&mut buffer)?;
        Ok(buffer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blake3_kdf_deterministic() {
        let psk = [0x55u8; 16];
        let salt = [0xAAu8; 16];
        let k1 = derive_tcp_session_key(Cipher::Aead2022Blake3Aes128Gcm, &psk, &salt);
        let k2 = derive_tcp_session_key(Cipher::Aead2022Blake3Aes128Gcm, &psk, &salt);
        assert_eq!(k1.len(), 16);
        assert_eq!(k1, k2);

        let k_diff = derive_tcp_session_key(Cipher::Aead2022Blake3Aes128Gcm, &psk, &[0xAB; 16]);
        assert_ne!(k1, k_diff);
    }

    #[test]
    fn test_aes_ecb_header_round_trip() {
        let psk16 = [0x42u8; 16];
        let mut header = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
            0xff, 0x00,
        ];
        let orig = header;
        encrypt_header_block(Cipher::Aead2022Blake3Aes128Gcm, &psk16, &mut header);
        assert_ne!(header, orig);
        decrypt_header_block(Cipher::Aead2022Blake3Aes128Gcm, &psk16, &mut header);
        assert_eq!(header, orig);

        let psk32 = [0x77u8; 32];
        let mut header32 = orig;
        encrypt_header_block(Cipher::Aead2022Blake3Aes256Gcm, &psk32, &mut header32);
        assert_ne!(header32, orig);
        decrypt_header_block(Cipher::Aead2022Blake3Aes256Gcm, &psk32, &mut header32);
        assert_eq!(header32, orig);
    }

    #[test]
    fn test_sealer_opener_round_trip() {
        for cipher in [
            Cipher::Aead2022Blake3Aes128Gcm,
            Cipher::Aead2022Blake3Aes256Gcm,
            Cipher::Aead2022Blake3ChaCha20Poly1305,
        ] {
            let psk = vec![0x12; cipher.key_len()];
            let salt = vec![0x34; cipher.salt_len()];
            let subkey = derive_tcp_session_key(cipher, &psk, &salt);

            let mut sealer = Sealer2022::new(cipher, &subkey);
            let mut opener = Opener2022::new(cipher, &subkey);

            let payload = b"hello world 2022";
            let sealed = sealer.seal_chunk(payload).expect("seals chunk");

            let len_len = opener.length_record_len();
            let len = opener
                .open_length(&sealed[..len_len])
                .expect("opens length");
            assert_eq!(len, payload.len());

            let opened = opener
                .open_payload(&sealed[len_len..])
                .expect("opens payload");
            assert_eq!(&opened, payload);
        }
    }
}
