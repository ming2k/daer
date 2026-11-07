// SPDX-License-Identifier: AGPL-3.0-only

//! Shadowsocks 2017 AEAD (SIP004 / SIP007): the cipher, key derivation and framing.

use std::collections::VecDeque;

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use md5::{Digest, Md5};
use sha1::Sha1;
use zeroize::Zeroize;

use crate::shadowsocks::{Cipher, DecryptError};

/// Derives the master key from a password.
///
/// `EVP_BytesToKey` with MD5 and no salt: the construction the protocol inherited from
/// OpenSSL and legacy clients still use.
#[must_use]
pub fn master_key(cipher: Cipher, password: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(cipher.key_len());
    let mut previous: Vec<u8> = Vec::new();
    while key.len() < cipher.key_len() {
        let mut hasher = Md5::new();
        hasher.update(&previous);
        hasher.update(password.as_bytes());
        previous = hasher.finalize().to_vec();
        key.extend_from_slice(&previous);
    }
    key.truncate(cipher.key_len());
    previous.zeroize();
    key
}

/// Derives a per-connection subkey from the master key and the salt.
#[must_use]
pub fn subkey(cipher: Cipher, master: &[u8], salt: &[u8]) -> Vec<u8> {
    // HKDF-SHA1 with the protocol's fixed info string
    let hkdf = Hkdf::<Sha1>::new(Some(salt), master);
    let mut key = vec![0u8; cipher.key_len()];
    hkdf.expand(b"ss-subkey", &mut key)
        .expect("the output length is a valid HKDF length");
    key
}

/// A nonce that counts up, little-endian (12 bytes).
#[derive(Debug, Clone)]
pub struct Nonce12 {
    value: [u8; 12],
}

impl Nonce12 {
    #[must_use]
    pub fn new() -> Self {
        Self { value: [0; 12] }
    }

    #[must_use]
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

impl Default for Nonce12 {
    fn default() -> Self {
        Self::new()
    }
}

/// A nonce that counts up, 24 bytes for XChaCha.
#[derive(Debug, Clone)]
pub struct Nonce24 {
    value: [u8; 24],
}

impl Nonce24 {
    #[must_use]
    pub fn new() -> Self {
        Self { value: [0; 24] }
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8; 24] {
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

impl Default for Nonce24 {
    fn default() -> Self {
        Self::new()
    }
}

/// One direction of an AEAD stream: the sealing half.
#[derive(Debug)]
pub struct Sealer {
    cipher: Cipher,
    master: Vec<u8>,
    key: Vec<u8>,
    nonce12: Nonce12,
    nonce24: Nonce24,
    salt: Vec<u8>,
}

impl Sealer {
    #[must_use]
    pub fn new(cipher: Cipher, master: &[u8], salt: &[u8]) -> Self {
        let key = subkey(cipher, master, salt);
        Self {
            cipher,
            master: master.to_vec(),
            key,
            nonce12: Nonce12::new(),
            nonce24: Nonce24::new(),
            salt: salt.to_vec(),
        }
    }

    #[must_use]
    pub fn salt(&self) -> &[u8] {
        &self.salt
    }

    #[must_use]
    pub fn master_key(&self) -> &[u8] {
        &self.master
    }

    pub fn seal_record(&mut self, buffer: &mut Vec<u8>) -> Result<(), DecryptError> {
        self.seal(buffer)
    }

    fn seal(&mut self, buffer: &mut Vec<u8>) -> Result<(), DecryptError> {
        match self.cipher {
            Cipher::Aes128Gcm => {
                let cipher = Aes128Gcm::new_from_slice(&self.key).map_err(|_| DecryptError)?;
                cipher
                    .encrypt_in_place(Nonce::from_slice(self.nonce12.bytes()), b"", buffer)
                    .map_err(|_| DecryptError)?;
                self.nonce12.increment();
            }
            Cipher::Aes256Gcm => {
                let cipher = Aes256Gcm::new_from_slice(&self.key).map_err(|_| DecryptError)?;
                cipher
                    .encrypt_in_place(Nonce::from_slice(self.nonce12.bytes()), b"", buffer)
                    .map_err(|_| DecryptError)?;
                self.nonce12.increment();
            }
            Cipher::ChaCha20Poly1305 => {
                let cipher =
                    ChaCha20Poly1305::new_from_slice(&self.key).map_err(|_| DecryptError)?;
                cipher
                    .encrypt_in_place(Nonce::from_slice(self.nonce12.bytes()), b"", buffer)
                    .map_err(|_| DecryptError)?;
                self.nonce12.increment();
            }
            Cipher::XChaCha20Poly1305 => {
                use chacha20poly1305::{XChaCha20Poly1305, XNonce};
                let cipher =
                    XChaCha20Poly1305::new_from_slice(&self.key).map_err(|_| DecryptError)?;
                cipher
                    .encrypt_in_place(XNonce::from_slice(self.nonce24.bytes()), b"", buffer)
                    .map_err(|_| DecryptError)?;
                self.nonce24.increment();
            }
            _ => unreachable!("v1 Sealer invoked for non-v1 cipher"),
        }
        Ok(())
    }

    pub fn seal_chunk(&mut self, payload: &[u8]) -> Result<Vec<u8>, DecryptError> {
        debug_assert!(payload.len() <= self.cipher.max_payload());
        let mut length_record = Vec::with_capacity(2 + 16);
        length_record.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        self.seal(&mut length_record)?;

        let mut payload_record = payload.to_vec();
        self.seal(&mut payload_record)?;

        length_record.extend_from_slice(&payload_record);
        Ok(length_record)
    }
}

/// One direction of an AEAD stream: the opening half.
#[derive(Debug)]
pub struct Opener {
    cipher: Cipher,
    key: Vec<u8>,
    nonce12: Nonce12,
    nonce24: Nonce24,
}

impl Opener {
    #[must_use]
    pub fn new(cipher: Cipher, master: &[u8], salt: &[u8]) -> Self {
        Self {
            cipher,
            key: subkey(cipher, master, salt),
            nonce12: Nonce12::new(),
            nonce24: Nonce24::new(),
        }
    }

    pub fn open_record(&mut self, buffer: &mut Vec<u8>) -> Result<(), DecryptError> {
        self.open(buffer)
    }

    fn open(&mut self, buffer: &mut Vec<u8>) -> Result<(), DecryptError> {
        match self.cipher {
            Cipher::Aes128Gcm => {
                let cipher = Aes128Gcm::new_from_slice(&self.key).map_err(|_| DecryptError)?;
                cipher
                    .decrypt_in_place(Nonce::from_slice(self.nonce12.bytes()), b"", buffer)
                    .map_err(|_| DecryptError)?;
                self.nonce12.increment();
            }
            Cipher::Aes256Gcm => {
                let cipher = Aes256Gcm::new_from_slice(&self.key).map_err(|_| DecryptError)?;
                cipher
                    .decrypt_in_place(Nonce::from_slice(self.nonce12.bytes()), b"", buffer)
                    .map_err(|_| DecryptError)?;
                self.nonce12.increment();
            }
            Cipher::ChaCha20Poly1305 => {
                let cipher =
                    ChaCha20Poly1305::new_from_slice(&self.key).map_err(|_| DecryptError)?;
                cipher
                    .decrypt_in_place(Nonce::from_slice(self.nonce12.bytes()), b"", buffer)
                    .map_err(|_| DecryptError)?;
                self.nonce12.increment();
            }
            Cipher::XChaCha20Poly1305 => {
                use chacha20poly1305::{XChaCha20Poly1305, XNonce};
                let cipher =
                    XChaCha20Poly1305::new_from_slice(&self.key).map_err(|_| DecryptError)?;
                cipher
                    .decrypt_in_place(XNonce::from_slice(self.nonce24.bytes()), b"", buffer)
                    .map_err(|_| DecryptError)?;
                self.nonce24.increment();
            }
            _ => unreachable!("v1 Opener invoked for non-v1 cipher"),
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
        self.open(&mut buffer)?;
        let length = usize::from(u16::from_be_bytes([buffer[0], buffer[1]]));
        if length > self.cipher.max_payload() {
            return Err(DecryptError);
        }
        Ok(length)
    }

    pub fn open_payload(&mut self, record: &[u8]) -> Result<Vec<u8>, DecryptError> {
        let mut buffer = record.to_vec();
        self.open(&mut buffer)?;
        Ok(buffer)
    }
}

/// Remembers recently seen salts so a replayed connection is refused.
#[derive(Debug)]
pub struct SaltReplayFilter {
    seen: VecDeque<Vec<u8>>,
    capacity: usize,
}

impl SaltReplayFilter {
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            seen: VecDeque::with_capacity(capacity.min(1024)),
            capacity,
        }
    }

    pub fn observe(&mut self, salt: &[u8]) -> bool {
        if self.capacity == 0 {
            return true;
        }
        if self.seen.iter().any(|seen| seen == salt) {
            return false;
        }
        if self.seen.len() == self.capacity {
            self.seen.pop_front();
        }
        self.seen.push_back(salt.to_vec());
        true
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWORD: &str = "correct horse battery staple";

    fn master(cipher: Cipher) -> Vec<u8> {
        master_key(cipher, PASSWORD)
    }

    #[test]
    fn the_master_key_has_the_cipher_key_length() {
        assert_eq!(master(Cipher::Aes128Gcm).len(), 16);
        assert_eq!(master(Cipher::Aes256Gcm).len(), 32);
        assert_eq!(master(Cipher::ChaCha20Poly1305).len(), 32);
        assert_eq!(master(Cipher::Aes256Gcm), master(Cipher::Aes256Gcm));
        assert_ne!(
            master_key(Cipher::Aes256Gcm, "a"),
            master_key(Cipher::Aes256Gcm, "b")
        );
    }

    #[test]
    fn every_aead_cipher_round_trips_a_chunk() {
        for cipher in [
            Cipher::Aes128Gcm,
            Cipher::Aes256Gcm,
            Cipher::ChaCha20Poly1305,
            Cipher::XChaCha20Poly1305,
        ] {
            let master = master(cipher);
            let salt = vec![0x42; cipher.salt_len()];
            let mut sealer = Sealer::new(cipher, &master, &salt);
            let mut opener = Opener::new(cipher, &master, &salt);

            let payload = b"it came from the ocean";
            let sealed = sealer.seal_chunk(payload).expect("seals");

            let length_len = opener.length_record_len();
            let length = opener
                .open_length(&sealed[..length_len])
                .expect("decrypts length");
            assert_eq!(length, payload.len());

            let opened = opener
                .open_payload(&sealed[length_len..])
                .expect("decrypts payload");
            assert_eq!(&opened, payload);
        }
    }
}
