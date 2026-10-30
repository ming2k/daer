// SPDX-License-Identifier: AGPL-3.0-only

//! Shadowsocks AEAD (SIP004 / SIP007): the cipher, the key derivation and the framing.
//!
//! # Scope, and what is deliberately absent
//!
//! Only AEAD ciphers are implemented: `aes-128-gcm`, `aes-256-gcm`,
//! `chacha20-ietf-poly1305`, `xchacha20-ietf-poly1305`. The old stream ciphers
//! (`aes-256-cfb`, `rc4-md5`, …) are **not** implemented and cannot be enabled: they have
//! no integrity protection, so an attacker on the path can flip bits in traffic this program
//! sends, and a proxy that speaks them is a liability to its user. A link naming one is
//! rejected with a message that says so, rather than silently failing at handshake time.
//!
//! # The construction
//!
//! ```text
//!   master key  = KDF(password)              EVP_BytesToKey (MD5), legacy but required by
//!                                           the protocol's link format
//!   subkey      = HKDF-SHA1(master, salt, "ss-subkey")
//!   nonce       = 12 bytes, little-endian counter, incremented per record
//!   record      = [len(2)][tag(16)] [payload(len)][tag(16)]
//! ```
//!
//! Two things about that are easy to get wrong and are asserted by tests:
//!
//! * the length field is **encrypted as its own record**, with its own tag, so the first
//!   record of a stream can never be mistaken for a payload;
//! * the nonce is **little-endian** and shared across the two records of one chunk — it
//!   increments once per record, not once per chunk.
//!
//! # Replay defence
//!
//! The salt must be unique per connection; a repeated salt under the same key lets an
//! observer correlate and, worse, replay. A [`SaltReplayFilter`] is provided and is used by
//! the stream wrapper, but its state is per-process: a restart forgets it. That is stated
//! here because a proxy that claims replay protection across restarts without persisting
//! salts is claiming something it does not do.

use std::collections::VecDeque;
use std::fmt;

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use md5::{Digest, Md5};
use sha1::Sha1;
use zeroize::Zeroize;

/// The AEAD ciphers this build speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cipher {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
    XChaCha20Poly1305,
}

impl Cipher {
    /// Parses a cipher name as it appears in a `ss://` link.
    ///
    /// # Errors
    ///
    /// Returns [`CipherError::Unsupported`] for a recognised-but-rejected legacy cipher, and
    /// [`CipherError::Unknown`] for a name this build does not know. The two are separated
    /// because the first is a security decision and the second is usually a typo.
    pub fn parse(name: &str) -> Result<Self, CipherError> {
        match name.trim().to_ascii_lowercase().as_str() {
            "aes-128-gcm" => Ok(Self::Aes128Gcm),
            "aes-256-gcm" => Ok(Self::Aes256Gcm),
            "chacha20-ietf-poly1305" => Ok(Self::ChaCha20Poly1305),
            "xchacha20-ietf-poly1305" => Ok(Self::XChaCha20Poly1305),
            legacy @ ("aes-128-cfb" | "aes-192-cfb" | "aes-256-cfb" | "aes-128-ctr"
            | "aes-192-ctr" | "aes-256-ctr" | "rc4-md5" | "chacha20"
            | "chacha20-ietf" | "salsa20" | "bf-cfb" | "camellia-128-cfb"
            | "camellia-192-cfb" | "camellia-256-cfb" | "des-cfb" | "table") => {
                Err(CipherError::Unsupported(legacy.to_owned()))
            }
            other => Err(CipherError::Unknown(other.to_owned())),
        }
    }

    /// The cipher name as a link spells it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Aes128Gcm => "aes-128-gcm",
            Self::Aes256Gcm => "aes-256-gcm",
            Self::ChaCha20Poly1305 => "chacha20-ietf-poly1305",
            Self::XChaCha20Poly1305 => "xchacha20-ietf-poly1305",
        }
    }

    /// Key length in bytes.
    #[must_use]
    pub const fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm | Self::ChaCha20Poly1305 | Self::XChaCha20Poly1305 => 32,
        }
    }

    /// Salt length in bytes, which is the key length for every AEAD mode.
    #[must_use]
    pub const fn salt_len(self) -> usize {
        self.key_len()
    }

    /// Tag length in bytes (16 for all supported AEAD modes).
    #[must_use]
    pub const fn tag_len(self) -> usize {
        16
    }

    /// Nonce length: 12 for the IETF constructions, 24 for XChaCha.
    #[must_use]
    pub const fn nonce_len(self) -> usize {
        match self {
            Self::XChaCha20Poly1305 => 24,
            _ => 12,
        }
    }

    /// The largest payload one record may carry.
    ///
    /// The protocol's length field is 16 bits, and the limit below is the conventional
    /// `0x3FFF` that interoperates with every implementation.
    #[must_use]
    pub const fn max_payload(self) -> usize {
        0x3FFF
    }
}

impl fmt::Display for Cipher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Why a cipher name was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CipherError {
    /// A legacy cipher with no integrity protection.
    Unsupported(String),
    /// A name this build does not know.
    Unknown(String),
}

impl fmt::Display for CipherError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported(name) => write!(
                f,
                "shadowsocks cipher {name:?} is not supported: it has no authentication, so \
                 traffic could be modified in transit. Use an AEAD cipher \
                 (aes-128-gcm, aes-256-gcm, chacha20-ietf-poly1305) instead"
            ),
            Self::Unknown(name) => write!(f, "unknown shadowsocks cipher {name:?}"),
        }
    }
}

impl std::error::Error for CipherError {}

/// A decryption failure.
///
/// Carries no detail on purpose: the difference between "wrong key", "wrong nonce" and
/// "tampered record" is exactly what an attacker would use to probe, and the operator can do
/// nothing different in any of the three cases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecryptError;

impl fmt::Display for DecryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("shadowsocks record failed authentication")
    }
}

impl std::error::Error for DecryptError {}

/// Derives the master key from a password.
///
/// `EVP_BytesToKey` with MD5 and no salt: the construction the protocol inherited from
/// OpenSSL and every client still uses. It is not a password hash and offers no work factor;
/// it is here because the link format has nothing else to offer. Stated plainly rather than
/// hidden, so nobody mistakes it for a KDF with a security parameter.
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
    // HKDF-SHA1 with the protocol's fixed info string; there is no way to negotiate it.
    let hkdf = Hkdf::<Sha1>::new(Some(salt), master);
    let mut key = vec![0u8; cipher.key_len()];
    hkdf.expand(b"ss-subkey", &mut key)
        .expect("the output length is a valid HKDF length");
    key
}

/// A nonce that counts up, little-endian.
///
/// Little-endian is not an aesthetic choice: the protocol says so, and a big-endian nonce
/// interoperates with nothing.
#[derive(Debug, Clone)]
struct Nonce12 {
    value: [u8; 12],
}

impl Nonce12 {
    fn new() -> Self {
        Self { value: [0; 12] }
    }

    fn bytes(&self) -> &[u8; 12] {
        &self.value
    }

    fn increment(&mut self) {
        for byte in &mut self.value {
            let (next, overflow) = byte.overflowing_add(1);
            *byte = next;
            if !overflow {
                return;
            }
        }
        // Wrapping is the protocol's behaviour; 2^96 records is not reachable.
    }
}

/// A nonce that counts up, 24 bytes for XChaCha.
#[derive(Debug, Clone)]
struct Nonce24 {
    value: [u8; 24],
}

impl Nonce24 {
    fn new() -> Self {
        Self { value: [0; 24] }
    }

    fn bytes(&self) -> &[u8; 24] {
        &self.value
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

/// One direction of an AEAD stream: the sealing half.
#[derive(Debug)]
pub struct Sealer {
    cipher: Cipher,
    /// The master key, retained so a stream can build its opener from the same material
    /// without the caller having to thread it through twice.
    master: Vec<u8>,
    key: Vec<u8>,
    nonce12: Nonce12,
    nonce24: Nonce24,
    salt: Vec<u8>,
}

impl Sealer {
    /// Creates a sealer for `key`, generating the salt from `entropy`.
    ///
    /// The caller supplies the salt's bytes so this module stays free of a random source:
    /// a cipher whose output can be predicted from a test seed is testable, and a production
    /// caller passes OS entropy.
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

    /// The salt, which the peer needs before it can decrypt anything.
    #[must_use]
    pub fn salt(&self) -> &[u8] {
        &self.salt
    }

    /// The master key this sealer was built from.
    ///
    /// Named for the field it returns: `key` would be ambiguous between the master key and
    /// the derived subkey, and a caller who wants the subkey should not get it by accident.
    #[must_use]
    pub fn master_key(&self) -> &[u8] {
        &self.master
    }

    /// Seals one record in place, appending its tag.
    pub fn seal_record(&mut self, buffer: &mut Vec<u8>) -> Result<(), DecryptError> {
        self.seal(buffer)
    }

    /// Seals one record in place, appending its tag.
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
        }
        Ok(())
    }

    /// Encrypts one chunk: the length record, then the payload record.
    ///
    /// # Errors
    ///
    /// Returns [`DecryptError`] if the cipher refuses the key, which cannot happen for a key
    /// of the right length.
    pub fn seal_chunk(&mut self, payload: &[u8]) -> Result<Vec<u8>, DecryptError> {
        debug_assert!(payload.len() <= self.cipher.max_payload());
        // The length is a record of its own: length(2) + tag(16).
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
    /// Creates an opener for the peer's salt.
    #[must_use]
    pub fn new(cipher: Cipher, master: &[u8], salt: &[u8]) -> Self {
        Self {
            cipher,
            key: subkey(cipher, master, salt),
            nonce12: Nonce12::new(),
            nonce24: Nonce24::new(),
        }
    }

    /// Opens one record in place, stripping its tag.
    ///
    /// The unit the protocol actually has: a length record and a payload record are both
    /// records. Exposed so a caller can implement a different chunking strategy without a
    /// second copy of the cipher wiring.
    ///
    /// # Errors
    ///
    /// Returns [`DecryptError`] when the record does not authenticate.
    pub fn open_record(&mut self, buffer: &mut Vec<u8>) -> Result<(), DecryptError> {
        self.open(buffer)
    }

    /// Opens one record in place, stripping its tag.
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
        }
        Ok(())
    }

    /// The number of bytes one length record occupies.
    #[must_use]
    pub const fn length_record_len(&self) -> usize {
        2 + 16
    }

    /// Opens a length record, returning the payload length it declares.
    ///
    /// # Errors
    ///
    /// Returns [`DecryptError`] when the record does not authenticate, or when it declares a
    /// payload larger than [`Cipher::max_payload`] — an authenticated but absurd length is a
    /// protocol violation, not a memory request.
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

    /// Opens a payload record of `length` bytes plus its tag.
    ///
    /// # Errors
    ///
    /// Returns [`DecryptError`] when the record does not authenticate.
    pub fn open_payload(&mut self, record: &[u8]) -> Result<Vec<u8>, DecryptError> {
        let mut buffer = record.to_vec();
        self.open(&mut buffer)?;
        Ok(buffer)
    }
}

/// Remembers recently seen salts so a replayed connection is refused.
///
/// Bounded and per-process. The bound is what keeps it from growing without limit under a
/// flood; the fact that it is not persisted is stated in the module documentation rather
/// than implied, because "replay protection" across a restart would be a lie.
#[derive(Debug)]
pub struct SaltReplayFilter {
    seen: VecDeque<Vec<u8>>,
    capacity: usize,
}

impl SaltReplayFilter {
    /// A filter remembering `capacity` salts.
    ///
    /// A capacity of zero disables the check, which exists so a caller that is testing a
    /// cipher can opt out explicitly rather than by accident.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            seen: VecDeque::with_capacity(capacity.min(1024)),
            capacity,
        }
    }

    /// Records `salt`, returning false when it was already seen.
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

    /// How many salts are remembered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// True when nothing is remembered.
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
        // The derivation is deterministic: two calls agree.
        assert_eq!(master(Cipher::Aes256Gcm), master(Cipher::Aes256Gcm));
        // And a different password gives a different key.
        assert_ne!(
            master_key(Cipher::Aes256Gcm, "a"),
            master_key(Cipher::Aes256Gcm, "b")
        );
    }

    #[test]
    fn the_master_key_matches_the_published_evp_bytestokey_construction() {
        // `EVP_BytesToKey(MD5, no salt)` for "password" is MD5("password") for the first 16
        // bytes. Asserting it pins the construction: a change here would silently
        // de-interoperate with every client.
        let key = master_key(Cipher::Aes128Gcm, "password");
        assert_eq!(
            key,
            vec![
                0x5f, 0x4d, 0xcc, 0x3b, 0x5a, 0xa7, 0x65, 0xd6, 0x1d, 0x83, 0x27, 0xde, 0xb8, 0x82,
                0xcf, 0x99
            ]
        );
        // The second block continues from the first, not from a fresh hash.
        let long = master_key(Cipher::Aes256Gcm, "password");
        assert_eq!(&long[..16], &key[..]);
        assert_ne!(&long[16..], &key[..]);
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
            let salt = vec![0x11u8; cipher.salt_len()];
            let mut sealer = Sealer::new(cipher, &master, &salt);
            let mut opener = Opener::new(cipher, &master, &salt);

            let payload = b"the quick brown fox".to_vec();
            let sealed = sealer.seal_chunk(&payload).expect("seals");
            assert_eq!(
                sealed.len(),
                2 + 16 + payload.len() + 16,
                "{cipher}: length record then payload record"
            );

            let length = opener
                .open_length(&sealed[..opener.length_record_len()])
                .expect("opens length");
            assert_eq!(length, payload.len());
            let opened = opener
                .open_payload(&sealed[opener.length_record_len()..])
                .expect("opens payload");
            assert_eq!(opened, payload, "{cipher}");
        }
    }

    #[test]
    fn several_chunks_in_sequence_use_distinct_nonces() {
        // A repeated nonce under one key destroys the cipher; the counter is what prevents
        // it, and this is the test that would catch it being reset per chunk.
        let cipher = Cipher::Aes256Gcm;
        let master = master(cipher);
        let salt = vec![0x22u8; cipher.salt_len()];
        let mut sealer = Sealer::new(cipher, &master, &salt);
        let mut opener = Opener::new(cipher, &master, &salt);

        for payload in [b"one".to_vec(), b"two".to_vec(), b"three".to_vec()] {
            let sealed = sealer.seal_chunk(&payload).expect("seals");
            let length = opener
                .open_length(&sealed[..opener.length_record_len()])
                .expect("opens");
            assert_eq!(length, payload.len());
            assert_eq!(
                opener
                    .open_payload(&sealed[opener.length_record_len()..])
                    .expect("opens"),
                payload
            );
        }
    }

    #[test]
    fn a_tampered_record_fails_to_open() {
        let cipher = Cipher::ChaCha20Poly1305;
        let master = master(cipher);
        let salt = vec![0x33u8; cipher.salt_len()];
        let mut sealer = Sealer::new(cipher, &master, &salt);
        let mut opener = Opener::new(cipher, &master, &salt);

        let mut sealed = sealer.seal_chunk(b"payload").expect("seals");
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        assert!(
            opener
                .open_length(&sealed[..opener.length_record_len()])
                .and_then(|length| {
                    let _ = length;
                    opener.open_payload(&sealed[opener.length_record_len()..])
                })
                .is_err()
        );
    }

    #[test]
    fn a_wrong_salt_does_not_open() {
        let cipher = Cipher::Aes256Gcm;
        let master = master(cipher);
        let mut sealer = Sealer::new(cipher, &master, &[0x44; 32]);
        let mut opener = Opener::new(cipher, &master, &[0x55; 32]);

        let sealed = sealer.seal_chunk(b"payload").expect("seals");
        assert!(
            opener
                .open_length(&sealed[..opener.length_record_len()])
                .is_err()
        );
    }

    #[test]
    fn an_absurd_authenticated_length_is_refused() {
        // A length above the protocol maximum is a violation, not a memory request: the
        // point is that even a *successfully authenticated* length record cannot ask for
        // 64 KiB, so a sender cannot make the reader allocate on demand.
        let cipher = Cipher::Aes128Gcm;
        let master = master(cipher);
        let mut sealer = Sealer::new(cipher, &master, &[0x66; 16]);
        let mut opener = Opener::new(cipher, &master, &[0x66; 16]);

        let mut record = u16::MAX.to_be_bytes().to_vec();
        sealer.seal_record(&mut record).expect("seals");
        assert_eq!(record.len(), opener.length_record_len());
        assert!(
            opener.open_length(&record).is_err(),
            "0xFFFF exceeds the maximum payload"
        );

        // The maximum itself is accepted, so the check is a bound and not a blanket refusal.
        let mut at_limit = (cipher.max_payload() as u16).to_be_bytes().to_vec();
        sealer.seal_record(&mut at_limit).expect("seals");
        assert_eq!(
            opener.open_length(&at_limit).expect("opens"),
            cipher.max_payload()
        );
    }

    #[test]
    fn a_length_record_of_the_wrong_size_is_refused() {
        let cipher = Cipher::Aes128Gcm;
        let master = master(cipher);
        let mut opener = Opener::new(cipher, &master, &[0x77; 16]);
        assert!(opener.open_length(&[0u8; 5]).is_err());
    }

    #[test]
    fn legacy_ciphers_are_rejected_with_the_reason() {
        for legacy in ["aes-256-cfb", "rc4-md5", "chacha20", "table"] {
            match Cipher::parse(legacy) {
                Err(CipherError::Unsupported(name)) => {
                    assert_eq!(name, legacy);
                }
                other => panic!("{legacy} must be Unsupported, got {other:?}"),
            }
        }
        let rendered = Cipher::parse("aes-256-cfb").unwrap_err().to_string();
        assert!(rendered.contains("no authentication"), "{rendered}");
        assert!(rendered.contains("aes-256-gcm"), "{rendered}");
    }

    #[test]
    fn an_unknown_cipher_is_distinguished_from_a_rejected_one() {
        assert!(matches!(
            Cipher::parse("aes-512-gcm"),
            Err(CipherError::Unknown(_))
        ));
        assert!(matches!(
            Cipher::parse("AES-256-GCM"),
            Ok(Cipher::Aes256Gcm)
        ));
    }

    #[test]
    fn nonces_increment_little_endian() {
        let mut nonce = Nonce12::new();
        assert_eq!(nonce.bytes(), &[0u8; 12]);
        nonce.increment();
        assert_eq!(nonce.bytes()[0], 1, "little-endian: the first byte carries");
        nonce.increment();
        assert_eq!(nonce.bytes()[0], 2);

        // Carry into the next byte.
        let mut nonce = Nonce12 { value: [0xff; 12] };
        nonce.increment();
        assert_eq!(nonce.bytes(), &[0u8; 12], "all-ones wraps");
    }

    #[test]
    fn the_replay_filter_refuses_a_second_salt() {
        let mut filter = SaltReplayFilter::new(4);
        assert!(filter.observe(b"salt-a"));
        assert!(!filter.observe(b"salt-a"), "a replay must be refused");
        assert!(filter.observe(b"salt-b"));
        assert_eq!(filter.len(), 2);
        assert!(!filter.is_empty());
    }

    #[test]
    fn the_replay_filter_is_bounded() {
        let mut filter = SaltReplayFilter::new(2);
        assert!(filter.observe(b"a"));
        assert!(filter.observe(b"b"));
        assert!(filter.observe(b"c"));
        assert_eq!(filter.len(), 2, "the oldest was dropped");
        // `a` was forgotten, so it is accepted again. That is the honest cost of a bounded
        // window, and why the module documentation does not claim more.
        assert!(filter.observe(b"a"));
    }

    #[test]
    fn a_zero_capacity_filter_checks_nothing() {
        let mut filter = SaltReplayFilter::new(0);
        assert!(filter.observe(b"x"));
        assert!(filter.observe(b"x"), "explicitly disabled");
        assert!(filter.is_empty());
    }
}
