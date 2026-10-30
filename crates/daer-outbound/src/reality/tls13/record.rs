// SPDX-License-Identifier: AGPL-3.0-only

//! The TLS 1.3 record layer.
//!
//! Reads and writes RFC 8446 §5 records. Two things make this small rather than
//! sprawling: TLS 1.3 forbids renegotiation and compression, so the record header is
//! always five bytes and a record never changes its meaning mid-connection; and only the
//! three AEAD suites a REALITY handshake can meet are implemented.
//!
//! # Why the parser is written defensively
//!
//! A ClientHello goes to a server we do not trust until its `Finished` verifies, and the
//! records it answers with are attacker-controlled bytes on the open internet. Every
//! length is checked against the buffer before use, and a record larger than the RFC's
//! ceiling is rejected rather than allocated: a 2-byte length field is not permission to
//! allocate 64 KiB per record on a hostile connection.

use aes_gcm::Aes128Gcm;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::ChaCha20Poly1305;

/// TLS record content types (RFC 8446 §5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ContentType {
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
}

impl ContentType {
    fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            20 => Self::ChangeCipherSpec,
            21 => Self::Alert,
            22 => Self::Handshake,
            23 => Self::ApplicationData,
            _ => return None,
        })
    }
}

/// The largest plaintext a TLS record may carry (RFC 8446 §5.1: 2^14).
pub const MAX_PLAINTEXT: usize = 1 << 14;

/// The largest ciphertext a TLS record may carry: plaintext plus 256 bytes of
/// expansion, as the RFC allows for future AEADs (RFC 8446 §5.2).
pub const MAX_CIPHERTEXT: usize = MAX_PLAINTEXT + 256;

/// The AEAD tag length for every TLS 1.3 suite, in bytes (RFC 8446 §5.2).
pub const AEAD_TAG_LEN: usize = 16;

/// A record header, five bytes on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordHeader {
    pub content_type: u8,
    /// The legacy version. TLS 1.3 pins this to 0x0303 everywhere except an initial
    /// ClientHello, which writes 0x0301 for middlebox compatibility.
    pub version: u16,
    pub length: u16,
}

impl RecordHeader {
    pub const LEN: usize = 5;

    /// Parses a five-byte header.
    ///
    /// # Errors
    ///
    /// Returns a message when the bytes are not a header this client will accept: an
    /// unknown content type, an over-large length, or a version below `TLS 1.2`.
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < Self::LEN {
            return Err(format!(
                "record header is {} bytes, need {}",
                bytes.len(),
                Self::LEN
            ));
        }
        let content_type = bytes[0];
        if ContentType::from_u8(content_type).is_none() {
            return Err(format!("unknown record content type {content_type}"));
        }
        let version = u16::from_be_bytes([bytes[1], bytes[2]]);
        // 0x0300 is the lowest legacy version worth tolerating; anything below is not a
        // TLS record and reading it would misinterpret the stream.
        if version < 0x0300 {
            return Err(format!("record version {version:#06x} is not TLS"));
        }
        let length = u16::from_be_bytes([bytes[3], bytes[4]]);
        if usize::from(length) > MAX_CIPHERTEXT {
            return Err(format!(
                "record length {length} exceeds the {MAX_CIPHERTEXT}-byte ceiling"
            ));
        }
        Ok(Self {
            content_type,
            version,
            length,
        })
    }

    /// Serializes the header.
    #[must_use]
    pub fn encode(&self) -> [u8; Self::LEN] {
        let mut out = [0u8; Self::LEN];
        out[0] = self.content_type;
        out[1..3].copy_from_slice(&self.version.to_be_bytes());
        out[3..5].copy_from_slice(&self.length.to_be_bytes());
        out
    }
}

/// A traffic key and its IV, for one direction and one encryption level.
///
/// The IV is not fixed: TLS 1.3 XORs the sequence number into it per record (RFC 8446
/// §5.3), which is what lets one key encrypt many records without a per-record nonce on
/// the wire.
pub struct TrafficKey {
    cipher: CipherKind,
    iv: [u8; 12],
    sequence: u64,
}

#[derive(Clone)]
enum CipherKind {
    // Boxed because an AES key schedule is ~736 bytes and a ChaCha key is 32: without the
    // indirection every `CipherKind` (and every `TrafficKey`) would be that large.
    Aes128Gcm(Box<Aes128Gcm>),
    ChaCha20Poly1305(Box<ChaCha20Poly1305>),
}

impl std::fmt::Debug for TrafficKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Key material is never printed, only the suite name.
        f.debug_struct("TrafficKey")
            .field("cipher", &self.cipher.name())
            .field("sequence", &self.sequence)
            .finish_non_exhaustive()
    }
}

impl CipherKind {
    fn name(&self) -> &'static str {
        match self {
            Self::Aes128Gcm(_) => "TLS_AES_128_GCM_SHA256",
            Self::ChaCha20Poly1305(_) => "TLS_CHACHA20_POLY1305_SHA256",
        }
    }
}

impl TrafficKey {
    /// Builds a traffic key for `suite` from a 32-byte key and a 12-byte IV.
    ///
    /// The three suites are the only ones TLS 1.3 defines with a 32-byte key schedule
    /// output; `TLS_AES_256_GCM_SHA384` needs a 48-byte key and is therefore not built
    /// here — a REALITY node offering only it is refused by name rather than negotiating
    /// something the schedule cannot key.
    ///
    /// # Errors
    ///
    /// Returns a message when the suite is unsupported or the key/IV length is wrong.
    pub fn new(suite: u16, key: &[u8], iv: &[u8; 12]) -> Result<Self, String> {
        let cipher = match suite {
            // TLS_AES_128_GCM_SHA256
            0x1301 => {
                if key.len() != 16 {
                    return Err(format!(
                        "AES-128-GCM needs a 16-byte key, got {}",
                        key.len()
                    ));
                }
                CipherKind::Aes128Gcm(Box::new(
                    Aes128Gcm::new_from_slice(key).map_err(|_| "AES-128-GCM key")?,
                ))
            }
            // TLS_CHACHA20_POLY1305_SHA256
            0x1303 => {
                if key.len() != 32 {
                    return Err(format!(
                        "ChaCha20-Poly1305 needs a 32-byte key, got {}",
                        key.len()
                    ));
                }
                CipherKind::ChaCha20Poly1305(Box::new(
                    ChaCha20Poly1305::new_from_slice(key).map_err(|_| "ChaCha20-Poly1305 key")?,
                ))
            }
            // TLS_AES_256_GCM_SHA384 needs a 48-byte key; unreachable with SHA-256.
            0x1302 => {
                return Err(
                    "TLS_AES_256_GCM_SHA384 is not offered: its key schedule needs SHA-384"
                        .to_owned(),
                );
            }
            other => return Err(format!("unsupported TLS 1.3 cipher suite {other:#06x}")),
        };
        Ok(Self {
            cipher,
            iv: *iv,
            sequence: 0,
        })
    }

    /// The nonce for the current record: the IV with the sequence number XORed into its
    /// last eight bytes (RFC 8446 §5.3).
    fn nonce(&self) -> [u8; 12] {
        let mut nonce = self.iv;
        let sequence = self.sequence.to_be_bytes();
        for (index, byte) in sequence.iter().enumerate() {
            nonce[4 + index] ^= byte;
        }
        nonce
    }

    /// Seals `plaintext` as the next record, with `aad` as associated data.
    ///
    /// Sequence numbers are spent once and never reused: reusing one under the same key
    /// destroys AEAD security, so the counter advances only after a successful seal.
    fn seal(&mut self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
        let nonce = self.nonce();
        let encrypted = match &self.cipher {
            CipherKind::Aes128Gcm(cipher) => cipher
                .encrypt(
                    &nonce.into(),
                    Payload {
                        msg: plaintext,
                        aad,
                    },
                )
                .map_err(|_| "AES-128-GCM seal failed")?,
            CipherKind::ChaCha20Poly1305(cipher) => cipher
                .encrypt(
                    &nonce.into(),
                    Payload {
                        msg: plaintext,
                        aad,
                    },
                )
                .map_err(|_| "ChaCha20-Poly1305 seal failed")?,
        };
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or("TLS record sequence counter exhausted; the key must be replaced")?;
        Ok(encrypted)
    }

    /// Opens `ciphertext` as the next record.
    fn open(&mut self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
        let nonce = self.nonce();
        let plaintext = match &self.cipher {
            CipherKind::Aes128Gcm(cipher) => cipher
                .decrypt(
                    &nonce.into(),
                    Payload {
                        msg: ciphertext,
                        aad,
                    },
                )
                .map_err(|_| "AES-128-GCM open failed: the record was altered")?,
            CipherKind::ChaCha20Poly1305(cipher) => cipher
                .decrypt(
                    &nonce.into(),
                    Payload {
                        msg: ciphertext,
                        aad,
                    },
                )
                .map_err(|_| "ChaCha20-Poly1305 open failed: the record was altered")?,
        };
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or("TLS record sequence counter exhausted; the key must be replaced")?;
        Ok(plaintext)
    }
}

/// The record layer: one `TrafficKey` per direction, plus the record framing.
pub struct RecordLayer {
    pub read_key: Option<TrafficKey>,
    pub write_key: Option<TrafficKey>,
    /// Handshake bytes that have been read but not yet consumed by the handshake state
    /// machine. Records are not message-aligned, so a fragment can split a message.
    pub pending: Vec<u8>,
}

impl std::fmt::Debug for RecordLayer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecordLayer")
            .field("has_read_key", &self.read_key.is_some())
            .field("has_write_key", &self.write_key.is_some())
            .field("pending", &self.pending.len())
            .finish_non_exhaustive()
    }
}

impl Default for RecordLayer {
    fn default() -> Self {
        Self::new()
    }
}

impl RecordLayer {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            read_key: None,
            write_key: None,
            pending: Vec::new(),
        }
    }

    /// Frames `payload` as a record, encrypting it when a write key is installed.
    ///
    /// The associated data is the five-byte header of the *plaintext* record, per RFC
    /// 8446 §5.2 — it is what binds the length to the ciphertext.
    ///
    /// # Errors
    ///
    /// Returns a message when the payload exceeds [`MAX_PLAINTEXT`] or the seal fails.
    pub fn frame(&mut self, content_type: ContentType, payload: &[u8]) -> Result<Vec<u8>, String> {
        let inner = ContentType::ApplicationData as u8;
        // Once a write key exists, everything (including handshake) is wrapped as
        // application_data, which is what RFC 8446 §5.2 requires and what an observer
        // expects to see.
        let (outer_type, plaintext) = match self.write_key {
            Some(_) => (inner, payload.to_vec()),
            None => (content_type as u8, payload.to_vec()),
        };
        if plaintext.len() > MAX_PLAINTEXT {
            return Err(format!(
                "record payload is {} bytes, over {MAX_PLAINTEXT}",
                plaintext.len()
            ));
        }

        let body = match &mut self.write_key {
            None => plaintext,
            Some(key) => {
                // The inner content type is appended before encryption; on the wire the
                // outer type is always application_data, so the real type is hidden.
                let mut with_type = plaintext;
                with_type.push(content_type as u8);
                // RFC 8446 §5.2: the additional data is the *ciphertext* record's header,
                // so its length field is plaintext + inner type + AEAD tag. Authenticating
                // the plaintext length instead makes every record fail to open, with no
                // diagnostic beyond "altered".
                let ciphertext_len = with_type.len() + AEAD_TAG_LEN;
                let aad_header = RecordHeader {
                    content_type: ContentType::ApplicationData as u8,
                    version: 0x0303,
                    length: u16::try_from(ciphertext_len)
                        .map_err(|_| "record length does not fit 16 bits")?,
                };
                key.seal(&with_type, &aad_header.encode())?
            }
        };

        let header = RecordHeader {
            content_type: outer_type,
            // RFC 8446 §5.1: the legacy version for every record after the first
            // ClientHello is 0x0303.
            version: 0x0303,
            length: u16::try_from(body.len()).map_err(|_| "record does not fit 16 bits")?,
        };
        let mut out = Vec::with_capacity(RecordHeader::LEN + body.len());
        out.extend_from_slice(&header.encode());
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Decrypts one record body.
    ///
    /// # Errors
    ///
    /// Returns a message when a read key is required but absent, when the record was
    /// altered, or when the inner content type is not a legal one.
    pub fn unframe(
        &mut self,
        header: &RecordHeader,
        body: &[u8],
    ) -> Result<(ContentType, Vec<u8>), String> {
        let Some(key) = &mut self.read_key else {
            // Before keys exist the record is plaintext: only the handshake messages of
            // the first flight arrive this way.
            let content = ContentType::from_u8(header.content_type)
                .ok_or_else(|| format!("unknown content type {}", header.content_type))?;
            return Ok((content, body.to_vec()));
        };

        if body.is_empty() {
            return Err("empty encrypted record".to_owned());
        }
        // The AAD is the header with the *ciphertext* length, which is what the sender
        // authenticated.
        let aad = header.encode();
        let plaintext = key.open(body, &aad)?;
        // RFC 8446 §5.4: the inner plaintext is `content || content_type || zeros*`.
        // The content type is therefore the last **non-zero** byte, and any trailing
        // zeroes are padding. Reading the last byte instead fails the moment a peer pads —
        // which a REALITY node does on its first flight — with an error that looks like a
        // key problem rather than a framing one.
        let end = plaintext
            .iter()
            .rposition(|byte| *byte != 0)
            .ok_or_else(|| "encrypted record decrypted to all zeroes".to_owned())?;
        let (&inner_type, payload) = plaintext[..=end]
            .split_last()
            .ok_or_else(|| "encrypted record decrypted to nothing".to_owned())?;
        let content = ContentType::from_u8(inner_type).ok_or_else(|| {
            format!("encrypted record hides an unknown content type {inner_type}")
        })?;
        Ok((content, payload.to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_header_round_trips() {
        let header = RecordHeader {
            content_type: ContentType::Handshake as u8,
            version: 0x0303,
            length: 42,
        };
        let encoded = header.encode();
        assert_eq!(RecordHeader::parse(&encoded).expect("parses"), header);
    }

    #[test]
    fn an_unknown_content_type_is_rejected() {
        let bytes = [99u8, 0x03, 0x03, 0x00, 0x01];
        assert!(RecordHeader::parse(&bytes).is_err());
    }

    #[test]
    fn an_over_large_record_is_rejected_rather_than_allocated() {
        // 0xffff is a legal u16 but not a legal record; accepting it would let a hostile
        // peer make us allocate 64 KiB per record.
        let bytes = [22u8, 0x03, 0x03, 0xff, 0xff];
        let error = RecordHeader::parse(&bytes).expect_err("must reject");
        assert!(error.contains("ceiling"), "{error}");
    }

    #[test]
    fn a_non_tls_version_is_rejected() {
        let bytes = [22u8, 0x02, 0x00, 0x00, 0x01];
        assert!(RecordHeader::parse(&bytes).is_err());
    }

    #[test]
    fn a_plaintext_record_is_framed_without_encryption() {
        let mut layer = RecordLayer::new();
        let framed = layer
            .frame(ContentType::Handshake, b"hello")
            .expect("frames");
        let header = RecordHeader::parse(&framed).expect("parses");
        assert_eq!(header.content_type, ContentType::Handshake as u8);
        assert_eq!(header.length, 5);

        let (content, payload) = layer.unframe(&header, &framed[5..]).expect("unframes");
        assert_eq!(content, ContentType::Handshake);
        assert_eq!(payload, b"hello");
    }

    #[test]
    fn an_encrypted_record_round_trips_and_hides_its_type() {
        let mut write = RecordLayer::new();
        let mut read = RecordLayer::new();
        let key = [7u8; 32];
        let iv = [9u8; 12];
        write.write_key = Some(TrafficKey::new(0x1303, &key, &iv).expect("key"));
        read.read_key = Some(TrafficKey::new(0x1303, &key, &iv).expect("key"));

        let framed = write
            .frame(ContentType::Handshake, b"secret handshake")
            .expect("frames");
        let header = RecordHeader::parse(&framed).expect("parses");
        // The wire type is application_data: the real one is inside the ciphertext.
        assert_eq!(header.content_type, ContentType::ApplicationData as u8);

        let (content, payload) = read.unframe(&header, &framed[5..]).expect("unframes");
        assert_eq!(content, ContentType::Handshake);
        assert_eq!(payload, b"secret handshake");
    }

    #[test]
    fn a_tampered_record_fails_to_open() {
        let mut write = RecordLayer::new();
        let mut read = RecordLayer::new();
        let key = [1u8; 32];
        let iv = [2u8; 12];
        write.write_key = Some(TrafficKey::new(0x1303, &key, &iv).expect("key"));
        read.read_key = Some(TrafficKey::new(0x1303, &key, &iv).expect("key"));

        let mut framed = write
            .frame(ContentType::Handshake, b"integrity matters")
            .expect("frames");
        let header = RecordHeader::parse(&framed).expect("parses");
        let last = framed.len() - 1;
        framed[last] ^= 0xff;

        let error = read
            .unframe(&header, &framed[5..])
            .expect_err("must reject");
        assert!(error.contains("altered"), "{error}");
    }

    #[test]
    fn sequence_numbers_advance_so_two_records_use_different_nonces() {
        let key = [3u8; 32];
        let iv = [4u8; 12];
        let mut first = TrafficKey::new(0x1303, &key, &iv).expect("key");
        let second = {
            let mut key2 = TrafficKey::new(0x1303, &key, &iv).expect("key");
            key2.sequence = 1;
            key2
        };
        assert_ne!(first.nonce(), second.nonce());
        // Sealing advances the counter, so the next nonce differs from this one.
        let before = first.nonce();
        first.seal(b"x", b"aad").expect("seals");
        assert_ne!(first.nonce(), before);
    }

    #[test]
    fn an_unsupported_suite_is_refused_by_name() {
        let error = TrafficKey::new(0x1302, &[0u8; 48], &[0u8; 12]).expect_err("must refuse");
        assert!(error.contains("SHA-384"), "{error}");
    }

    #[test]
    fn an_over_large_plaintext_is_refused() {
        let mut layer = RecordLayer::new();
        let payload = vec![0u8; MAX_PLAINTEXT + 1];
        let error = layer
            .frame(ContentType::ApplicationData, &payload)
            .expect_err("must refuse");
        assert!(error.contains("over"), "{error}");
    }
}
