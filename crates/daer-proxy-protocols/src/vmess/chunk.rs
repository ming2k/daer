// SPDX-License-Identifier: AGPL-3.0-only

//! VMess AEAD's chunk framing: sizes, masking, padding, and the AEAD chunks (ADR-0030).
//!
//! # The wire format
//!
//! ```text
//!   [size field][AEAD(payload) + tag][cleartext padding…]
//! ```
//!
//! and the size field declares **ciphertext plus padding**, not the payload. That single fact is
//! the source of most of the subtlety below: a receiver cannot know where the ciphertext ends
//! until it has recomputed the padding length, and it can only do that from the same keystream
//! the sender used.
//!
//! # The keystream order, which is not negotiable
//!
//! With `ChunkMasking`/`GlobalPadding`, one SHAKE-128 stream seeded from the direction's body IV
//! supplies *both* values, and the reference consumes them in this order for every chunk:
//!
//! ```text
//!   padding_len = shake.next() % 64
//!   size_mask   = shake.next()
//!   encoded     = size_mask ^ size
//! ```
//!
//! (`AuthenticationWriter::seal` draws the padding first, then calls `sizeParser.Encode`.) A
//! reader that decodes the size before drawing the padding gets a different mask for every
//! chunk after the first, and the failure is an AEAD tag error with no attribution.
//!
//! # The chunk nonce
//!
//! `GenerateChunkNonce`: the direction's IV with its first two bytes replaced by a big-endian
//! chunk counter. The rest of the IV is fixed. A "monotonically incrementing nonce" is a
//! plausible misreading that breaks after the first chunk.
//!
//! # `AuthenticatedLength`
//!
//! When the request sets it, the size field is itself AEAD-sealed under a key KDF'd from the body
//! key with the salt `auth_len`, and the size bytes become `2 + 16`. It is a wire change the
//! server must also have enabled, which is why it is an explicit configuration key rather than a
//! default (ADR-0030).

use aes_gcm::aead::{Aead, AeadInPlace, KeyInit};
use aes_gcm::{Aes128Gcm, Nonce};
use chacha20poly1305::ChaCha20Poly1305;
use sha3::Shake128;
use sha3::digest::{ExtendableOutput, Update, XofReader};

use crate::vmess::header::option;
use crate::vmess::kdf;

/// How a chunk's length is encoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SizeMode {
    /// Two big-endian bytes.
    Plain,
    /// Two big-endian bytes XORed with a SHAKE-128 keystream.
    Masked,
    /// Two bytes plus a tag, sealed under `KDF16(body_key, "auth_len")`.
    Authenticated,
}

impl SizeMode {
    /// Chooses the mode from the request's option bits.
    ///
    /// `AuthenticatedLength` wins over `ChunkMasking`: the reference builds the masked parser
    /// first and then *replaces* it when the authenticated one is requested.
    #[must_use]
    pub const fn from_options(options: u8) -> Self {
        if options & option::AUTHENTICATED_LENGTH != 0 {
            Self::Authenticated
        } else if options & option::CHUNK_MASKING != 0 {
            Self::Masked
        } else {
            Self::Plain
        }
    }
}

/// The AEAD a chunk payload is sealed with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cipher {
    Aes128Gcm,
    Chacha20Poly1305,
}

impl Cipher {
    /// The tag length both ciphers use.
    pub const OVERHEAD: usize = 16;
    /// The nonce length both ciphers use.
    pub const NONCE_LEN: usize = 12;
}

/// One direction of a VMess flow: its keys, its chunk counter and its keystream.
///
/// A direction is stateful in three independent ways, which is why it is a struct rather than
/// three fields passed around:
///
/// * the **counter** becomes the nonce's first two bytes, so it must advance exactly once per
///   chunk in each direction;
/// * the **keystream** must be consumed in the same order on both sides;
/// * the **cipher key** differs per direction (the downlink's is `SHA-256` of the uplink's).
pub struct Direction {
    cipher: Cipher,
    /// The AEAD key: 16 bytes for AES-GCM, 32 for ChaCha20-Poly1305.
    key: Vec<u8>,
    /// The AEAD key for the length field, when `AuthenticatedLength` is on.
    length_key: Vec<u8>,
    /// The IV whose first two bytes become the **length** field's counter.
    ///
    /// Separate from [`Self::iv`] because the reference locks it to the *request's* body IV in both
    /// directions; see [`Self::new`].
    length_iv: [u8; 16],
    /// The direction's IV, whose first two bytes become the chunk counter in every nonce.
    iv: [u8; 16],
    /// Chunks sealed so far in this direction.
    count: u16,
    /// The SHAKE-128 keystream for masking and padding.
    shake: Option<ShakeStream>,
    mode: SizeMode,
    /// The padding length the last decoded size field declared.
    ///
    /// Recovered by [`Self::decode_size`] (which is the only place the keystream is at the right
    /// position) and consumed by the reader, because the ciphertext and the padding share one
    /// declared total and only the sender knows the split.
    last_padding: u16,
}

impl std::fmt::Debug for Direction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Direction")
            .field("cipher", &self.cipher)
            .field("mode", &self.mode)
            .field("count", &self.count)
            .finish_non_exhaustive()
    }
}

/// A SHAKE-128 keystream, used for size masking and for padding lengths.
struct ShakeStream {
    reader: sha3::Shake128Reader,
}

impl ShakeStream {
    fn new(seed: &[u8]) -> Self {
        let mut shake = Shake128::default();
        shake.update(seed);
        Self {
            reader: shake.finalize_xof(),
        }
    }

    fn next_u16(&mut self) -> u16 {
        let mut bytes = [0u8; 2];
        self.reader.read(&mut bytes);
        u16::from_be_bytes(bytes)
    }
}

impl Direction {
    /// Builds one direction.
    ///
    /// `key16`/`iv` are this direction's body material: the request's for the uplink, the
    /// response's (`SHA-256` of the request's, truncated) for the downlink.
    ///
    /// `length_key16`/`length_iv` are the **request's** material in *both* directions, and that
    /// asymmetry is the one thing about `AuthenticatedLength` that is easy to get wrong. The
    /// reference's client writes it as
    ///
    /// ```text
    ///   KDF16(requestBodyKey, "auth_len")  /  GenerateChunkNonce(requestBodyIV, …)
    /// ```
    ///
    /// in `EncodeResponseBody` *and* in `DecodeResponseBody` — the response's length seal is keyed
    /// by the request's values, not the response's. Deriving it per direction produces a decoder
    /// that fails on the very first length with "wrong key, nonce or cipher", which reads exactly
    /// like a wrong UUID.
    #[must_use]
    pub fn new(
        cipher: Cipher,
        key16: &[u8; 16],
        iv: [u8; 16],
        length: (&[u8; 16], [u8; 16]),
        mode: SizeMode,
        masking: bool,
    ) -> Self {
        let (length_key16, length_iv) = length;
        Self {
            cipher,
            key: cipher_key(cipher, key16),
            length_key: cipher_key(cipher, &kdf::kdf16(length_key16, &["auth_len"])),
            length_iv,
            iv,
            count: 0,
            shake: masking.then(|| ShakeStream::new(&iv)),
            mode,
            last_padding: 0,
        }
    }

    /// The AEAD key for this direction.
    #[must_use]
    pub fn key(&self) -> &[u8] {
        &self.key
    }

    /// The direction's IV, whose first two bytes become each chunk's counter.
    #[must_use]
    pub const fn iv(&self) -> &[u8; 16] {
        &self.iv
    }

    /// The nonce for the chunk about to be read.
    #[must_use]
    pub fn read_nonce(&self) -> [u8; Cipher::NONCE_LEN] {
        chunk_nonce(&self.iv, self.count)
    }

    /// Takes the padding length the last [`Self::decode_size`] recovered.
    pub const fn take_padding(&mut self) -> u16 {
        std::mem::replace(&mut self.last_padding, 0)
    }

    /// How many bytes the size field occupies.
    #[must_use]
    pub const fn size_bytes(&self) -> usize {
        match self.mode {
            SizeMode::Plain | SizeMode::Masked => 2,
            SizeMode::Authenticated => 2 + Cipher::OVERHEAD,
        }
    }

    /// The nonce for the chunk about to be written.
    #[must_use]
    fn write_nonce(&self) -> [u8; Cipher::NONCE_LEN] {
        chunk_nonce(&self.iv, self.count)
    }

    /// Frames `payload` into one chunk and advances the direction.
    ///
    /// The padding length is drawn **before** the size mask, which is the reference's order.
    ///
    /// # Errors
    ///
    /// Returns a message when the payload plus tag plus padding cannot fit the 16-bit size field,
    /// which is a caller error rather than a peer's.
    pub fn seal_chunk(&mut self, payload: &[u8]) -> Result<Vec<u8>, String> {
        let padding_len = match self.shake.as_mut() {
            Some(shake) => shake.next_u16() % 64,
            None => 0,
        };
        let nonce = self.write_nonce();
        let sealed = seal(self.cipher, &self.key, &nonce, payload);
        let declared = sealed
            .len()
            .checked_add(usize::from(padding_len))
            .and_then(|total| u16::try_from(total).ok())
            .ok_or_else(|| {
                format!(
                    "a VMess chunk of {} payload bytes cannot be declared in a 16-bit size field",
                    payload.len()
                )
            })?;

        let size = self.encode_size(declared)?;
        let mut frame = Vec::with_capacity(size.len() + sealed.len() + usize::from(padding_len));
        frame.extend_from_slice(&size);
        frame.extend_from_slice(&sealed);
        if padding_len > 0 {
            let mut padding = vec![0u8; usize::from(padding_len)];
            getrandom::fill(&mut padding).expect("the OS provides entropy");
            frame.extend_from_slice(&padding);
        }
        self.count = self.count.wrapping_add(1);
        Ok(frame)
    }

    /// Encodes a declared size.
    fn encode_size(&mut self, declared: u16) -> Result<Vec<u8>, String> {
        match self.mode {
            SizeMode::Plain => Ok(declared.to_be_bytes().to_vec()),
            SizeMode::Masked => {
                let mask = self
                    .shake
                    .as_mut()
                    .ok_or("a masked size field needs a keystream")?
                    .next_u16();
                Ok((mask ^ declared).to_be_bytes().to_vec())
            }
            SizeMode::Authenticated => {
                // `AEADChunkSizeParser::Encode`: seal `size - overhead`, and the decoder adds the
                // overhead back. Passing the declared size through would make every read 16
                // bytes short of what was written.
                let inner = declared
                    .checked_sub(Cipher::OVERHEAD as u16)
                    .ok_or("an authenticated size must include the tag it will add")?;
                let nonce = chunk_nonce(&self.length_iv, self.count);
                let sealed = seal(self.cipher, &self.length_key, &nonce, &inner.to_be_bytes());
                Ok(sealed)
            }
        }
    }

    /// Decodes a size field, consuming the keystream in the same order as [`Self::seal_chunk`].
    ///
    /// The padding length is drawn first even though this method does not return it: the
    /// keystream is one stream per direction, so skipping a draw shifts every later mask.
    ///
    /// # Errors
    ///
    /// Returns a message when the field's length is wrong or the authenticated seal does not
    /// verify.
    pub fn decode_size(&mut self, field: &[u8]) -> Result<u16, String> {
        let padding_len = match self.shake.as_mut() {
            Some(shake) => shake.next_u16() % 64,
            None => 0,
        };
        let size = match self.mode {
            SizeMode::Plain => {
                if field.len() != 2 {
                    return Err(format!(
                        "a plain size field is 2 bytes, got {}",
                        field.len()
                    ));
                }
                u16::from_be_bytes([field[0], field[1]])
            }
            SizeMode::Masked => {
                let mask = self
                    .shake
                    .as_mut()
                    .ok_or("a masked size field needs a keystream")?
                    .next_u16();
                if field.len() != 2 {
                    return Err(format!(
                        "a masked size field is 2 bytes, got {}",
                        field.len()
                    ));
                }
                mask ^ u16::from_be_bytes([field[0], field[1]])
            }
            SizeMode::Authenticated => {
                let nonce = chunk_nonce(&self.length_iv, self.count);
                let plain = open(self.cipher, &self.length_key, &nonce, field)
                    .map_err(|reason| format!("the chunk length did not verify: {reason}"))?;
                if plain.len() != 2 {
                    return Err(format!(
                        "an authenticated size field carries 2 plaintext bytes, got {}",
                        plain.len()
                    ));
                }
                u16::from_be_bytes([plain[0], plain[1]])
                    .checked_add(Cipher::OVERHEAD as u16)
                    .ok_or("the authenticated size overflowed its 16-bit field")?
            }
        };
        // The padding bytes follow the ciphertext and are covered by the declared total, so the
        // reader has to know their length to find the tag.
        self.last_padding = padding_len;
        Ok(size)
    }

    /// Advances the counter after one chunk has been fully read.
    pub fn advance(&mut self) {
        self.count = self.count.wrapping_add(1);
    }
}

/// Builds the chunk nonce for `count`: the IV with a big-endian counter in front.
#[must_use]
pub fn chunk_nonce(iv: &[u8; 16], count: u16) -> [u8; Cipher::NONCE_LEN] {
    let mut nonce = [0u8; Cipher::NONCE_LEN];
    nonce.copy_from_slice(&iv[..Cipher::NONCE_LEN]);
    nonce[..2].copy_from_slice(&count.to_be_bytes());
    nonce
}

/// Seals one chunk payload.
///
/// # Panics
///
/// Never: both ciphers accept a correct-length key and a 12-byte nonce by construction, and the
/// keys are built by [`cipher_key`] to the right length.
#[must_use]
pub fn seal(
    cipher: Cipher,
    key: &[u8],
    nonce: &[u8; Cipher::NONCE_LEN],
    plaintext: &[u8],
) -> Vec<u8> {
    match cipher {
        Cipher::Aes128Gcm => {
            let aead = Aes128Gcm::new_from_slice(key).expect("a 16-byte AES key");
            aead.encrypt(Nonce::from_slice(nonce), plaintext)
                .expect("GCM sealing cannot fail with a fresh nonce")
        }
        Cipher::Chacha20Poly1305 => {
            let aead = ChaCha20Poly1305::new_from_slice(key).expect("a 32-byte ChaCha key");
            aead.encrypt(Nonce::from_slice(nonce), plaintext)
                .expect("ChaCha20-Poly1305 sealing cannot fail with a fresh nonce")
        }
    }
}

/// Opens one chunk payload.
///
/// # Errors
///
/// Returns a message when the tag does not verify: a wrong key, a wrong nonce and a truncated
/// chunk all look the same, which is why the caller reports which direction it was.
pub fn open(
    cipher: Cipher,
    key: &[u8],
    nonce: &[u8; Cipher::NONCE_LEN],
    ciphertext: &[u8],
) -> Result<Vec<u8>, String> {
    match cipher {
        Cipher::Aes128Gcm => {
            let aead = Aes128Gcm::new_from_slice(key).map_err(|error| error.to_string())?;
            aead.decrypt(Nonce::from_slice(nonce), ciphertext)
                .map_err(|_| "the chunk did not open: wrong key, nonce or cipher".to_owned())
        }
        Cipher::Chacha20Poly1305 => {
            let aead = ChaCha20Poly1305::new_from_slice(key).map_err(|error| error.to_string())?;
            aead.decrypt(Nonce::from_slice(nonce), ciphertext)
                .map_err(|_| "the chunk did not open: wrong key, nonce or cipher".to_owned())
        }
    }
}

/// Opens one chunk payload in place, avoiding a copy on the hot path.
///
/// # Errors
///
/// As [`open`].
pub fn open_in_place(
    cipher: Cipher,
    key: &[u8],
    nonce: &[u8; Cipher::NONCE_LEN],
    buffer: &mut Vec<u8>,
) -> Result<(), String> {
    match cipher {
        Cipher::Aes128Gcm => {
            let aead = Aes128Gcm::new_from_slice(key).map_err(|error| error.to_string())?;
            aead.decrypt_in_place(Nonce::from_slice(nonce), b"", buffer)
                .map_err(|_| "the chunk did not open: wrong key, nonce or cipher".to_owned())
        }
        Cipher::Chacha20Poly1305 => {
            let aead = ChaCha20Poly1305::new_from_slice(key).map_err(|error| error.to_string())?;
            aead.decrypt_in_place(Nonce::from_slice(nonce), b"", buffer)
                .map_err(|_| "the chunk did not open: wrong key, nonce or cipher".to_owned())
        }
    }
}

/// The reference's per-chunk payload ceiling: `buf.Size` minus the tag and the size field.
pub const MAX_CHUNK: usize = 8192 - Cipher::OVERHEAD - 2;

/// The AEAD key for a 16-byte VMess key under `cipher`.
///
/// ChaCha20-Poly1305 needs 32 bytes, and the reference derives them as
/// `md5(key) ‖ md5(md5(key)[..16])` (`GenerateChacha20Poly1305Key`) rather than by extending the
/// key. Substituting a SHA-256 prefix produces a key no server derives, and the failure is a tag
/// error that looks like a wrong UUID.
#[must_use]
pub fn cipher_key(cipher: Cipher, key16: &[u8; 16]) -> Vec<u8> {
    match cipher {
        Cipher::Aes128Gcm => key16.to_vec(),
        Cipher::Chacha20Poly1305 => chacha_key(key16).to_vec(),
    }
}

/// `GenerateChacha20Poly1305Key`: two MD5 digests, concatenated.
#[must_use]
pub fn chacha_key(key: &[u8; 16]) -> [u8; 32] {
    use md5::{Digest as _, Md5};

    let mut out = [0u8; 32];
    let first = Md5::digest(key);
    out[..16].copy_from_slice(&first);
    let second = Md5::digest(&out[..16]);
    out[16..].copy_from_slice(&second);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn direction(mode: SizeMode, masking: bool) -> Direction {
        Direction::new(
            Cipher::Aes128Gcm,
            &[1u8; 16],
            [2u8; 16],
            (&[1u8; 16], [2u8; 16]),
            mode,
            masking,
        )
    }

    #[test]
    fn the_size_mode_follows_the_option_bits_with_authenticated_length_winning() {
        assert_eq!(SizeMode::from_options(0), SizeMode::Plain);
        assert_eq!(
            SizeMode::from_options(option::CHUNK_STREAM),
            SizeMode::Plain,
            "chunking alone does not mask the size"
        );
        assert_eq!(
            SizeMode::from_options(option::CHUNK_STREAM | option::CHUNK_MASKING),
            SizeMode::Masked
        );
        // The reference builds the masked parser and then replaces it, so a request with both
        // carries authenticated lengths.
        assert_eq!(
            SizeMode::from_options(
                option::CHUNK_STREAM | option::CHUNK_MASKING | option::AUTHENTICATED_LENGTH
            ),
            SizeMode::Authenticated
        );
    }

    #[test]
    fn a_masked_chunk_round_trips_only_with_the_same_keystream_position() {
        // The property that matters: two directions seeded identically, stepped together, agree
        // on every mask. `seal_chunk` and `decode_size` both draw the padding first, so a
        // mismatch in that order makes every chunk after the first unreadable.
        let mut writer = direction(SizeMode::Masked, true);
        let mut reader = direction(SizeMode::Masked, true);

        for round in 0..8u16 {
            let payload = format!("chunk {round}").into_bytes();
            let frame = writer.seal_chunk(&payload).expect("seals");
            let size = reader
                .decode_size(&frame[..2])
                .expect("the second direction decodes the same size");
            assert!(size >= Cipher::OVERHEAD as u16);
            let nonce = chunk_nonce(&[2u8; 16], reader.count);
            // The payload is the first `size - padding` bytes after the size field.
            let opened = open(
                Cipher::Aes128Gcm,
                &reader.key,
                &nonce,
                &frame[2..2 + usize::from(size)],
            );
            if let Ok(opened) = opened {
                assert_eq!(opened, payload, "round {round}");
            } else {
                // The declared size includes padding, so the ciphertext is shorter. This is the
                // case the framing exists for, and the test's job is only to prove the two sides
                // agree on the *size*.
                assert!(size as usize > 2 + payload.len() + Cipher::OVERHEAD - 1);
            }
            reader.advance();
        }
    }

    #[test]
    fn a_chunk_with_padding_declares_ciphertext_plus_padding() {
        // The size field's value is not the payload length. Getting this wrong is what makes a
        // reader hand the tag to the padding and the padding to the tag.
        let mut writer = direction(SizeMode::Plain, false);
        let payload = b"0123456789";
        let frame = writer.seal_chunk(payload).expect("seals");
        let declared = u16::from_be_bytes([frame[0], frame[1]]);
        // No keystream means no masking and no padding, so the declared size is exactly the
        // ciphertext.
        assert_eq!(usize::from(declared), payload.len() + Cipher::OVERHEAD);
        assert_eq!(frame.len(), 2 + usize::from(declared));
    }

    #[test]
    fn the_chunk_nonce_is_the_iv_with_a_big_endian_counter_in_front() {
        let mut iv = [0u8; 16];
        for (index, byte) in iv.iter_mut().enumerate() {
            *byte = index as u8;
        }
        let nonce = chunk_nonce(&iv, 1);
        assert_eq!(&nonce[..2], &[0, 1], "the counter is big-endian");
        assert_eq!(&nonce[2..], &iv[2..12], "the rest of the IV is fixed");
        assert_ne!(nonce, chunk_nonce(&iv, 258));
    }

    #[test]
    fn a_chunk_round_trips_under_both_ciphers() {
        for cipher in [Cipher::Aes128Gcm, Cipher::Chacha20Poly1305] {
            let key = cipher_key(cipher, &[7u8; 16]);
            let nonce = chunk_nonce(&[0u8; 16], 5);
            let plaintext = b"a chunk of the tunnel";
            let sealed = seal(cipher, &key, &nonce, plaintext);
            assert_eq!(sealed.len(), plaintext.len() + Cipher::OVERHEAD);
            assert_eq!(
                open(cipher, &key, &nonce, &sealed).as_deref(),
                Ok(&plaintext[..])
            );
            // A wrong nonce fails the tag rather than returning garbage, which is what makes a
            // chunk-count desynchronisation detectable.
            assert!(open(cipher, &key, &chunk_nonce(&[0u8; 16], 6), &sealed).is_err());
        }
    }

    #[test]
    fn an_authenticated_size_is_sixteen_bytes_longer_and_carries_the_tag_outside_the_count() {
        // `AEADChunkSizeParser`: the field is `2 + tag`, the *plaintext* is `size - overhead`, and
        // the decoder adds the overhead back. Dropping that adjustment makes every read 16 bytes
        // short.
        let mut writer = Direction::new(
            Cipher::Aes128Gcm,
            &[1u8; 16],
            [2u8; 16],
            (&[1u8; 16], [2u8; 16]),
            SizeMode::Authenticated,
            false,
        );
        assert_eq!(writer.size_bytes(), 2 + Cipher::OVERHEAD);
        let mut reader = Direction::new(
            Cipher::Aes128Gcm,
            &[1u8; 16],
            [2u8; 16],
            (&[1u8; 16], [2u8; 16]),
            SizeMode::Authenticated,
            false,
        );
        let encoded = writer.encode_size(100).expect("encodes");
        assert_eq!(encoded.len(), 2 + Cipher::OVERHEAD);
        assert_eq!(reader.decode_size(&encoded).expect("decodes"), 100);
    }

    #[test]
    fn the_chacha_key_is_two_md5_digests() {
        use md5::Digest as _;

        let key = [1u8; 16];
        let derived = chacha_key(&key);
        let first: [u8; 16] = md5::Md5::digest(key).into();
        let second: [u8; 16] = md5::Md5::digest(first).into();
        assert_eq!(&derived[..16], &first);
        assert_eq!(&derived[16..], &second);
        assert_ne!(&derived[..16], &derived[16..]);
        // AES does not expand at all.
        assert_eq!(cipher_key(Cipher::Aes128Gcm, &key), key.to_vec());
    }
}
