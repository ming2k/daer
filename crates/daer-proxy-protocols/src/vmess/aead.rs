// SPDX-License-Identifier: AGPL-3.0-only

//! VMess AEAD's authentication: `AuthID` and the sealed request header (ADR-0030).
//!
//! # What replaced the legacy handshake
//!
//! The legacy VMess header was encrypted with AES-CFB under a key derived from the user's UUID
//! alone, which made a captured first packet replayable forever. AEAD replaces it with three
//! things that change per connection:
//!
//! 1. **`AuthID`** — a 16-byte value that proves the client knows the `cmdKey` *and* is
//!    current:
//!
//!    ```text
//!      plaintext = unix_time(8) ‖ random(4) ‖ crc32(plaintext[..12])(4)
//!      AuthID    = AES-128-ECB(KDF16(cmdKey, "AES Auth ID Encryption"), plaintext)
//!    ```
//!
//!    A server accepts it only within ±120 s and only once (it keeps a replay filter).
//!
//! 2. **A connection nonce** — 8 fresh random bytes, sent in the clear, which together with
//!    `AuthID` derives the two header keys.
//!
//! 3. **Two AES-GCM seals** — one over the 2-byte header length, one over the header itself,
//!    both using `AuthID` as associated data so a ciphertext cannot be moved to another
//!    connection.
//!
//! # Why the derivation is spelled out
//!
//! Every input to the KDF is a *byte string that is usually not valid UTF-8*: the `AuthID` and
//! the nonce are raw bytes, and Go passes them as `string(...)`. Reading them as text, or
//! hex-encoding them, produces keys that no server derives — and the failure is a silent
//! decrypt error on the node, indistinguishable from a wrong UUID.

use aes::Aes128;
use aes::cipher::{BlockDecrypt, BlockEncrypt, generic_array::GenericArray};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Nonce};

use crate::vmess::kdf::{self, kdf16};

/// Builds the `AuthID` for `unix_time`, the way `aead.CreateAuthID` does.
///
/// `random` is the four bytes the reference reads from `crypto/rand`; it is a parameter here so
/// the construction is testable against the reference's own output.
#[must_use]
pub fn create_auth_id(cmd_key: &[u8; 16], unix_time: i64, random: [u8; 4]) -> [u8; 16] {
    let mut plaintext = [0u8; 16];
    plaintext[..8].copy_from_slice(&unix_time.to_be_bytes());
    plaintext[8..12].copy_from_slice(&random);
    let checksum = crc32_ieee(&plaintext[..12]);
    plaintext[12..].copy_from_slice(&checksum.to_be_bytes());

    let key = kdf16(cmd_key, &[kdf::SALT_AUTH_ID_ENCRYPTION_KEY]);
    let cipher = Aes128::new(GenericArray::from_slice(&key));
    let mut block = GenericArray::clone_from_slice(&plaintext);
    cipher.encrypt_block(&mut block);
    block.into()
}

/// Decrypts an `AuthID`, for a test that wants to see what was sealed.
///
/// The reference's server does this (`AuthIDDecoder.Decode`); daer is a client and never needs
/// it in production, but the round trip is the only way to prove the construction without a
/// server, and it is also what a differential test against `xray` would compare.
#[must_use]
pub fn decode_auth_id(cmd_key: &[u8; 16], auth_id: [u8; 16]) -> ([u8; 8], [u8; 4], u32) {
    let key = kdf16(cmd_key, &[kdf::SALT_AUTH_ID_ENCRYPTION_KEY]);
    let cipher = Aes128::new(GenericArray::from_slice(&key));
    let mut block = GenericArray::clone_from_slice(&auth_id);
    cipher.decrypt_block(&mut block);
    let plaintext: [u8; 16] = block.into();
    let mut time = [0u8; 8];
    time.copy_from_slice(&plaintext[..8]);
    let mut random = [0u8; 4];
    random.copy_from_slice(&plaintext[8..12]);
    let checksum = u32::from_be_bytes([plaintext[12], plaintext[13], plaintext[14], plaintext[15]]);
    (time, random, checksum)
}

/// CRC-32 with the IEEE polynomial, which is what `hash/crc32.ChecksumIEEE` computes.
#[must_use]
pub fn crc32_ieee(bytes: &[u8]) -> u32 {
    let mut crc: u32 = 0xffff_ffff;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

/// Seals a request header, producing the bytes that go on the wire.
///
/// ```text
///   [auth_id 16] [AEAD(length 2) 18] [nonce 8] [AEAD(header) header+16]
/// ```
#[must_use]
pub fn seal_header(
    cmd_key: &[u8; 16],
    header: &[u8],
    auth_id: [u8; 16],
    nonce: [u8; 8],
) -> Vec<u8> {
    // The reference passes `string(authid)` and `string(nonce)` to the KDF: raw bytes, not
    // text. `kdf::kdf` takes `&[&str]` for the *named* salts, so the byte-valued path
    // components are appended as a separate slice here.
    let auth_bytes = auth_id;
    let nonce_bytes = nonce;
    let path = |salt: &'static str| (salt, auth_bytes, nonce_bytes);

    let (length_salt, _, _) = path(kdf::SALT_HEADER_PAYLOAD_LENGTH_AEAD_KEY);
    let length_key = kdf16_bytes(cmd_key, length_salt, &auth_bytes, &nonce_bytes);
    let (length_iv_salt, _, _) = path(kdf::SALT_HEADER_PAYLOAD_LENGTH_AEAD_IV);
    let length_iv = kdf_bytes(cmd_key, length_iv_salt, &auth_bytes, &nonce_bytes);

    let length_cipher = Aes128Gcm::new_from_slice(&length_key).expect("a 16-byte AES key");
    let length_plain = (header.len() as u16).to_be_bytes();
    let length_sealed = length_cipher
        .encrypt(
            Nonce::from_slice(&length_iv[..12]),
            aes_gcm::aead::Payload {
                msg: &length_plain,
                aad: &auth_id,
            },
        )
        .expect("GCM sealing cannot fail with a fresh nonce");

    let payload_key = kdf16_bytes(
        cmd_key,
        kdf::SALT_HEADER_PAYLOAD_AEAD_KEY,
        &auth_bytes,
        &nonce_bytes,
    );
    let payload_iv = kdf_bytes(
        cmd_key,
        kdf::SALT_HEADER_PAYLOAD_AEAD_IV,
        &auth_bytes,
        &nonce_bytes,
    );
    let payload_cipher = Aes128Gcm::new_from_slice(&payload_key).expect("a 16-byte AES key");
    let payload_sealed = payload_cipher
        .encrypt(
            Nonce::from_slice(&payload_iv[..12]),
            aes_gcm::aead::Payload {
                msg: header,
                aad: &auth_id,
            },
        )
        .expect("GCM sealing cannot fail with a fresh nonce");

    let mut out = Vec::with_capacity(16 + length_sealed.len() + 8 + payload_sealed.len());
    out.extend_from_slice(&auth_id);
    out.extend_from_slice(&length_sealed);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&payload_sealed);
    out
}

/// Opens a sealed request header. Used by tests and by a future differential check; daer is a
/// client and never opens its own header in production.
///
/// # Errors
///
/// Returns a message when either AEAD refuses or the buffer is truncated.
pub fn open_header(cmd_key: &[u8; 16], sealed: &[u8]) -> Result<Vec<u8>, String> {
    if sealed.len() < 16 + 18 + 8 {
        return Err("the sealed header is too short to hold its fixed fields".to_owned());
    }
    let mut auth_id = [0u8; 16];
    auth_id.copy_from_slice(&sealed[..16]);
    let length_sealed = &sealed[16..34];
    let mut nonce = [0u8; 8];
    nonce.copy_from_slice(&sealed[34..42]);

    let length_key = kdf16_bytes(
        cmd_key,
        kdf::SALT_HEADER_PAYLOAD_LENGTH_AEAD_KEY,
        &auth_id,
        &nonce,
    );
    let length_iv = kdf_bytes(
        cmd_key,
        kdf::SALT_HEADER_PAYLOAD_LENGTH_AEAD_IV,
        &auth_id,
        &nonce,
    );
    let length_cipher = Aes128Gcm::new_from_slice(&length_key).expect("a 16-byte AES key");
    let length_plain = length_cipher
        .decrypt(
            Nonce::from_slice(&length_iv[..12]),
            aes_gcm::aead::Payload {
                msg: length_sealed,
                aad: &auth_id,
            },
        )
        .map_err(|_| "the header length did not open: wrong cmdKey or AuthID".to_owned())?;
    let length = usize::from(u16::from_be_bytes([length_plain[0], length_plain[1]]));
    if sealed.len() < 42 + length + 16 {
        return Err(format!(
            "the sealed header is {} bytes, but its length field declares {}",
            sealed.len(),
            42 + length + 16
        ));
    }

    let payload_key = kdf16_bytes(cmd_key, kdf::SALT_HEADER_PAYLOAD_AEAD_KEY, &auth_id, &nonce);
    let payload_iv = kdf_bytes(cmd_key, kdf::SALT_HEADER_PAYLOAD_AEAD_IV, &auth_id, &nonce);
    let payload_cipher = Aes128Gcm::new_from_slice(&payload_key).expect("a 16-byte AES key");
    payload_cipher
        .decrypt(
            Nonce::from_slice(&payload_iv[..12]),
            aes_gcm::aead::Payload {
                msg: &sealed[42..42 + length + 16],
                aad: &auth_id,
            },
        )
        .map_err(|_| "the header body did not open: wrong cmdKey or AuthID".to_owned())
}

/// `KDF(key, salt, auth_id, nonce)` where the last two are raw bytes.
///
/// Kept separate from [`kdf::kdf`] because that function takes `&[&str]`: the *salt* is text,
/// the other two components are arbitrary bytes, and Go's `string(b)` conversion means the KDF
/// sees them as bytes rather than as their text representation.
fn kdf_bytes(key: &[u8], salt: &str, auth_id: &[u8; 16], nonce: &[u8; 8]) -> [u8; 32] {
    // The reference's `kdf.go` accepts `...string`, and Go strings are byte slices. Rebuilding
    // the path as text would lose any byte that is not valid UTF-8, which is most of them.
    let mut components: Vec<Vec<u8>> = vec![salt.as_bytes().to_vec()];
    components.push(auth_id.to_vec());
    components.push(nonce.to_vec());
    kdf::kdf_components(key, &components)
}

/// As [`kdf_bytes`], truncated to 16 bytes.
fn kdf16_bytes(key: &[u8], salt: &str, auth_id: &[u8; 16], nonce: &[u8; 8]) -> [u8; 16] {
    let full = kdf_bytes(key, salt, auth_id, nonce);
    let mut out = [0u8; 16];
    out.copy_from_slice(&full[..16]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vmess::kdf::cmd_key;

    fn uuid() -> [u8; 16] {
        [
            0xdf, 0x4a, 0xf3, 0xd0, 0x03, 0x0e, 0x40, 0x62, 0xba, 0xa6, 0xeb, 0x9d, 0xd4, 0x52,
            0x98, 0xef,
        ]
    }

    #[test]
    fn crc32_matches_the_ieee_polynomial() {
        // The reference uses `crc32.ChecksumIEEE`. The empty value is zero and the standard
        // check value is 0xcbf43926, so both are asserted before any AuthID depends on it.
        assert_eq!(crc32_ieee(b""), 0);
        assert_eq!(crc32_ieee(b"123456789"), 0xcbf4_3926);
    }

    #[test]
    fn an_auth_id_round_trips_and_carries_its_own_checksum() {
        let cmd = cmd_key(&uuid());
        let auth_id = create_auth_id(&cmd, 1_700_000_000, [1, 2, 3, 4]);
        let (time, random, checksum) = decode_auth_id(&cmd, auth_id);
        assert_eq!(time, 1_700_000_000i64.to_be_bytes());
        assert_eq!(random, [1, 2, 3, 4]);
        // The checksum is over the first 12 plaintext bytes, which is what makes a corrupted
        // AuthID detectable instead of just opening as garbage.
        let mut plaintext = [0u8; 12];
        plaintext[..8].copy_from_slice(&time);
        plaintext[8..].copy_from_slice(&random);
        assert_eq!(checksum, crc32_ieee(&plaintext));
    }

    #[test]
    fn an_auth_id_changes_with_time_and_with_the_random_part() {
        // The server accepts an AuthID once, inside a ±120 s window; a constant one is a
        // replay and is rejected outright.
        let cmd = cmd_key(&uuid());
        let first = create_auth_id(&cmd, 1_700_000_000, [0, 0, 0, 1]);
        assert_ne!(first, create_auth_id(&cmd, 1_700_000_001, [0, 0, 0, 1]));
        assert_ne!(first, create_auth_id(&cmd, 1_700_000_000, [0, 0, 0, 2]));
    }

    #[test]
    fn a_sealed_header_opens_only_with_its_own_auth_id_and_nonce() {
        // The associated data is the AuthID, so a ciphertext cannot be moved to another
        // connection — which is the whole point of the AEAD format.
        let cmd = cmd_key(&uuid());
        let header = b"a VMess request header, shaped exactly as the node expects";
        let auth_id = create_auth_id(&cmd, 1_700_000_000, [9, 9, 9, 9]);
        let nonce = [7u8; 8];
        let sealed = seal_header(&cmd, header, auth_id, nonce);

        assert_eq!(&sealed[..16], &auth_id, "the AuthID is sent in the clear");
        assert_eq!(&sealed[34..42], &nonce, "and so is the nonce");
        assert_eq!(open_header(&cmd, &sealed).as_deref(), Ok(&header[..]));

        // A different nonce derives different keys, so the same bytes do not open.
        let mut tampered = sealed.clone();
        tampered[34] ^= 0xff;
        assert!(open_header(&cmd, &tampered).is_err());

        // And a different cmdKey does not open it either.
        let other_cmd = cmd_key(&[0u8; 16]);
        assert!(open_header(&other_cmd, &sealed).is_err());
    }

    #[test]
    fn the_sealed_header_has_the_references_field_order_and_sizes() {
        let cmd = cmd_key(&uuid());
        let header = b"0123456789";
        let auth_id = create_auth_id(&cmd, 1_700_000_000, [0; 4]);
        let nonce = [0u8; 8];
        let sealed = seal_header(&cmd, header, auth_id, nonce);

        // 16 auth + (2 length + 16 tag) + 8 nonce + (10 header + 16 tag)
        assert_eq!(sealed.len(), 16 + 18 + 8 + header.len() + 16);
    }
}
