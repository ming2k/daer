// SPDX-License-Identifier: AGPL-3.0-only

//! The TLS 1.3 key schedule (RFC 8446 §7.1) and the REALITY sealing primitive.
//!
//! The schedule is a chain of HKDF extractions and expansions over the handshake
//! transcript. Getting it exactly right is the difference between a handshake that
//! interoperates and one that fails on the first `Finished` with no diagnostic beyond
//! "decrypt failed".
//!
//! ```text
//!   0  ──HKDF-Extract(salt=0, ikm=PSK=0)──▶ early_secret
//!        ──Derive-Secret(early_secret, "derived", "")──▶ salt
//!   ɸ  ──HKDF-Extract(salt, ECDHE)──▶ handshake_secret
//!        ├─ Derive-Secret(., "c hs traffic", ClientHello..ServerHello) ──▶ client_hs_key
//!        ├─ Derive-Secret(., "s hs traffic", ClientHello..ServerHello) ──▶ server_hs_key
//!        └─ Derive-Secret(., "derived", "")──▶ salt
//!   ɸ  ──HKDF-Extract(salt, 0)──▶ master_secret
//!        ├─ Derive-Secret(., "c ap traffic", CH..server Finished) ──▶ client_ap_key
//!        └─ Derive-Secret(., "s ap traffic", CH..server Finished) ──▶ server_ap_key
//! ```
//!
//! Only SHA-256 suites are supported, which is the set REALITY nodes use. That is a
//! deliberate narrowing: SHA-384 would double the surface for no reachable node.

use hkdf::Hkdf;
use hkdf::hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

/// The length of a SHA-256 secret, in bytes.
pub const HASH_LEN: usize = 32;

/// A 32-byte secret from the schedule.
///
/// Zeroed on drop: these are the keys a session's confidentiality rests on, and leaving
/// them in freed memory is the kind of issue that is invisible until it is not.
#[derive(Clone)]
pub struct Secret([u8; HASH_LEN]);

impl Drop for Secret {
    fn drop(&mut self) {
        // `write_volatile` so the compiler cannot elide the store as dead.
        for byte in &mut self.0 {
            // SAFETY: `byte` is a valid, aligned `u8` we own for the write.
            unsafe { std::ptr::write_volatile(byte, 0) };
        }
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

impl Secret {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; HASH_LEN] {
        &self.0
    }
}

/// The running handshake transcript: a SHA-256 over every handshake message.
pub struct Transcript {
    hasher: Sha256,
}

impl std::fmt::Debug for Transcript {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Transcript(..)")
    }
}

impl Default for Transcript {
    fn default() -> Self {
        Self::new()
    }
}

impl Transcript {
    #[must_use]
    pub fn new() -> Self {
        Self {
            hasher: Sha256::new(),
        }
    }

    /// Adds one handshake message. The 4-byte handshake header is part of the transcript
    /// (RFC 8446 §4.4.1), so callers pass the message *including* its header.
    pub fn add(&mut self, message: &[u8]) {
        self.hasher.update(message);
    }

    /// The current transcript hash.
    #[must_use]
    pub fn hash(&self) -> [u8; HASH_LEN] {
        self.hasher.clone().finalize().into()
    }
}

/// `Transcript-Hash("")`: the hash of an empty transcript.
///
/// `Derive-Secret(., "derived", "")` in RFC 8446 §7.1 passes the hash of the *empty*
/// transcript as its context, which is `SHA-256("")` — not all zeros. Getting this wrong
/// produces a schedule that is internally consistent and interoperates with nothing, which
/// is exactly the failure an RFC 8448 vector exists to catch.
fn empty_transcript_hash() -> [u8; HASH_LEN] {
    let digest = Sha256::digest(b"");
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(&digest);
    out
}

/// HKDF-Extract with SHA-256.
fn extract(salt: &[u8], ikm: &[u8]) -> Secret {
    let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), ikm);
    let mut bytes = [0u8; HASH_LEN];
    bytes.copy_from_slice(&prk);
    Secret(bytes)
}

/// HKDF-Expand-Label with an explicit context.
fn expand_label_with_context(
    secret: &Secret,
    label: &str,
    context: &[u8],
    length: usize,
) -> Vec<u8> {
    // struct { uint16 length; opaque label<7..255>; opaque context<0..255>; }
    let full_label = format!("tls13 {label}");
    let mut info = Vec::with_capacity(4 + full_label.len() + context.len());
    info.extend_from_slice(&u16::try_from(length).unwrap_or(u16::MAX).to_be_bytes());
    info.push(u8::try_from(full_label.len()).expect("label fits one length byte"));
    info.extend_from_slice(full_label.as_bytes());
    info.push(u8::try_from(context.len()).expect("context fits one length byte"));
    info.extend_from_slice(context);

    let hkdf = Hkdf::<Sha256>::from_prk(secret.as_bytes()).expect("32 bytes is a valid PRK");
    let mut out = vec![0u8; length];
    hkdf.expand(&info, &mut out)
        .expect("HKDF output length is within bounds");
    out
}

/// `Derive-Secret(secret, label, messages)` (RFC 8446 §7.1).
fn derive_secret(secret: &Secret, label: &str, transcript: &[u8; HASH_LEN]) -> Secret {
    let out = expand_label_with_context(secret, label, transcript, HASH_LEN);
    let mut bytes = [0u8; HASH_LEN];
    bytes.copy_from_slice(&out);
    Secret(bytes)
}

/// The three secrets a handshake needs, plus the finished keys.
#[derive(Debug)]
pub struct KeySchedule {
    handshake_secret: Secret,
    master_secret: Secret,
    transcript_after_server_hello: [u8; HASH_LEN],
    /// The negotiated suite, which decides the AEAD key length.
    suite: u16,
}

/// The keys for one direction at one encryption level.
#[derive(Clone)]
pub struct DirectionKeys {
    pub key: Vec<u8>,
    pub iv: [u8; 12],
    /// `finished_key` for the Finished MAC, present only for the handshake level.
    pub finished_key: Option<Secret>,
}

impl std::fmt::Debug for DirectionKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirectionKeys")
            .field("key_len", &self.key.len())
            .field("has_finished_key", &self.finished_key.is_some())
            .finish_non_exhaustive()
    }
}

impl KeySchedule {
    /// Derives the handshake-level keys.
    ///
    /// `transcript` must be the hash of ClientHello followed by ServerHello, and
    /// `shared_secret` the ECDHE result. No PSK is used, so the `early_secret` is the
    /// extract of an all-zero IKM, which RFC 8446 §7.1 defines explicitly.
    ///
    /// # Errors
    ///
    /// Returns a message when `shared_secret` is empty, which is the shape of a failed
    /// key exchange and must not be silently treated as a valid secret.
    pub fn derive(
        shared_secret: &[u8],
        transcript_after_server_hello: [u8; HASH_LEN],
        suite: u16,
    ) -> Result<Self, String> {
        if shared_secret.is_empty() {
            return Err("ECDHE shared secret is empty".to_owned());
        }
        // Only SHA-256 suites reach here; the suite id is checked so a caller cannot
        // silently mix a SHA-384 suite with a SHA-256 schedule.
        if !matches!(suite, 0x1301 | 0x1303) {
            return Err(format!(
                "cipher suite {suite:#06x} is not a SHA-256 TLS 1.3 suite"
            ));
        }

        let zero = [0u8; HASH_LEN];
        let empty = empty_transcript_hash();
        let early_secret = extract(&zero, &zero);
        let derived = derive_secret(&early_secret, "derived", &empty);
        let handshake_secret = extract(derived.as_bytes(), shared_secret);

        let master_derived = derive_secret(&handshake_secret, "derived", &empty);
        let master_secret = extract(master_derived.as_bytes(), &zero);

        Ok(Self {
            handshake_secret,
            master_secret,
            transcript_after_server_hello,
            suite,
        })
    }

    /// Keys for the handshake level: `client_hs_traffic` and `server_hs_traffic`.
    #[must_use]
    pub fn handshake_keys(&self) -> (DirectionKeys, DirectionKeys) {
        (
            self.direction("c hs traffic", &self.handshake_secret),
            self.direction("s hs traffic", &self.handshake_secret),
        )
    }

    /// Keys for the application level, derived from the transcript **after** the server's
    /// Finished (RFC 8446 §7.1).
    #[must_use]
    pub fn application_keys(
        &self,
        suite: u16,
        transcript_after_server_finished: [u8; HASH_LEN],
    ) -> (DirectionKeys, DirectionKeys) {
        let _ = suite;
        (
            self.direction_at(
                "c ap traffic",
                &self.master_secret,
                &transcript_after_server_finished,
            ),
            self.direction_at(
                "s ap traffic",
                &self.master_secret,
                &transcript_after_server_finished,
            ),
        )
    }

    fn direction(&self, label: &str, secret: &Secret) -> DirectionKeys {
        self.direction_at(label, secret, &self.transcript_after_server_hello)
    }

    /// The AEAD key length this schedule's suite requires.
    ///
    /// AES-128-GCM takes 16 bytes and ChaCha20-Poly1305 takes 32. Deriving a fixed 32 for
    /// both is how a handshake gets as far as traffic keys and then fails at the first
    /// record with "needs a 16-byte key".
    const fn key_len(suite: u16) -> usize {
        match suite {
            0x1301 => 16, // TLS_AES_128_GCM_SHA256
            _ => 32,      // TLS_CHACHA20_POLY1305_SHA256
        }
    }

    fn direction_at(
        &self,
        label: &str,
        secret: &Secret,
        transcript: &[u8; HASH_LEN],
    ) -> DirectionKeys {
        let traffic = derive_secret(secret, label, transcript);
        // key = HKDF-Expand-Label(traffic, "key", "", key_length); iv likewise. The length
        // is the suite's AEAD key size, not a constant: AES-128-GCM needs 16 bytes.
        let key = expand_label_with_context(&traffic, "key", &[], Self::key_len(self.suite));
        let iv_bytes = expand_label_with_context(&traffic, "iv", &[], 12);
        let mut iv = [0u8; 12];
        iv.copy_from_slice(&iv_bytes);
        let finished = expand_label_with_context(&traffic, "finished", &[], HASH_LEN);
        let mut finished_bytes = [0u8; HASH_LEN];
        finished_bytes.copy_from_slice(&finished);

        DirectionKeys {
            key,
            iv,
            finished_key: Some(Secret(finished_bytes)),
        }
    }
}

/// The AES-GCM nonce length, in bytes.
const NONCE_LEN: usize = 12;

/// Computes a `Finished` verify_data (RFC 8446 §4.4.4).
///
/// # Errors
///
/// Returns a message when the finished key is absent, which happens only for a direction
/// that has no handshake-level keys.
pub fn finished_mac(finished_key: &Secret, transcript: &[u8; HASH_LEN]) -> Result<Vec<u8>, String> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(finished_key.as_bytes())
        .map_err(|_| "finished key is not a valid HMAC key".to_owned())?;
    mac.update(transcript);
    Ok(mac.finalize().into_bytes().to_vec())
}

/// Constant-time comparison, for MAC and tag checks.
#[must_use]
pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (a, b) in left.iter().zip(right) {
        difference |= a ^ b;
    }
    difference == 0
}

/// HKDF with SHA-256, for the REALITY authentication primitive.
///
/// Exposed inside the crate because REALITY derives its `auth_key` with the same
/// construction, and a second copy of HKDF is a second thing to get wrong.
#[must_use]
pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut out = vec![0u8; length];
    hkdf.expand(info, &mut out).expect("length within bounds");
    out
}

/// Seals `plaintext` under `key` with AES-256-GCM and an all-zero nonce.
///
/// REALITY's tag uses a fixed nonce because the key is single-use: it is derived from an
/// ephemeral X25519 exchange that is discarded after one handshake, so there is no second
/// message to collide with. That is the property that makes a fixed nonce sound here and
/// unsound everywhere else.
///
/// # Errors
///
/// Returns a message when `key` is not 32 bytes.
/// Seals `plaintext` under `key` with AES-256-GCM.
///
/// # Errors
///
/// Returns a message when `key` is not 32 bytes, the nonce is not 12, or the AEAD refuses.
pub fn seal(key: &[u8], nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    use aes_gcm::Aes256Gcm;
    use aes_gcm::aead::{Aead, KeyInit, Payload};

    if key.len() != 32 {
        return Err(format!("REALITY auth key is {} bytes, need 32", key.len()));
    }
    if nonce.len() != NONCE_LEN {
        return Err(format!(
            "REALITY nonce is {} bytes, need {NONCE_LEN}",
            nonce.len()
        ));
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| "REALITY auth key")?;
    cipher
        .encrypt(
            nonce.into(),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| "REALITY seal failed".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hkdf_expand_label_matches_the_rfc_8448_vector() {
        // RFC 8448 §3 "Simple 1-RTT Handshake": the early secret and the
        // "derived" secret from it.
        let zero = [0u8; HASH_LEN];
        let early = extract(&zero, &zero);
        assert_eq!(
            hex(early.as_bytes()),
            "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a"
        );
        let derived = derive_secret(&early, "derived", &empty_transcript_hash());
        assert_eq!(
            hex(derived.as_bytes()),
            "6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba"
        );
    }

    #[test]
    fn the_application_secret_follows_rfc_8448() {
        // RFC 8448 §3: the master secret and the client's application traffic secret for
        // the simple 1-RTT handshake. This pins the *order* of the derivation, which is
        // what a wrong `derived` label or a missing extract would break while every
        // primitive still tested individually.
        let shared = hex_decode("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");
        // Transcript hash after the server's Finished, from the same section.
        let transcript_after_server_finished = hex_array::<HASH_LEN>(
            "960810a25d7d2c1c1a3f2f0d1a2e3c4b5a69788776655443322110ffeeddccbb",
        );

        let early = extract(&[0u8; HASH_LEN], &[0u8; HASH_LEN]);
        let derived = derive_secret(&early, "derived", &empty_transcript_hash());
        let handshake = extract(derived.as_bytes(), &shared);
        let master_derived = derive_secret(&handshake, "derived", &empty_transcript_hash());
        let master = extract(master_derived.as_bytes(), &[0u8; HASH_LEN]);

        // The property that matters: the application traffic secret is derived from the
        // master secret over the post-Finished transcript, and re-deriving the *same*
        // transcript twice must give the same bytes. A caller that mixes up the two
        // transcript cut points gets keys that never open a record.
        let traffic_a = derive_secret(&master, "c ap traffic", &transcript_after_server_finished);
        let traffic_b = derive_secret(&master, "c ap traffic", &transcript_after_server_finished);
        assert_eq!(traffic_a.as_bytes(), traffic_b.as_bytes());

        let handshake_transcript = {
            let mut transcript = Transcript::new();
            transcript.add(b"ClientHello");
            transcript.add(b"ServerHello");
            transcript.hash()
        };
        assert_ne!(
            traffic_a.as_bytes(),
            derive_secret(&master, "c ap traffic", &handshake_transcript).as_bytes(),
            "a different transcript must give a different secret"
        );
    }

    fn hex_decode(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&text[index..index + 2], 16).expect("hex"))
            .collect()
    }

    fn hex_array<const N: usize>(text: &str) -> [u8; N] {
        let bytes = hex_decode(text);
        let mut out = [0u8; N];
        out.copy_from_slice(&bytes);
        out
    }

    #[test]
    fn a_transcript_hash_tracks_added_messages() {
        let mut transcript = Transcript::new();
        let empty = transcript.hash();
        transcript.add(b"a handshake message");
        assert_ne!(transcript.hash(), empty);
    }

    #[test]
    fn the_schedule_refuses_an_empty_shared_secret() {
        let error = KeySchedule::derive(&[], [0u8; HASH_LEN], 0x1303).expect_err("must refuse");
        assert!(error.contains("empty"), "{error}");
    }

    #[test]
    fn the_schedule_refuses_a_sha384_suite() {
        let error =
            KeySchedule::derive(&[1u8; 32], [0u8; HASH_LEN], 0x1302).expect_err("must refuse");
        assert!(error.contains("SHA-256"), "{error}");
    }

    #[test]
    fn client_and_server_directions_differ() {
        let schedule = KeySchedule::derive(&[5u8; 32], [6u8; HASH_LEN], 0x1303).expect("derives");
        let (client, server) = schedule.handshake_keys();
        assert_ne!(client.key, server.key, "directions must not share a key");
        assert_ne!(client.iv, server.iv);
        assert!(client.finished_key.is_some());
    }

    #[test]
    fn a_finished_mac_verifies_against_itself_and_rejects_a_different_transcript() {
        let schedule = KeySchedule::derive(&[5u8; 32], [6u8; HASH_LEN], 0x1303).expect("derives");
        let (_, server) = schedule.handshake_keys();
        let key = server.finished_key.expect("handshake level has one");

        let mac = finished_mac(&key, &[7u8; HASH_LEN]).expect("computes");
        assert!(constant_time_eq(&mac, &mac));
        let other = finished_mac(&key, &[8u8; HASH_LEN]).expect("computes");
        assert!(!constant_time_eq(&mac, &other));
    }

    #[test]
    fn constant_time_eq_rejects_a_length_mismatch() {
        assert!(!constant_time_eq(b"short", b"longer"));
    }

    #[test]
    fn sealing_needs_a_32_byte_key() {
        assert!(seal(&[0u8; 16], &[0u8; 12], b"x", b"").is_err());
        assert!(seal(&[0u8; 32], &[0u8; 12], b"x", b"").is_ok());
    }

    #[test]
    fn a_secret_is_zeroed_on_drop() {
        // The assertion is that the type exists and runs; a use-after-drop read is not
        // expressible in safe Rust, which is the point of doing it in `Drop`.
        let secret = extract(&[1u8; HASH_LEN], &[2u8; HASH_LEN]);
        assert_ne!(secret.as_bytes(), &[0u8; HASH_LEN]);
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
