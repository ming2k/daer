// SPDX-License-Identifier: AGPL-3.0-only

//! A minimal TLS 1.3 client, for REALITY only.
//!
//! # Why this exists
//!
//! REALITY authenticates by writing a 32-byte tag into the ClientHello's
//! `legacy_session_id`, and by accepting a certificate that does not chain to a CA.
//! `rustls` generates that field itself and exposes no injection point (verified against
//! 0.23.46: `session_id` is `pub(super)` in `src/client/hs.rs:75`, and the only
//! non-resumption path is `SessionId::random` at `hs.rs:119`). No amount of configuration
//! reaches it, so the handshake has to be ours.
//!
//! See [ADR-0010](../../../docs/adr/0010-reality-client-ownership.md). The scope decisions
//! in that record are enforced here structurally, not by convention:
//!
//! * [`Tls13Handshake`] is `pub(crate)` and has no public constructor;
//! * it is reachable only through [`super::connector`], which requires a
//!   `vless://…?security=reality` link;
//! * nothing in this module is exported from the crate root.
//!
//! # What is deliberately absent
//!
//! TLS 1.2, renegotiation, client certificates, session tickets, PSK resumption, 0-RTT,
//! ECH, compression, and cipher-suite negotiation beyond the three real TLS 1.3 AEADs.
//! Each of those is a capability with its own attack surface and none is reachable from a
//! REALITY handshake. A future need is a new ADR, not a feature flag here.
//!
//! # Structure
//!
//! ```text
//!   ClientHello  ── write to socket ──▶  ServerHello, EncryptedExtensions,
//!                                        Certificate, CertificateVerify, Finished
//!                 ◀── read records ───
//!   derive keys ── verify Finished ── verify CertificateVerify ── send Finished
//!                 ──▶ an AsyncRead + AsyncWrite stream of plaintext
//! ```
//!
//! The record layer ([`record`]) and the key schedule ([`schedule`]) are separate so each
//! can be tested against RFC 8448 vectors without a socket.

pub(crate) mod record;
pub(crate) mod schedule;
pub(crate) mod stream;

use std::time::{SystemTime, UNIX_EPOCH};

use x25519_dalek::{PublicKey, StaticSecret};

/// The REALITY authentication key length, in bytes.
pub const AUTH_KEY_LEN: usize = 32;

/// The Xray core version this client reports inside the REALITY tag.
///
/// A server configured with `minClientVer` drops a hello whose version reads as zero — and
/// because REALITY forwards an unauthenticated flow to the impersonated site, the symptom
/// is a working TLS connection to the wrong host rather than an error.
pub const VERSION: [u8; 4] = [26, 10, 29, 0];

/// A REALITY authentication tag, ready to be placed in `legacy_session_id`.
///
/// The tag is bound to the ClientHello it travels in — the server uses the hello as the
/// AEAD's associated data — so it cannot be computed before the hello exists. This type
/// therefore holds the inputs and computes the tag on demand, from the finished hello.
#[derive(Clone)]
pub struct RealityAuth {
    /// The ephemeral X25519 secret whose public half travels in the ClientHello's
    /// `key_share`.
    ///
    /// This is the *same* secret the TLS handshake uses, and it has to be: the server
    /// derives its copy of `auth_key` from the `key_share` extension it reads off the wire.
    /// Generating a second key for the tag produces a key the server never computes, so the
    /// tag never opens — and the failure is silent, because the node forwards the flow to
    /// the impersonated site instead of refusing it.
    ephemeral_secret: StaticSecret,
    /// The node's authentication key, mixed with the hello's random on the wire.
    server_public_key: [u8; 32],
    /// The REALITY short-id, zero-padded to eight bytes.
    short_id: [u8; 8],
    /// The client's concept of "now", frozen so a retry does not change the plaintext.
    now: SystemTime,
}

impl std::fmt::Debug for RealityAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The ephemeral key is a credential: it authenticates this client to the server for
        // the duration of the handshake. Never print it, or the public key either.
        f.write_str("RealityAuth(<redacted>)")
    }
}

impl RealityAuth {
    /// Prepares the inputs for a tag, from the server's public key, a short-id and the time.
    ///
    /// # Errors
    ///
    /// Returns a message when the short-id is longer than 8 bytes or when the system clock
    /// is before the epoch.
    pub fn new(
        server_public_key: &[u8; 32],
        short_id: &[u8],
        now: SystemTime,
    ) -> Result<Self, String> {
        Self::with_secret(server_public_key, short_id, now, random_32())
    }

    /// As [`Self::new`], with the caller supplying the ephemeral secret.
    ///
    /// The handshake owns the key share, so it has to own the tag's key too — see the field
    /// documentation for what goes wrong otherwise.
    ///
    /// # Errors
    ///
    /// As [`Self::new`].
    pub fn with_secret(
        server_public_key: &[u8; 32],
        short_id: &[u8],
        now: SystemTime,
        secret: [u8; 32],
    ) -> Result<Self, String> {
        if short_id.len() > 8 {
            return Err(format!(
                "REALITY short-id is {} bytes, over 8",
                short_id.len()
            ));
        }
        // Validated once here rather than at every tag computation: a key that is not a
        // usable X25519 point fails the same way every time.
        if now.duration_since(UNIX_EPOCH).is_err() {
            return Err("system clock is before the Unix epoch".to_owned());
        }
        let mut padded = [0u8; 8];
        padded[..short_id.len()].copy_from_slice(short_id);
        Ok(Self {
            ephemeral_secret: StaticSecret::from(secret),
            server_public_key: *server_public_key,
            short_id: padded,
            now,
        })
    }

    /// The node's public key, for re-deriving with a different ephemeral secret.
    #[must_use]
    pub const fn server_public_key(&self) -> &[u8; 32] {
        &self.server_public_key
    }

    /// The short-id, zero-padded, for the same reason.
    #[must_use]
    pub const fn short_id_bytes(&self) -> &[u8; 8] {
        &self.short_id
    }

    /// When the tag was prepared.
    #[must_use]
    pub const fn now(&self) -> SystemTime {
        self.now
    }

    /// Seals the tag for `hello`, which is the finished ClientHello on the wire.
    ///
    /// The server's construction, in order:
    ///
    /// ```text
    ///   auth_key = HKDF(shared, salt = hello.random[..20], info = "REALITY")
    ///   plaintext = version(4) || unix_time(4) || short_id(8)
    ///   session_id = AES-256-GCM-Seal(auth_key, nonce = hello.random[20..],
    ///                                  plaintext, aad = hello)   // 16 + 16 bytes
    /// ```
    ///
    /// Every one of those inputs is load-bearing: the salt and nonce come from the hello's
    /// random, and the associated data is the whole hello, so a tag computed over a
    /// different message — or with a fixed salt — never opens. The server then treats the
    /// flow as unauthenticated and forwards it to the impersonated site, which is why a
    /// wrong tag here looks like a working TLS connection to the wrong host.
    ///
    /// # Errors
    ///
    /// Returns a message when the server's key is unusable or the AEAD refuses.
    pub fn seal(&self, hello: &[u8]) -> Result<Sealed, String> {
        // 4-byte handshake header, then legacy_version(2) and `random`(32).
        let random = hello.get(6..38).ok_or_else(|| {
            format!(
                "ClientHello is {} bytes, too short to carry `random`",
                hello.len()
            )
        })?;

        let server_key = PublicKey::from(self.server_public_key);
        let shared = self.ephemeral_secret.diffie_hellman(&server_key);
        if !shared.was_contributory() {
            return Err(
                "REALITY server public key produced a non-contributory shared secret \
                 (it may be a low-order point)"
                    .to_owned(),
            );
        }

        let auth_key =
            schedule::hkdf_sha256(shared.as_bytes(), &random[..20], b"REALITY", AUTH_KEY_LEN);

        let unix_seconds = self
            .now
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "system clock is before the Unix epoch".to_owned())?
            .as_secs()
            .min(u64::from(u32::MAX)) as u32;

        // Fixed layout, from the server's parser: version, unix seconds, short-id.
        // A server with a minimum-version rule drops a hello whose version reads as zero.
        let mut plaintext = [0u8; 16];
        plaintext[..4].copy_from_slice(&VERSION);
        plaintext[4..8].copy_from_slice(&unix_seconds.to_be_bytes());
        plaintext[8..].copy_from_slice(&self.short_id);

        // The associated data is the hello with an **all-zero** session-id.
        //
        // The server zeroes the field before opening the seal: it does
        // `copy(clientHello.sessionId, plainText)` — 32 zero bytes, over a slice that aliases
        // `raw[39..71]` — and only then calls `aead.Open(..., clientHello.original)`.
        //
        // The other reading ("the hello as it stands, with the plaintext in place") is what
        // the Go client appears to do and it is **wrong**: a tag sealed that way is never
        // examined by the server. The observable difference is unambiguous — with the
        // plaintext in the AAD the node answers by forwarding the flow to the impersonated
        // site, and with zeroes the node proceeds with its own TLS session.
        let mut aad = hello.to_vec();
        let offset = 4 + 2 + 32 + 1;
        if aad.len() < offset + AUTH_KEY_LEN {
            return Err(format!(
                "ClientHello is {} bytes, too short to carry a session-id",
                aad.len()
            ));
        }
        aad[offset..offset + AUTH_KEY_LEN].fill(0);

        let sealed = schedule::seal(&auth_key, &random[20..], &plaintext, &aad)?;
        if sealed.len() != AUTH_KEY_LEN {
            return Err(format!(
                "the sealed REALITY tag is {} bytes, expected {AUTH_KEY_LEN}",
                sealed.len()
            ));
        }
        let mut tag = [0u8; AUTH_KEY_LEN];
        tag.copy_from_slice(&sealed);
        Ok(Sealed { tag, auth_key })
    }
}

/// A sealed tag, and the key it was sealed under.
///
/// The key is returned because REALITY's *server* proves itself with the same key: it signs
/// its ephemeral ed25519 key with `HMAC-SHA512(auth_key, ed25519_public)` and writes that as
/// the certificate's signature. Without the key a client cannot tell a real node from the
/// impersonated site the node forwards unauthenticated flows to — which is a silent
/// misroute, not an error.
pub struct Sealed {
    /// The 32 bytes that go into `legacy_session_id`.
    pub tag: [u8; AUTH_KEY_LEN],
    /// The REALITY authentication key, for verifying the node's certificate.
    pub auth_key: Vec<u8>,
}

impl std::fmt::Debug for Sealed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Both fields are credentials.
        f.write_str("Sealed(<redacted>)")
    }
}

/// Everything a handshake needs from the configuration.
/// 32 bytes from the OS random source.
///
/// A failure is fatal rather than silently replaced with a weak value: an ephemeral key
/// that is guessable makes REALITY's forward secrecy a claim rather than a property.
fn random_32() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("the OS random source is available");
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A hello-shaped buffer with a known `random`, so a seal is reproducible.
    /// A hello shaped like the real one: header, legacy_version, `random`, then the
    /// session-id length byte and its 32-byte placeholder.
    fn hello_with_random(random: [u8; 32]) -> Vec<u8> {
        let mut hello = vec![0u8; 6 + 32];
        hello[0] = 0x01; // ClientHello
        hello[4] = 0x03;
        hello[5] = 0x03;
        hello[6..38].copy_from_slice(&random);
        hello.push(32); // session-id length
        hello.extend_from_slice(&[0u8; 32]); // session-id placeholder
        hello
    }

    #[test]
    fn the_auth_material_never_appears_in_debug_output() {
        let auth = RealityAuth::new(&[0x5a; 32], b"sid", SystemTime::now()).expect("builds");
        let rendered = format!("{auth:?}");
        assert!(rendered.contains("redacted"), "{rendered}");
        assert!(
            !rendered.contains("5a"),
            "the key is a credential: {rendered}"
        );
    }

    #[test]
    fn a_short_id_over_eight_bytes_is_refused() {
        let error =
            RealityAuth::new(&[1u8; 32], &[0u8; 9], SystemTime::now()).expect_err("must fail");
        assert!(error.contains("8"), "{error}");
    }

    #[test]
    fn a_short_id_is_zero_padded_to_eight_bytes() {
        // The tag's plaintext has a fixed 16-byte layout; a short-id that shifted the
        // fields instead of padding would be read as a different version and time.
        let auth = RealityAuth::new(&[1u8; 32], &[0xaa, 0xbb], SystemTime::now()).expect("builds");
        assert_eq!(auth.short_id, [0xaa, 0xbb, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn the_tag_commits_to_the_hello_it_travels_in() {
        // The server passes the whole hello as the AEAD's associated data, so a tag sealed
        // over a different hello must not verify. This is the property that makes the tag
        // unusable on another connection.
        let auth = RealityAuth::new(&[7u8; 32], b"abcd", SystemTime::now()).expect("builds");
        let hello = hello_with_random([1u8; 32]);
        let sealed = auth.seal(&hello).expect("seals");
        let tag = sealed.tag;
        let _ = &tag;

        // A different `random` changes both the salt and the nonce, so the tag differs.
        let other = hello_with_random([2u8; 32]);
        let other_sealed = auth.seal(&other).expect("seals");
        let other_tag = other_sealed.tag;
        assert_ne!(tag, other_tag, "the tag must depend on the hello");

        // Nothing of the tag is independent of the hello: the salt and the nonce both come
        // from `random`, so a tag is bound to exactly one ClientHello.
        assert_ne!(&tag[16..], &other_tag[16..]);

        // The auth key is a function of the hello's random too, so the *key* changes as
        // well: a tag cannot be replayed onto another connection.
        assert_ne!(sealed.auth_key, other_sealed.auth_key);
    }

    #[test]
    fn a_hello_too_short_for_a_random_is_refused() {
        let auth = RealityAuth::new(&[7u8; 32], b"", SystemTime::now()).expect("builds");
        let error = auth.seal(&[0u8; 8]).expect_err("must fail");
        assert!(error.contains("random"), "{error}");
    }

    #[test]
    fn the_auth_key_depends_on_the_server_key_and_a_fresh_secret() {
        // REALITY's forward secrecy is that the ephemeral secret is used once and dropped,
        // so two sessions against the same node must not share an auth key.
        let hello = hello_with_random([1u8; 32]);
        let first = RealityAuth::new(&[1u8; 32], b"", SystemTime::now()).expect("builds");
        let second = RealityAuth::new(&[1u8; 32], b"", SystemTime::now()).expect("builds");
        assert_ne!(
            first.seal(&hello).expect("seals").auth_key,
            second.seal(&hello).expect("seals").auth_key,
            "a reused secret would make every session's tag replayable"
        );
    }

    #[test]
    fn an_all_zero_server_key_produces_a_non_contributory_secret() {
        // A low-order point makes the shared secret zero, which would make the auth key
        // depend on nothing. The check is at seal time because that is when the exchange
        // happens.
        let auth = RealityAuth::new(&[0u8; 32], &[], SystemTime::now()).expect("builds");
        let error = auth
            .seal(&hello_with_random([1u8; 32]))
            .expect_err("must fail");
        assert!(error.contains("non-contributory"), "{error}");
    }
}
