// SPDX-License-Identifier: AGPL-3.0-only

//! The `X25519MLKEM768` hybrid key exchange (code point `0x11ec`).
//!
//! # Why this is not optional
//!
//! REALITY servers from `xtls/reality` v0.0.0-20260908062103 onward **require** this group.
//! The server's authentication loop refuses to try at all when the ClientHello carries no
//! `X25519MLKEM768` share:
//!
//! ```text
//!   if peerPub2 == nil {
//!       break // reject outdated/strange Client Hello that doesn't have X25519MLKEM768
//!   }
//! ```
//!
//! `peerPub2` is set only from the ML-KEM half of that group. So a client offering plain
//! `x25519` is not "downgraded" — its tag is never examined, the flow is forwarded to the
//! impersonated site, and the connection succeeds against the wrong host. Every layer below
//! therefore reports success while nothing is proxied.
//!
//! # The construction
//!
//! Per draft-kwiatkowski-tls-ecdhe-mlkem, the group is the concatenation, in this order:
//!
//! ```text
//!   key_share.client  = ML-KEM-768 encapsulation key (1184) || X25519 public key (32)
//!   key_share.server  = ML-KEM-768 ciphertext          (1088) || X25519 public key (32)
//!   shared secret     = ML-KEM-768 shared secret       (32)   || X25519 shared secret (32)
//! ```
//!
//! The shared secret is 64 bytes and is used directly as the ECDHE input to the key
//! schedule — it is *not* hashed down first. The order matters in both directions, and
//! getting it wrong produces a key schedule that disagrees with the server without any
//! visible error beyond a `Finished` that does not verify.

use ml_kem::kem::Decapsulate;
use ml_kem::{EncodedSizeUser, KemCore, MlKem768};

use rand_core::CryptoRngCore;
use x25519_dalek::{PublicKey, StaticSecret};

/// The TLS group code point for `X25519MLKEM768`.
pub const GROUP: u16 = 0x11ec;

/// The ML-KEM-768 encapsulation key length, in bytes.
pub const MLKEM_ENCAPSULATION_KEY_LEN: usize = 1184;

/// The ML-KEM-768 ciphertext length, in bytes.
pub const MLKEM_CIPHERTEXT_LEN: usize = 1088;

/// The client's share length: ML-KEM encapsulation key followed by X25519.
pub const CLIENT_SHARE_LEN: usize = MLKEM_ENCAPSULATION_KEY_LEN + 32;

/// The total shared secret length: ML-KEM secret followed by X25519 secret.
pub const SHARED_SECRET_LEN: usize = 64;

/// The client's half of the exchange, kept until the server's share arrives.
pub struct Client {
    decapsulation_key: <MlKem768 as KemCore>::DecapsulationKey,
    x25519_secret: StaticSecret,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Both halves are secret; only the fact that a session exists is printed.
        f.write_str("hybrid::Client(<redacted>)")
    }
}

impl Client {
    /// Generates a fresh key pair.
    ///
    /// `rng` is a parameter rather than read from the OS inside, so a test can make the
    /// exchange deterministic without reaching into this module.
    pub fn generate(rng: &mut impl CryptoRngCore) -> Self {
        let (decapsulation_key, _) = MlKem768::generate(rng);
        let mut secret = [0u8; 32];
        rng.fill_bytes(&mut secret);
        Self {
            decapsulation_key,
            x25519_secret: StaticSecret::from(secret),
        }
    }

    /// The share that goes into the ClientHello's `key_share` for [`GROUP`].
    ///
    /// ML-KEM's encapsulation key first, then X25519: the server slices the first 1184
    /// bytes for ML-KEM and the last 32 for X25519, so the order is the format.
    #[must_use]
    pub fn client_share(&self) -> [u8; CLIENT_SHARE_LEN] {
        let key = self.decapsulation_key.encapsulation_key();
        let encoded_bytes = key.as_bytes();
        let encoded: &[u8] = encoded_bytes.as_slice();
        let mut share = [0u8; CLIENT_SHARE_LEN];
        share[..MLKEM_ENCAPSULATION_KEY_LEN].copy_from_slice(encoded);
        share[MLKEM_ENCAPSULATION_KEY_LEN..]
            .copy_from_slice(&PublicKey::from(&self.x25519_secret).to_bytes());
        share
    }

    /// The X25519 private key, which REALITY's tag is derived from.
    ///
    /// The tag's exchange is plain X25519 over the *same* key pair whose public half sits at
    /// the end of the hybrid share: the server slices the last 32 bytes of the share for its
    /// ECDH, so a tag computed from a different key cannot open.
    pub(crate) fn x25519_secret_bytes(&self) -> [u8; 32] {
        self.x25519_secret.to_bytes()
    }

    /// Completes the exchange against the server's share.
    ///
    /// # Errors
    ///
    /// Returns a message when the server's share is not the expected length: a short share
    /// means the server picked a different group, and guessing would produce a key schedule
    /// that fails much later with a less useful message.
    pub fn complete(&self, server_share: &[u8]) -> Result<[u8; SHARED_SECRET_LEN], String> {
        if server_share.len() != MLKEM_CIPHERTEXT_LEN + 32 {
            return Err(format!(
                "X25519MLKEM768 server share is {} bytes, expected {}",
                server_share.len(),
                MLKEM_CIPHERTEXT_LEN + 32
            ));
        }

        let (ciphertext, peer_x25519) = server_share.split_at(MLKEM_CIPHERTEXT_LEN);

        // ML-KEM: the ciphertext is decoded and decapsulated, yielding 32 bytes.
        let ciphertext = ml_kem::Ciphertext::<MlKem768>::try_from(ciphertext)
            .map_err(|_| "the ML-KEM ciphertext is malformed".to_owned())?;
        let mlkem_secret = self
            .decapsulation_key
            .decapsulate(&ciphertext)
            .map_err(|_| "ML-KEM decapsulation failed".to_owned())?;

        // X25519: the classic exchange, over the same session.
        let peer = PublicKey::from(
            <[u8; 32]>::try_from(peer_x25519).map_err(|_| "x25519 share is not 32 bytes")?,
        );
        let shared = self.x25519_secret.diffie_hellman(&peer);
        if !shared.was_contributory() {
            return Err(
                "the server's X25519 share produced a non-contributory secret \
                 (it may be a low-order point)"
                    .to_owned(),
            );
        }

        // Concatenate in the group's order: ML-KEM first.
        let mut secret = [0u8; SHARED_SECRET_LEN];
        secret[..32].copy_from_slice(mlkem_secret.as_slice());
        secret[32..].copy_from_slice(shared.as_bytes());
        Ok(secret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ml_kem::kem::Encapsulate;

    /// A deterministic RNG, so the exchange can be replayed.
    struct Fixed(u64);

    impl rand_core::RngCore for Fixed {
        fn next_u32(&mut self) -> u32 {
            self.next_u64() as u32
        }

        fn next_u64(&mut self) -> u64 {
            // xorshift64*: deterministic and good enough to drive key generation.
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for chunk in dest.chunks_mut(8) {
                let bytes = self.next_u64().to_le_bytes();
                chunk.copy_from_slice(&bytes[..chunk.len()]);
            }
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    impl rand_core::CryptoRng for Fixed {}

    #[test]
    fn the_client_share_has_the_length_the_server_slices() {
        let mut rng = Fixed(0x1234_5678);
        let client = Client::generate(&mut rng);
        let share = client.client_share();
        assert_eq!(share.len(), CLIENT_SHARE_LEN);
        assert_eq!(CLIENT_SHARE_LEN, MLKEM_ENCAPSULATION_KEY_LEN + 32);
        // The X25519 half is the last 32 bytes, per the draft.
        let expected = PublicKey::from(&client.x25519_secret).to_bytes();
        assert_eq!(&share[MLKEM_ENCAPSULATION_KEY_LEN..], &expected);
    }

    #[test]
    fn a_share_of_the_wrong_length_is_refused_by_name() {
        let mut rng = Fixed(1);
        let client = Client::generate(&mut rng);
        let error = client.complete(&[0u8; 32]).expect_err("must refuse");
        assert!(error.contains("X25519MLKEM768"), "{error}");
        assert!(error.contains("expected"), "{error}");
    }

    #[test]
    fn a_non_contributory_x25519_share_is_refused() {
        // An all-zero X25519 public key is a low-order point: the shared secret would be
        // zero, so the session key would depend on nothing.
        let mut rng = Fixed(2);
        let client = Client::generate(&mut rng);
        let mut server_share = vec![0u8; MLKEM_CIPHERTEXT_LEN + 32];
        server_share[..MLKEM_CIPHERTEXT_LEN].fill(0x11);
        let error = client.complete(&server_share).expect_err("must refuse");
        assert!(
            error.contains("non-contributory") || error.contains("ML-KEM"),
            "{error}"
        );
    }

    #[test]
    fn the_shared_secret_is_mlkem_then_x25519() {
        // The order is the format. A server that concatenates the other way derives a
        // different key schedule, and the only symptom is a Finished that fails to verify —
        // so the order is asserted rather than assumed.
        let mut client_rng = Fixed(9);
        let client = Client::generate(&mut client_rng);

        // Enact the server's half against the client's share.
        let share = client.client_share();
        let encapsulation_key = <MlKem768 as KemCore>::EncapsulationKey::from_bytes(
            &share[..MLKEM_ENCAPSULATION_KEY_LEN]
                .try_into()
                .expect("the key is 1184 bytes"),
        );
        let mut server_rng = Fixed(11);
        let (ciphertext, mlkem_secret) = encapsulation_key
            .encapsulate(&mut server_rng)
            .expect("encapsulates");

        let server_x25519_secret = StaticSecret::from([7u8; 32]);
        let client_x25519 = PublicKey::from(
            <[u8; 32]>::try_from(&share[MLKEM_ENCAPSULATION_KEY_LEN..]).expect("32 bytes"),
        );
        let x25519_shared = server_x25519_secret.diffie_hellman(&client_x25519);

        let mut server_share = Vec::new();
        server_share.extend_from_slice(ciphertext.as_slice());
        server_share.extend_from_slice(&PublicKey::from(&server_x25519_secret).to_bytes());

        let client_secret = client.complete(&server_share).expect("completes");

        assert_eq!(
            &client_secret[..32],
            mlkem_secret.as_slice(),
            "ML-KEM first"
        );
        assert_eq!(
            &client_secret[32..],
            x25519_shared.as_bytes(),
            "X25519 second"
        );
        assert_eq!(client_secret.len(), SHARED_SECRET_LEN);
    }
}
