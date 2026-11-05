// SPDX-License-Identifier: AGPL-3.0-only

//! Does the certificate prove the peer is the node, or just some site?
//!
//! # The failure this exists to catch
//!
//! REALITY answers a flow it cannot authenticate by **forwarding it to the impersonated
//! site**. So a client with a wrong tag, a wrong public key or a wrong short-id completes a
//! perfectly valid TLS 1.3 handshake — against `apple.com` instead of the node. Every layer
//! below this one reports success, and the traffic goes to a server the operator never
//! named.
//!
//! Worse, the mistake is invisible in the response: a request for `example.com` comes back
//! with a real HTTP reply, because Apple's CDN answered it. That is exactly what happened
//! while this module was being written, and a test that only asserted "a reply arrived"
//! passed on it.
//!
//! # How the node proves itself
//!
//! The server's certificate is not signed by a CA. It is a self-signed ed25519 certificate
//! whose *signature field* is
//!
//! ```text
//!   certificate.signature = HMAC-SHA512(auth_key, ed25519_public_key)
//! ```
//!
//! where `auth_key` is the same key the client used to seal its tag. Only the node and the
//! client can compute it, so a forwarded flow cannot produce it — the site behind the node
//! signs with its own CA key, which has nothing to do with `auth_key`.
//!
//! # Scope
//!
//! Only what verification needs: the leaf certificate's `SubjectPublicKeyInfo` algorithm and
//! key, and its `signatureValue`. The rest of the certificate is parsed to find those two
//! fields and then discarded. Nothing here trusts the certificate *chain* — REALITY does not
//! use one, and validating it against a CA store would fail on every correct node.

use hmac::{Hmac, Mac};
use sha2::Sha512;

type HmacSha512 = Hmac<Sha512>;

/// The verified identity of the peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Identity {
    /// The certificate signature matched `auth_key`: this is the node.
    Node,
    /// The certificate did not match. The flow reached the impersonated site instead.
    Forwarded {
        /// The name the certificate claims, when it could be read.
        subject: Option<String>,
    },
    /// The certificate could not be parsed, so nothing can be concluded. Treated as a
    /// failure by callers: an unverifiable peer is not a verified one.
    Unparsable(String),
}

/// The two facts verification needs from a DER certificate.
#[derive(Debug)]
struct LeafCertificate<'a> {
    /// The `SubjectPublicKeyInfo` key bytes — 32 for ed25519.
    public_key: &'a [u8],
    /// The certificate's `signatureValue` bits.
    signature: &'a [u8],
    /// The `signatureAlgorithm` OID, so a non-ed25519 certificate is not misread.
    signature_algorithm: Vec<u8>,
}

/// Checks the leaf certificate against the REALITY authentication key.
///
/// # Errors
///
/// Never: an unreadable certificate is [`Identity::Unparsable`] rather than an error,
/// because the caller's decision is the same either way — the peer is not proven to be the
/// node.
pub(crate) fn verify(leaf_der: &[u8], auth_key: &[u8]) -> Identity {
    let leaf = match LeafCertificate::parse(leaf_der) {
        Ok(leaf) => leaf,
        Err(reason) => return Identity::Unparsable(reason),
    };

    // A REALITY certificate signs with ed25519. A CA-signed certificate cannot match, and
    // saying so by name is more useful than a bare "did not verify".
    if !leaf.signature_algorithm.is_empty() && leaf.signature_algorithm != ED25519_OID {
        return Identity::Forwarded { subject: None };
    }

    let mut mac = match HmacSha512::new_from_slice(auth_key) {
        Ok(mac) => mac,
        Err(_) => return Identity::Unparsable("auth key is not a usable HMAC key".to_owned()),
    };
    mac.update(leaf.public_key);
    let expected = mac.finalize().into_bytes();

    if constant_time_eq(leaf.signature, &expected) {
        Identity::Node
    } else {
        Identity::Forwarded { subject: None }
    }
}

/// DER OID for `id-Ed25519` (`1.3.101.112`), as the bytes inside an OID tag.
const ED25519_OID: [u8; 3] = [0x2b, 0x65, 0x70];

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (a, b) in left.iter().zip(right) {
        difference |= a ^ b;
    }
    difference == 0
}

impl<'a> LeafCertificate<'a> {
    /// Walks the DER tree far enough to find the two fields.
    ///
    /// ```text
    ///   Certificate ::= SEQUENCE {
    ///     tbsCertificate       TBSCertificate,
    ///     signatureAlgorithm   AlgorithmIdentifier,
    ///     signatureValue       BIT STRING }
    ///
    ///   TBSCertificate ::= SEQUENCE {
    ///     [0] version, serialNumber, signature, issuer, validity, subject,
    ///     subjectPublicKeyInfo  SubjectPublicKeyInfo, … }
    /// ```
    fn parse(der: &'a [u8]) -> Result<Self, String> {
        let mut outer = Der::new(der);
        let mut certificate = outer.expect_tag(TAG_SEQUENCE, "Certificate")?;

        let mut tbs = certificate.expect_tag(TAG_SEQUENCE, "tbsCertificate")?;
        let mut signature_algorithm = certificate.expect_tag(TAG_SEQUENCE, "signatureAlgorithm")?;
        let signature = certificate.expect_tag(TAG_BIT_STRING, "signatureValue")?;
        // The first byte of a BIT STRING is the number of unused bits; zero for a signature.
        let signature = signature.contents().get(1..).unwrap_or_default();

        // The signature algorithm's own OID, so a CA-signed certificate is recognised before
        // any HMAC is computed.
        let algorithm = signature_algorithm.expect_tag(TAG_OID, "signatureAlgorithm.algorithm")?;
        let oid = algorithm.contents();

        // Inside the TBS: skip the optional version, serial, signature, issuer, validity and
        // subject, then read the SPKI. Each is a TLV, so skipping is length-driven rather
        // than value-driven.
        if tbs.peek_tag() == Some(TAG_CONTEXT_0) {
            let _ = tbs.expect_any()?;
        }
        for _ in 0..5 {
            // serialNumber, signature, issuer, validity, subject
            let _ = tbs.expect_any()?;
        }
        let mut spki = tbs.expect_tag(TAG_SEQUENCE, "subjectPublicKeyInfo")?;
        let _algorithm = spki.expect_tag(TAG_SEQUENCE, "algorithm")?;
        let key_bits = spki.expect_tag(TAG_BIT_STRING, "subjectPublicKey")?;
        // BIT STRING: one unused-bits byte, then the key.
        let key = key_bits
            .contents()
            .get(1..)
            .ok_or("an empty subjectPublicKey")?;

        Ok(Self {
            public_key: key,
            signature,
            signature_algorithm: oid.to_vec(),
        })
    }
}

const TAG_SEQUENCE: u8 = 0x30;
const TAG_BIT_STRING: u8 = 0x03;
const TAG_OID: u8 = 0x06;
const TAG_CONTEXT_0: u8 = 0xa0;

/// A minimal DER cursor: a definite-length TLV reader.
struct Der<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Der<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    /// The contents of this cursor, as a slice.
    const fn contents(&self) -> &'a [u8] {
        self.bytes
    }

    fn peek_tag(&self) -> Option<u8> {
        self.bytes.get(self.offset).copied()
    }

    /// Reads one TLV whose tag must be `tag`, returning a cursor over its contents.
    fn expect_tag(&mut self, tag: u8, what: &str) -> Result<Der<'a>, String> {
        let start = self.offset;
        let got = self
            .bytes
            .get(start)
            .copied()
            .ok_or_else(|| format!("{what}: nothing left to read"))?;
        if got != tag {
            return Err(format!("{what}: expected tag {tag:#04x}, found {got:#04x}"));
        }
        let contents = self.read_len(start + 1, what)?;
        Ok(Der::new(contents))
    }

    /// Reads one TLV of any tag, for skipping.
    fn expect_any(&mut self) -> Result<&'a [u8], String> {
        self.bytes
            .get(self.offset)
            .copied()
            .ok_or_else(|| "nothing left to read".to_owned())?;
        self.read_len(self.offset + 1, "field")
    }

    /// Reads a DER length at `position`, advances the cursor, and returns the contents.
    fn read_len(&mut self, position: usize, what: &str) -> Result<&'a [u8], String> {
        let first = *self
            .bytes
            .get(position)
            .ok_or_else(|| format!("{what}: length is missing"))?;
        let (length, length_bytes) = if first < 0x80 {
            (usize::from(first), 0usize)
        } else {
            let count = usize::from(first & 0x7f);
            // A length over four bytes is not something a certificate carries, and refusing
            // it keeps a hostile certificate from asking for a huge allocation.
            if count == 0 || count > 4 {
                return Err(format!("{what}: unsupported length width {count}"));
            }
            let mut value = 0usize;
            for index in 0..count {
                let byte = *self
                    .bytes
                    .get(position + 1 + index)
                    .ok_or_else(|| format!("{what}: length is truncated"))?;
                value = (value << 8) | usize::from(byte);
            }
            (value, count)
        };

        let start = position + 1 + length_bytes;
        let end = start
            .checked_add(length)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| {
                format!(
                    "{what}: claims {length} bytes at offset {start}, buffer is {}",
                    self.bytes.len()
                )
            })?;
        self.offset = end;
        Ok(&self.bytes[start..end])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a DER TLV.
    fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        let length = contents.len();
        if length < 0x80 {
            out.push(length as u8);
        } else {
            out.push(0x81);
            out.push(length as u8);
        }
        out.extend_from_slice(contents);
        out
    }

    /// A certificate shaped like a REALITY node's: ed25519 SPKI, `auth_key` HMAC as the
    /// signature.
    fn reality_certificate(public_key: &[u8], auth_key: &[u8]) -> Vec<u8> {
        let mut mac = HmacSha512::new_from_slice(auth_key).expect("key");
        mac.update(public_key);
        let signature = mac.finalize().into_bytes();

        let mut tbs = Vec::new();
        tbs.extend_from_slice(&tlv(0x02, &[0x01])); // serialNumber
        tbs.extend_from_slice(&tlv(0x30, &tlv(0x06, &[0x2a, 0x86, 0x48]))); // signature alg
        tbs.extend_from_slice(&tlv(0x30, b"issuer")); // issuer
        tbs.extend_from_slice(&tlv(0x30, b"validity")); // validity
        tbs.extend_from_slice(&tlv(0x30, b"subject")); // subject
        // subjectPublicKeyInfo: algorithm (ed25519), then the BIT STRING key.
        let mut spki = Vec::new();
        spki.extend_from_slice(&tlv(0x30, &tlv(0x06, &ED25519_OID)));
        let mut key_bits = vec![0u8]; // no unused bits
        key_bits.extend_from_slice(public_key);
        spki.extend_from_slice(&tlv(0x03, &key_bits));
        tbs.extend_from_slice(&tlv(0x30, &spki));

        let mut certificate = Vec::new();
        certificate.extend_from_slice(&tlv(0x30, &tbs));
        certificate.extend_from_slice(&tlv(0x30, &tlv(0x06, &ED25519_OID)));
        let mut sig_bits = vec![0u8];
        sig_bits.extend_from_slice(&signature);
        certificate.extend_from_slice(&tlv(0x03, &sig_bits));
        tlv(0x30, &certificate)
    }

    #[test]
    fn a_certificate_signed_with_the_auth_key_identifies_the_node() {
        let public_key = [0x33u8; 32];
        let auth_key = [0x44u8; 32];
        let der = reality_certificate(&public_key, &auth_key);
        assert_eq!(verify(&der, &auth_key), Identity::Node);
    }

    #[test]
    fn a_certificate_signed_with_another_key_is_a_forwarded_flow() {
        // This is the case that matters: the node forwarded us to apple.com, whose
        // certificate is real but has nothing to do with our auth key.
        let public_key = [0x33u8; 32];
        let ours = [0x44u8; 32];
        let theirs = [0x55u8; 32];
        let der = reality_certificate(&public_key, &theirs);
        assert_eq!(verify(&der, &ours), Identity::Forwarded { subject: None });
    }

    #[test]
    fn a_ca_signed_certificate_is_recognised_before_any_hmac() {
        // A CA certificate names a real signature algorithm. Reporting "forwarded" by name
        // is what makes the failure readable.
        let mut tbs = Vec::new();
        tbs.extend_from_slice(&tlv(0x02, &[0x01]));
        tbs.extend_from_slice(&tlv(0x30, b"signature"));
        tbs.extend_from_slice(&tlv(0x30, b"issuer"));
        tbs.extend_from_slice(&tlv(0x30, b"validity"));
        tbs.extend_from_slice(&tlv(0x30, b"subject"));
        let mut spki = Vec::new();
        spki.extend_from_slice(&tlv(
            0x30,
            &tlv(0x06, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]),
        ));
        let mut key_bits = vec![0u8];
        key_bits.extend_from_slice(&[0x11u8; 65]);
        spki.extend_from_slice(&tlv(0x03, &key_bits));
        tbs.extend_from_slice(&tlv(0x30, &spki));

        let mut certificate = Vec::new();
        certificate.extend_from_slice(&tlv(0x30, &tbs));
        // ecdsa-with-SHA256, not ed25519.
        certificate.extend_from_slice(&tlv(
            0x30,
            &tlv(0x06, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]),
        ));
        let mut sig_bits = vec![0u8];
        sig_bits.extend_from_slice(&[0x22u8; 71]);
        certificate.extend_from_slice(&tlv(0x03, &sig_bits));

        assert_eq!(
            verify(&tlv(0x30, &certificate), &[0x44u8; 32]),
            Identity::Forwarded { subject: None }
        );
    }

    #[test]
    fn a_truncated_certificate_is_unparsable_not_a_panic() {
        // Hostile input reaches this parser: the peer chooses the certificate.
        for length in 0..24 {
            let der = vec![0x30u8; length];
            match verify(&der, &[0x44u8; 32]) {
                Identity::Unparsable(_) => {}
                other => panic!("a {length}-byte buffer must not verify as {other:?}"),
            }
        }
    }

    #[test]
    fn a_certificate_claiming_a_huge_length_is_refused() {
        // 0x30 0x84 0xff 0xff 0xff 0xff asks for a 4 GiB slice; the parser must refuse it
        // without allocating.
        let der = [0x30u8, 0x84, 0xff, 0xff, 0xff, 0xff];
        assert!(matches!(
            verify(&der, &[0x44u8; 32]),
            Identity::Unparsable(_)
        ));
    }
}
