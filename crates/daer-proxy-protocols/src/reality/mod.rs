// SPDX-License-Identifier: AGPL-3.0-only

//! REALITY: the TLS 1.3 client and its certificate verdict.
//!
//! # What is here, and what moved
//!
//! This module now owns exactly two things:
//!
//! * [`tls13`] — the minimal TLS 1.3 client, with REALITY's tag written into
//!   `legacy_session_id`. `rustls` generates that field itself and exposes no injection
//!   point, so the handshake has to be ours
//!   ([ADR-0010](../../../docs/adr/0010-reality-client-ownership.md));
//! * [`verify`] — "is this certificate signed with the authentication key?", which is the
//!   only question that distinguishes the node from the site it impersonates.
//!
//! The VLESS request header, the Vision framing and the datagram session all moved out in
//! [ADR-0028](../../../docs/adr/0028-protocol-layering.md): they are protocol layers, not
//! REALITY layers, and keeping them here is what made a `vless://…?security=tls` node
//! unreachable. [`crate::security::reality`] is the composition that remains — a byte
//! stream in, an opaque byte stream out, and no opinion about what is inside.
//!
//! # Scope enforcement
//!
//! [`stream::Tls13Connection`] is `pub(crate)` and has no public constructor. The only way
//! to obtain one is [`crate::security::reality::RealitySecurity::wrap`], which is reachable
//! only from a node whose `security.type = "reality"`. The scope decision in ADR-0010 is
//! enforced by the type system, not by review.

pub(crate) mod hybrid;
pub(crate) mod probe;
pub(crate) mod tls13;
pub(crate) mod verify;

pub use tls13::{AUTH_KEY_LEN, RealityAuth, VERSION};

/// Decodes a REALITY public key: base64url, exactly 32 bytes.
///
/// Shared with `daer-config`'s link parser through the dialer rather than duplicated: a
/// second decoder is a second place for the padding/URL-safety rules to drift, and a wrong
/// key produces a forwarded flow with no error at all.
pub fn decode_public_key(text: &str) -> Result<[u8; 32], String> {
    let bytes = decode_base64url(text)?;
    let bytes: [u8; 32] = bytes.try_into().map_err(|bytes: Vec<u8>| {
        format!(
            "REALITY public key {text:?} is {} bytes, not the 32 an X25519 key is",
            bytes.len()
        )
    })?;
    Ok(bytes)
}

/// Decodes a REALITY short-id: hex, at most 8 bytes.
pub fn decode_short_id(text: &str) -> Result<Vec<u8>, String> {
    let text = text.trim();
    if !text.len().is_multiple_of(2) {
        return Err(format!(
            "REALITY short-id {text:?} has an odd number of hex digits"
        ));
    }
    if text.len() > 16 {
        return Err(format!(
            "REALITY short-id {text:?} is {} bytes, over the 8 REALITY carries",
            text.len() / 2
        ));
    }
    let mut bytes = Vec::with_capacity(text.len() / 2);
    for pair in text.as_bytes().chunks(2) {
        let hex = std::str::from_utf8(pair)
            .map_err(|_| format!("REALITY short-id {text:?} is not ASCII"))?;
        bytes.push(
            u8::from_str_radix(hex, 16)
                .map_err(|_| format!("REALITY short-id {text:?} is not hex"))?,
        );
    }
    Ok(bytes)
}

/// URL-safe base64 without padding, which is what a `pbk` uses.
fn decode_base64url(text: &str) -> Result<Vec<u8>, String> {
    fn value(byte: u8) -> Option<u8> {
        Some(match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => return None,
        })
    }

    let filtered: Vec<u8> = text
        .bytes()
        .filter(|byte| *byte != b'=' && !byte.is_ascii_whitespace())
        .collect();
    let mut out = Vec::with_capacity(filtered.len() * 3 / 4);
    for chunk in filtered.chunks(4) {
        if chunk.len() == 1 {
            return Err(format!("{text:?} is not base64: a lone trailing byte"));
        }
        let mut accumulator = 0u32;
        for (index, byte) in chunk.iter().enumerate() {
            let value = value(*byte).ok_or_else(|| {
                format!(
                    "{text:?} is not base64: {:?} is not in the alphabet",
                    *byte as char
                )
            })?;
            accumulator |= u32::from(value) << (18 - 6 * index);
        }
        let bytes = accumulator.to_be_bytes();
        out.push(bytes[1]);
        if chunk.len() > 2 {
            out.push(bytes[2]);
        }
        if chunk.len() > 3 {
            out.push(bytes[3]);
        }
    }
    Ok(out)
}
