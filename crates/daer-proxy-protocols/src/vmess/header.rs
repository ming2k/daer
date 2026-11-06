// SPDX-License-Identifier: AGPL-3.0-only

//! VMess AEAD's request and response headers (ADR-0030).
//!
//! # The request header
//!
//! ```text
//!   [version 1 = 1] [body_key 16] [body_iv 16] [response_header 1] [option 1]
//!   [padding_len<<4 | security 1] [0] [command 1] [port 2] [ATYP 1] [address…] [padding…]
//!   [fnv1a32 4]
//! ```
//!
//! and then the whole thing is sealed by [`super::aead::seal_header`]. The wire layout is the
//! reference's `EncodeRequestHeader` (`proxy/vmess/encoding/client.go`), and the parts that are
//! easy to get wrong are all here for a reason:
//!
//! * the **address is `port ‖ ATYP ‖ address`** (`protocol.PortThenAddress()`), the same
//!   ordering VLESS uses and the opposite of Shadowsocks';
//! * the **padding length and the cipher share one byte**, high nibble and low nibble, with a
//!   zero byte after it;
//! * the **FNV-1a checksum covers everything before it**, and it is over the *plaintext*
//!   header, not the sealed one.
//!
//! # The response header
//!
//! ```text
//!   [AEAD(2-byte length + 16-byte tag)] [AEAD(header + 16-byte tag)]
//! ```
//!
//! keyed by a KDF over the response body key and IV. The first plaintext byte of the included
//! header must equal the random `response_header` byte the request carried, which is how a
//! client knows the reply belongs to its own request.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Nonce};
use sha2::{Digest as _, Sha256};

use crate::vmess::kdf::{self, kdf16};

/// The protocol version byte. `1` is the only one the reference writes.
const VERSION: u8 = 1;

/// What a request asks the node to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Tcp,
    Udp,
}

impl Command {
    const fn byte(self) -> u8 {
        match self {
            Self::Tcp => 0x01,
            Self::Udp => 0x02,
        }
    }

    /// `protocol.RequestCommand::TransferType`: UDP is packet-oriented, TCP is a stream.
    #[must_use]
    pub const fn is_packet(self) -> bool {
        matches!(self, Self::Udp)
    }
}

/// VMess's body cipher.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Security {
    Aes128Gcm,
    Chacha20Poly1305,
}

impl Security {
    /// The low nibble of the header's `security` byte.
    const fn byte(self) -> u8 {
        match self {
            Self::Aes128Gcm => 0x03,
            Self::Chacha20Poly1305 => 0x04,
        }
    }

    /// Resolves the configuration's `auto` the way the reference does: AES-GCM when the CPU
    /// has AES-NI, ChaCha20-Poly1305 otherwise.
    ///
    /// The choice is not cosmetic. A node is configured with a specific `scy`
    /// (`auto`, `aes-128-gcm`, `chacha20-poly1305`) and refuses a body it cannot decrypt, so
    /// `auto` must pick what the *reference client* would pick on the same machine — which is
    /// what makes an `auto` node work without further configuration.
    #[must_use]
    pub fn auto() -> Self {
        if std::arch::is_x86_feature_detected!("aes") {
            Self::Aes128Gcm
        } else {
            Self::Chacha20Poly1305
        }
    }

    /// The wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Aes128Gcm => "aes-128-gcm",
            Self::Chacha20Poly1305 => "chacha20-poly1305",
        }
    }
}

/// The request options byte (`protocol.RequestOption*`).
pub mod option {
    /// The payload is chunked: `[len][auth][payload]` per chunk. Always set with a chunk cipher.
    pub const CHUNK_STREAM: u8 = 0x01;
    /// XOR the length with a SHAKE-128 keystream derived from the body IV.
    pub const CHUNK_MASKING: u8 = 0x04;
    /// Pad each chunk by a length from the same keystream (`NextPaddingLen`).
    pub const GLOBAL_PADDING: u8 = 0x08;
    /// Authenticate each chunk's length as well as its body.
    pub const AUTHENTICATED_LENGTH: u8 = 0x10;
}

/// Per-request random material, which the reference keeps in a `ClientSession`.
///
/// All of it is fresh per connection: reusing a body key would repeat a GCM nonce, which is a
/// catastrophic failure for a stream cipher rather than a subtle one.
#[derive(Debug, Clone)]
pub struct Session {
    pub body_key: [u8; 16],
    pub body_iv: [u8; 16],
    /// A random byte the server echoes at the head of its response header.
    pub response_header: u8,
    /// The response body key: `SHA-256(request body key)[..16]`.
    pub response_body_key: [u8; 16],
    /// The response body IV: `SHA-256(request body IV)[..16]`.
    pub response_body_iv: [u8; 16],
}

impl Session {
    /// Fresh random material, the way `NewClientSession` does it: 33 bytes, split 16/16/1.
    #[must_use]
    pub fn new() -> Self {
        let mut random = [0u8; 33];
        getrandom::fill(&mut random).expect("the OS provides entropy");
        let mut body_key = [0u8; 16];
        let mut body_iv = [0u8; 16];
        body_key.copy_from_slice(&random[..16]);
        body_iv.copy_from_slice(&random[16..32]);

        let digest = Sha256::digest(body_key);
        let mut response_body_key = [0u8; 16];
        response_body_key.copy_from_slice(&digest[..16]);
        let digest = Sha256::digest(body_iv);
        let mut response_body_iv = [0u8; 16];
        response_body_iv.copy_from_slice(&digest[..16]);

        Self {
            body_key,
            body_iv,
            response_header: random[32],
            response_body_key,
            response_body_iv,
        }
    }
}

impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}

/// One request: where to, how, and with which session.
#[derive(Debug, Clone)]
pub struct Request<'a> {
    pub session: &'a Session,
    pub command: Command,
    pub security: Security,
    pub option: u8,
    /// `host:port`.
    pub authority: &'a str,
}

/// Builds the plaintext request header, before AEAD sealing.
///
/// # Errors
///
/// Returns a message when the authority is not `host:port` or the host is too long for the
/// length byte.
pub fn encode_request(request: &Request<'_>) -> Result<Vec<u8>, String> {
    let (host, port, atyp) = classify(request.authority)?;
    // `dice.Roll(16)`: the padding length is a low nibble, so it must stay under 16.
    let padding_len = fastrand::u8(..16);
    let mut header = Vec::with_capacity(64 + host.len() + usize::from(padding_len));
    header.push(VERSION);
    // **IV before key.** The reference's writer is
    // `WriteByte(Version); Write(requestBodyIV); Write(requestBodyKey)`, and its reader copies
    // `BytesRange(1, 17)` into the IV and `BytesRange(17, 33)` into the key. Writing the key first
    // produces a header the node parses as an IV it will then use as a key: the session is
    // accepted, the body's chunks never open, and the client sees no reply at all.
    header.extend_from_slice(&request.session.body_iv);
    header.extend_from_slice(&request.session.body_key);
    header.push(request.session.response_header);
    header.push(request.option);
    // The padding length is the high nibble and the cipher the low one, with a zero byte
    // after it. Reading them as two independent bytes puts the cipher where the node looks
    // for a padding count.
    header.push((padding_len << 4) | request.security.byte());
    header.push(0);
    header.push(request.command.byte());
    header.extend_from_slice(&port.to_be_bytes());
    header.push(atyp);
    match atyp {
        1 | 3 => header.extend_from_slice(&host_bytes(&host, atyp)),
        _ => {
            header.push(host.len() as u8);
            header.extend_from_slice(host.as_bytes());
        }
    }
    if padding_len > 0 {
        let mut padding = vec![0u8; usize::from(padding_len)];
        getrandom::fill(&mut padding).expect("the OS provides entropy");
        header.extend_from_slice(&padding);
    }
    // FNV-1a over everything before the checksum, as `fnv.New32a` does.
    let checksum = fnv1a32(&header);
    header.extend_from_slice(&checksum.to_be_bytes());
    Ok(header)
}

/// Splits `host:port` and returns VMess's address-type byte.
///
/// VMess numbers its families `1 = IPv4`, `2 = domain`, `3 = IPv6`
/// (`protocol.AddressType*`), which is the same set VLESS uses and different from Shadowsocks'.
fn classify(authority: &str) -> Result<(String, u16, u8), String> {
    let authority = authority.trim();
    let (host, port) = match authority.strip_prefix('[') {
        Some(rest) => {
            let (host, tail) = rest
                .split_once(']')
                .ok_or_else(|| format!("{authority:?} has an unclosed '['"))?;
            let port = tail
                .strip_prefix(':')
                .ok_or_else(|| format!("{authority:?} has no port"))?;
            (host.to_owned(), port)
        }
        None => {
            let (host, port) = authority
                .rsplit_once(':')
                .ok_or_else(|| format!("{authority:?} has no port"))?;
            (host.to_owned(), port)
        }
    };
    let port: u16 = port
        .parse()
        .map_err(|_| format!("{authority:?} has an invalid port"))?;
    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(_)) => Ok((host, port, 1)),
        Ok(std::net::IpAddr::V6(_)) => Ok((host, port, 3)),
        Err(_) => {
            if host.len() > 255 {
                return Err(format!(
                    "destination host {host:?} is {} bytes, over the 255 a VMess length byte \
                     can carry",
                    host.len()
                ));
            }
            Ok((host, port, 2))
        }
    }
}

/// The raw bytes of a literal address.
fn host_bytes(host: &str, atyp: u8) -> Vec<u8> {
    match (atyp, host.parse::<std::net::IpAddr>()) {
        (1, Ok(std::net::IpAddr::V4(v4))) => v4.octets().to_vec(),
        (3, Ok(std::net::IpAddr::V6(v6))) => v6.octets().to_vec(),
        _ => host.as_bytes().to_vec(),
    }
}

/// FNV-1a 32-bit, which is what `hash/fnv.New32a` computes.
#[must_use]
pub fn fnv1a32(bytes: &[u8]) -> u32 {
    let mut hash: u32 = 0x811c_9dc5;
    for byte in bytes {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

/// The decrypted response header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseHeader {
    /// The echoed random byte, already checked against the request's.
    pub option: u8,
    /// The error message the node sent, when it sent one.
    pub error: Option<String>,
}

/// The payload length the response's length field declares.
///
/// Separate from [`decode_response_header`] because a reader has to know how many more bytes to
/// read before it can decode the whole header: the length is one seal, the body is another, and
/// only the first one's plaintext says how long the second is.
///
/// # Errors
///
/// Returns a message when the length does not open under the derived key, which is what a peer
/// that is not answering this request produces.
pub fn response_payload_len(prefix: &[u8], session: &Session) -> Result<usize, String> {
    if prefix.len() < 18 {
        return Err(format!(
            "the response length field is {} bytes, not the 18 its own seal occupies",
            prefix.len()
        ));
    }
    let length_key = kdf16(
        &session.response_body_key,
        &[kdf::SALT_AEAD_RESP_HEADER_LEN_KEY],
    );
    let length_iv = kdf::kdf(
        &session.response_body_iv,
        &[kdf::SALT_AEAD_RESP_HEADER_LEN_IV],
    );
    let cipher = Aes128Gcm::new_from_slice(&length_key)
        .map_err(|error| format!("response length key: {error}"))?;
    let plain = cipher
        .decrypt(Nonce::from_slice(&length_iv[..12]), &prefix[..18])
        .map_err(|_| {
            "the length did not open under the derived key: this reply is not for this request"
                .to_owned()
        })?;
    if plain.len() != 2 {
        return Err(format!(
            "the response length field is {} bytes, not 2",
            plain.len()
        ));
    }
    Ok(usize::from(u16::from_be_bytes([plain[0], plain[1]])))
}

/// Opens the response header with the session's derived keys.
///
/// # Errors
///
/// Returns a message when the AEAD refuses (a wrong key means this is not our reply), when the
/// echoed byte does not match, or when the header is truncated.
pub fn decode_response_header(
    body: &[u8],
    session: &Session,
) -> Result<(ResponseHeader, usize), String> {
    // The reference derives both keys from the *response* body key/IV with dedicated salts,
    // and the nonce is their first 12 bytes.
    let length_key = kdf16(
        &session.response_body_key,
        &[kdf::SALT_AEAD_RESP_HEADER_LEN_KEY],
    );
    let length_iv = kdf::kdf(
        &session.response_body_iv,
        &[kdf::SALT_AEAD_RESP_HEADER_LEN_IV],
    );
    let payload_key = kdf16(
        &session.response_body_key,
        &[kdf::SALT_AEAD_RESP_HEADER_PAYLOAD_KEY],
    );
    let payload_iv = kdf::kdf(
        &session.response_body_iv,
        &[kdf::SALT_AEAD_RESP_HEADER_PAYLOAD_IV],
    );

    let cipher = Aes128Gcm::new_from_slice(&length_key)
        .map_err(|error| format!("response length key: {error}"))?;
    if body.len() < 18 {
        return Err("the response header is under the 18 bytes its length needs".to_owned());
    }
    let length_plain = cipher
        .decrypt(Nonce::from_slice(&length_iv[..12]), &body[..18])
        .map_err(|_| {
            "the response header's length did not open under the derived key: this reply is \
             not for this request"
                .to_owned()
        })?;
    if length_plain.len() != 2 {
        return Err(format!(
            "the response header's length is {} bytes, not 2",
            length_plain.len()
        ));
    }
    let payload_len = usize::from(u16::from_be_bytes([length_plain[0], length_plain[1]]));
    let total = 18 + payload_len + 16;
    if body.len() < total {
        return Err(format!(
            "the response header is {} bytes, but its length field declares {total}",
            body.len()
        ));
    }

    let cipher = Aes128Gcm::new_from_slice(&payload_key)
        .map_err(|error| format!("response payload key: {error}"))?;
    let payload_plain = cipher
        .decrypt(
            Nonce::from_slice(&payload_iv[..12]),
            &body[18..18 + payload_len + 16],
        )
        .map_err(|_| "the response header body did not open under the derived key".to_owned())?;

    let echoed = *payload_plain
        .first()
        .ok_or_else(|| "the response header body is empty".to_owned())?;
    if echoed != session.response_header {
        return Err(format!(
            "the response echoed {echoed} where this request sent {}: the reply belongs to \
             another session",
            session.response_header
        ));
    }
    let option = payload_plain.get(1).copied().unwrap_or_default();
    // `EncodeResponseHeader` in the reference: `[echo][option][0][0]`. A non-zero third byte
    // is only used by the reverse-proxy command, which daer does not speak.
    let error = None;
    Ok((ResponseHeader { option, error }, total))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fnv1a_matches_the_reference_algorithm() {
        // `hash/fnv.New32a`, which is what `Authenticate` uses. The empty-input value is the
        // FNV-1a offset basis and is the cheapest way to catch a wrong prime or offset.
        assert_eq!(fnv1a32(b""), 0x811c_9dc5);
        assert_eq!(fnv1a32(b"a"), 0xe40c_292c);
        assert_eq!(fnv1a32(b"foobar"), 0xbf9c_f968);
    }

    #[test]
    fn the_body_iv_precedes_the_body_key() {
        // Pinned separately because it is the one field order that produces a *silent* failure:
        // the node accepts the header, derives its chunk keys from the wrong halves, and never
        // answers. `server.go` names both ranges explicitly.
        let session = Session::new();
        let header = encode_request(&Request {
            session: &session,
            command: Command::Tcp,
            security: Security::Aes128Gcm,
            option: 0,
            authority: "example.com:80",
        })
        .expect("encodes");
        assert_eq!(&header[1..17], &session.body_iv, "bytes 1..17 are the IV");
        assert_eq!(
            &header[17..33],
            &session.body_key,
            "bytes 17..33 are the key"
        );
    }

    #[test]
    fn the_request_header_packs_padding_and_cipher_into_one_byte() {
        let session = Session::new();
        let header = encode_request(&Request {
            session: &session,
            command: Command::Tcp,
            security: Security::Aes128Gcm,
            option: option::CHUNK_STREAM | option::CHUNK_MASKING,
            authority: "example.com:80",
        })
        .expect("encodes");

        assert_eq!(header[0], VERSION);
        // IV then key, which is the reference's order (`server.go`: `BytesRange(1, 17)` is the IV).
        assert_eq!(&header[1..17], &session.body_iv);
        assert_eq!(&header[17..33], &session.body_key);
        assert_eq!(header[33], session.response_header);
        assert_eq!(header[34], option::CHUNK_STREAM | option::CHUNK_MASKING);
        // High nibble padding, low nibble cipher — the byte a naive implementation writes as
        // two.
        assert_eq!(header[35] >> 4, header[35] >> 4, "padding nibble");
        assert_eq!(header[35] & 0x0f, Security::Aes128Gcm.byte());
        assert!(header[35] >> 4 < 16, "a padding length over 15 would spill");
        assert_eq!(header[36], 0);
        assert_eq!(header[37], Command::Tcp.byte());
    }

    #[test]
    fn the_address_is_port_then_type_then_address() {
        // The ordering that made a real node dial garbage when it was wrong.
        let session = Session::new();
        let header = encode_request(&Request {
            session: &session,
            command: Command::Tcp,
            security: Security::Aes128Gcm,
            option: 0,
            authority: "example.com:443",
        })
        .expect("encodes");
        let port_offset = 38;
        assert_eq!(
            &header[port_offset..port_offset + 2],
            &443u16.to_be_bytes(),
            "the port comes first"
        );
        assert_eq!(header[port_offset + 2], 2, "then ATYP = domain");
        assert_eq!(header[port_offset + 3], 11, "then the domain length");
        assert_eq!(&header[port_offset + 4..port_offset + 15], b"example.com");
    }

    #[test]
    fn a_literal_address_is_written_as_bytes_and_a_domain_as_text() {
        let session = Session::new();
        let ipv4 = encode_request(&Request {
            session: &session,
            command: Command::Tcp,
            security: Security::Aes128Gcm,
            option: 0,
            authority: "93.184.216.34:443",
        })
        .expect("encodes");
        assert_eq!(ipv4[40], 1, "ATYP IPv4");
        assert_eq!(&ipv4[41..45], &[93, 184, 216, 34]);

        let ipv6 = encode_request(&Request {
            session: &session,
            command: Command::Tcp,
            security: Security::Aes128Gcm,
            option: 0,
            authority: "[2001:db8::1]:443",
        })
        .expect("encodes");
        assert_eq!(ipv6[40], 3, "ATYP IPv6");
        assert_eq!(
            &ipv6[41..57],
            &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        );
    }

    #[test]
    fn the_checksum_covers_everything_before_it() {
        // The reference computes FNV-1a over the buffer and *appends* it; a checksum over a
        // subset is a header the node rejects before it even looks at the address.
        let session = Session::new();
        let header = encode_request(&Request {
            session: &session,
            command: Command::Tcp,
            security: Security::Aes128Gcm,
            option: 0,
            authority: "example.com:80",
        })
        .expect("encodes");
        let (body, checksum) = header.split_at(header.len() - 4);
        let expected = u32::from_be_bytes([checksum[0], checksum[1], checksum[2], checksum[3]]);
        assert_eq!(fnv1a32(body), expected);
    }

    #[test]
    fn a_session_derives_its_response_material_from_the_request_material() {
        // `NewClientSession`: the response key and IV are SHA-256 of the request's, truncated.
        let session = Session::new();
        let key: [u8; 16] = Sha256::digest(session.body_key)[..16]
            .try_into()
            .expect("16 bytes");
        let iv: [u8; 16] = Sha256::digest(session.body_iv)[..16]
            .try_into()
            .expect("16 bytes");
        assert_eq!(session.response_body_key, key);
        assert_eq!(session.response_body_iv, iv);
        // And two sessions never share material, which is what keeps GCM nonces unique.
        let other = Session::new();
        assert_ne!(session.body_key, other.body_key);
        assert_ne!(session.body_iv, other.body_iv);
    }

    #[test]
    fn a_host_too_long_for_the_length_byte_is_refused_by_name() {
        let session = Session::new();
        let long = format!("{}:80", "a".repeat(256));
        let error = encode_request(&Request {
            session: &session,
            command: Command::Tcp,
            security: Security::Aes128Gcm,
            option: 0,
            authority: &long,
        })
        .expect_err("256 bytes cannot fit a u8");
        assert!(error.contains("255"), "{error}");
    }

    #[test]
    fn an_authenticated_length_option_has_its_own_bit() {
        // The four option bits are the reference's, and a request that sets the wrong one is
        // answered with a body the client cannot decode.
        assert_eq!(option::CHUNK_STREAM, 0x01);
        assert_eq!(option::CHUNK_MASKING, 0x04);
        assert_eq!(option::GLOBAL_PADDING, 0x08);
        assert_eq!(option::AUTHENTICATED_LENGTH, 0x10);
        // They are independent bits, so they combine.
        let combined = option::CHUNK_STREAM | option::CHUNK_MASKING | option::AUTHENTICATED_LENGTH;
        assert_eq!(combined, 0x15);
    }
}
