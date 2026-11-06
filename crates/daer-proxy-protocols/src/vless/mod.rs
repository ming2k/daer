// SPDX-License-Identifier: AGPL-3.0-only

//! VLESS: the request header, the response header, and the layer composition.
//!
//! # What VLESS is
//!
//! A VLESS session is one request header followed by a raw byte stream in each
//! direction. There is no inner encryption (`encryption=none` is the only valid value in
//! a link, and the reference refuses anything else), no length framing, and no
//! handshake beyond the header itself. Everything that makes the session look like
//! something else — TLS, REALITY, WebSocket, Vision — is a *layer* around it
//! ([ADR-0028](../../../docs/adr/0028-protocol-layering.md)).
//!
//! # The header
//!
//! ```text
//!   request:  [version 1 = 0] [uuid 16] [addon_len 1] [addons…] [CMD 1] [port 2] [ATYP 1] [addr…]
//!   response: [version 1 = 0] [addon_len 1] [addons…]
//! ```
//!
//! Two details are load-bearing and both were wrong at some point in this crate's
//! history, so each has a test:
//!
//! * **the address is `port ‖ ATYP ‖ address`**, because VLESS builds its parser with
//!   `protocol.PortThenAddress()`. Shadowsocks' ordering (`ATYP ‖ address ‖ port`) puts the
//!   port at the end and shifts every field by two bytes, which makes the node dial
//!   garbage;
//! * **the address types are VLESS's own numbers** — `1 = IPv4`, `2 = domain`, `3 = IPv6` —
//!   which differ from Shadowsocks' `1 / 3 / 4`.
//!
//! # Vision
//!
//! The flow, when present, is declared in the request's addons field as a length-prefixed
//! protobuf `Addons { Flow = 1 }`. A node whose user is configured for Vision **rejects**
//! a client that omits it, so the addon is not a tuning knob: it decides whether the
//! session carries a byte at all.

pub mod connector;
pub mod response;
pub mod vision;

pub use connector::VlessConnector;

use std::net::IpAddr;

use crate::error::ProxyProtocolError;

/// The version byte. VLESS has exactly one.
const VERSION: u8 = 0;

/// The command a request carries.
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
}

/// The address families VLESS numbers, which are not Shadowsocks' numbers.
const ATYP_IPV4: u8 = 1;
const ATYP_DOMAIN: u8 = 2;
const ATYP_IPV6: u8 = 3;

/// A destination written the way a VLESS header carries it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Address {
    V4([u8; 4]),
    V6([u8; 16]),
    Domain(String),
}

impl Address {
    /// Splits `host:port` and classifies the host.
    ///
    /// A literal address is written as bytes rather than as a domain name, because a
    /// node that receives `example.com` asks its resolver while a node that receives
    /// `93.184.216.34` does not — and the two are not interchangeable on the wire.
    ///
    /// # Errors
    ///
    /// Returns a message when the authority is not `host:port` or the host is too long
    /// for the length byte.
    pub fn parse(authority: &str) -> Result<(Self, u16), String> {
        let (host, port) = split_authority(authority)?;
        let address = match host.parse::<IpAddr>() {
            Ok(IpAddr::V4(v4)) => Self::V4(v4.octets()),
            Ok(IpAddr::V6(v6)) => Self::V6(v6.octets()),
            Err(_) => Self::Domain(host),
        };
        if let Self::Domain(domain) = &address
            && domain.len() > 255
        {
            return Err(format!(
                "destination host {domain:?} is {} bytes, over the 255 a VLESS length byte \
                 can carry",
                domain.len()
            ));
        }
        Ok((address, port))
    }

    /// Appends this address to a header under the `port ‖ ATYP ‖ address` layout.
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Self::V4(bytes) => {
                out.push(ATYP_IPV4);
                out.extend_from_slice(bytes);
            }
            Self::V6(bytes) => {
                out.push(ATYP_IPV6);
                out.extend_from_slice(bytes);
            }
            Self::Domain(domain) => {
                out.push(ATYP_DOMAIN);
                out.push(domain.len() as u8);
                out.extend_from_slice(domain.as_bytes());
            }
        }
    }

    /// Whether this address is a domain, for a log line that would otherwise print bytes.
    #[must_use]
    pub fn as_domain(&self) -> Option<&str> {
        match self {
            Self::Domain(domain) => Some(domain),
            _ => None,
        }
    }
}

/// Splits `host:port`, keeping a bracketed IPv6 literal intact.
///
/// # Errors
///
/// Returns a message when there is no port or the port is not a number.
pub fn split_authority(authority: &str) -> Result<(String, u16), String> {
    let authority = authority.trim();
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .ok_or_else(|| format!("{authority:?} has an unclosed '['"))?;
        let port = tail
            .strip_prefix(':')
            .ok_or_else(|| format!("{authority:?} has no port"))?;
        let port = port
            .parse()
            .map_err(|_| format!("{authority:?} has an invalid port"))?;
        return Ok((host.to_owned(), port));
    }
    let (host, port) = authority
        .rsplit_once(':')
        .ok_or_else(|| format!("{authority:?} has no port"))?;
    let port = port
        .parse()
        .map_err(|_| format!("{authority:?} has an invalid port"))?;
    Ok((host.to_owned(), port))
}

/// The flow a request declares in its addons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    None,
    /// `xtls-rprx-vision`, spelled exactly as the reference spells it.
    Vision,
    /// `xtls-rprx-vision-udp443`: Vision, with UDP/443 allowed through the flow.
    ///
    /// The difference is entirely on the **server**: the reference's inbound reads the account's
    /// `flow` string and, for plain `xtls-rprx-vision`, rejects a UDP destination on port 443
    /// (`outbound.go`: "XTLS rejected UDP/443 traffic"). The client's request bytes are identical
    /// either way — the flag lives in the server's account, not in the addons — so this variant
    /// changes no client-side encoding. It exists so a node's declared flow is *represented*
    /// rather than flattened to [`Self::Vision`], which would make `daer check --nodes` report a
    /// different flow from the one the operator wrote.
    VisionUdp443,
}

impl Flow {
    const VISION: &'static str = "xtls-rprx-vision";

    /// Whether the flow frames the payload at all.
    #[must_use]
    pub const fn is_vision(self) -> bool {
        matches!(self, Self::Vision | Self::VisionUdp443)
    }

    /// The addons value a request declares.
    ///
    /// Both Vision variants declare `xtls-rprx-vision`: the `-udp443` suffix is a server account
    /// setting, and sending it in the addons would make a reference node reject the session.
    #[must_use]
    pub const fn addons_name(self) -> Option<&'static str> {
        match self {
            Self::None => None,
            Self::Vision | Self::VisionUdp443 => Some(Self::VISION),
        }
    }

    /// The reference's spelling, for a diagnostic that has to name the flow.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Vision => Self::VISION,
            Self::VisionUdp443 => "xtls-rprx-vision-udp443",
        }
    }

    /// The protobuf `Addons { Flow = 1 }` the header carries.
    ///
    /// Field 1, wire type 2 (length-delimited): `0x0a`, then a length byte, then the
    /// name. An empty flow writes a zero length, which is what the reference does for
    /// every request that is not Vision.
    fn addons(self) -> Vec<u8> {
        match self.addons_name() {
            None => Vec::new(),
            Some(vision) => {
                let name = vision.as_bytes();
                let mut addons = Vec::with_capacity(2 + name.len());
                addons.push(0x0a);
                addons.push(name.len() as u8);
                addons.extend_from_slice(name);
                addons
            }
        }
    }
}

/// The parameters of one VLESS request.
#[derive(Debug, Clone)]
pub struct Request<'a> {
    /// The user id, already parsed.
    pub uuid: [u8; 16],
    pub command: Command,
    pub flow: Flow,
    /// `host:port`.
    pub authority: &'a str,
}

/// Encodes the request header.
///
/// # Errors
///
/// Returns a message when the authority cannot be classified or is too long.
pub fn encode_request(request: &Request<'_>) -> Result<Vec<u8>, ProxyProtocolError> {
    let (address, port) =
        Address::parse(request.authority).map_err(ProxyProtocolError::UnsupportedLink)?;
    let addons = request.flow.addons();
    let mut header = Vec::with_capacity(1 + 16 + 1 + addons.len() + 1 + 2 + 1 + 32);
    header.push(VERSION);
    header.extend_from_slice(&request.uuid);
    header.push(addons.len() as u8);
    header.extend_from_slice(&addons);
    header.push(request.command.byte());
    // `PortThenAddress`, not `AddressThenPort`: see this module's header comment.
    header.extend_from_slice(&port.to_be_bytes());
    address.encode(&mut header);
    Ok(header)
}

/// Parses a UUID in the canonical `8-4-4-4-12` layout.
///
/// # Errors
///
/// Returns a message naming the first byte that is neither a hex digit nor a separator,
/// because a mis-typed id on the wire produces a node's generic rejection and nothing
/// else.
pub fn parse_uuid(text: &str) -> Result<[u8; 16], String> {
    let mut digits = [0u8; 32];
    let mut count = 0;
    for byte in text.trim().bytes() {
        if byte == b'-' {
            continue;
        }
        if !byte.is_ascii_hexdigit() {
            return Err(format!(
                "{text:?} is not a UUID: {:?} is not a hex digit",
                byte as char
            ));
        }
        if count == 32 {
            return Err(format!("{text:?} is not a UUID: over 32 hex digits"));
        }
        digits[count] = byte;
        count += 1;
    }
    if count != 32 {
        return Err(format!(
            "{text:?} is not a UUID: expected 32 hex digits, got {count}"
        ));
    }
    let mut uuid = [0u8; 16];
    for (index, pair) in digits.chunks(2).enumerate() {
        let hex = std::str::from_utf8(pair).expect("two hex digits are ASCII");
        uuid[index] = u8::from_str_radix(hex, 16).expect("validated as hex above");
    }
    Ok(uuid)
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: [u8; 16] = [
        0xdf, 0x4a, 0xf3, 0xd0, 0x03, 0x0e, 0x40, 0x62, 0xba, 0xa6, 0xeb, 0x9d, 0xd4, 0x52, 0x98,
        0xef,
    ];

    #[test]
    fn a_uuid_is_sixteen_bytes_in_the_canonical_layout() {
        let parsed = parse_uuid("df4af3d0-030e-4062-baa6-eb9dd45298ef").expect("valid");
        assert_eq!(parsed, UUID);

        // The dashes are optional separators, not positional: anything with 32 hex
        // digits is the same id.
        assert_eq!(
            parse_uuid("df4af3d0030e4062baa6eb9dd45298ef").expect("valid"),
            UUID
        );

        // A wrong length and a non-hex byte are reported by name.
        assert!(parse_uuid("df4af3d0").expect_err("short").contains("got 8"));
        assert!(
            parse_uuid("df4af3d0-030e-4062-baa6-eb9dd45298eq")
                .expect_err("q is not hex")
                .contains('q')
        );
    }

    #[test]
    fn the_request_header_is_port_then_address() {
        // The two orderings differ, and the reference uses this one. A regression here
        // makes every node dial a garbage address, so the bytes are asserted exactly.
        let header = encode_request(&Request {
            uuid: UUID,
            command: Command::Tcp,
            flow: Flow::None,
            authority: "example.com:80",
        })
        .expect("encodes");

        assert_eq!(header[0], 0, "version");
        assert_eq!(&header[1..17], &UUID, "uuid");
        assert_eq!(header[17], 0, "addon length = 0 for no flow");
        assert_eq!(header[18], 0x01, "CMD TCP");
        assert_eq!(&header[19..21], &80u16.to_be_bytes(), "port comes first");
        assert_eq!(header[21], ATYP_DOMAIN, "then the address type");
        assert_eq!(header[22], 11, "then the domain length");
        assert_eq!(&header[23..], b"example.com");
    }

    #[test]
    fn an_ipv4_destination_is_written_as_four_bytes() {
        let header = encode_request(&Request {
            uuid: UUID,
            command: Command::Tcp,
            flow: Flow::None,
            authority: "93.184.216.34:443",
        })
        .expect("encodes");

        assert_eq!(header[21], ATYP_IPV4);
        assert_eq!(&header[22..26], &[93, 184, 216, 34]);
        assert_eq!(header.len(), 26, "no length byte for a fixed-width family");
    }

    #[test]
    fn an_ipv6_destination_keeps_its_sixteen_bytes_and_its_brackets() {
        let header = encode_request(&Request {
            uuid: UUID,
            command: Command::Tcp,
            flow: Flow::None,
            authority: "[2001:db8::1]:8443",
        })
        .expect("encodes");

        assert_eq!(header[21], ATYP_IPV6);
        assert_eq!(
            &header[22..38],
            &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        );
        assert_eq!(&header[19..21], &8443u16.to_be_bytes());
    }

    #[test]
    fn vision_declares_itself_in_the_addons_field() {
        // A node configured with `flow = "xtls-rprx-vision"` refuses a request whose
        // addons are empty, so this is the difference between a working session and a
        // rejected one.
        let header = encode_request(&Request {
            uuid: UUID,
            command: Command::Tcp,
            flow: Flow::Vision,
            authority: "example.com:443",
        })
        .expect("encodes");

        let addon_len = header[17] as usize;
        assert_eq!(addon_len, 2 + Flow::VISION.len());
        assert_eq!(header[18], 0x0a, "field 1, length-delimited");
        assert_eq!(header[19] as usize, Flow::VISION.len());
        assert_eq!(
            &header[20..20 + Flow::VISION.len()],
            Flow::VISION.as_bytes()
        );
        assert_eq!(
            header[20 + Flow::VISION.len()],
            0x01,
            "CMD follows the addons"
        );
    }

    #[test]
    fn both_vision_variants_declare_the_same_addons_but_report_their_own_name() {
        // `-udp443` is a *server account* setting: the reference's inbound reads the account's
        // `flow` and, for plain `xtls-rprx-vision`, rejects a UDP destination on port 443. The
        // client's request bytes are identical either way, and sending the suffixed name in the
        // addons would make a reference node reject the session.
        let base = Request {
            uuid: UUID,
            command: Command::Tcp,
            flow: Flow::Vision,
            authority: "example.com:443",
        };
        let suffixed = Request {
            flow: Flow::VisionUdp443,
            ..base.clone()
        };
        assert_eq!(
            encode_request(&base).expect("encodes"),
            encode_request(&suffixed).expect("encodes"),
            "the wire bytes must not differ"
        );

        // …but the flow is still *represented*, so `check --nodes` reports what was configured
        // rather than flattening it.
        assert_eq!(Flow::Vision.as_str(), "xtls-rprx-vision");
        assert_eq!(Flow::VisionUdp443.as_str(), "xtls-rprx-vision-udp443");
        assert_eq!(Flow::VisionUdp443.addons_name(), Some(Flow::VISION));
        assert!(Flow::VisionUdp443.is_vision());
        assert!(!Flow::None.is_vision());
    }

    #[test]
    fn a_host_too_long_for_the_length_byte_is_refused_rather_than_truncated() {
        let long = format!("{}:80", "a".repeat(256));
        let error = encode_request(&Request {
            uuid: UUID,
            command: Command::Tcp,
            flow: Flow::None,
            authority: &long,
        })
        .expect_err("256 bytes cannot fit a u8 length");
        assert!(error.to_string().contains("255"), "{error}");
    }
}
