// SPDX-License-Identifier: AGPL-3.0-only

//! Domain sniffing: recover the name a client asked for from the first bytes.
//!
//! # Why a proxy needs this
//!
//! `dial-mode = "domain"` routes by the name in the TLS ClientHello or the HTTP
//! `Host` header rather than by the destination IP, so a rule can say
//! `domain(suffix: example.com)` and mean the name the client actually used, even when
//! the IP is a shared CDN address. The name is in the first few hundred bytes and
//! nowhere else.
//!
//! # Shape: decisions, not a stream transformer
//!
//! [`sniff`] takes a buffer and returns a [`Sniffed`] decision. It never consumes,
//! rewrites or buffers a stream; the caller decides how many bytes to keep and when to
//! give up. This keeps the crate free of I/O, clocks and tasks, which is why every
//! property below is testable with a byte slice.
//!
//! ```text
//!   NeedMore  → read again, keeping what we have
//!   Domain    → route by this name
//!   None      → not a protocol we can name; stop trying
//!   Malformed → the bytes lie about their own length; stop trying
//! ```
//!
//! # Bounded work on hostile input
//!
//! The buffer arrives from the network, so every length field in it is hostile:
//!
//! * every read is bounds-checked, and a length that exceeds the remaining buffer is
//!   [`Sniffed::Malformed`] rather than a large allocation;
//! * `NeedMore` is only returned while the *declared* size still fits
//!   [`MAX_SNIFF_LEN`], so a client cannot make the caller buffer without limit;
//! * a ClientHello is rejected if its declared length alone exceeds the budget, before
//!   any of its interior lengths are read.
//!
//! # What is deliberately not here
//!
//! * **QUIC.** A QUIC Initial is encrypted; recovering the SNI needs the HP mask, header
//!   protection removal and TLS reassembly from CRYPTO frames. That is a real parser, and
//!   half of one would return wrong names — so it is absent rather than approximate. A
//!   QUIC flow currently sniffs as [`Sniffed::None`] and is routed by IP.
//! * **TLS 1.3 ECH.** When Encrypted ClientHello is used the name is not visible to a
//!   proxy, by design. Reporting the outer name as if it were the inner one would be a
//!   lie; [`Sniffed::None`] is the honest answer.

use std::fmt;

mod quic;

pub use quic::sniff_quic;

/// The most bytes the caller should buffer while sniffing.
///
/// A ClientHello that declares more than this is not worth waiting for: the name would
/// not arrive before the connection is already unusable. Callers should stop reading and
/// route by IP at this point.
pub const MAX_SNIFF_LEN: usize = 2048;

/// What the first bytes of a connection say.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sniffed {
    /// A name was recovered.
    Domain {
        name: String,
        /// Which protocol it came from, for logs and for `dial-mode` decisions.
        protocol: Protocol,
    },
    /// The bytes so far are a plausible prefix of something sniffable, but the name is
    /// not complete yet: keep reading and call again.
    NeedMore {
        /// The smallest total buffer the next call could possibly need, when the prefix
        /// declares a length. A caller can use it to avoid a read per byte.
        want: Option<usize>,
    },
    /// These bytes are not a protocol whose name we can recover. Stop.
    None,
    /// The bytes contradict themselves: a length field runs past the buffer, or a
    /// structure is truncated in a way no amount of reading will fix.
    Malformed(Malformed),
}

/// Which protocol produced a name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// A TLS handshake record carrying a ClientHello.
    Tls,
    /// An HTTP request line followed by headers.
    Http,
    /// A QUIC Initial packet carrying a ClientHello.
    Quic,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tls => f.write_str("tls"),
            Self::Http => f.write_str("http"),
            Self::Quic => f.write_str("quic"),
        }
    }
}

/// Why a buffer was rejected as malformed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Malformed {
    /// A length field describes more bytes than could ever be part of a sniffable
    /// handshake.
    Oversized,
    /// A length field points inside the buffer but past what a field may occupy.
    BadLength,
    /// The TLS handshake type is not `ClientHello`.
    NotClientHello,
    /// The record is not TLS 1.x.
    UnsupportedVersion,
}

impl fmt::Display for Malformed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Oversized => f.write_str("declared length exceeds the sniff budget"),
            Self::BadLength => f.write_str("a length field overruns its container"),
            Self::NotClientHello => f.write_str("TLS handshake is not a ClientHello"),
            Self::UnsupportedVersion => f.write_str("not a supported TLS record version"),
        }
    }
}

const TLS_HANDSHAKE: u8 = 0x16;
const TLS_CLIENT_HELLO: u8 = 0x01;
/// Server Name Indication, RFC 6066.
const EXT_SERVER_NAME: u16 = 0x0000;
/// `host_name` inside the server-name extension.
const SNI_HOST_NAME: u8 = 0x00;

/// Sniffs `buffer`, the first bytes of a connection.
///
/// The caller passes everything it has; the function says what it learned and whether
/// more bytes would help. It is safe to call repeatedly with a growing buffer.
#[must_use]
pub fn sniff(buffer: &[u8]) -> Sniffed {
    if buffer.is_empty() {
        return Sniffed::NeedMore { want: None };
    }
    match buffer[0] {
        TLS_HANDSHAKE => sniff_tls(buffer),
        // Every HTTP method a browser sends starts with an uppercase letter; anything
        // else is not worth guessing at.
        b'A'..=b'Z' => sniff_http(buffer),
        b if (b & 0x80) != 0 => {
            let res = quic::sniff_quic(buffer);
            if !matches!(res, Sniffed::None) {
                res
            } else {
                Sniffed::None
            }
        }
        _ => Sniffed::None,
    }
}

/// Sniffs a TLS stream.
///
/// A handshake may be split across several records (a large ClientHello is), so the
/// fragments are concatenated before parsing the handshake body.
fn sniff_tls(buffer: &[u8]) -> Sniffed {
    if buffer.len() < 5 {
        return Sniffed::NeedMore { want: Some(5) };
    }
    if buffer[1] != 0x03 {
        return Sniffed::Malformed(Malformed::UnsupportedVersion);
    }

    let mut handshake = Vec::new();
    let mut offset = 0usize;
    loop {
        let Some(header) = buffer.get(offset..offset + 5) else {
            return Sniffed::NeedMore {
                want: Some(offset + 5),
            };
        };
        if header[0] != TLS_HANDSHAKE {
            // A non-handshake record inside the first flight: not something we sniff.
            return if handshake.is_empty() {
                Sniffed::None
            } else {
                finish_tls(&handshake)
            };
        }
        let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
        if length > MAX_SNIFF_LEN {
            return Sniffed::Malformed(Malformed::Oversized);
        }
        let body_start = offset + 5;
        let Some(body) = buffer.get(body_start..body_start + length) else {
            return Sniffed::NeedMore {
                want: Some(body_start + length),
            };
        };
        handshake.extend_from_slice(body);
        offset = body_start + length;

        if handshake.len() >= 4 {
            let declared = 4
                + (usize::from(handshake[1]) << 16)
                + (usize::from(handshake[2]) << 8)
                + usize::from(handshake[3]);
            if declared > MAX_SNIFF_LEN {
                return Sniffed::Malformed(Malformed::Oversized);
            }
            if handshake.len() >= declared {
                return finish_tls(&handshake[..declared]);
            }
        }

        // More records are needed; keep reading from the stream.
        if offset >= buffer.len() {
            return Sniffed::NeedMore {
                want: Some(offset + 5),
            };
        }
    }
}

/// Parses a complete handshake message.
fn finish_tls(handshake: &[u8]) -> Sniffed {
    if handshake.len() < 4 {
        return Sniffed::NeedMore { want: Some(4) };
    }
    if handshake[0] != TLS_CLIENT_HELLO {
        return Sniffed::Malformed(Malformed::NotClientHello);
    }
    match client_hello_sni(&handshake[4..]) {
        Ok(Some(name)) => Sniffed::Domain {
            name,
            protocol: Protocol::Tls,
        },
        Ok(None) => Sniffed::None,
        Err(error) => Sniffed::Malformed(error),
    }
}

/// Extracts the SNI from a ClientHello body (after the 4-byte handshake header).
fn client_hello_sni(body: &[u8]) -> Result<Option<String>, Malformed> {
    // version(2) random(32) session_id_len(1) …
    let mut cursor = Cursor::new(body);
    cursor.skip(2)?;
    cursor.skip(32)?;

    let session_id_len = usize::from(cursor.u8()?);
    cursor.skip(session_id_len)?;

    let cipher_suites_len = usize::from(cursor.u16()?);
    cursor.skip(cipher_suites_len)?;

    let compression_len = usize::from(cursor.u8()?);
    cursor.skip(compression_len)?;

    // No extensions: an old-style ClientHello, no SNI.
    if cursor.remaining() == 0 {
        return Ok(None);
    }
    let extensions_len = usize::from(cursor.u16()?);
    let extensions = cursor.take(extensions_len)?;

    let mut extensions = Cursor::new(extensions);
    while extensions.remaining() >= 4 {
        let kind = extensions.u16()?;
        let length = usize::from(extensions.u16()?);
        let data = extensions.take(length)?;
        if kind != EXT_SERVER_NAME {
            continue;
        }
        // server_name_list_len(2) then entries of type(1) len(2) name.
        let mut list = Cursor::new(data);
        let list_len = usize::from(list.u16()?);
        let entries = list.take(list_len)?;
        let mut entries = Cursor::new(entries);
        while entries.remaining() >= 3 {
            let kind = entries.u8()?;
            let length = usize::from(entries.u16()?);
            let name = entries.take(length)?;
            if kind == SNI_HOST_NAME {
                // A host name is ASCII (or A-labels); invalid UTF-8 means the bytes are
                // not a name, so it is not reported as one.
                return match std::str::from_utf8(name) {
                    Ok(text) if !text.is_empty() => Ok(Some(text.to_owned())),
                    Ok(_) => Ok(None),
                    Err(_) => Ok(None),
                };
            }
        }
        return Ok(None);
    }
    Ok(None)
}

/// Sniffs an HTTP request.
fn sniff_http(buffer: &[u8]) -> Sniffed {
    // A request line is `METHOD SP target SP HTTP/x.y CRLF`; the shortest plausible one
    // is `A / HTTP/1.0` plus terminators.
    if buffer.len() < 16 {
        // Only keep waiting while the prefix still looks like a method token.
        return if buffer
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
        {
            Sniffed::NeedMore { want: Some(16) }
        } else {
            Sniffed::None
        };
    }
    if !buffer.starts_with(b"HTTP/") {
        // The request line must be present before headers are: find its end.
        let Some(line_end) = find(buffer, b"\r\n") else {
            return if buffer.len() >= MAX_SNIFF_LEN {
                Sniffed::Malformed(Malformed::Oversized)
            } else {
                Sniffed::NeedMore {
                    want: Some(buffer.len() + 64),
                }
            };
        };
        let line = &buffer[..line_end];
        if !line.ends_with(b"HTTP/1.1") && !line.ends_with(b"HTTP/1.0") {
            return Sniffed::None;
        }
        if !line.contains(&b' ') {
            return Sniffed::None;
        }
    }

    let Some(headers_end) = find(buffer, b"\r\n\r\n") else {
        return if buffer.len() >= MAX_SNIFF_LEN {
            Sniffed::Malformed(Malformed::Oversized)
        } else {
            Sniffed::NeedMore {
                want: Some(buffer.len() + 128),
            }
        };
    };

    let mut start = 0usize;
    for line in buffer[..headers_end].split(|byte| *byte == b'\n') {
        let line = trim_cr(line);
        if line.is_empty() {
            start += line.len() + 2;
            continue;
        }
        let line_start = start;
        start += line.len() + 2;
        if line_start == 0 {
            // The request line itself: an absolute-form target (`GET http://host/…`)
            // carries the host, which is how a proxy request states it.
            if let Some(host) = absolute_form_host(line) {
                return Sniffed::Domain {
                    name: host,
                    protocol: Protocol::Http,
                };
            }
            continue;
        }
        let Some((name, value)) = split_header(line) else {
            continue;
        };
        // `Host` is the only header that names the origin. Forwarded-* headers are set
        // by intermediaries and are not the client's target, so they are ignored.
        if !name.eq_ignore_ascii_case(b"host") {
            continue;
        }
        let host = std::str::from_utf8(value).unwrap_or_default().trim();
        // A `Host` may carry a port (`example.com:8443`); the name is the part before it.
        let host = host.rsplit_once(':').map_or(host, |(name, port)| {
            if port.chars().all(|c| c.is_ascii_digit()) {
                name
            } else {
                host
            }
        });
        return if host.is_empty() {
            Sniffed::None
        } else {
            Sniffed::Domain {
                name: host.to_owned(),
                protocol: Protocol::Http,
            }
        };
    }
    Sniffed::None
}

/// The host from an absolute-form request target (`GET http://example.com/x HTTP/1.1`).
fn absolute_form_host(line: &[u8]) -> Option<String> {
    let mut parts = line.splitn(3, |byte| *byte == b' ');
    parts.next()?;
    let target = parts.next()?;
    let rest = target
        .strip_prefix(b"http://")
        .or_else(|| target.strip_prefix(b"https://"))?;
    let end = rest
        .iter()
        .position(|byte| *byte == b'/' || *byte == b'?' || *byte == b'#')
        .unwrap_or(rest.len());
    let authority = std::str::from_utf8(&rest[..end]).ok()?;
    if authority.is_empty() {
        return None;
    }
    // Drop `user@` and `:port`.
    let authority = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let host = authority
        .rsplit_once(':')
        .filter(|(_, port)| port.chars().all(|c| c.is_ascii_digit()))
        .map_or(authority, |(host, _)| host);
    (!host.is_empty()).then(|| host.to_owned())
}

fn split_header(line: &[u8]) -> Option<(&[u8], &[u8])> {
    let colon = line.iter().position(|byte| *byte == b':')?;
    let name = &line[..colon];
    let value = line.get(colon + 1..)?;
    Some((name, trim_ascii(value)))
}

fn trim_ascii(value: &[u8]) -> &[u8] {
    let mut start = 0;
    let mut end = value.len();
    while start < end && value[start].is_ascii_whitespace() {
        start += 1;
    }
    while end > start && value[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    &value[start..end]
}

fn trim_cr(line: &[u8]) -> &[u8] {
    line.strip_suffix(b"\r").unwrap_or(line)
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// A bounds-checked reader over a byte slice.
struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }

    fn u8(&mut self) -> Result<u8, Malformed> {
        let byte = *self.bytes.get(self.offset).ok_or(Malformed::BadLength)?;
        self.offset += 1;
        Ok(byte)
    }

    fn u16(&mut self) -> Result<u16, Malformed> {
        let bytes = self
            .bytes
            .get(self.offset..self.offset + 2)
            .ok_or(Malformed::BadLength)?;
        self.offset += 2;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn skip(&mut self, count: usize) -> Result<(), Malformed> {
        if self.remaining() < count {
            return Err(Malformed::BadLength);
        }
        self.offset += count;
        Ok(())
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], Malformed> {
        let slice = self
            .bytes
            .get(self.offset..self.offset + count)
            .ok_or(Malformed::BadLength)?;
        self.offset += count;
        Ok(slice)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a ClientHello, written by hand so the test does not depend on the parser
    /// being tested. `sni: None` produces a handshake with no server_name extension.
    fn client_hello(sni: Option<&str>) -> Vec<u8> {
        let mut extensions = Vec::new();
        if let Some(sni) = sni {
            let name = sni.as_bytes();
            let mut sni_body = Vec::new();
            sni_body.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes()); // list length
            sni_body.push(SNI_HOST_NAME);
            sni_body.extend_from_slice(&(name.len() as u16).to_be_bytes());
            sni_body.extend_from_slice(name);
            extensions.extend_from_slice(&EXT_SERVER_NAME.to_be_bytes());
            extensions.extend_from_slice(&(sni_body.len() as u16).to_be_bytes());
            extensions.extend_from_slice(&sni_body);
        }
        // supported_versions extension, to prove unrelated extensions are skipped
        extensions.extend_from_slice(&0x002bu16.to_be_bytes());
        extensions.extend_from_slice(&3u16.to_be_bytes());
        extensions.extend_from_slice(&[0x02, 0x03, 0x04]);

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // legacy version
        body.extend_from_slice(&[0x42; 32]); // random
        body.push(0); // session id
        body.extend_from_slice(&2u16.to_be_bytes()); // cipher suites length
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(1); // compression methods length
        body.push(0); // null compression
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut handshake = Vec::new();
        handshake.push(TLS_CLIENT_HELLO);
        let length = body.len();
        handshake.extend_from_slice(&[
            ((length >> 16) & 0xff) as u8,
            ((length >> 8) & 0xff) as u8,
            (length & 0xff) as u8,
        ]);
        handshake.extend_from_slice(&body);

        let mut record = Vec::new();
        record.push(TLS_HANDSHAKE);
        record.extend_from_slice(&[0x03, 0x01]);
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn a_client_hello_yields_its_sni() {
        let bytes = client_hello(Some("example.com"));
        assert_eq!(
            sniff(&bytes),
            Sniffed::Domain {
                name: "example.com".to_owned(),
                protocol: Protocol::Tls,
            }
        );
    }

    #[test]
    fn a_split_handshake_needs_more_and_then_works() {
        let bytes = client_hello(Some("split.example.com"));
        let split = bytes.len() / 2;
        assert!(
            matches!(sniff(&bytes[..split]), Sniffed::NeedMore { .. }),
            "a half handshake must ask for more"
        );
        assert_eq!(
            sniff(&bytes),
            Sniffed::Domain {
                name: "split.example.com".to_owned(),
                protocol: Protocol::Tls,
            }
        );
    }

    #[test]
    fn every_prefix_asks_for_more_and_none_is_malformed() {
        // A truncated handshake is a prefix, never an error: the caller is expected to
        // keep reading. This is what makes the incremental API usable.
        let bytes = client_hello(Some("prefix.example.com"));
        for length in 1..bytes.len() {
            match sniff(&bytes[..length]) {
                Sniffed::NeedMore { .. } => {}
                other => panic!("prefix of {length} bytes returned {other:?}"),
            }
        }
        assert!(matches!(sniff(&bytes), Sniffed::Domain { .. }));
    }

    #[test]
    fn a_handshake_across_two_records_is_reassembled() {
        // A large ClientHello is split by the sender across records; the fragments must be
        // concatenated before the handshake body is read.
        let bytes = client_hello(Some("record-split.example.com"));
        let body = &bytes[5..];
        let split = body.len() / 2;

        let mut out = Vec::new();
        for fragment in [&body[..split], &body[split..]] {
            out.push(TLS_HANDSHAKE);
            out.extend_from_slice(&[0x03, 0x01]);
            out.extend_from_slice(&(fragment.len() as u16).to_be_bytes());
            out.extend_from_slice(fragment);
        }
        assert_eq!(
            sniff(&out),
            Sniffed::Domain {
                name: "record-split.example.com".to_owned(),
                protocol: Protocol::Tls,
            }
        );
    }

    #[test]
    fn an_oversized_declared_length_is_rejected_before_allocating() {
        // The record says 4 KiB; the budget is smaller, so this is malformed rather than
        // an invitation to buffer.
        let mut bytes = vec![TLS_HANDSHAKE, 0x03, 0x01];
        bytes.extend_from_slice(&u16::MAX.to_be_bytes());
        bytes.extend_from_slice(&[0; 32]);
        assert_eq!(sniff(&bytes), Sniffed::Malformed(Malformed::Oversized));
    }

    #[test]
    fn a_non_client_hello_handshake_is_malformed_not_a_guess() {
        let mut bytes = vec![TLS_HANDSHAKE, 0x03, 0x03, 0x00, 0x04];
        bytes.extend_from_slice(&[0x02, 0x00, 0x00, 0x00]); // ServerHello
        assert_eq!(sniff(&bytes), Sniffed::Malformed(Malformed::NotClientHello));
    }

    #[test]
    fn a_non_tls_first_byte_is_none() {
        assert_eq!(sniff(b"\x00\x01\x02\x03\x04"), Sniffed::None);
        assert_eq!(sniff(b"\x47\x45\x54"), Sniffed::NeedMore { want: Some(16) });
    }

    #[test]
    fn an_http_host_header_is_found() {
        let request = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: x\r\n\r\n";
        assert_eq!(
            sniff(request),
            Sniffed::Domain {
                name: "example.com".to_owned(),
                protocol: Protocol::Http,
            }
        );
    }

    #[test]
    fn a_host_header_with_a_port_reports_the_name_only() {
        let request = b"GET / HTTP/1.1\r\nHost: example.com:8443\r\n\r\n";
        assert_eq!(
            sniff(request),
            Sniffed::Domain {
                name: "example.com".to_owned(),
                protocol: Protocol::Http,
            }
        );
    }

    #[test]
    fn header_names_are_case_insensitive() {
        let request = b"GET / HTTP/1.1\r\nhOsT: example.com\r\n\r\n";
        assert_eq!(
            sniff(request),
            Sniffed::Domain {
                name: "example.com".to_owned(),
                protocol: Protocol::Http,
            }
        );
    }

    #[test]
    fn a_forwarded_header_is_not_the_target() {
        // `Forwarded`/`X-Forwarded-Host` are set by intermediaries; the client's target is
        // `Host`, and guessing otherwise would route by someone else's idea of the name.
        let request =
            b"GET / HTTP/1.1\r\nX-Forwarded-Host: evil.example\r\nHost: real.example\r\n\r\n";
        assert_eq!(
            sniff(request),
            Sniffed::Domain {
                name: "real.example".to_owned(),
                protocol: Protocol::Http,
            }
        );
    }

    #[test]
    fn an_absolute_form_target_names_the_host() {
        let request = b"GET http://example.com/path?q=1 HTTP/1.1\r\n\r\n";
        assert_eq!(
            sniff(request),
            Sniffed::Domain {
                name: "example.com".to_owned(),
                protocol: Protocol::Http,
            }
        );
    }

    #[test]
    fn an_incomplete_http_request_asks_for_more_within_the_budget() {
        let request = b"GET / HTTP/1.1\r\nHost: example.com\r\n";
        assert!(matches!(sniff(request), Sniffed::NeedMore { .. }));

        // Past the budget it stops asking: the caller must not buffer forever.
        let mut huge = b"GET / HTTP/1.1\r\n".to_vec();
        huge.resize(MAX_SNIFF_LEN + 1, b'a');
        assert_eq!(sniff(&huge), Sniffed::Malformed(Malformed::Oversized));
    }

    #[test]
    fn an_http_request_without_a_host_is_none() {
        assert_eq!(
            sniff(b"GET / HTTP/1.1\r\nUser-Agent: x\r\n\r\n"),
            Sniffed::None
        );
    }

    #[test]
    fn a_non_http_uppercase_prefix_is_none() {
        // Uppercase, but not a request: it must not be mistaken for one.
        assert_eq!(
            sniff(b"HELLO-WORLD-THIS-IS-NOT-HTTP-AT-ALL\r\n\r\n"),
            Sniffed::None
        );
    }

    #[test]
    fn a_client_hello_without_sni_is_none() {
        // A handshake with no server_name extension is not an error: the client simply
        // did not name a host, so there is nothing to route by.
        let bytes = client_hello(None);
        assert_eq!(sniff(&bytes), Sniffed::None);
    }
}
