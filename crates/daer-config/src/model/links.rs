// SPDX-License-Identifier: AGPL-3.0-only

//! URI link parsing, encoding, and node-level validation helpers.

use super::*;

pub(super) fn format_host(server: &str) -> String {
    let server = server.trim();
    if server.contains(':') && !server.starts_with('[') && !server.ends_with(']') {
        format!("[{server}]")
    } else {
        server.to_owned()
    }
}

pub(super) fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push_str(&format!("%{b:02X}"));
            }
        }
    }
    out
}

pub(super) fn encode_base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = if chunk.len() > 1 { chunk[1] } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] } else { 0 };

        out.push(ALPHABET[(b0 >> 2) as usize] as char);
        out.push(ALPHABET[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(b2 & 0x3f) as usize] as char);
        }
    }
    out
}

pub(super) fn validate_ss_method(method: &str) -> Result<(), String> {
    match method.trim().to_ascii_lowercase().as_str() {
        "aes-128-gcm"
        | "aes-256-gcm"
        | "chacha20-ietf-poly1305"
        | "xchacha20-ietf-poly1305"
        | "2022-blake3-aes-128-gcm"
        | "2022-blake3-aes-256-gcm"
        | "2022-blake3-chacha20-poly1305" => Ok(()),
        legacy @ ("aes-128-cfb" | "aes-192-cfb" | "aes-256-cfb" | "aes-128-ctr" | "aes-192-ctr"
        | "aes-256-ctr" | "rc4-md5" | "chacha20" | "chacha20-ietf" | "salsa20"
        | "bf-cfb" | "camellia-128-cfb" | "camellia-192-cfb" | "camellia-256-cfb"
        | "des-cfb" | "table") => Err(format!(
            "shadowsocks: method '{legacy}' is an insecure legacy cipher and is not supported (use an AEAD cipher like chacha20-ietf-poly1305 or aes-256-gcm)"
        )),
        other => Err(format!(
            "shadowsocks: unknown method '{other}'; supported ciphers are chacha20-ietf-poly1305, aes-128-gcm, aes-256-gcm, xchacha20-ietf-poly1305, 2022-blake3-aes-128-gcm, 2022-blake3-aes-256-gcm, 2022-blake3-chacha20-poly1305"
        )),
    }
}

pub(super) fn ss_2022_key_len(method: &str) -> Option<usize> {
    match method.trim().to_ascii_lowercase().as_str() {
        "2022-blake3-aes-128-gcm" => Some(16),
        "2022-blake3-aes-256-gcm" | "2022-blake3-chacha20-poly1305" => Some(32),
        _ => None,
    }
}

pub(super) fn validate_base64_len(text: &str) -> Result<usize, String> {
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

    let text: Vec<u8> = text.trim().bytes().filter(|byte| *byte != b'=').collect();
    if text.is_empty() {
        return Ok(0);
    }
    let mut out_len = 0;
    for chunk in text.chunks(4) {
        if chunk.len() == 1 {
            return Err("a single trailing character is not a valid group".to_owned());
        }
        for byte in chunk {
            if value(*byte).is_none() {
                return Err(format!("{:?} is not in the base64 alphabet", *byte as char));
            }
        }
        out_len += match chunk.len() {
            2 => 1,
            3 => 2,
            4 => 3,
            _ => unreachable!(),
        };
    }
    Ok(out_len)
}

/// Parses a UUID the way both VLESS and VMess need it: 32 hex digits in the canonical
/// 8-4-4-4-12 layout.
///
/// Validated at load rather than at connect because a malformed id produces a session
/// that authenticates to nobody and fails with the node's generic rejection — the one
/// error an operator cannot attribute.
pub(super) fn parse_node_uuid(text: &str) -> Result<[u8; 16], String> {
    let mut digits = [0u8; 32];
    let mut count = 0;
    for byte in text.trim().bytes() {
        if byte == b'-' {
            continue;
        }
        if !byte.is_ascii_hexdigit() {
            return Err(format!(
                "'{text}' is not a UUID: {:?} is not a hex digit",
                byte as char
            ));
        }
        if count == 32 {
            return Err(format!("'{text}' is not a UUID: more than 32 hex digits"));
        }
        digits[count] = byte;
        count += 1;
    }
    if count != 32 {
        return Err(format!(
            "'{text}' is not a UUID: expected 32 hex digits, got {count}"
        ));
    }
    let mut uuid = [0u8; 16];
    for (index, pair) in digits.chunks(2).enumerate() {
        let hex = std::str::from_utf8(pair).map_err(|_| "uuid is not UTF-8".to_owned())?;
        uuid[index] = u8::from_str_radix(hex, 16).map_err(|_| format!("'{text}' is not a UUID"))?;
    }
    Ok(uuid)
}

/// Checks the security layer's own invariants.
pub(super) fn validate_security(
    security: &SecurityConfig,
    protocol: &str,
    server: &str,
) -> Result<(), String> {
    match security {
        SecurityConfig::None {} => Ok(()),
        SecurityConfig::Tls(tls) => {
            // A certificate cannot be verified against an address: the TLS client would present
            // the IP as SNI, and no CA signs an IP for a proxy node. Failing here gives the
            // operator a message instead of an opaque handshake error.
            if tls.sni.is_none() && server.parse::<std::net::IpAddr>().is_ok() {
                return Err(format!(
                    "{protocol}: a TLS node whose server is an address needs an explicit SNI; \
                     write `[node.security] sni = \"…\"` (or `?sni=…` in a link), because a \
                     certificate cannot be verified against an address"
                ));
            }
            if let Some(sni) = &tls.sni {
                if sni.trim().is_empty() {
                    return Err(format!("{protocol}.security.sni must not be empty"));
                }
                if sni.parse::<std::net::IpAddr>().is_ok() {
                    return Err(format!(
                        "{protocol}.security.sni = {sni:?} is an address; SNI names the host \
                         whose certificate the node presents"
                    ));
                }
            }
            if let Some(fingerprint) = &tls.fingerprint
                && fingerprint.trim().is_empty()
            {
                return Err(format!("{protocol}.security.fingerprint must not be empty"));
            }
            for protocol_name in &tls.alpn {
                if protocol_name.is_empty() || protocol_name.len() > 255 {
                    return Err(format!(
                        "{protocol}.security.alpn entry {protocol_name:?} is not a protocol name"
                    ));
                }
            }
            Ok(())
        }
        SecurityConfig::Reality(reality) => {
            if reality.sni.trim().is_empty() {
                return Err(format!("{protocol}.security.sni must not be empty"));
            }
            if reality.sni.parse::<std::net::IpAddr>().is_ok() {
                return Err(format!(
                    "{protocol}.security.sni = {:?} is an address; REALITY impersonates a site, \
                     and a site is named, not addressed",
                    reality.sni
                ));
            }
            if reality.public_key.trim().is_empty() {
                return Err(format!("{protocol}.security.public-key must not be empty"));
            }
            if let Some(short_id) = &reality.short_id {
                let digits = short_id.trim();
                if digits.len() > 16 || (digits.len() % 2 != 0) {
                    return Err(format!(
                        "{protocol}.security.short-id = {short_id:?} must be an even number of \
                         hex digits (at most 16, i.e. 8 bytes)"
                    ));
                }
                if !digits.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Err(format!(
                        "{protocol}.security.short-id = {short_id:?} is not hex"
                    ));
                }
            }
            // VMess has no REALITY client: REALITY authenticates a VLESS flow, and the
            // reference's VMess outbound has no branch for it at all.
            if protocol == "vmess" {
                return Err(
                    "vmess.security.type = \"reality\" is not a combination the reference \
                     implements; REALITY authenticates a vless flow"
                        .to_owned(),
                );
            }
            Ok(())
        }
    }
}

/// Checks the transport layer's own invariants.
pub(super) fn validate_transport(
    transport: &TransportConfig,
    protocol: &str,
) -> Result<(), String> {
    match transport {
        TransportConfig::Tcp => Ok(()),
        TransportConfig::Ws(ws) => {
            if !ws.path.starts_with('/') {
                return Err(format!(
                    "{protocol}.transport.path = {:?} must start with '/', because a WebSocket \
                     upgrade targets a path",
                    ws.path
                ));
            }
            if let Some(host) = &ws.host
                && host.trim().is_empty()
            {
                return Err(format!("{protocol}.transport.host must not be empty"));
            }
            for (name, value) in &ws.headers {
                if name.is_empty() || name.chars().any(|c| c.is_ascii_control() || c == ':') {
                    return Err(format!(
                        "{protocol}.transport.headers: {name:?} is not a header name"
                    ));
                }
                if value.chars().any(|c| c.is_ascii_control()) {
                    return Err(format!(
                        "{protocol}.transport.headers.{name} contains a control character"
                    ));
                }
            }
            Ok(())
        }
    }
}

/// The `scy` spelling a VMess link uses.
pub(super) const fn vmess_cipher_name(cipher: VmessCipher) -> &'static str {
    match cipher {
        VmessCipher::Auto => "auto",
        VmessCipher::Aes128Gcm => "aes-128-gcm",
        VmessCipher::Chacha20Poly1305 => "chacha20-poly1305",
    }
}

/// Escapes the characters a JSON string literal cannot carry bare.
pub(super) fn json_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// A display-only name for a link this build cannot parse.
///
/// `scheme://user:secret@host:443#name` is a link, and the part before `@` is a credential.
/// A node's `default_name` is printed by `daer probe`, `daer check --nodes` and the daemon's
/// own logs, so returning the raw link writes a secret wherever a node name goes. Only the
/// scheme is kept: it is what tells an operator *why* the node was skipped, and it is the
/// one part of the link that cannot be a credential.
pub(super) fn redact_link(scheme: &str, _link: &str) -> String {
    format!("{scheme}://<redacted>")
}

fn percent_decode(s: &str) -> String {
    let mut bytes = Vec::with_capacity(s.len());
    let mut chars = s.bytes();
    while let Some(b) = chars.next() {
        if b == b'%' {
            let h1 = chars.next().unwrap_or(b'0');
            let h2 = chars.next().unwrap_or(b'0');
            let hex_str = [h1, h2];
            if let Ok(hex_ascii) = std::str::from_utf8(&hex_str)
                && let Ok(val) = u8::from_str_radix(hex_ascii, 16)
            {
                bytes.push(val);
                continue;
            }
            bytes.push(b'%');
            bytes.push(h1);
            bytes.push(h2);
            continue;
        }
        bytes.push(b);
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

fn decode_base64(text: &str) -> Result<String, String> {
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

    let text: Vec<u8> = text
        .bytes()
        .filter(|byte| *byte != b'=' && !byte.is_ascii_whitespace())
        .collect();
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    for chunk in text.chunks(4) {
        if chunk.len() == 1 {
            return Err("base64: invalid trailing byte".to_owned());
        }
        let mut accumulator = 0u32;
        for (index, byte) in chunk.iter().enumerate() {
            let value = value(*byte).ok_or_else(|| {
                format!("base64: byte {:?} is not in the alphabet", *byte as char)
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
    String::from_utf8(out).map_err(|_| "base64 payload is not UTF-8".to_owned())
}

fn parse_host_port(authority: &str) -> Result<(String, u16), String> {
    let authority = authority.trim();
    let authority = match authority.split_once('?') {
        Some((auth, _query)) => auth,
        None => authority,
    };
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .ok_or_else(|| format!("{authority:?} has an unclosed '['"))?;
        let port = tail
            .strip_prefix(':')
            .ok_or_else(|| format!("{authority:?} has no port"))?;
        let port: u16 = port
            .parse()
            .map_err(|_| format!("{authority:?} has an invalid port"))?;
        return Ok((host.to_owned(), port));
    }
    let (host, port) = authority
        .rsplit_once(':')
        .ok_or_else(|| format!("{authority:?} has no port"))?;
    let port: u16 = port
        .parse()
        .map_err(|_| format!("{authority:?} has an invalid port"))?;
    Ok((host.to_owned(), port))
}

/// Splits `host:ports` where `ports` may be a set (`443,8443`, `1-100`, `all`).
///
/// Distinct from [`parse_host_port`] because the port field is the only one that can
/// carry a list, and a list is what port hopping needs (ADR-0029). The split is on the
/// last colon so an IPv6 literal survives, and bracketed literals are handled first.
fn split_host_ports(authority: &str) -> Result<(String, String), String> {
    let authority = authority.trim();
    let authority = match authority.split_once('?') {
        Some((auth, _query)) => auth,
        None => authority,
    };
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .ok_or_else(|| format!("{authority:?} has an unclosed '['"))?;
        let ports = tail
            .strip_prefix(':')
            .ok_or_else(|| format!("{authority:?} has no port"))?;
        return Ok((host.to_owned(), ports.to_owned()));
    }
    let (host, ports) = authority
        .rsplit_once(':')
        .ok_or_else(|| format!("{authority:?} has no port"))?;
    Ok((host.to_owned(), ports.to_owned()))
}

/// Whether a query value means "on": `1`, `true`, `yes`.
fn truthy(value: &str) -> bool {
    value == "1" || value.eq_ignore_ascii_case("true") || value.eq_ignore_ascii_case("yes")
}

/// A hop interval: bare milliseconds, or a Go duration (`30s`, `1m`).
fn parse_interval_ms(value: &str) -> Option<u64> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    if let Ok(millis) = value.parse::<u64>() {
        return Some(millis);
    }
    parse_duration(value).and_then(|span| u64::try_from(span.as_nanos() / 1_000_000).ok())
}

/// Builds a VLESS node from a link's query, splitting the security and transport layers
/// out of the flat parameter list the link format uses (ADR-0028).
fn parse_vless_layers(
    name: Option<String>,
    user_part: &str,
    server: String,
    port: u16,
    query: &str,
) -> Result<VlessNode, String> {
    let mut security_kind = None;
    let mut public_key = None;
    let mut short_id = None;
    let mut fingerprint = None;
    let mut flow_text = None;
    let mut kind = None;
    let mut sni = None;
    let mut alpn: Vec<String> = Vec::new();
    let mut allow_insecure = false;
    let mut path = None;
    let mut host = None;

    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (key, value) = match pair.split_once('=') {
            Some((k, v)) => (k, v),
            None => (pair, ""),
        };
        // Xray's own spelling for "no encryption" is mandatory in a link and carries no
        // information daer does not already know; anything else is a real request.
        if key == "encryption" && !value.eq_ignore_ascii_case("none") {
            return Err(format!(
                "vless link asks for encryption={value}; VLESS carries no inner encryption, and \
                 only `none` is a valid value"
            ));
        }
        let decoded = percent_decode(value);
        match key {
            "security" => security_kind = Some(decoded),
            "pbk" if !decoded.is_empty() => public_key = Some(decoded),
            "sid" if !decoded.is_empty() => short_id = Some(decoded),
            "fp" if !decoded.is_empty() => fingerprint = Some(decoded),
            "flow" if !decoded.is_empty() => flow_text = Some(decoded),
            "type" if !decoded.is_empty() => kind = Some(decoded),
            "sni" | "peer" if !decoded.is_empty() => sni = Some(decoded),
            "alpn" if !decoded.is_empty() => {
                alpn = decoded.split(',').map(str::to_owned).collect();
            }
            "allowInsecure" | "allow_insecure" | "insecure" => allow_insecure = truthy(value),
            "path" if !decoded.is_empty() => path = Some(decoded),
            "host" if !decoded.is_empty() => host = Some(decoded),
            "headerType" | "serviceName" | "mode" | "extra" => {}
            // Unknown parameters are not an error: panels add them freely and a strict
            // parser would lock an operator out of their own subscription.
            _ => {}
        }
    }

    let flow = match flow_text.as_deref() {
        None | Some("") | Some("none") => Flow::None,
        Some("xtls-rprx-vision") | Some("vision") => Flow::Vision,
        Some("xtls-rprx-vision-udp443") | Some("vision-udp443") => Flow::VisionUdp443,
        Some(other) => {
            return Err(format!(
                "vless link asks for flow={other}; the implemented flows are none, \
                 xtls-rprx-vision and xtls-rprx-vision-udp443"
            ));
        }
    };

    let transport = match kind.as_deref() {
        None | Some("") | Some("tcp") | Some("raw") | Some("none") => TransportConfig::Tcp,
        Some("ws") | Some("websocket") => TransportConfig::Ws(WsTransport {
            path: path.unwrap_or_else(|| "/".to_owned()),
            host,
            headers: BTreeMap::new(),
        }),
        Some(other) => {
            return Err(format!(
                "vless link asks for type={other}; the implemented transports are tcp and ws. \
                 A {other} session is a framing layer daer does not have, so it is refused \
                 rather than silently downgraded to tcp"
            ));
        }
    };

    let security = match security_kind.as_deref() {
        None | Some("") | Some("none") => SecurityConfig::None {},
        Some("tls") => SecurityConfig::Tls(TlsSecurity {
            sni,
            allow_insecure,
            alpn,
            fingerprint,
        }),
        Some("reality") => SecurityConfig::Reality(RealitySecurity {
            sni: sni.ok_or_else(|| {
                "vless:// REALITY link has no `sni`; REALITY impersonates a named site, and the \
                 node's address cannot be one"
                    .to_owned()
            })?,
            public_key: public_key.ok_or_else(|| {
                "vless:// REALITY link has no `pbk`; the server's public key is what the tag is \
                 derived from, and without it no handshake can be attempted"
                    .to_owned()
            })?,
            short_id,
            alpn,
        }),
        Some("xtls") => {
            return Err(
                "vless link asks for security=xtls; that is the retired pre-Vision XTLS, which \
                 the reference removed. Use security=reality with flow=xtls-rprx-vision"
                    .to_owned(),
            );
        }
        Some(other) => {
            return Err(format!(
                "vless link asks for security={other}; the implemented security layers are none, \
                 tls and reality"
            ));
        }
    };

    let vless = VlessNode {
        name,
        server,
        port,
        uuid: user_part.to_owned(),
        flow,
        security,
        transport,
    };
    vless
        .validate_self()
        .map_err(|reason| format!("vless link is not usable: {reason}"))?;
    Ok(vless)
}

impl VlessNode {
    /// Validates this node, for the link path where the caller wants a usable node.
    fn validate_self(&self) -> Result<(), String> {
        NodeEndpoint::Vless(self.clone()).validate()
    }
}

impl VmessNode {
    /// Validates this node, for the link path where the caller wants a usable node.
    fn validate_self(&self) -> Result<(), String> {
        NodeEndpoint::Vmess(self.clone()).validate()
    }
}

/// Parses `vmess://<base64(json)>` (ADR-0030).
///
/// The reference's share format is a base64url JSON object rather than a query string, so
/// there is no shared query parser to reuse. Unknown fields are ignored — panels add
/// them — but a field naming a layer daer does not implement is refused, because silently
/// dialling `net = "kcp"` as TCP produces a session that never authenticates.
fn parse_vmess_link(
    name: Option<String>,
    body: &str,
    whole_link: &str,
) -> Result<VmessNode, String> {
    let json = decode_base64(body.trim())
        .map_err(|reason| format!("vmess link payload is not base64 JSON: {reason}"))?;
    let fields = parse_json_object(&json)?;

    let get = |key: &str| fields.get(key).map(String::as_str).unwrap_or("");
    let server = get("add");
    if server.is_empty() {
        return Err("vmess link has no `add` (server)".to_owned());
    }
    let port: u16 = get("port")
        .parse()
        .map_err(|_| format!("vmess link port {:?} is not a number", get("port")))?;
    let uuid = get("id");
    if uuid.is_empty() {
        return Err("vmess link has no `id` (uuid)".to_owned());
    }
    // `aid` is the legacy handshake's parameter. Accepting a non-zero value while
    // speaking AEAD would be a lie about which handshake is on the wire.
    match get("aid") {
        "" | "0" => {}
        other => {
            return Err(format!(
                "vmess link has aid={other}; a non-zero alterId selects the legacy handshake, \
                 which daer does not implement (ADR-0030). Only VMess AEAD is spoken"
            ));
        }
    }

    let cipher = match get("scy").to_ascii_lowercase().as_str() {
        "" | "auto" => VmessCipher::Auto,
        "aes-128-gcm" => VmessCipher::Aes128Gcm,
        "chacha20-poly1305" => VmessCipher::Chacha20Poly1305,
        other => {
            return Err(format!(
                "vmess link asks for scy={other}; the implemented ciphers are auto, \
                 aes-128-gcm and chacha20-poly1305"
            ));
        }
    };

    let tls_field = get("tls").to_ascii_lowercase();
    let alpn: Vec<String> = if get("alpn").is_empty() {
        Vec::new()
    } else {
        get("alpn").split(',').map(str::to_owned).collect()
    };
    let security = match tls_field.as_str() {
        "" | "none" => SecurityConfig::None {},
        "tls" => SecurityConfig::Tls(TlsSecurity {
            sni: (!get("sni").is_empty()).then(|| get("sni").to_owned()),
            allow_insecure: truthy(get("allowinsecure")) || truthy(get("allow_insecure")),
            alpn,
            fingerprint: (!get("fp").is_empty()).then(|| get("fp").to_owned()),
        }),
        "reality" => {
            return Err(
                "vmess link asks for tls=reality; REALITY authenticates a vless flow, and the \
                 reference implements no VMess REALITY client"
                    .to_owned(),
            );
        }
        other => {
            return Err(format!(
                "vmess link asks for tls={other}; the implemented security layers are none and \
                 tls"
            ));
        }
    };

    let transport = match get("net").to_ascii_lowercase().as_str() {
        "" | "tcp" | "raw" => TransportConfig::Tcp,
        "ws" | "websocket" => {
            let path = get("path");
            TransportConfig::Ws(WsTransport {
                path: if path.is_empty() {
                    "/".to_owned()
                } else {
                    path.to_owned()
                },
                host: (!get("host").is_empty()).then(|| get("host").to_owned()),
                headers: BTreeMap::new(),
            })
        }
        other => {
            return Err(format!(
                "vmess link asks for net={other}; the implemented transports are tcp and ws \
                 (in {whole_link:?})"
            ));
        }
    };

    let name = name.or_else(|| (!get("ps").is_empty()).then(|| get("ps").to_owned()));
    let vmess = VmessNode {
        name,
        server: server.to_owned(),
        port,
        uuid: uuid.to_owned(),
        cipher,
        authenticated_length: get("authenticatedLength").eq_ignore_ascii_case("true"),
        no_termination_signal: get("noTerminationSignal").eq_ignore_ascii_case("true"),
        security,
        transport,
    };
    vmess
        .validate_self()
        .map_err(|reason| format!("vmess link is not usable: {reason}"))?;
    Ok(vmess)
}

/// A flat JSON object of string values, which is all a `vmess://` payload is.
///
/// Hand-rolled rather than a `serde_json` dependency in `daer-config`: the payload is a
/// dozen string fields, `serde_json` is already a workspace dependency but pulling a JSON
/// parser into the configuration crate for one link format would put a second
/// deserializer on the load path. Escapes are decoded; nested values are refused because
/// a `vmess://` payload has none and accepting one would silently drop it.
fn parse_json_object(json: &str) -> Result<BTreeMap<String, String>, String> {
    let bytes: Vec<char> = json.trim().chars().collect();
    let mut index = 0;
    let mut fields = BTreeMap::new();

    let skip_ws = |index: &mut usize| {
        while *index < bytes.len() && bytes[*index].is_whitespace() {
            *index += 1;
        }
    };
    let parse_string = |index: &mut usize| -> Result<String, String> {
        skip_ws(index);
        if bytes.get(*index) != Some(&'"') {
            return Err(format!("expected a string at offset {index}"));
        }
        *index += 1;
        let mut out = String::new();
        loop {
            let c = *bytes.get(*index).ok_or("unterminated string")?;
            *index += 1;
            match c {
                '"' => return Ok(out),
                '\\' => {
                    let escape = *bytes.get(*index).ok_or("unterminated escape")?;
                    *index += 1;
                    match escape {
                        '"' => out.push('"'),
                        '\\' => out.push('\\'),
                        '/' => out.push('/'),
                        'b' => out.push('\u{8}'),
                        'f' => out.push('\u{c}'),
                        'n' => out.push('\n'),
                        'r' => out.push('\r'),
                        't' => out.push('\t'),
                        'u' => {
                            let hex: String = bytes
                                .get(*index..*index + 4)
                                .ok_or("truncated \\u escape")?
                                .iter()
                                .collect();
                            *index += 4;
                            let code = u32::from_str_radix(&hex, 16)
                                .map_err(|_| format!("{hex:?} is not a code point"))?;
                            out.push(char::from_u32(code).ok_or("invalid code point")?);
                        }
                        other => return Err(format!("unknown escape \\{other}")),
                    }
                }
                c => out.push(c),
            }
        }
    };

    skip_ws(&mut index);
    if bytes.get(index) != Some(&'{') {
        return Err("payload is not a JSON object".to_owned());
    }
    index += 1;
    loop {
        skip_ws(&mut index);
        match bytes.get(index) {
            Some('}') => break,
            Some('"') => {}
            Some(other) => return Err(format!("expected a key or '}}', got {other:?}")),
            None => return Err("unterminated object".to_owned()),
        }
        let key = parse_string(&mut index)?;
        skip_ws(&mut index);
        if bytes.get(index) != Some(&':') {
            return Err(format!("expected ':' after key {key:?}"));
        }
        index += 1;
        skip_ws(&mut index);
        match bytes.get(index) {
            Some('"') => {
                let value = parse_string(&mut index)?;
                fields.insert(key, value);
            }
            Some('{') | Some('[') => {
                return Err(format!(
                    "vmess link field {key:?} holds a nested value; a `vmess://` payload is a \
                     flat object of strings"
                ));
            }
            Some(_) => {
                // Numbers and booleans are written bare by some panels. Reading the token
                // as text is what the reference does, and it keeps `"port": 443` working.
                let start = index;
                while index < bytes.len() && !matches!(bytes[index], ',' | '}') {
                    index += 1;
                }
                let token: String = bytes[start..index].iter().collect();
                fields.insert(key, token.trim().to_owned());
            }
            None => return Err("unterminated object".to_owned()),
        }
        skip_ws(&mut index);
        match bytes.get(index) {
            Some(',') => index += 1,
            Some('}') => {}
            Some(other) => return Err(format!("expected ',' or '}}', got {other:?}")),
            None => return Err("unterminated object".to_owned()),
        }
    }
    Ok(fields)
}

impl StructuredNode {
    /// Parses an outbound URI link (`vless://`, `ss://`, `trojan://`, `socks5://`, `http://`,
    /// `direct://`) into a structured node representation.
    pub fn from_link(link: &str) -> Result<Self, String> {
        let endpoint = Self::from_link_unchecked(link)?;
        // Deliberately **not** validated here.
        //
        // Parsing a link and supporting it are different questions, and subscription
        // handling depends on the difference: an airport's `vless://…?security=tls` or
        // `tuic://` link is well formed and unsupported, and it has to enter the pool so the
        // generation builder can report it by name. Validating here made such a link vanish
        // during resolution instead — a pool that looks populated while a node was silently
        // dropped, which is the failure mode
        // `a_subscription_with_no_usable_node_is_not_a_silent_empty_group` exists to prevent.
        //
        // The conversion path, where emitting an unusable node *is* a defect, validates in
        // [`to_toml_node`](Self::to_toml_node).
        Ok(endpoint)
    }

    /// Splits a link into a node **without** checking that the result is usable.
    ///
    /// Only [`from_link`](Self::from_link) should call this: an unchecked node may declare a
    /// cipher that is not implemented, an empty server, or a `vless` node with no REALITY.
    fn from_link_unchecked(link: &str) -> Result<Self, String> {
        let link = link.trim();
        if link.is_empty() || link == "direct" || link.starts_with("direct://") {
            return Err(
                "`direct` is a routing verdict, not a node: use `action = \"direct\"` in a \
                 [[routing.rule]] or as `routing.default`"
                    .to_owned(),
            );
        }

        if link.contains("->") {
            return Err("chained links ('a -> b') are not implemented".to_owned());
        }

        let Some((scheme, rest)) = link.split_once("://") else {
            return Err(format!("{link:?} has no '://' scheme separator"));
        };

        // Split off #fragment as name
        let (before_fragment, name) = match rest.split_once('#') {
            Some((before, fragment)) => {
                let name = percent_decode(fragment);
                let name = if name.is_empty() { None } else { Some(name) };
                (before, name)
            }
            None => (rest, None),
        };

        match scheme.to_ascii_lowercase().as_str() {
            "socks" | "socks5" | "socks5h" => {
                let (auth, authority) = match before_fragment.rsplit_once('@') {
                    Some((auth, hostport)) => (Some(auth), hostport),
                    None => (None, before_fragment),
                };
                let (username, password) = match auth {
                    Some(auth) => match auth.split_once(':') {
                        Some((u, p)) => (Some(percent_decode(u)), Some(percent_decode(p))),
                        None => (Some(percent_decode(auth)), None),
                    },
                    None => (None, None),
                };
                let (server, port) = parse_host_port(authority)?;
                Ok(Self::Socks5(Socks5Node {
                    name,
                    server,
                    port,
                    username,
                    password,
                }))
            }
            "http" => {
                let (auth, authority) = match before_fragment.rsplit_once('@') {
                    Some((auth, hostport)) => (Some(auth), hostport),
                    None => (None, before_fragment),
                };
                let (username, password) = match auth {
                    Some(auth) => match auth.split_once(':') {
                        Some((u, p)) => (Some(percent_decode(u)), Some(percent_decode(p))),
                        None => (Some(percent_decode(auth)), None),
                    },
                    None => (None, None),
                };
                let (server, port) = parse_host_port(authority)?;
                Ok(Self::Http(HttpNode {
                    name,
                    server,
                    port,
                    username,
                    password,
                }))
            }
            "ss" | "shadowsocks" => {
                let (creds, authority) = match before_fragment.rsplit_once('@') {
                    Some((userinfo, hostport)) => {
                        if userinfo.contains(':')
                            && validate_ss_method(userinfo.split_once(':').unwrap().0).is_ok()
                        {
                            (userinfo.to_owned(), hostport.to_owned())
                        } else {
                            match decode_base64(userinfo) {
                                Ok(decoded) => (decoded, hostport.to_owned()),
                                Err(_) if userinfo.contains(':') => {
                                    (userinfo.to_owned(), hostport.to_owned())
                                }
                                Err(e) => return Err(e),
                            }
                        }
                    }
                    None => {
                        let decoded = decode_base64(before_fragment)?;
                        let (creds, hostport) = decoded.rsplit_once('@').ok_or_else(|| {
                            "ss link has no '@' separating credentials from server".to_owned()
                        })?;
                        (creds.to_owned(), hostport.to_owned())
                    }
                };
                let (method, password) = creds.split_once(':').ok_or_else(|| {
                    "ss credentials are not in 'method:password' format".to_owned()
                })?;
                let (server, port) = parse_host_port(&authority)?;
                Ok(Self::Shadowsocks(ShadowsocksNode {
                    name,
                    server,
                    port,
                    method: method.to_owned(),
                    password: password.to_owned(),
                }))
            }
            "trojan" | "trojan-go" => {
                let (authority, query) = match before_fragment.split_once('?') {
                    Some((auth, q)) => (auth, q),
                    None => (before_fragment, ""),
                };
                let (password, hostport) = authority
                    .rsplit_once('@')
                    .ok_or_else(|| "trojan link has no 'password@server:port'".to_owned())?;
                let (server, port) = parse_host_port(hostport)?;

                let mut sni = None;
                let mut allow_insecure = false;
                for pair in query.split('&').filter(|p| !p.is_empty()) {
                    let (k, v) = match pair.split_once('=') {
                        Some((k, v)) => (k, v),
                        None => (pair, ""),
                    };
                    match k {
                        "sni" | "peer" if !v.is_empty() => {
                            sni = Some(percent_decode(v));
                        }
                        "allowInsecure" | "allow_insecure" => {
                            allow_insecure = v == "1" || v.eq_ignore_ascii_case("true");
                        }
                        _ => {}
                    }
                }
                Ok(Self::Trojan(TrojanNode {
                    name,
                    server,
                    port,
                    password: password.to_owned(),
                    tls: NodeTls {
                        sni,
                        allow_insecure,
                    },
                }))
            }
            "anytls" => {
                let (authority, query) = match before_fragment.split_once('?') {
                    Some((auth, q)) => (auth, q),
                    None => (before_fragment, ""),
                };
                let (password, hostport) = authority
                    .rsplit_once('@')
                    .ok_or_else(|| "anytls link has no 'password@server:port'".to_owned())?;
                let (server, port) = parse_host_port(hostport)?;

                let mut sni = None;
                let mut allow_insecure = false;
                let mut idle_sessions = 1;
                for pair in query.split('&').filter(|p| !p.is_empty()) {
                    let (k, v) = match pair.split_once('=') {
                        Some((k, v)) => (k, v),
                        None => (pair, ""),
                    };
                    match k {
                        "sni" | "peer" if !v.is_empty() => {
                            sni = Some(percent_decode(v));
                        }
                        "allowInsecure" | "allow_insecure" | "insecure" => {
                            allow_insecure = v == "1" || v.eq_ignore_ascii_case("true");
                        }
                        "idle_sessions" | "min_idle_sessions" => {
                            if let Ok(n) = v.parse::<usize>() {
                                idle_sessions = n.max(1);
                            }
                        }
                        _ => {}
                    }
                }
                Ok(Self::AnyTls(AnyTlsNode {
                    name,
                    server,
                    port,
                    password: percent_decode(password),
                    tls: NodeTls {
                        sni,
                        allow_insecure,
                    },
                    idle_sessions,
                }))
            }
            "hysteria2" | "hy2" => {
                let (authority, query) = match before_fragment.split_once('?') {
                    Some((auth, q)) => (auth, q),
                    None => (before_fragment, ""),
                };
                let (password, hostport) = authority
                    .rsplit_once('@')
                    .ok_or_else(|| "hysteria2 link has no 'password@server:port'".to_owned())?;
                // The port field may be a set (`443,8443`, `20000-30000`, `all`), which is
                // what the reference's port hopping needs. Splitting on the *last* colon
                // keeps an IPv6 literal intact.
                let (server, port_text) = split_host_ports(hostport)?;
                let ports = PortSet::parse(&port_text)?;

                let mut sni = None;
                let mut allow_insecure = false;
                let mut pin_sha256 = None;
                let mut up_mbps = 0;
                let mut down_mbps = 0;
                let mut obfs_kind = None;
                let mut obfs_password = None;
                let mut congestion = Hysteria2Congestion::Bbr;
                let mut gecko_min = 0u16;
                let mut gecko_max = 0u16;
                let mut port_hopping = PortHopping::default();

                for pair in query.split('&').filter(|p| !p.is_empty()) {
                    let (k, v) = match pair.split_once('=') {
                        Some((k, v)) => (k, v),
                        None => (pair, ""),
                    };
                    match k {
                        "sni" | "peer" if !v.is_empty() => sni = Some(percent_decode(v)),
                        "insecure" | "allowInsecure" | "allow_insecure" => {
                            allow_insecure = truthy(v);
                        }
                        "pinSHA256" | "pin-sha256" if !v.is_empty() => {
                            pin_sha256 = Some(percent_decode(v));
                        }
                        "upmbps" | "up_mbps" => up_mbps = v.parse().unwrap_or(0),
                        "downmbps" | "down_mbps" => down_mbps = v.parse().unwrap_or(0),
                        "obfs" if !v.is_empty() => obfs_kind = Some(percent_decode(v)),
                        "obfs-password" if !v.is_empty() => {
                            obfs_password = Some(percent_decode(v));
                        }
                        "hop-interval" | "hop_interval" => {
                            port_hopping.interval = TimeSpan::from_millis(
                                i64::try_from(parse_interval_ms(v).unwrap_or(0))
                                    .unwrap_or(i64::MAX),
                            );
                        }
                        "hop-min-interval" | "hop_min_interval" => {
                            port_hopping.min_interval = TimeSpan::from_millis(
                                i64::try_from(parse_interval_ms(v).unwrap_or(0))
                                    .unwrap_or(i64::MAX),
                            );
                        }
                        "hop-max-interval" | "hop_max_interval" => {
                            port_hopping.max_interval = TimeSpan::from_millis(
                                i64::try_from(parse_interval_ms(v).unwrap_or(0))
                                    .unwrap_or(i64::MAX),
                            );
                        }
                        "congestion" if !v.is_empty() => {
                            congestion = match percent_decode(v).to_ascii_lowercase().as_str() {
                                "bbr" => Hysteria2Congestion::Bbr,
                                "cubic" => Hysteria2Congestion::Cubic,
                                "new_reno" | "newreno" | "reno" => Hysteria2Congestion::NewReno,
                                "brutal" => Hysteria2Congestion::Brutal,
                                other => {
                                    return Err(format!(
                                        "hysteria2 link asks for congestion={other}; the \
                                         implemented controllers are bbr, cubic, new-reno and \
                                         brutal"
                                    ));
                                }
                            };
                        }
                        "gecko-min-packet-size" => gecko_min = v.parse().unwrap_or(0),
                        "gecko-max-packet-size" => gecko_max = v.parse().unwrap_or(0),
                        _ => {}
                    }
                }

                let obfs = match (obfs_kind.as_deref(), obfs_password) {
                    (None, None) | (Some(""), None) => None,
                    (Some(kind), Some(password)) => match kind.to_ascii_lowercase().as_str() {
                        "salamander" => Some(Hysteria2Obfs::Salamander { password }),
                        "gecko" => Some(Hysteria2Obfs::Gecko {
                            password,
                            min_packet_size: gecko_min,
                            max_packet_size: gecko_max,
                        }),
                        other => {
                            return Err(format!(
                                "hysteria2 link asks for obfs={other}; the implemented \
                                 obfuscations are salamander and gecko (and omitting obfs)"
                            ));
                        }
                    },
                    (Some(kind), None) => {
                        return Err(format!(
                            "hysteria2 link names obfs={kind} without obfs-password; the \
                             obfuscation is a pre-shared key"
                        ));
                    }
                    (None, Some(_)) => {
                        return Err(
                            "hysteria2 link names obfs-password without obfs; the password has \
                             no meaning on its own"
                                .to_owned(),
                        );
                    }
                };

                Ok(Self::Hysteria2(Hysteria2Node {
                    name,
                    server,
                    ports,
                    password: percent_decode(password),
                    tls: Hysteria2Tls {
                        sni,
                        allow_insecure,
                        pin_sha256,
                    },
                    bandwidth: Hysteria2Bandwidth { up_mbps, down_mbps },
                    obfs,
                    quic: Hysteria2Quic {
                        congestion,
                        ..Hysteria2Quic::default()
                    },
                    port_hopping,
                }))
            }
            "vless" => {
                let (user_part, rest) = before_fragment
                    .split_once('@')
                    .ok_or_else(|| "vless link has no 'uuid@server:port'".to_owned())?;
                let (authority, query) = match rest.split_once('?') {
                    Some((auth, q)) => (auth, q),
                    None => (rest, ""),
                };
                let (server, port) = parse_host_port(authority)?;
                parse_vless_layers(name, user_part, server, port, query).map(Self::Vless)
            }
            "vmess" => parse_vmess_link(name, before_fragment, link).map(Self::Vmess),
            other => Ok(Self::Unsupported {
                scheme: other.to_owned(),
                link: link.to_owned(),
            }),
        }
    }
}

impl<'de> Deserialize<'de> for Node {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let value = toml::Value::deserialize(d)?;
        match value {
            toml::Value::String(_) => Err(D::Error::custom(
                "bare URL strings in 'node' have been retired; configure nodes as [[node]] structured tables, or use [[subscription]] to fetch URL lists",
            )),
            toml::Value::Table(table) => {
                if table.contains_key("url") {
                    return Err(D::Error::custom(
                        "the 'url' field in [[node]] has been retired in favor of structured configuration tables; \
                         declare node fields directly (e.g. type = \"vless\", server = ..., port = ...) or run 'daer node convert <url>' to convert your link",
                    ));
                }
                if !table.contains_key("type") {
                    return Err(D::Error::custom(
                        "missing 'type' in [[node]] table (expected e.g. type = \"vless\", \"anytls\", \"shadowsocks\", \"trojan\", \"socks5\", \"http\")",
                    ));
                }

                #[derive(Deserialize)]
                #[serde(rename_all = "kebab-case")]
                struct NodeHelper {
                    name: Option<String>,
                    detour: Option<String>,
                    #[serde(flatten)]
                    endpoint: NodeEndpoint,
                }

                let helper =
                    NodeHelper::deserialize(toml::Value::Table(table)).map_err(D::Error::custom)?;
                helper.endpoint.validate().map_err(D::Error::custom)?;
                Ok(Self {
                    name: helper.name,
                    endpoint: helper.endpoint,
                    detour: helper.detour,
                    subscription: None,
                })
            }
            other => Err(D::Error::custom(format!(
                "expected [[node]] to be a structured table, got {}",
                other.type_str()
            ))),
        }
    }
}
