// SPDX-License-Identifier: AGPL-3.0-only

//! Unified Shadowsocks link parser supporting SIP002 (Base64 credentials),
//! legacy full-base64 links, and Shadowsocks 2022 plain userinfo links.

use super::Cipher;

/// A parsed `ss://` link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    pub cipher: Cipher,
    /// Kept for master/pre-shared key derivation; never logged.
    password: String,
    pub server: String,
    pub tag: Option<String>,
}

impl Link {
    /// The password or base64-encoded PSK.
    #[must_use]
    pub fn password(&self) -> &str {
        &self.password
    }

    /// Derives the master key (for 2017 AEAD) or returns the decoded PSK (for 2022 AEAD).
    #[must_use]
    pub fn master_key(&self) -> Vec<u8> {
        if self.cipher.is_2022() {
            decode_base64_bytes(&self.password).expect("validated 2022 PSK")
        } else {
            super::v1::master_key(self.cipher, &self.password)
        }
    }

    /// Parses an `ss://` link.
    ///
    /// # Errors
    ///
    /// Returns a message naming what is invalid: base64 encoding, cipher name,
    /// key length (for 2022 ciphers), or server authority.
    pub fn parse(link: &str) -> Result<Self, String> {
        let body = link
            .trim()
            .strip_prefix("ss://")
            .ok_or_else(|| format!("{link:?} does not start with ss://"))?;

        // Fragment is the optional tag; keep verbatim per SIP002.
        let (body, tag) = match body.split_once('#') {
            Some((body, tag)) => (body, Some(tag.to_owned())),
            None => (body, None),
        };

        // Two link formats in the wild:
        // 1. Plain or base64 userinfo followed by `@server:port`
        // 2. Legacy form where the entire link payload is base64-encoded.
        let (credentials, server) = match body.rsplit_once('@') {
            Some((userinfo, server)) => {
                // Try decoding userinfo as base64 first (SIP002 standard).
                // If it fails or if userinfo already contains a colon (plain format used by AEAD 2022),
                // fall back to plain userinfo.
                if userinfo.contains(':')
                    && Cipher::parse(userinfo.split_once(':').unwrap().0).is_ok()
                {
                    (userinfo.to_owned(), server.to_owned())
                } else {
                    match decode_base64_string(userinfo) {
                        Ok(decoded) => (decoded, server.to_owned()),
                        Err(_) if userinfo.contains(':') => {
                            (userinfo.to_owned(), server.to_owned())
                        }
                        Err(e) => return Err(e),
                    }
                }
            }
            None => {
                // Legacy form: everything is base64 and holds the server too.
                let decoded = decode_base64_string(body)?;
                let (credentials, server) = decoded.rsplit_once('@').ok_or_else(|| {
                    format!("ss:// link {link:?} has no `@` separating credentials from server")
                })?;
                (credentials.to_owned(), server.to_owned())
            }
        };

        let (method, password) = credentials.split_once(':').ok_or_else(|| {
            format!("ss:// credentials {credentials:?} do not contain a `method:password` split")
        })?;

        let cipher = Cipher::parse(method).map_err(|e| e.to_string())?;

        // Validate 2022 PSK encoding and length
        if cipher.is_2022() {
            let key_bytes = decode_base64_bytes(password).map_err(|e| {
                format!("shadowsocks 2022: method '{method}' password must be valid base64: {e}")
            })?;
            if key_bytes.len() != cipher.key_len() {
                return Err(format!(
                    "shadowsocks 2022: method '{method}' requires a {}-byte base64-encoded key, but got {} bytes",
                    cipher.key_len(),
                    key_bytes.len()
                ));
            }
        }

        if server.trim().is_empty() {
            return Err("ss:// link has an empty server address".to_owned());
        }

        Ok(Self {
            cipher,
            password: password.to_owned(),
            server,
            tag,
        })
    }
}

/// Decodes standard or URL-safe base64 into a UTF-8 string.
pub fn decode_base64_string(text: &str) -> Result<String, String> {
    let bytes = decode_base64_bytes(text)?;
    String::from_utf8(bytes).map_err(|error| format!("base64 decoded bytes are not UTF-8: {error}"))
}

/// Decodes standard or URL-safe base64, with or without padding, into raw bytes.
pub fn decode_base64_bytes(text: &str) -> Result<Vec<u8>, String> {
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
        return Ok(Vec::new());
    }

    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    for chunk in text.chunks(4) {
        if chunk.len() == 1 {
            return Err("base64: a single trailing character is not a valid group".to_owned());
        }
        let mut accumulator = 0u32;
        for (index, byte) in chunk.iter().enumerate() {
            let val = value(*byte)
                .ok_or_else(|| format!("base64: {:?} is not in the alphabet", *byte as char))?;
            accumulator |= u32::from(val) << (18 - 6 * index);
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

/// True when a link is a shadowsocks link.
#[must_use]
pub fn is_shadowsocks(link: &str) -> bool {
    link.trim_start().starts_with("ss://")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_classic_sip002_link() {
        let link = "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ@192.0.2.1:8388#example";
        let parsed = Link::parse(link).expect("parses");
        assert_eq!(parsed.cipher, Cipher::Aes128Gcm);
        assert_eq!(parsed.password(), "password");
        assert_eq!(parsed.server, "192.0.2.1:8388");
        assert_eq!(parsed.tag.as_deref(), Some("example"));
        assert_eq!(parsed.master_key().len(), 16);
    }

    #[test]
    fn parses_legacy_full_base64_link() {
        let link = "ss://YWVzLTEyOC1nY206cGFzc3dvcmRAMTkyLjAuMi4xOjgzODg#example";
        let parsed = Link::parse(link).expect("parses");
        assert_eq!(parsed.cipher, Cipher::Aes128Gcm);
        assert_eq!(parsed.password(), "password");
        assert_eq!(parsed.server, "192.0.2.1:8388");
        assert_eq!(parsed.tag.as_deref(), Some("example"));
        assert_eq!(parsed.master_key().len(), 16);
    }

    #[test]
    fn parses_2022_plain_userinfo_link() {
        let link_clean =
            "ss://2022-blake3-aes-128-gcm:3L69X4PF2eSL/JSLkoWnXg==@192.0.2.1:8388#ss22";
        let parsed = Link::parse(link_clean).expect("parses");
        assert_eq!(parsed.cipher, Cipher::Aead2022Blake3Aes128Gcm);
        assert_eq!(parsed.password(), "3L69X4PF2eSL/JSLkoWnXg==");
        assert_eq!(parsed.server, "192.0.2.1:8388");
        assert_eq!(parsed.tag.as_deref(), Some("ss22"));
        assert_eq!(parsed.master_key().len(), 16);
    }

    #[test]
    fn rejects_2022_with_invalid_key_length() {
        let link = "ss://2022-blake3-aes-128-gcm:bm90MTZieXRlcw==@192.0.2.1:8388";
        let err = Link::parse(link).expect_err("must fail");
        assert!(err.contains("requires a 16-byte"), "{err}");
    }
}
