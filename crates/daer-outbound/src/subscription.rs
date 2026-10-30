// SPDX-License-Identifier: AGPL-3.0-only

//! Subscription fetching and decoding.
//!
//! A subscription is a URL that returns a list of node links. The wire formats in
//! the wild, in the order they must be tried:
//!
//! 1. **plain text** — one link per line;
//! 2. **base64** — the whole body is a base64 blob whose decode is (1); both the
//!    standard and the URL-safe alphabet are in use, with and without padding;
//! 3. **SIP008** — a JSON document (`{"version":1,"servers":[…]}`), whose entries
//!    are shadowsocks servers rather than links.
//!
//! # Design rules
//!
//! * **A fetch that fails never replaces a good cache.** A subscription server
//!   that returns an HTML error page, a captive-portal redirect, or a truncated
//!   body must not overwrite the last working node list — an operator's proxy
//!   would break at the next restart for a reason that has nothing to do with them.
//! * **Decoding is not guessing.** Each format is tried by its own parser and a
//!   body that matches none is reported with what was tried, not silently treated
//!   as an empty list.
//! * **Parsing is the existing parsers.** A node from a subscription goes through
//!   the same strict link parsing as an inline `[[node]]`, so a subscription cannot
//!   smuggle in a protocol shape that the inline path would reject.
//! * **Credentials never enter a log line or an error.** The URL carries a token;
//!   every error path reports the subscription's *tag*, never its URL.

use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use netune::{Client, ClientConfig, Pool, RequestHead, Target, TcpConnector, TlsRouterConnector};

/// Which wire format a subscription body was decoded from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Plain,
    Base64,
    Sip008,
}

impl Format {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Plain => "plain",
            Self::Base64 => "base64",
            Self::Sip008 => "sip008",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubscriptionError {
    /// The HTTP fetch failed.
    Fetch(String),
    /// The response was not a success status.
    Status(u16),
    /// The body was larger than the configured cap.
    TooLarge { limit: usize },
    /// None of the three formats matched.
    Undecodable { detail: String },
    /// The cache could not be read or written.
    Cache(String),
}

impl fmt::Display for SubscriptionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fetch(message) => write!(f, "fetch failed: {message}"),
            Self::Status(status) => write!(f, "server answered HTTP {status}"),
            Self::TooLarge { limit } => {
                write!(f, "response exceeded the {limit}-byte limit")
            }
            Self::Undecodable { detail } => write!(f, "unrecognised subscription body: {detail}"),
            Self::Cache(message) => write!(f, "cache: {message}"),
        }
    }
}

impl std::error::Error for SubscriptionError {}

/// The decoded contents of one subscription.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decoded {
    pub format: Format,
    /// Node links, in the order the server listed them.
    pub links: Vec<String>,
    /// Entries that were present but could not be understood. Reported, never
    /// silently dropped: a subscription that loses half its nodes must say so.
    pub rejected: Vec<String>,
}

impl Decoded {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.links.is_empty()
    }
}

/// The largest body we will read from a subscription endpoint.
///
/// A node link is ~100–400 bytes, so 8 MiB is ~20,000–80,000 nodes: far beyond any
/// real subscription and low enough that a hostile or misconfigured endpoint cannot
/// exhaust memory before the format check rejects it.
pub const MAX_BODY: usize = 8 * 1024 * 1024;

/// Fetches and decodes `url`.
///
/// # Errors
///
/// Every failure mode is reported; none is turned into an empty node list, because
/// "this subscription has no nodes" and "this subscription could not be read" lead
/// an operator to opposite conclusions.
pub async fn fetch(url: &str, timeout: Duration) -> Result<Decoded, SubscriptionError> {
    let body = fetch_body(url, timeout).await?;
    decode(&body)
}

/// Fetches the raw body.
pub async fn fetch_body(url: &str, timeout: Duration) -> Result<Vec<u8>, SubscriptionError> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| SubscriptionError::Fetch("no scheme in the subscription URL".to_owned()))?;

    // Split the authority from the path. The query belongs to the path: it is the
    // part that carries the token, and it must reach the server.
    let (authority, path) = match rest.find('/') {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, "/"),
    };
    if authority.is_empty() {
        return Err(SubscriptionError::Fetch(
            "no host in the subscription URL".to_owned(),
        ));
    }

    let connector = TcpConnector::new().with_connect_timeout(Some(timeout));
    let connector = TlsRouterConnector::new(connector);
    let mut config = ClientConfig {
        max_redirects: 5,
        ..ClientConfig::default()
    };
    config.user_agent = format!("daer/{}", env!("CARGO_PKG_VERSION"));
    let client = Client::new(connector, Pool::default(), config);

    let target = match scheme.to_ascii_lowercase().as_str() {
        "https" => {
            let (endpoint, host) = if let Some((host, _port)) = authority.rsplit_once(':') {
                (authority.to_owned(), host.to_owned())
            } else {
                (format!("{authority}:443"), authority.to_owned())
            };
            Target::tls(endpoint, host)
        }
        "http" => {
            let endpoint = if authority.contains(':') {
                authority.to_owned()
            } else {
                format!("{authority}:80")
            };
            Target::plain(endpoint)
        }
        other => {
            return Err(SubscriptionError::Fetch(format!(
                "unsupported subscription scheme {other:?}; expected http or https"
            )));
        }
    };

    let head = RequestHead::new(netune::Method::GET, path);
    let response = tokio::time::timeout(timeout, client.request(&target, head, None))
        .await
        .map_err(|_| SubscriptionError::Fetch("the fetch timed out".to_owned()))?
        .map_err(|error| SubscriptionError::Fetch(error.to_string()))?;

    if !response.head.status.is_success() {
        return Err(SubscriptionError::Status(response.head.status.as_u16()));
    }

    // Reject on the declared length before reading, when the server told us.
    if let netune::BodyKind::Length(length) = response.head.body
        && length > MAX_BODY as u64
    {
        return Err(SubscriptionError::TooLarge { limit: MAX_BODY });
    }

    let mut body = response.body;
    let bytes = tokio::time::timeout(timeout, body.read_to_end())
        .await
        .map_err(|_| SubscriptionError::Fetch("the body timed out".to_owned()))?
        .map_err(|error| SubscriptionError::Fetch(error.to_string()))?;

    if bytes.len() > MAX_BODY {
        return Err(SubscriptionError::TooLarge { limit: MAX_BODY });
    }
    Ok(bytes.to_vec())
}

/// Decodes a subscription body into node links.
///
/// # Errors
///
/// Returns [`SubscriptionError::Undecodable`] when no format matches, naming what
/// was tried.
pub fn decode(body: &[u8]) -> Result<Decoded, SubscriptionError> {
    // A BOM and a trailing newline are both common; neither is content.
    let text = std::str::from_utf8(body).map(|text| text.trim_start_matches('\u{feff}'));
    let text = text.unwrap_or_default();

    // SIP008 first: it is JSON, which no plain-text or base64 body starts with, and
    // its entries are server records rather than links — a format that only its own
    // parser can read.
    if let Some(decoded) = try_sip008(text) {
        return Ok(decoded);
    }
    if let Some(decoded) = try_links(text, Format::Plain) {
        return Ok(decoded);
    }
    if let Some(decoded) = try_base64(text) {
        return Ok(decoded);
    }

    Err(SubscriptionError::Undecodable {
        detail: format!(
            "{} bytes; tried SIP008 JSON, plain link lines and base64. \
             The body starts with {:?}",
            body.len(),
            preview(body)
        ),
    })
}

fn preview(body: &[u8]) -> String {
    let end = body.len().min(48);
    // Lossy on purpose: this is a diagnostic about a response that is already wrong.
    String::from_utf8_lossy(&body[..end])
        .chars()
        .map(|ch| if ch.is_control() { '.' } else { ch })
        .collect()
}

/// Parses a body as one link per line.
fn try_links(text: &str, format: Format) -> Option<Decoded> {
    let mut links = Vec::new();
    let mut rejected = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
            continue;
        }
        if looks_like_link(line) {
            links.push(line.to_owned());
        } else {
            rejected.push(line.to_owned());
        }
    }
    if links.is_empty() {
        return None;
    }
    Some(Decoded {
        format,
        links,
        rejected,
    })
}

/// True when `line` is shaped like `scheme://…`.
///
/// The scheme is not checked against a known list: an unknown scheme must reach the
/// node parser, which reports it by name, rather than be discarded here as garbage.
fn looks_like_link(line: &str) -> bool {
    let Some((scheme, rest)) = line.split_once("://") else {
        return false;
    };
    !scheme.is_empty()
        && !rest.is_empty()
        && scheme
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '-' | '.'))
}

/// Parses a base64 body into links.
fn try_base64(text: &str) -> Option<Decoded> {
    // A base64 blob has no whitespace except line wrapping, so anything with a
    // scheme separator on the first line was already handled by `try_links`.
    let compact: String = text.chars().filter(|ch| !ch.is_whitespace()).collect();
    if compact.is_empty() {
        return None;
    }
    let decoded = decode_base64(&compact)?;
    let decoded = String::from_utf8(decoded).ok()?;
    try_links(decoded.trim(), Format::Base64)
}

/// Decodes base64 with either alphabet, with or without padding.
///
/// Both alphabets are in use: standard base64 (`+/`) appears in older panels, and
/// URL-safe (`-_`) in newer ones. Padding is frequently stripped, so it is restored
/// rather than required.
pub fn decode_base64(input: &str) -> Option<Vec<u8>> {
    const STANDARD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const URL_SAFE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    let mut output = Vec::with_capacity(input.len() / 4 * 3 + 3);
    let mut accum: u32 = 0;
    let mut bits = 0u32;

    for byte in input.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' => continue,
            _ => return None,
        };
        accum = (accum << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push((accum >> bits) as u8);
            accum &= (1 << bits) - 1;
        }
    }
    // A trailing single character cannot encode a byte; anything else is fine.
    if bits >= 6 {
        return None;
    }
    let _ = (STANDARD, URL_SAFE);
    Some(output)
}

/// Parses a SIP008 document.
fn try_sip008(text: &str) -> Option<Decoded> {
    let trimmed = text.trim_start();
    if !trimmed.starts_with('{') {
        return None;
    }
    let value: serde_json::Value = serde_json::from_str(trimmed).ok()?;
    let servers = value.get("servers")?.as_array()?;

    let mut links = Vec::new();
    let mut rejected = Vec::new();
    for server in servers {
        match sip008_link(server) {
            Ok(link) => links.push(link),
            Err(reason) => rejected.push(reason),
        }
    }
    if links.is_empty() {
        return None;
    }
    Some(Decoded {
        format: Format::Sip008,
        links,
        rejected,
    })
}

/// Renders one SIP008 server as an `ss://` link.
fn sip008_link(server: &serde_json::Value) -> Result<String, String> {
    let text = |key: &str| server.get(key).and_then(serde_json::Value::as_str);
    let id = text("id").unwrap_or("<no id>");
    let host = text("server").ok_or_else(|| format!("{id}: no server"))?;
    let port = server
        .get("server_port")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| format!("{id}: no server_port"))?;
    let method = text("method").ok_or_else(|| format!("{id}: no method"))?;
    let password = text("password").ok_or_else(|| format!("{id}: no password"))?;

    // `ss://` carries the cipher and password in URL-safe base64 of
    // `method:password`, which is what every shadowsocks client expects.
    let credentials = encode_base64_url(format!("{method}:{password}").as_bytes());
    let tag = text("remarks").unwrap_or(id);
    Ok(format!(
        "ss://{credentials}@{host}:{port}#{}",
        encode_percent(tag)
    ))
}

fn encode_base64_url(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let mut block = [0u8; 3];
        block[..chunk.len()].copy_from_slice(chunk);
        let value = (u32::from(block[0]) << 16) | (u32::from(block[1]) << 8) | u32::from(block[2]);
        for index in 0..4 {
            if index <= chunk.len() {
                let shift = 18 - index * 6;
                out.push(ALPHABET[((value >> shift) & 0x3f) as usize] as char);
            }
        }
    }
    out
}

/// Percent-encodes a link fragment.
fn encode_percent(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// The on-disk cache for one subscription.
///
/// The cache is keyed by the subscription's tag, not by its URL: the URL carries a
/// token, and a file named after it would leak that token into directory listings
/// and backups.
#[derive(Debug, Clone)]
pub struct Cache {
    directory: PathBuf,
    tag: String,
}

impl Cache {
    /// A cache for `tag` under `directory`.
    ///
    /// The tag is sanitized so it cannot escape the directory: a tag is operator
    /// input, and `../` in it would otherwise write outside the cache root.
    #[must_use]
    pub fn new(directory: impl Into<PathBuf>, tag: &str) -> Self {
        Self {
            directory: directory.into(),
            tag: sanitize_tag(tag),
        }
    }

    fn path(&self) -> PathBuf {
        self.directory.join(format!("{}.sub", self.tag))
    }

    /// Reads the cached node links, if any.
    ///
    /// # Errors
    ///
    /// A cache that exists but cannot be read is an error, not a miss: silently
    /// falling back to "no nodes" would hide a permissions problem behind an empty
    /// group.
    pub fn read(&self) -> Result<Option<Vec<String>>, SubscriptionError> {
        let path = self.path();
        match std::fs::read_to_string(&path) {
            Ok(text) => {
                let links: Vec<String> = text
                    .lines()
                    .map(str::trim)
                    .filter(|line| !line.is_empty() && !line.starts_with('#'))
                    .map(str::to_owned)
                    .collect();
                Ok(Some(links))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(SubscriptionError::Cache(format!(
                "cannot read {}: {error}",
                path.display()
            ))),
        }
    }

    /// Writes `links`, replacing the previous contents atomically.
    ///
    /// # Errors
    ///
    /// Reported rather than swallowed: a cache that silently fails to write is
    /// discovered at the next restart, when the nodes are already gone.
    pub fn write(&self, links: &[String]) -> Result<(), SubscriptionError> {
        std::fs::create_dir_all(&self.directory).map_err(|error| {
            SubscriptionError::Cache(format!(
                "cannot create {}: {error}",
                self.directory.display()
            ))
        })?;
        let path = self.path();
        // A temp file in the same directory, then a rename: a crash mid-write must
        // not leave a truncated cache that the next start believes.
        let temporary = path.with_extension("sub.tmp");
        let mut text = String::new();
        for link in links {
            text.push_str(link);
            text.push('\n');
        }
        std::fs::write(&temporary, text).map_err(|error| {
            SubscriptionError::Cache(format!("cannot write {}: {error}", temporary.display()))
        })?;
        std::fs::rename(&temporary, &path).map_err(|error| {
            SubscriptionError::Cache(format!("cannot rename into {}: {error}", path.display()))
        })?;
        Ok(())
    }
}

/// Keeps a tag usable as a file name.
fn sanitize_tag(tag: &str) -> String {
    // Dots are allowed inside a name but never as a whole component, so a run of
    // them is collapsed to one underscore. That makes `..`, `../..` and a leading
    // dot all inert without making ordinary tags (`my.sub`) unrecognizable.
    let mut cleaned = String::with_capacity(tag.len());
    let mut run = 0usize;
    for ch in tag.chars() {
        if ch == '.' {
            run += 1;
            continue;
        }
        if run > 0 {
            cleaned.push('.');
            run = 0;
        }
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_') {
            cleaned.push(ch);
        } else {
            cleaned.push('_');
        }
    }
    let cleaned = cleaned.trim_matches('.').to_owned();
    if cleaned.is_empty() {
        "subscription".to_owned()
    } else {
        cleaned
    }
}

/// Resolves every declared subscription into node links.
///
/// `persist` subscriptions fall back to their cache when the fetch fails; the fetch
/// result is written to the cache **only when it produced at least one node**, so a
/// failing endpoint cannot destroy the last good copy.
pub async fn resolve(
    subscriptions: &[daer_config::Subscription],
    cache_directory: Option<&Path>,
    timeout: Duration,
) -> Vec<ResolvedSubscription> {
    let mut resolved = Vec::with_capacity(subscriptions.len());
    for subscription in subscriptions {
        let tag = subscription
            .tag
            .clone()
            .unwrap_or_else(|| "subscription".to_owned());
        let cache = cache_directory
            .filter(|_| subscription.persist)
            .map(|directory| Cache::new(directory, &tag));

        let outcome = fetch(&subscription.url, timeout).await;
        let entry = match outcome {
            Ok(decoded) => {
                // Persist only a result that is worth restoring.
                if let Some(cache) = &cache
                    && !decoded.links.is_empty()
                {
                    let _ = cache.write(&decoded.links);
                }
                ResolvedSubscription {
                    tag,
                    format: Some(decoded.format),
                    links: decoded.links,
                    rejected: decoded.rejected,
                    error: None,
                    from_cache: false,
                }
            }
            Err(error) => {
                // The fetch failed. A cache is exactly what it is for.
                // A cache that cannot be read is treated as a miss here: the fetch
                // error is the actionable one, and it is reported either way.
                let cached: Option<Vec<String>> = match cache.as_ref() {
                    Some(cache) => match cache.read() {
                        Ok(Some(links)) if !links.is_empty() => Some(links),
                        _ => None,
                    },
                    None => None,
                };
                match cached {
                    Some(links) => ResolvedSubscription {
                        tag,
                        format: None,
                        links,
                        rejected: Vec::new(),
                        error: Some(error),
                        from_cache: true,
                    },
                    None => ResolvedSubscription {
                        tag,
                        format: None,
                        links: Vec::new(),
                        rejected: Vec::new(),
                        error: Some(error),
                        from_cache: false,
                    },
                }
            }
        };
        resolved.push(entry);
    }
    resolved
}

/// What happened to one subscription.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedSubscription {
    pub tag: String,
    pub format: Option<Format>,
    pub links: Vec<String>,
    pub rejected: Vec<String>,
    /// Set when the fetch failed, even if a cache rescued the node list.
    pub error: Option<SubscriptionError>,
    /// True when the links came from the cache rather than this fetch.
    pub from_cache: bool,
}

impl ResolvedSubscription {
    #[must_use]
    pub fn is_usable(&self) -> bool {
        !self.links.is_empty()
    }
}

impl fmt::Display for ResolvedSubscription {
    /// One line, safe to log: the tag and the outcome, never the URL or a node.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {} node(s)", self.tag, self.links.len())?;
        if let Some(format) = self.format {
            write!(f, " [{}]", format.as_str())?;
        }
        if self.from_cache {
            write!(f, " (from cache)")?;
        }
        if !self.rejected.is_empty() {
            write!(f, ", {} rejected", self.rejected.len())?;
        }
        match &self.error {
            Some(error) => write!(f, " — {error}"),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_plain_lines() {
        let body = "ss://a@1.2.3.4:8388#one\n\ntrojan://p@b.example.com:443#two\n";
        let decoded = decode(body.as_bytes()).expect("decodes");
        assert_eq!(decoded.format, Format::Plain);
        assert_eq!(decoded.links.len(), 2);
        assert!(decoded.rejected.is_empty());
    }

    #[test]
    fn decodes_base64_with_either_alphabet() {
        let plain = "ss://a@1.2.3.4:8388#one\ntrojan://p@b.example.com:443#two";
        for encoded in [
            base64_standard(plain.as_bytes()),
            encode_base64_url(plain.as_bytes()),
        ] {
            let decoded = decode(encoded.as_bytes()).expect("decodes");
            assert_eq!(decoded.format, Format::Base64, "{encoded}");
            assert_eq!(decoded.links.len(), 2);
        }
    }

    #[test]
    fn decodes_base64_with_line_wrapping() {
        let plain = "ss://a@1.2.3.4:8388#one\ntrojan://p@b.example.com:443#two";
        let encoded = base64_standard(plain.as_bytes());
        let wrapped: String = encoded
            .as_bytes()
            .chunks(32)
            .map(|chunk| format!("{}\n", std::str::from_utf8(chunk).expect("ascii")))
            .collect();
        let decoded = decode(wrapped.as_bytes()).expect("decodes");
        assert_eq!(decoded.links.len(), 2);
    }

    #[test]
    fn decodes_sip008() {
        let body = r#"{
            "version": 1,
            "servers": [
                {"id":"a","remarks":"Tokyo","server":"1.2.3.4","server_port":8388,
                 "method":"aes-256-gcm","password":"hunter2"}
            ]
        }"#;
        let decoded = decode(body.as_bytes()).expect("decodes");
        assert_eq!(decoded.format, Format::Sip008);
        assert_eq!(decoded.links.len(), 1);
        // The rendered link must be a shadowsocks link the strict parser accepts.
        let link = &decoded.links[0];
        assert!(link.starts_with("ss://"), "{link}");
        let parsed = crate::shadowsocks::Link::parse(link).expect("the rendered link parses");
        assert_eq!(parsed.cipher.to_string(), "aes-256-gcm");
        assert_eq!(parsed.server, "1.2.3.4:8388");
    }

    #[test]
    fn a_sip008_entry_that_cannot_be_rendered_is_reported_not_dropped() {
        let body = r#"{"version":1,"servers":[
            {"id":"good","server":"1.2.3.4","server_port":8388,"method":"aes-256-gcm","password":"p"},
            {"id":"broken","server_port":1}
        ]}"#;
        let decoded = decode(body.as_bytes()).expect("decodes");
        assert_eq!(decoded.links.len(), 1);
        assert_eq!(decoded.rejected.len(), 1);
        assert!(
            decoded.rejected[0].contains("broken"),
            "{:?}",
            decoded.rejected
        );
    }

    #[test]
    fn comments_and_blank_lines_are_not_nodes() {
        let body = "# my subscription\n\nss://a@1.2.3.4:8388#one\n// note\n";
        let decoded = decode(body.as_bytes()).expect("decodes");
        assert_eq!(decoded.links.len(), 1);
        assert!(decoded.rejected.is_empty());
    }

    #[test]
    fn a_body_that_is_not_a_subscription_says_what_was_tried() {
        let error = decode(b"<html><body>captive portal</body></html>").expect_err("must fail");
        let message = error.to_string();
        assert!(message.contains("SIP008"), "{message}");
        assert!(message.contains("base64"), "{message}");
        assert!(
            message.contains("html"),
            "the preview must identify the body: {message}"
        );
    }

    #[test]
    fn an_empty_body_is_not_an_empty_subscription() {
        // "no nodes" and "unreadable" lead an operator to opposite conclusions.
        assert!(decode(b"").is_err());
        assert!(decode(b"   \n\n  ").is_err());
    }

    #[test]
    fn an_unknown_scheme_reaches_parsing_rather_than_being_discarded() {
        // The node parser must be the one to reject it, by name.
        let decoded = decode(b"vmess://eyJhZGQiOiJ4In0\n").expect("decodes");
        assert_eq!(decoded.links, ["vmess://eyJhZGQiOiJ4In0"]);
    }

    #[test]
    fn base64_decoding_handles_both_alphabets_and_missing_padding() {
        let cases = [
            ("aGVsbG8", b"hello".as_slice()),
            ("aGVsbG8=", b"hello".as_slice()),
            ("-_8", &[0xfb, 0xff][..]),
            ("+/8", &[0xfb, 0xff][..]),
        ];
        for (encoded, expected) in cases {
            assert_eq!(
                decode_base64(encoded).as_deref(),
                Some(expected),
                "{encoded}"
            );
        }
    }

    #[test]
    fn a_cache_round_trips_and_misses_cleanly() {
        let directory = std::env::temp_dir().join(format!("daer-sub-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        let cache = Cache::new(&directory, "my_sub");

        assert_eq!(cache.read().expect("read"), None, "a miss is not an error");
        let links = vec!["ss://a@1.2.3.4:8388#one".to_owned()];
        cache.write(&links).expect("writes");
        assert_eq!(cache.read().expect("read"), Some(links));
        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn a_tag_cannot_escape_the_cache_directory() {
        let cache = Cache::new("/tmp/daer-cache", "../../etc/passwd");
        let path = cache.path().to_string_lossy().to_string();
        assert!(!path.contains(".."), "{path}");
        assert!(path.starts_with("/tmp/daer-cache/"), "{path}");
        assert_eq!(
            path, "/tmp/daer-cache/_._etc_passwd.sub",
            "dots are kept inside a name but never as a component"
        );
    }

    #[test]
    fn the_token_in_a_url_never_reaches_a_display() {
        let entry = ResolvedSubscription {
            tag: "sub".to_owned(),
            format: Some(Format::Base64),
            links: vec!["ss://a@1.2.3.4:8388".to_owned()],
            rejected: Vec::new(),
            error: Some(SubscriptionError::Fetch("connection refused".to_owned())),
            from_cache: false,
        };
        let rendered = entry.to_string();
        assert!(rendered.contains("sub"), "{rendered}");
        assert!(!rendered.contains("http"), "{rendered}");
    }

    fn base64_standard(input: &[u8]) -> String {
        const PAD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in input.chunks(3) {
            let mut block = [0u8; 3];
            block[..chunk.len()].copy_from_slice(chunk);
            let value =
                (u32::from(block[0]) << 16) | (u32::from(block[1]) << 8) | u32::from(block[2]);
            for index in 0..4 {
                if index <= chunk.len() {
                    let shift = 18 - index * 6;
                    out.push(PAD[((value >> shift) & 0x3f) as usize] as char);
                } else {
                    out.push('=');
                }
            }
        }
        out
    }
}
