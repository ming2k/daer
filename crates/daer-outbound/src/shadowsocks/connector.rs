// SPDX-License-Identifier: AGPL-3.0-only

//! The shadowsocks `Connector`: link parsing, the handshake, and the framed stream.
//!
//! # The link
//!
//! ```text
//!   ss://BASE64URL(method:password)@host:port#tag
//!   ss://BASE64URL(method:password@host:port)#tag        (SIP002, legacy form)
//! ```
//!
//! Both are accepted because both are in the wild. The first is what SIP002 specifies, the
//! second is what many panels emit; refusing either would make the proxy unusable with
//! existing subscriptions for a reason that is not the operator's fault.
//!
//! # The handshake
//!
//! A shadowsocks *client* opens a TCP connection to the server and immediately sends its
//! salt followed by an encrypted frame whose plaintext is the target address:
//!
//! ```text
//!   [salt][len][tag][ATYP | addr | port][tag][first payload bytes …]
//! ```
//!
//! There is no reply before that: the protocol has no greeting and no negotiation. The
//! server's own salt arrives with its first frame, which is why [`ShadowSocksStream`] takes
//! the receive salt up front — the caller reads it from the wire before any plaintext can
//! come back, and this module does that read for it.
//!
//! # Why the address is sent inside the first frame
//!
//! Sending it as a separate frame would work but costs a record: two tags for fourteen bytes.
//! Coalescing it with the first payload write is both smaller and what every implementation
//! does, so a stream this module writes is byte-identical to one they write for the same
//! input — which is what makes differential testing possible at all.

use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use netune::{
    Connector, DatagramConnector, DatagramTransport, Established, EstablishedDatagrams, NetError,
    SocketConfig, Target, TcpConnector, Transport,
};
use netune_trace::Recorder;
use tokio::io::AsyncWriteExt;

use super::crypto::{Cipher, CipherError, SaltReplayFilter, Sealer, master_key};
use super::stream::{ShadowSocksError, ShadowSocksStream, write_salt};
use crate::error::OutboundError;
use crate::node_dialer::DialerOptions;
use crate::property::Protocol;

/// The address types shadowsocks encodes in its handshake.
mod atyp {
    pub const IPV4: u8 = 1;
    pub const DOMAIN: u8 = 3;
    pub const IPV6: u8 = 4;
}

/// A parsed `ss://` link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    pub cipher: Cipher,
    /// Kept for the master key derivation; never logged.
    password: String,
    pub server: String,
    pub tag: Option<String>,
}

impl Link {
    /// Parses an `ss://` link.
    ///
    /// # Errors
    ///
    /// Returns a message naming the part that is wrong: the base64 payload, the
    /// `method:password` split, the cipher, or the server address.
    pub fn parse(link: &str) -> Result<Self, String> {
        let body = link
            .strip_prefix("ss://")
            .ok_or_else(|| format!("{link:?} does not start with ss://"))?;

        // A fragment is the tag; SIP002 says it is not percent-decoded, and every client
        // treats it as opaque, so it is kept verbatim.
        let (body, tag) = match body.split_once('#') {
            Some((body, tag)) => (body, Some(tag.to_owned())),
            None => (body, None),
        };

        // SIP002: userinfo before `@`, server after. That split is unambiguous and must be
        // tried first, because the base64 alphabet can itself contain `/`.
        let (credentials, server) = match body.rsplit_once('@') {
            Some((userinfo, server)) => (decode_base64(userinfo)?, server.to_owned()),
            None => {
                // Legacy form: everything is base64 and holds the server too.
                let decoded = decode_base64(body)?;
                let (credentials, server) = decoded.rsplit_once('@').ok_or_else(|| {
                    format!("ss:// link {link:?} has no `@` separating credentials from server")
                })?;
                (credentials.to_owned(), server.to_owned())
            }
        };

        let (method, password) = credentials.split_once(':').ok_or_else(|| {
            format!("ss:// credentials {credentials:?} are not `method:password`")
        })?;
        let cipher = Cipher::parse(method).map_err(|error| error.to_string())?;
        if password.is_empty() {
            return Err("ss:// link has an empty password".to_owned());
        }
        if server.is_empty() || !server.contains(':') {
            return Err(format!("ss:// link server {server:?} is not `host:port`"));
        }

        Ok(Self {
            cipher,
            password: password.to_owned(),
            server,
            tag,
        })
    }

    /// The cipher this link uses.
    #[must_use]
    pub const fn cipher(&self) -> Cipher {
        self.cipher
    }

    /// The derived master key.
    ///
    /// A method rather than a public field so the password does not sit in a `Debug` output:
    /// a proxy log that prints its configuration must not print credentials.
    #[must_use]
    pub fn master_key(&self) -> Vec<u8> {
        master_key(self.cipher, &self.password)
    }
}

impl fmt::Display for Link {
    /// Renders the link without its credentials, which is what belongs in a log.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ss://{}@{}", self.cipher, self.server)?;
        if let Some(tag) = &self.tag {
            write!(f, "#{tag}")?;
        }
        Ok(())
    }
}

/// Decodes standard or URL-safe base64, with or without padding.
///
/// A hand-written decoder rather than a dependency: the alphabet is twelve lines, and it is
/// the only base64 this project needs.
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

    let text: Vec<u8> = text.bytes().filter(|byte| *byte != b'=').collect();
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    for chunk in text.chunks(4) {
        if chunk.len() == 1 {
            return Err("base64: a single trailing character is not a valid group".to_owned());
        }
        let mut accumulator = 0u32;
        for (index, byte) in chunk.iter().enumerate() {
            let value = value(*byte)
                .ok_or_else(|| format!("base64: {:?} is not in the alphabet", *byte as char))?;
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

/// The shadowsocks client connector.
#[derive(Debug, Clone)]
pub struct ShadowSocksConnector {
    cipher: Cipher,
    master: Vec<u8>,
    server: String,
    connector: TcpConnector,
    timeout: Duration,
    so_mark: Option<u32>,
}

impl ShadowSocksConnector {
    /// Builds a connector directly from typed parameters.
    pub fn new(
        server: &str,
        port: u16,
        method: &str,
        password: &str,
        options: DialerOptions,
    ) -> Result<Self, OutboundError> {
        let cipher =
            Cipher::parse(method).map_err(|e| OutboundError::UnsupportedLink(e.to_string()))?;
        let master = master_key(cipher, password);
        let server = format!("{server}:{port}");
        Ok(Self {
            cipher,
            master,
            server,
            connector: TcpConnector::new()
                .with_socket_config(match options.so_mark {
                    Some(mark) => SocketConfig::default().with_mark(mark),
                    None => SocketConfig::default(),
                })
                .with_connect_timeout(Some(options.timeout)),
            timeout: options.timeout,
            so_mark: options.so_mark,
        })
    }

    /// Builds a connector from a link.
    ///
    /// # Errors
    ///
    /// Returns [`OutboundError::UnsupportedLink`] for a link this module cannot use, with the
    /// message the parser produced.
    pub fn from_link(link: &str, options: DialerOptions) -> Result<Self, OutboundError> {
        let parsed = Link::parse(link).map_err(OutboundError::UnsupportedLink)?;
        Ok(Self {
            cipher: parsed.cipher,
            master: parsed.master_key(),
            server: parsed.server,
            connector: TcpConnector::new()
                .with_socket_config(match options.so_mark {
                    Some(mark) => SocketConfig::default().with_mark(mark),
                    None => SocketConfig::default(),
                })
                .with_connect_timeout(Some(options.timeout)),
            timeout: options.timeout,
            so_mark: options.so_mark,
        })
    }

    /// The shadowsocks server this connector dials.
    #[must_use]
    pub fn server(&self) -> &str {
        &self.server
    }
}

/// Encodes a target address the way shadowsocks expects it.
///
/// # Errors
///
/// Returns a message for an empty host or a port of zero.
pub fn encode_address(host: &str, port: u16) -> Result<Vec<u8>, String> {
    if host.is_empty() {
        return Err("empty host".to_owned());
    }
    if port == 0 {
        return Err("port 0 is not a destination".to_owned());
    }
    let mut out = Vec::with_capacity(1 + 1 + host.len() + 2);
    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(address)) => {
            out.push(atyp::IPV4);
            out.extend_from_slice(&address.octets());
        }
        Ok(std::net::IpAddr::V6(address)) => {
            out.push(atyp::IPV6);
            out.extend_from_slice(&address.octets());
        }
        Err(_) => {
            if host.len() > 255 {
                return Err(format!("host {host:?} is longer than 255 bytes"));
            }
            out.push(atyp::DOMAIN);
            out.push(host.len() as u8);
            out.extend_from_slice(host.as_bytes());
        }
    }
    out.extend_from_slice(&port.to_be_bytes());
    Ok(out)
}

/// Splits `host:port`, honouring `[v6]:port`.
///
/// # Errors
///
/// Returns a message for a missing port or an unparseable one.
pub fn split_authority(authority: &str) -> Result<(&str, u16), String> {
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .ok_or_else(|| format!("{authority:?} has an unclosed `[`"))?;
        let port = tail
            .strip_prefix(':')
            .ok_or_else(|| format!("{authority:?} has no port"))?;
        let port = port
            .parse()
            .map_err(|_| format!("{authority:?} has an invalid port"))?;
        return Ok((host, port));
    }
    let (host, port) = authority
        .rsplit_once(':')
        .ok_or_else(|| format!("{authority:?} has no port"))?;
    let port = port
        .parse()
        .map_err(|_| format!("{authority:?} has an invalid port"))?;
    Ok((host, port))
}

impl ShadowSocksConnector {
    /// Connects to `authority` (`host:port`) through the shadowsocks server.
    ///
    /// An inherent method rather than only a [`Connector`] impl: this is the call the data
    /// path makes, and it is testable without naming netune's trait.
    ///
    /// # Errors
    ///
    /// Returns [`OutboundError`] for a bad target, a failed dial, a handshake write failure,
    /// or a server that does not send its salt.
    pub async fn connect(
        &self,
        authority: &str,
        recorder: &Arc<Mutex<netune_trace::Recorder>>,
    ) -> Result<Established, OutboundError> {
        let (host, port) = split_authority(authority).map_err(OutboundError::UnsupportedLink)?;
        let address = encode_address(host, port).map_err(OutboundError::UnsupportedLink)?;

        // The connection to the *server*, resolved like any other dial.
        let server = Target::plain(&self.server);
        let established =
            tokio::time::timeout(self.timeout, self.connector.connect(&server, recorder))
                .await
                .map_err(|_| OutboundError::Timeout)?
                .map_err(|error| OutboundError::Connect(error.to_string()))?;

        let mut salt = vec![0u8; self.cipher.salt_len()];
        fill_random(&mut salt);
        let mut sealer = Sealer::new(self.cipher, &self.master, &salt);
        let request = sealer
            .seal_chunk(&address)
            .map_err(|error| OutboundError::Connect(ShadowSocksError::Crypto(error).to_string()))?;

        let mut stream = established.stream;
        write_salt(&mut stream, &salt)
            .await
            .map_err(|error| OutboundError::Connect(error.to_string()))?;
        stream
            .write_all(&request)
            .await
            .map_err(|error| OutboundError::Connect(error.to_string()))?;

        // The server's salt is what its first frame is encrypted under; read it now so the
        // returned stream can be used immediately.
        let mut peer_salt = vec![0u8; self.cipher.salt_len()];
        read_exact(&mut stream, &mut peer_salt)
            .await
            .map_err(|error| OutboundError::Connect(error.to_string()))?;

        // Continue from the handshake's sealer: a fresh one would restart the nonce at zero
        // and the server would reject every record after the address frame.
        let framed: ShadowSocksStream<Box<dyn Transport>> =
            ShadowSocksStream::with_sealer(stream, self.cipher, sealer, &peer_salt);
        Ok(Established {
            stream: Box::new(framed),
            local_port: established.local_port,
            socket: established.socket,
            alpn: None,
        })
    }

    /// Returns a [`DatagramConnector`] that carries UDP over this Shadowsocks node.
    #[must_use]
    pub fn datagram_connector(&self) -> Arc<dyn DatagramConnector> {
        Arc::new(ShadowSocksDatagramConnector::new(self.clone()))
    }

    /// Opens a Shadowsocks datagram session to `authority` (`host:port`).
    pub async fn connect_datagram(
        &self,
        authority: &str,
        _recorder: &Arc<Mutex<Recorder>>,
    ) -> Result<EstablishedDatagrams, NetError> {
        let (host, port) = split_authority(authority).map_err(NetError::Protocol)?;
        let addr_bytes = encode_address(host, port).map_err(NetError::Protocol)?;

        let server_addr = tokio::net::lookup_host(&self.server)
            .await
            .map_err(|e| NetError::Resolve(e.to_string()))?
            .next()
            .ok_or_else(|| NetError::Resolve(format!("cannot resolve {}", self.server)))?;

        let bind_addr = if server_addr.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let socket = tokio::net::UdpSocket::bind(bind_addr)
            .await
            .map_err(|e| NetError::Connect(e.to_string()))?;

        if let Some(mark) = self.so_mark {
            #[cfg(unix)]
            // SAFETY: socket is an open UDP socket owned by us; libc::SO_MARK is a valid sockopt on Linux.
            unsafe {
                use std::os::fd::AsRawFd;
                let val = mark as libc::c_int;
                let _ = libc::setsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_MARK,
                    &val as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
            }
        }

        socket
            .connect(server_addr)
            .await
            .map_err(|e| NetError::Connect(e.to_string()))?;

        let local_port = socket.local_addr().ok().map(|a| a.port());
        let session = ShadowSocksDatagramSession {
            socket: Arc::new(socket),
            cipher: self.cipher,
            master: self.master.clone(),
            target_addr: addr_bytes,
        };

        Ok(EstablishedDatagrams {
            datagrams: Box::new(session),
            local_port,
        })
    }
}

/// A datagram session over Shadowsocks AEAD.
pub struct ShadowSocksDatagramSession {
    socket: Arc<tokio::net::UdpSocket>,
    cipher: Cipher,
    master: Vec<u8>,
    target_addr: Vec<u8>,
}

impl fmt::Debug for ShadowSocksDatagramSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShadowSocksDatagramSession")
            .field("cipher", &self.cipher)
            .finish_non_exhaustive()
    }
}

impl DatagramTransport for ShadowSocksDatagramSession {
    fn send<'a>(
        &'a self,
        payload: &'a [u8],
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<usize, std::io::Error>> + Send + 'a>,
    > {
        Box::pin(async move {
            let mut salt = vec![0u8; self.cipher.salt_len()];
            fill_random(&mut salt);
            let mut sealer = Sealer::new(self.cipher, &self.master, &salt);
            let mut packet =
                Vec::with_capacity(self.target_addr.len() + payload.len() + self.cipher.tag_len());
            packet.extend_from_slice(&self.target_addr);
            packet.extend_from_slice(payload);
            sealer.seal_record(&mut packet).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "crypto error")
            })?;

            let mut wire = Vec::with_capacity(salt.len() + packet.len());
            wire.extend_from_slice(&salt);
            wire.extend_from_slice(&packet);
            self.socket.send(&wire).await?;
            Ok(payload.len())
        })
    }

    fn recv<'a>(
        &'a self,
        buffer: &'a mut [u8],
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<usize, std::io::Error>> + Send + 'a>,
    > {
        Box::pin(async move {
            let salt_len = self.cipher.salt_len();
            let tag_len = self.cipher.tag_len();
            let mut raw = vec![0u8; 65535];
            let read = self.socket.recv(&mut raw).await?;
            if read < salt_len + tag_len {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "datagram too short",
                ));
            }
            let salt = &raw[..salt_len];
            let mut ciphertext = raw[salt_len..read].to_vec();
            let mut opener = super::crypto::Opener::new(self.cipher, &self.master, salt);
            opener
                .open_record(&mut ciphertext)
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "auth failed"))?;

            let mut cursor = 0;
            if ciphertext.is_empty() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "empty payload",
                ));
            }
            let atyp = ciphertext[cursor];
            cursor += 1;
            match atyp {
                atyp::IPV4 => cursor += 4 + 2,
                atyp::IPV6 => cursor += 16 + 2,
                atyp::DOMAIN => {
                    let dlen = ciphertext.get(cursor).copied().ok_or_else(|| {
                        std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "bad domain len")
                    })? as usize;
                    cursor += 1 + dlen + 2;
                }
                _ => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "bad atyp in shadowsocks udp reply",
                    ));
                }
            }
            if cursor > ciphertext.len() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "header exceeds payload",
                ));
            }
            let payload = &ciphertext[cursor..];
            let to_copy = payload.len().min(buffer.len());
            buffer[..to_copy].copy_from_slice(&payload[..to_copy]);
            Ok(to_copy)
        })
    }

    fn max_datagram_size(&self) -> usize {
        65507
    }
}

/// A connector establishing datagram sessions over Shadowsocks AEAD.
#[derive(Clone)]
pub struct ShadowSocksDatagramConnector {
    connector: ShadowSocksConnector,
}

impl ShadowSocksDatagramConnector {
    #[must_use]
    pub const fn new(connector: ShadowSocksConnector) -> Self {
        Self { connector }
    }
}

impl fmt::Debug for ShadowSocksDatagramConnector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShadowSocksDatagramConnector")
            .field("server", &self.connector.server())
            .finish()
    }
}

impl DatagramConnector for ShadowSocksDatagramConnector {
    fn connect<'a>(
        &'a self,
        authority: &'a str,
        recorder: &'a Arc<Mutex<Recorder>>,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<EstablishedDatagrams, NetError>> + Send + 'a>,
    > {
        let connector = self.connector.clone();
        let authority = authority.to_owned();
        let recorder = Arc::clone(recorder);
        Box::pin(async move { connector.connect_datagram(&authority, &recorder).await })
    }
}

/// Fills `buffer` from the OS random source.
fn fill_random(buffer: &mut [u8]) {
    // `getrandom` is not a dependency; `/dev/urandom` is the portable-in-Linux answer here and
    // a failure is not recoverable, so it is loud rather than silent.
    use std::io::Read as _;
    match std::fs::File::open("/dev/urandom") {
        Ok(mut file) => {
            if file.read_exact(buffer).is_err() {
                panic!("cannot read entropy from /dev/urandom");
            }
        }
        Err(error) => panic!("cannot open /dev/urandom: {error}"),
    }
}

/// Reads exactly `buffer.len()` bytes.
async fn read_exact(stream: &mut Box<dyn Transport>, buffer: &mut [u8]) -> std::io::Result<()> {
    use tokio::io::AsyncReadExt as _;
    stream.read_exact(buffer).await.map(|_| ())
}

/// The replay filter a connector shares with its streams.
///
/// Returned separately rather than owned by the connector so a caller can decide the window:
/// a proxy handling many nodes wants one filter with a larger capacity, while a test wants
/// none.
#[must_use]
pub fn replay_filter() -> SaltReplayFilter {
    // 4096 salts of up to 32 bytes is ~128 KiB, which is small enough to not matter and large
    // enough that a replay within one process lifetime is caught.
    SaltReplayFilter::new(4096)
}

/// True when a link is a shadowsocks link.
#[must_use]
pub fn is_shadowsocks(link: &str) -> bool {
    link.trim_start().starts_with("ss://")
}

/// The protocol a parsed link reports.
#[must_use]
pub const fn protocol() -> Protocol {
    Protocol::ShadowSocks
}

/// Kept so the cipher error type is part of this module's surface: a caller matching on a
/// link failure wants to distinguish an unsupported cipher from a typo.
pub type LinkError = CipherError;

/// Re-exported for callers that build a stream by hand.
pub use super::crypto::Opener as LinkOpener;

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_base64(text: &str) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let bytes = text.as_bytes();
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let mut buffer = [0u8; 3];
            buffer[..chunk.len()].copy_from_slice(chunk);
            let value =
                (u32::from(buffer[0]) << 16) | (u32::from(buffer[1]) << 8) | u32::from(buffer[2]);
            out.push(ALPHABET[(value >> 18) as usize & 0x3f] as char);
            out.push(ALPHABET[(value >> 12) as usize & 0x3f] as char);
            if chunk.len() > 1 {
                out.push(ALPHABET[(value >> 6) as usize & 0x3f] as char);
            }
            if chunk.len() > 2 {
                out.push(ALPHABET[value as usize & 0x3f] as char);
            }
        }
        out
    }

    #[test]
    fn base64_round_trips_including_url_safe_and_unpadded_forms() {
        for text in ["a:b", "aes-256-gcm:password", "x", "ab", "abc"] {
            let encoded = encode_base64(text);
            assert_eq!(decode_base64(&encoded).expect("decodes"), text);
        }
        // URL-safe alphabet.
        assert_eq!(
            decode_base64("YWVzLTI1Ni1nY206cGFzc3dvcmQ").expect("decodes"),
            "aes-256-gcm:password"
        );
    }

    #[test]
    fn a_sip002_link_parses() {
        let credentials = encode_base64("aes-256-gcm:secret");
        let link =
            Link::parse(&format!("ss://{credentials}@example.com:8388#edge")).expect("parses");
        assert_eq!(link.cipher, Cipher::Aes256Gcm);
        assert_eq!(link.server, "example.com:8388");
        assert_eq!(link.tag.as_deref(), Some("edge"));
        assert_eq!(link.master_key().len(), 32);
    }

    #[test]
    fn a_legacy_fully_encoded_link_parses() {
        // What many panels emit: the server is inside the base64 payload.
        let encoded = encode_base64("chacha20-ietf-poly1305:pw@1.2.3.4:8388");
        let link = Link::parse(&format!("ss://{encoded}")).expect("parses");
        assert_eq!(link.cipher, Cipher::ChaCha20Poly1305);
        assert_eq!(link.server, "1.2.3.4:8388");
        assert_eq!(link.tag, None);
    }

    #[test]
    fn a_legacy_link_with_a_tag_parses() {
        let encoded = encode_base64("aes-128-gcm:pw@1.2.3.4:8388");
        let link = Link::parse(&format!("ss://{encoded}#tagged")).expect("parses");
        assert_eq!(link.tag.as_deref(), Some("tagged"));
    }

    #[test]
    fn a_legacy_cipher_is_rejected_by_name() {
        let credentials = encode_base64("aes-256-cfb:secret");
        let error =
            Link::parse(&format!("ss://{credentials}@example.com:8388")).expect_err("must reject");
        assert!(error.contains("no authentication"), "{error}");
    }

    #[test]
    fn broken_links_name_the_broken_part() {
        let credentials = encode_base64("aes-256-gcm:secret");
        let cases = [
            ("http://x", "does not start with ss://"),
            // `ss://` alone has neither an `@` nor decodable credentials, so the legacy path
            // reports the missing separator; either message names a real defect.
            ("ss://", "has no `@`"),
            (
                &format!("ss://{credentials}@example.com"),
                "is not `host:port`",
            ),
            (
                &format!("ss://{}@example.com:1", encode_base64("aes-256-gcm:")),
                "empty password",
            ),
        ];
        for (link, expected) in cases {
            let error = Link::parse(link).expect_err("must reject");
            assert!(
                error.contains(expected),
                "{link}: expected {expected:?}, got {error:?}"
            );
        }
    }

    #[test]
    fn the_link_renders_without_credentials() {
        // A log line must never print the password.
        let credentials = encode_base64("aes-256-gcm:secret");
        let link =
            Link::parse(&format!("ss://{credentials}@example.com:8388#edge")).expect("parses");
        let rendered = link.to_string();
        assert!(!rendered.contains("secret"), "{rendered}");
        assert!(!rendered.contains(&credentials), "{rendered}");
        assert!(rendered.contains("aes-256-gcm"), "{rendered}");
        assert!(rendered.contains("example.com:8388"), "{rendered}");
        assert!(rendered.contains("#edge"), "{rendered}");
    }

    #[test]
    fn addresses_are_encoded_with_the_right_address_type() {
        assert_eq!(
            encode_address("1.2.3.4", 443).expect("encodes"),
            vec![1, 1, 2, 3, 4, 1, 187]
        );

        let v6 = encode_address("2001:db8::1", 53).expect("encodes");
        assert_eq!(v6[0], 4);
        assert_eq!(v6.len(), 1 + 16 + 2);
        assert_eq!(&v6[v6.len() - 2..], &53u16.to_be_bytes());

        let domain = encode_address("example.com", 8388).expect("encodes");
        assert_eq!(domain[0], 3);
        assert_eq!(domain[1], 11);
        assert_eq!(&domain[2..13], b"example.com");
    }

    #[test]
    fn address_encoding_rejects_impossible_targets() {
        assert!(encode_address("", 80).is_err());
        assert!(encode_address("example.com", 0).is_err());
        assert!(encode_address(&"a".repeat(256), 80).is_err());
    }

    #[test]
    fn authorities_split_for_v4_v6_and_names() {
        assert_eq!(
            split_authority("1.2.3.4:443").expect("splits"),
            ("1.2.3.4", 443)
        );
        assert_eq!(
            split_authority("example.com:8388").expect("splits"),
            ("example.com", 8388)
        );
        assert_eq!(
            split_authority("[2001:db8::1]:53").expect("splits"),
            ("2001:db8::1", 53)
        );
        assert!(split_authority("example.com").is_err());
        assert!(split_authority("example.com:").is_err());
        assert!(split_authority("[2001:db8::1").is_err());
    }

    #[test]
    fn a_connector_rejects_a_link_it_cannot_use() {
        let error = ShadowSocksConnector::from_link(
            "ss://bm90LWEtbGluaw@example.com:1",
            DialerOptions::new(None, Duration::from_secs(1)),
        )
        .expect_err("must reject");
        assert!(matches!(error, OutboundError::UnsupportedLink(_)));
    }

    #[test]
    fn link_detection_is_prefix_based() {
        assert!(is_shadowsocks("ss://x"));
        assert!(is_shadowsocks("  ss://x"));
        assert!(!is_shadowsocks("socks5://x"));
        assert_eq!(protocol(), Protocol::ShadowSocks);
    }

    #[test]
    fn the_replay_filter_has_a_bounded_window() {
        let mut filter = replay_filter();
        let salt = vec![7u8; 32];
        assert!(filter.observe(&salt));
        assert!(!filter.observe(&salt));
    }
}
