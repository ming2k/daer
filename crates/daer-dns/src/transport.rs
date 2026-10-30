// SPDX-License-Identifier: AGPL-3.0-only

//! Upstream transports, and the `dns.upstream` entry syntax.
//!
//! # The entry syntax
//!
//! ```text
//!   tag:protocol://host:port                 # one transport
//!   tag:udp+tcp://host:port                  # try in order, first success wins
//!   tag:https://1.1.1.1:443/dns-query        # DoH needs its path
//! ```
//!
//! The tag names the upstream in `[dns.request]` / `[dns.response]` rules. The protocol is
//! required: an entry without one is a configuration error, not a guess, because "UDP
//! unless it fails" is a policy decision an operator must make explicitly.
//!
//! # What is implemented
//!
//! | Protocol | Wire | Where it comes from |
//! | --- | --- | --- |
//! | `udp` | RFC 1035 §4.2.1 | a plain `UdpSocket` — no dependency on any other subsystem |
//! | `tcp` | RFC 1035 §4.2.2 | a plain `TcpStream` |
//! | `tls` / `dot` | RFC 7858 | netune's [`TlsConnector`], used only as a byte pipe |
//! | `https` / `doh` | RFC 8484 | netune's HTTP client, for framing and `Content-Type` |
//!
//! Every one of these is fully implemented. A protocol that could not be built is a
//! **load-time** error ([`UpstreamError::Missing`] from [`UpstreamSpec::build`]), not a
//! per-query failure: a resolver that loads and then refuses every query is a
//! configuration an operator believes is working, which is the worst of both.
//!
//! # Encryption is netune's; DNS is ours
//!
//! For DoT and DoH this module supplies the DNS framing and nothing else. What TLS
//! identity is presented is [`Target::tls`]'s business, and what HTTP looks like on the
//! wire is the client's — so a fingerprint profile configured for the resolver is the
//! same mechanism as for any other dial, not a parallel one.
//!
//! # UDP and truncation
//!
//! A UDP answer that does not fit sets `TC`, and the client is expected to retry over TCP
//! ([`is_truncated`]). Retrying automatically is a **policy** decision, not a transport
//! detail: a resolver that always retries doubles its cost for the one large answer per
//! zone, so `udp+tcp` is how an operator asks for it explicitly.

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use netune::{Client, ClientConfig, Method, Pool, RequestHead, Target, TcpConnector, TlsConnector};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use crate::resolver::{ExchangeFuture, Upstream, UpstreamError};
use crate::wire::{self, Message};

/// How long one exchange may take.
///
/// A resolver upstream that has not answered in this long is not going to: the client has
/// already retried elsewhere. Bounding it here keeps a stuck upstream from holding the
/// ingress slot.
pub const DEFAULT_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(3);

/// The largest DNS message that fits a two-byte length prefix.
pub const MAX_MESSAGE: usize = u16::MAX as usize;

/// A DNS upstream protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// Plain UDP (RFC 1035 §4.2.1).
    Udp,
    /// Plain TCP with a two-byte length prefix (RFC 1035 §4.2.2).
    Tcp,
    /// DNS over TLS (RFC 7858).
    Tls,
    /// DNS over HTTPS (RFC 8484).
    Https,
}

impl Protocol {
    /// Parses a protocol token.
    ///
    /// # Errors
    ///
    /// Returns a message for an unknown token, naming what is accepted.
    pub fn parse(text: &str) -> Result<Self, String> {
        match text {
            "udp" => Ok(Self::Udp),
            "tcp" => Ok(Self::Tcp),
            "tls" | "dot" => Ok(Self::Tls),
            "https" | "doh" => Ok(Self::Https),
            other => Err(format!(
                "unknown DNS upstream protocol {other:?}; expected udp, tcp, tls or https \
                 (or a `+` chain such as tcp+udp)"
            )),
        }
    }

    /// True for the protocols that carry DNS inside TLS.
    #[must_use]
    pub const fn is_encrypted(self) -> bool {
        matches!(self, Self::Tls | Self::Https)
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
            Self::Tls => "tls",
            Self::Https => "https",
        })
    }
}

/// One parsed `dns.upstream` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamSpec {
    /// The tag rules refer to.
    pub tag: String,
    /// The protocols to try, in order.
    pub protocols: Vec<Protocol>,
    /// Where to send.
    pub address: SocketAddr,
    /// SNI for DoT, `Host` for DoH.
    pub server_name: String,
    /// The request path. `/dns-query` for DoH, `/` otherwise.
    pub path: String,
}

/// The path a DoH endpoint is queried at when the entry does not name one.
pub const DEFAULT_DOH_PATH: &str = "/dns-query";

impl UpstreamSpec {
    /// Parses `tag:protocol://host:port[/path]`.
    ///
    /// # Errors
    ///
    /// Returns a message naming the offending part: a missing tag separator, a missing
    /// protocol, an unknown protocol token, or an address that is not `host:port`.
    pub fn parse(entry: &str) -> Result<Self, String> {
        let (tag, rest) = entry.split_once(':').ok_or_else(|| {
            format!("dns.upstream entry {entry:?} has no tag; write `tag:protocol://host:port`")
        })?;
        let tag = tag.trim();
        if tag.is_empty() {
            return Err(format!("dns.upstream entry {entry:?} has an empty tag"));
        }
        if tag == "asis" || tag == "reject" {
            return Err(format!(
                "dns.upstream tag {tag:?} is reserved: {tag} is a decision, not an upstream"
            ));
        }

        let (scheme, address) = rest.split_once("://").ok_or_else(|| {
            format!("dns.upstream entry {entry:?} has no protocol; write `{tag}:udp://host:port`")
        })?;
        let protocols = scheme
            .split('+')
            .map(Protocol::parse)
            .collect::<Result<Vec<_>, _>>()?;
        if protocols.is_empty() {
            return Err(format!(
                "dns.upstream entry {entry:?} has an empty protocol"
            ));
        }

        // A DoH endpoint is a URL, so the socket part is what precedes the first `/` and
        // the remainder is the path. DoT ignores the path; a stray one is kept so the
        // syntax does not have to change per protocol.
        let (socket_part, path) = match address.split_once('/') {
            Some((socket, path)) => (socket, format!("/{path}")),
            None => (address, DEFAULT_DOH_PATH.to_owned()),
        };
        let address: SocketAddr = socket_part.parse().map_err(|_| {
            format!(
                "dns.upstream entry {entry:?}: {socket_part:?} is not ip:port \
                 (name resolution for upstreams is not implemented yet)"
            )
        })?;

        Ok(Self {
            tag: tag.to_owned(),
            protocols,
            address,
            server_name: address.ip().to_string(),
            path,
        })
    }

    /// Overrides the name presented in the TLS handshake.
    ///
    /// Needed when the endpoint is reached by address but its certificate is for a name,
    /// which is how every public DoT/DoH resolver is published. Without an override the
    /// handshake would have to verify a certificate against a bare IP, which fails.
    #[must_use]
    pub fn with_server_name(mut self, name: impl Into<String>) -> Self {
        self.server_name = name.into();
        self
    }

    /// Builds the transport this spec describes.
    ///
    /// # Errors
    ///
    /// Returns [`UpstreamError::Missing`] when the spec names no protocol this build can
    /// speak. Every protocol in [`Protocol`] is implemented, so this can only happen if a
    /// variant is added without an arm here — which is exactly the case a `match` makes
    /// impossible to forget.
    pub fn build(&self) -> Result<Arc<dyn Upstream>, UpstreamError> {
        let upstream: Arc<dyn Upstream> = match self.protocols.as_slice() {
            // A chain is tried in order; the first protocol that is *built* is used, and
            // `Failover` handles the rest at query time.
            [] => return Err(UpstreamError::Missing(self.tag.clone())),
            [only] => match only {
                Protocol::Udp => Arc::new(UdpUpstream::new(self)),
                Protocol::Tcp => Arc::new(TcpUpstream::new(self)),
                Protocol::Tls => Arc::new(TlsUpstream::new(self)),
                Protocol::Https => Arc::new(HttpsUpstream::new(self)),
            },
            _ => Arc::new(ChainUpstream::new(self)?),
        };
        Ok(upstream)
    }
}

/// Everything an upstream needs that is not the wire itself.
#[derive(Debug, Clone)]
struct Common {
    address: SocketAddr,
    server_name: String,
    timeout: Duration,
}

impl Common {
    fn new(spec: &UpstreamSpec) -> Self {
        Self {
            address: spec.address,
            server_name: spec.server_name.clone(),
            timeout: DEFAULT_EXCHANGE_TIMEOUT,
        }
    }

    fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

/// Validates a reply against the query it answers.
///
/// Every transport shares this: an answer must be a response, must carry the same id, and
/// must parse. A racing client receiving someone else's answer is the failure this
/// prevents, and it is not protocol-specific.
fn validate(bytes: &[u8], query: &Message, from: &str) -> Result<Message, UpstreamError> {
    let reply = wire::parse(bytes)
        .map_err(|error| UpstreamError::Failed(format!("malformed reply from {from}: {error}")))?;
    if reply.id != query.id {
        return Err(UpstreamError::Failed(format!(
            "reply id {} from {from} does not match query id {}",
            reply.id, query.id
        )));
    }
    if !reply.is_response() {
        return Err(UpstreamError::Failed(format!(
            "reply from {from} is not marked as a response"
        )));
    }
    Ok(reply)
}

fn payload_bytes(query: &Message) -> Result<Vec<u8>, UpstreamError> {
    let payload = wire::encode(query);
    if payload.len() > MAX_MESSAGE {
        return Err(UpstreamError::Failed(format!(
            "query is {} bytes, over {MAX_MESSAGE}",
            payload.len()
        )));
    }
    Ok(payload)
}

async fn timed<R>(
    timeout: Duration,
    name: String,
    future: impl std::future::Future<Output = Result<R, UpstreamError>>,
) -> Result<R, UpstreamError> {
    tokio::time::timeout(timeout, future).await.map_err(|_| {
        UpstreamError::Failed(format!(
            "{name} did not answer within {}ms",
            timeout.as_millis()
        ))
    })?
}

// ── UDP ──────────────────────────────────────────────────────────────────────

/// DNS over plain UDP.
#[derive(Debug)]
pub struct UdpUpstream {
    common: Common,
}

impl UdpUpstream {
    fn new(spec: &UpstreamSpec) -> Self {
        Self {
            common: Common::new(spec),
        }
    }

    /// Overrides the exchange timeout.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.common = self.common.with_timeout(timeout);
        self
    }

    /// The address this upstream sends to.
    #[must_use]
    pub const fn address(&self) -> SocketAddr {
        self.common.address
    }
}

impl Upstream for UdpUpstream {
    fn exchange<'a>(&'a self, query: &'a Message) -> ExchangeFuture<'a> {
        Box::pin(async move {
            let payload = payload_bytes(query)?;
            let address = self.common.address;
            let exchange = async {
                // A fresh socket per exchange. Reuse would need its own id-demultiplexing
                // and a stale-socket story; one socket per query costs a syscall pair and
                // makes "this reply belongs to this query" true by construction, because
                // only one datagram can ever arrive on it.
                let socket = UdpSocket::bind(bind_any_for(address))
                    .await
                    .map_err(|error| {
                        UpstreamError::Failed(format!("bind for {address}: {error}"))
                    })?;
                socket.connect(address).await.map_err(|error| {
                    UpstreamError::Failed(format!("connect to {address}: {error}"))
                })?;
                socket.send(&payload).await.map_err(|error| {
                    UpstreamError::Failed(format!("send to {address}: {error}"))
                })?;

                // EDNS0 advertises the client's buffer size; without a reply larger than
                // the classic 512 bytes a large answer can only arrive truncated. 64 KiB is
                // the practical ceiling for a UDP payload.
                let mut buffer = vec![0u8; MAX_MESSAGE];
                let read = socket.recv(&mut buffer).await.map_err(|error| {
                    UpstreamError::Failed(format!("receive from {address}: {error}"))
                })?;
                buffer.truncate(read);
                Ok::<Vec<u8>, UpstreamError>(buffer)
            };

            let bytes = timed(
                self.common.timeout,
                self.common.server_name.clone(),
                exchange,
            )
            .await?;
            validate(&bytes, query, &self.common.server_name)
        })
    }
}

/// The unspecified address of the same family as `peer`.
fn bind_any_for(peer: SocketAddr) -> SocketAddr {
    match peer {
        SocketAddr::V4(_) => SocketAddr::from(([0, 0, 0, 0], 0)),
        SocketAddr::V6(_) => SocketAddr::from(([0u16; 8], 0)),
    }
}

// ── TCP ──────────────────────────────────────────────────────────────────────

/// DNS over TCP, with a two-byte length prefix.
#[derive(Debug)]
pub struct TcpUpstream {
    common: Common,
}

impl TcpUpstream {
    pub fn new(spec: &UpstreamSpec) -> Self {
        Self {
            common: Common::new(spec),
        }
    }

    /// Overrides the exchange timeout.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.common = self.common.with_timeout(timeout);
        self
    }

    /// The address this upstream sends to.
    #[must_use]
    pub const fn address(&self) -> SocketAddr {
        self.common.address
    }
}

impl Upstream for TcpUpstream {
    fn exchange<'a>(&'a self, query: &'a Message) -> ExchangeFuture<'a> {
        Box::pin(async move {
            let payload = payload_bytes(query)?;
            let length = u16::try_from(payload.len()).expect("bounded by MAX_MESSAGE");
            let address = self.common.address;

            let exchange = async {
                let mut stream = TcpStream::connect(address).await.map_err(|error| {
                    UpstreamError::Failed(format!("connect to {address}: {error}"))
                })?;
                stream
                    .set_nodelay(true)
                    .map_err(|error| UpstreamError::Failed(format!("set TCP_NODELAY: {error}")))?;
                write_length_prefixed(&mut stream, length, &payload, address).await?;
                read_length_prefixed(&mut stream, address).await
            };

            let bytes = timed(
                self.common.timeout,
                self.common.server_name.clone(),
                exchange,
            )
            .await?;
            validate(&bytes, query, &self.common.server_name)
        })
    }
}

async fn write_length_prefixed<S: AsyncWriteExt + Unpin>(
    stream: &mut S,
    length: u16,
    payload: &[u8],
    address: SocketAddr,
) -> Result<(), UpstreamError> {
    stream
        .write_all(&length.to_be_bytes())
        .await
        .map_err(|error| UpstreamError::Failed(format!("write length to {address}: {error}")))?;
    stream
        .write_all(payload)
        .await
        .map_err(|error| UpstreamError::Failed(format!("write body to {address}: {error}")))?;
    stream
        .flush()
        .await
        .map_err(|error| UpstreamError::Failed(format!("flush to {address}: {error}")))
}

async fn read_length_prefixed<S: AsyncReadExt + Unpin>(
    stream: &mut S,
    address: SocketAddr,
) -> Result<Vec<u8>, UpstreamError> {
    let mut length_bytes = [0u8; 2];
    stream
        .read_exact(&mut length_bytes)
        .await
        .map_err(|error| UpstreamError::Failed(format!("read length from {address}: {error}")))?;
    let length = usize::from(u16::from_be_bytes(length_bytes));
    if length == 0 {
        return Err(UpstreamError::Failed(format!(
            "reply from {address} has a zero length"
        )));
    }
    let mut response = vec![0u8; length];
    stream
        .read_exact(&mut response)
        .await
        .map_err(|error| UpstreamError::Failed(format!("read body from {address}: {error}")))?;
    Ok(response)
}

// ── DoT ──────────────────────────────────────────────────────────────────────

/// DNS over TLS (RFC 7858).
///
/// The TLS stack is netune's: this module opens a byte stream through
/// [`TlsConnector`] and speaks the same length-prefixed framing as plain TCP inside it.
/// The identity presented is `Target::tls`'s business, so a resolver honours the same
/// fingerprint profile as every other dial.
pub struct TlsUpstream {
    common: Common,
    connector: TlsConnector<TcpConnector>,
}

impl fmt::Debug for TlsUpstream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The connector holds a TLS configuration, which holds key material for a client
        // certificate if one is configured. Print the shape, never the contents.
        f.debug_struct("TlsUpstream")
            .field("address", &self.common.address)
            .field("server_name", &self.common.server_name)
            .field("timeout", &self.common.timeout)
            .finish_non_exhaustive()
    }
}

impl TlsUpstream {
    fn new(spec: &UpstreamSpec) -> Self {
        let common = Common::new(spec);
        let connector =
            TlsConnector::platform(TcpConnector::new().with_connect_timeout(Some(common.timeout)))
                .expect("the platform trust store is available");
        Self { common, connector }
    }

    /// Overrides the exchange timeout.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.common = self.common.with_timeout(timeout);
        self
    }

    /// The address this upstream sends to.
    #[must_use]
    pub const fn address(&self) -> SocketAddr {
        self.common.address
    }
}

impl Upstream for TlsUpstream {
    fn exchange<'a>(&'a self, query: &'a Message) -> ExchangeFuture<'a> {
        Box::pin(async move {
            use netune::Connector;

            let payload = payload_bytes(query)?;
            let length = u16::try_from(payload.len()).expect("bounded by MAX_MESSAGE");
            let address = self.common.address;
            let server_name = self.common.server_name.clone();
            let target = Target::tls(address.to_string(), server_name.clone());
            let recorder = Arc::new(std::sync::Mutex::new(netune_trace::Recorder::start(16)));

            let exchange = async {
                let established =
                    self.connector
                        .connect(&target, &recorder)
                        .await
                        .map_err(|error| {
                            UpstreamError::Failed(format!("TLS to {server_name}: {error}"))
                        })?;
                let mut stream = established.stream;
                write_length_prefixed(&mut stream, length, &payload, address).await?;
                read_length_prefixed(&mut stream, address).await
            };

            let bytes = timed(self.common.timeout, server_name.clone(), exchange).await?;
            validate(&bytes, query, &server_name)
        })
    }
}

// ── DoH ──────────────────────────────────────────────────────────────────────

/// DNS over HTTPS (RFC 8484).
///
/// Uses netune's HTTP client, so framing, `Content-Length`, chunking and redirects are
/// the same code the rest of daer uses. `POST` with `application/dns-message` is the
/// required method; `GET` with a base64url `?dns=` is an optional optimisation whose
/// benefit (cacheability) does not apply to a resolver that has its own cache.
pub struct HttpsUpstream {
    common: Common,
    client: Client<TlsConnector<TcpConnector>>,
    path: String,
}

impl fmt::Debug for HttpsUpstream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpsUpstream")
            .field("address", &self.common.address)
            .field("server_name", &self.common.server_name)
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl HttpsUpstream {
    fn new(spec: &UpstreamSpec) -> Self {
        let common = Common::new(spec);
        let connector =
            TlsConnector::platform(TcpConnector::new().with_connect_timeout(Some(common.timeout)))
                .expect("the platform trust store is available");
        let config = ClientConfig {
            // A redirect on a DNS endpoint is a configuration error, not a hop to follow:
            // silently querying a different host would send the query somewhere the
            // operator did not name.
            max_redirects: 0,
            ..ClientConfig::default()
        };
        Self {
            common,
            client: Client::new(connector, Pool::default(), config),
            path: spec.path.clone(),
        }
    }

    /// Overrides the exchange timeout.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.common = self.common.with_timeout(timeout);
        self
    }

    /// The address this upstream sends to.
    #[must_use]
    pub const fn address(&self) -> SocketAddr {
        self.common.address
    }
}

impl Upstream for HttpsUpstream {
    fn exchange<'a>(&'a self, query: &'a Message) -> ExchangeFuture<'a> {
        Box::pin(async move {
            let payload = payload_bytes(query)?;
            let address = self.common.address;
            let server_name = self.common.server_name.clone();
            let target = Target::tls(address.to_string(), server_name.clone());
            let head = RequestHead::new(Method::POST, self.path.clone())
                .with_header("accept", "application/dns-message")
                .with_header("content-type", "application/dns-message");
            let body = bytes_of(payload);

            let exchange = async {
                let response = self
                    .client
                    .request(&target, head, Some(body))
                    .await
                    .map_err(|error| {
                        UpstreamError::Failed(format!("DoH to {server_name}: {error}"))
                    })?;
                let status = response.head.status;
                if !status.is_success() {
                    return Err(UpstreamError::Failed(format!(
                        "DoH endpoint {server_name} answered HTTP {}",
                        status.as_u16()
                    )));
                }
                let mut body = response.body;
                let bytes = body.read_to_end().await.map_err(|error| {
                    UpstreamError::Failed(format!("read DoH body from {server_name}: {error}"))
                })?;
                Ok::<Vec<u8>, UpstreamError>(bytes.to_vec())
            };

            let bytes = timed(self.common.timeout, server_name.clone(), exchange).await?;
            validate(&bytes, query, &server_name)
        })
    }
}

fn bytes_of(payload: Vec<u8>) -> bytes::Bytes {
    bytes::Bytes::from(payload)
}

// ── Chains ───────────────────────────────────────────────────────────────────

/// A chain (`udp+tcp`): try each member in order, first success wins.
///
/// This is the explicit spelling of "UDP, but fall back to TCP", and it exists as a
/// transport rather than as resolver logic so the choice is visible where it is
/// configured. A member that fails does not abort the chain; only every member failing
/// does.
#[derive(Debug)]
pub struct ChainUpstream {
    tag: String,
    members: Vec<Arc<dyn Upstream>>,
}

impl ChainUpstream {
    fn new(spec: &UpstreamSpec) -> Result<Self, UpstreamError> {
        let mut members = Vec::with_capacity(spec.protocols.len());
        for protocol in &spec.protocols {
            let mut single = spec.clone();
            single.protocols = vec![*protocol];
            members.push(single.build()?);
        }
        Ok(Self {
            tag: spec.tag.clone(),
            members,
        })
    }
}

impl Upstream for ChainUpstream {
    fn exchange<'a>(&'a self, query: &'a Message) -> ExchangeFuture<'a> {
        Box::pin(async move {
            let mut last: Option<UpstreamError> = None;
            for member in &self.members {
                match member.exchange(query).await {
                    Ok(reply) => return Ok(reply),
                    Err(error) => last = Some(error),
                }
            }
            Err(last.unwrap_or_else(|| {
                UpstreamError::Failed(format!("chain {} has no member", self.tag))
            }))
        })
    }
}

/// A truncation-aware TCP retry: UDP answers set `TC` when the answer did not fit.
///
/// Exposed as a value rather than performed automatically, because the retry is a policy
/// decision: a resolver that always retries over TCP doubles its cost for one large answer
/// per zone.
#[must_use]
pub fn is_truncated(message: &Message) -> bool {
    message.flags.is_truncated()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{Flags, RecordType};
    use std::net::Ipv4Addr;
    use tokio::net::TcpListener;

    fn query(id: u16) -> Message {
        wire::query(id, "example.com", RecordType::A).expect("builds a query")
    }

    fn spec(entry: &str) -> UpstreamSpec {
        UpstreamSpec::parse(entry).expect("parses")
    }

    #[test]
    fn parses_every_protocol() {
        for (token, expected) in [
            ("udp", Protocol::Udp),
            ("tcp", Protocol::Tcp),
            ("tls", Protocol::Tls),
            ("dot", Protocol::Tls),
            ("https", Protocol::Https),
            ("doh", Protocol::Https),
        ] {
            assert_eq!(Protocol::parse(token), Ok(expected), "{token}");
        }
        assert!(Protocol::parse("quic").is_err());
    }

    #[test]
    fn every_protocol_builds() {
        // The regression this guards: a protocol that parses and is documented but has no
        // transport, which is the state `udp`, `tls` and `https` were in.
        for token in ["udp", "tcp", "tls", "https"] {
            let spec = spec(&format!("u:{token}://1.1.1.1:53"));
            let built = spec.build().unwrap_or_else(|error| {
                panic!("{token} must build, got {error}");
            });
            let _ = built;
        }
    }

    #[test]
    fn a_doh_path_is_kept_and_defaults_when_absent() {
        assert_eq!(spec("g:https://1.1.1.1:443").path, DEFAULT_DOH_PATH);
        assert_eq!(spec("g:https://1.1.1.1:443/custom").path, "/custom");
    }

    #[test]
    fn a_hostname_upstream_is_rejected_with_the_reason() {
        // Upstreams are addressed by IP only; bootstrapping a name is a resolver problem of
        // its own. The rejection must name that, not report a syntax error.
        let error = UpstreamSpec::parse("g:https://dns.example:443/dns-query")
            .expect_err("names are not accepted");
        assert!(error.contains("not ip:port"), "{error}");
        assert!(error.contains("name resolution"), "{error}");
    }

    #[test]
    fn the_handshake_name_defaults_to_the_address_and_can_be_overridden() {
        // A public DoT resolver is published by address with a certificate for a name.
        assert_eq!(spec("g:tls://1.1.1.1:853").server_name, "1.1.1.1");
        assert_eq!(
            spec("g:tls://1.1.1.1:853")
                .with_server_name("cloudflare-dns.com")
                .server_name,
            "cloudflare-dns.com"
        );
    }

    #[test]
    fn a_chain_builds_one_member_per_protocol() {
        // Building must succeed for both members; the chain's behaviour at query time is
        // covered by the `udp+tcp` integration test in `tests/upstreams.rs`.
        let spec = spec("u:udp+tcp://1.1.1.1:53");
        let built = spec.build().expect("builds");
        drop(built);
    }

    #[tokio::test]
    async fn udp_answers_a_query() {
        let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("binds");
        let address = server.local_addr().expect("addr");
        tokio::spawn(async move {
            let mut buffer = vec![0u8; 4096];
            let (read, peer) = server.recv_from(&mut buffer).await.expect("receives");
            let reply = wire::reply(&wire::parse(&buffer[..read]).expect("parses"), &[]);
            let _ = server.send_to(&wire::encode(&reply), peer).await;
        });

        let upstream = spec(&format!("local:udp://{address}"))
            .build()
            .expect("builds");
        let reply = upstream.exchange(&query(7)).await.expect("answers");
        assert_eq!(reply.id, 7);
        assert!(reply.is_response());
    }

    #[tokio::test]
    async fn udp_times_out_on_a_silent_upstream() {
        let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("binds");
        let address = server.local_addr().expect("addr");
        tokio::spawn(async move {
            let mut buffer = vec![0u8; 64];
            let _ = server.recv_from(&mut buffer).await;
            tokio::time::sleep(Duration::from_secs(30)).await;
        });

        let spec = spec(&format!("local:udp://{address}"));
        let upstream = UdpUpstream::new(&spec).with_timeout(Duration::from_millis(80));
        let error = upstream.exchange(&query(1)).await.expect_err("must fail");
        assert!(error.to_string().contains("did not answer"), "{error}");
    }

    #[tokio::test]
    async fn udp_rejects_a_reply_with_the_wrong_id() {
        let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("binds");
        let address = server.local_addr().expect("addr");
        tokio::spawn(async move {
            let mut buffer = vec![0u8; 4096];
            let (read, peer) = server.recv_from(&mut buffer).await.expect("receives");
            let mut reply = wire::reply(&wire::parse(&buffer[..read]).expect("parses"), &[]);
            // Someone else's answer.
            reply.id = 999;
            let _ = server.send_to(&wire::encode(&reply), peer).await;
        });

        let upstream = spec(&format!("local:udp://{address}"))
            .build()
            .expect("builds");
        let error = upstream.exchange(&query(7)).await.expect_err("must reject");
        assert!(error.to_string().contains("does not match"), "{error}");
    }

    #[tokio::test]
    async fn tcp_answers_a_query() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("binds");
        let address = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accepts");
            let mut length = [0u8; 2];
            stream.read_exact(&mut length).await.expect("length");
            let mut body = vec![0u8; usize::from(u16::from_be_bytes(length))];
            stream.read_exact(&mut body).await.expect("body");
            let reply = wire::reply(&wire::parse(&body).expect("parses"), &[]);
            let encoded = wire::encode(&reply);
            let _ = stream
                .write_all(&(encoded.len() as u16).to_be_bytes())
                .await;
            let _ = stream.write_all(&encoded).await;
        });

        let upstream = spec(&format!("local:tcp://{address}"))
            .build()
            .expect("builds");
        let reply = upstream.exchange(&query(11)).await.expect("answers");
        assert_eq!(reply.id, 11);
    }

    #[tokio::test]
    async fn a_malformed_tcp_reply_is_reported_as_malformed() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("binds");
        let address = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accepts");
            let mut length = [0u8; 2];
            let _ = stream.read_exact(&mut length).await;
            let mut body = vec![0u8; usize::from(u16::from_be_bytes(length))];
            let _ = stream.read_exact(&mut body).await;
            let body = [0u8, 1, 2, 3];
            let _ = stream.write_all(&(body.len() as u16).to_be_bytes()).await;
            let _ = stream.write_all(&body).await;
        });

        let upstream = spec(&format!("local:tcp://{address}"))
            .build()
            .expect("builds");
        let error = upstream.exchange(&query(1)).await.expect_err("must reject");
        assert!(error.to_string().contains("malformed"), "{error}");
    }

    #[tokio::test]
    async fn a_silent_tcp_upstream_times_out() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("binds");
        let address = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accepts");
            tokio::time::sleep(Duration::from_secs(30)).await;
            drop(stream);
        });

        let spec = spec(&format!("local:tcp://{address}"));
        let upstream = TcpUpstream::new(&spec).with_timeout(Duration::from_millis(50));
        let error = upstream.exchange(&query(1)).await.expect_err("must fail");
        assert!(error.to_string().contains("did not answer"), "{error}");
    }

    #[tokio::test]
    async fn a_refused_connection_is_reported_with_the_address() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("binds");
        let address = listener.local_addr().expect("addr");
        drop(listener);

        let spec = spec(&format!("local:tcp://{address}"));
        let upstream = TcpUpstream::new(&spec).with_timeout(Duration::from_millis(500));
        let error = upstream.exchange(&query(1)).await.expect_err("must fail");
        assert!(error.to_string().contains("connect"), "{error}");
    }

    #[test]
    fn truncation_is_read_from_the_tc_bit() {
        let mut message = query(1);
        assert!(!is_truncated(&message));
        message.flags = Flags(0x8380); // QR | TC | RD | RA
        assert!(is_truncated(&message));
    }
}
