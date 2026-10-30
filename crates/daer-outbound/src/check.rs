// SPDX-License-Identifier: AGPL-3.0-only

//! Node connectivity checks.
//!
//! Port of the probe in `connectivity_check.go`, with the transport delegated to
//! [`netune`]:
//!
//! * [`HttpChecker`] performs the `tcp_check_url` request (HEAD by default) to a
//!   *specific* address while presenting the URL's host as `Host` and TLS SNI.
//! * [`TcpChecker`] measures a bare TCP handshake.
//!
//! The check URL host is resolved once per IP family and every resolved
//! address, so both checkers take an [`IpAddr`]/[`SocketAddr`] rather than a
//! hostname. That also keeps DNS cost out of the measured latency.

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use daer_config::TimeSpan;
use netune::{
    Client, ClientConfig, Connector, DatagramConnector, Method, Pool, RequestHead, Target,
    TcpConnector, TlsRouterConnector, UdpConnector,
};
use netune_trace::Recorder;
use tokio::time::timeout;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckError {
    InvalidUrl(String),
    /// The probe did not finish within its deadline.
    Timeout,
    /// The transport failed; the message comes from netune.
    Request(String),
}

impl fmt::Display for CheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUrl(message) => write!(f, "invalid check url: {message}"),
            Self::Timeout => f.write_str("check timed out"),
            Self::Request(message) => write!(f, "check failed: {message}"),
        }
    }
}

impl std::error::Error for CheckError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Http,
    Https,
}

impl Scheme {
    fn default_port(self) -> u16 {
        match self {
            Self::Http => 80,
            Self::Https => 443,
        }
    }
}

/// A parsed `tcp_check_url`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckUrl {
    scheme: Scheme,
    host: String,
    port: u16,
    path: String,
}

impl CheckUrl {
    /// Parses `scheme://host[:port][/path]`. Only `http` and `https` are
    /// accepted; check URLs are HTTP probes.
    pub fn parse(raw: &str) -> Result<Self, CheckError> {
        let raw = raw.trim();
        let Some((scheme, rest)) = raw.split_once("://") else {
            return Err(CheckError::InvalidUrl(format!(
                "{raw:?} has no scheme; expected http:// or https://"
            )));
        };
        let scheme = match scheme.to_ascii_lowercase().as_str() {
            "http" => Scheme::Http,
            "https" => Scheme::Https,
            other => {
                return Err(CheckError::InvalidUrl(format!(
                    "unsupported scheme {other:?}; expected http or https"
                )));
            }
        };

        let (authority, path) = match rest.find('/') {
            Some(index) => (&rest[..index], &rest[index..]),
            None => (rest, "/"),
        };
        if authority.is_empty() {
            return Err(CheckError::InvalidUrl("missing host".to_owned()));
        }

        let (host, port) = split_authority(authority)?;
        if host.is_empty() {
            return Err(CheckError::InvalidUrl("missing host".to_owned()));
        }
        Ok(Self {
            scheme,
            host,
            port: port.unwrap_or(scheme.default_port()),
            path: path.to_owned(),
        })
    }

    pub fn scheme(&self) -> Scheme {
        self.scheme
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    /// The `Host` header value: the port is omitted when it is the default.
    pub fn host_header(&self) -> String {
        if self.port == self.scheme.default_port() {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

fn split_authority(authority: &str) -> Result<(String, Option<u16>), CheckError> {
    if let Some(bracketed) = authority.strip_prefix('[') {
        let Some((host, rest)) = bracketed.split_once(']') else {
            return Err(CheckError::InvalidUrl(format!(
                "unterminated IPv6 literal in {authority:?}"
            )));
        };
        let port = match rest.strip_prefix(':') {
            Some(port) => Some(parse_port(port)?),
            None if rest.is_empty() => None,
            None => {
                return Err(CheckError::InvalidUrl(format!(
                    "unexpected {rest:?} after IPv6 literal"
                )));
            }
        };
        return Ok((host.to_owned(), port));
    }

    match authority.rsplit_once(':') {
        Some((host, port)) => Ok((host.to_owned(), Some(parse_port(port)?))),
        None => Ok((authority.to_owned(), None)),
    }
}

fn parse_port(port: &str) -> Result<u16, CheckError> {
    port.parse()
        .map_err(|_| CheckError::InvalidUrl(format!("invalid port {port:?}")))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HttpMethod {
    #[default]
    Head,
    Get,
}

impl HttpMethod {
    /// Parses `tcp-method`.
    ///
    /// # What is accepted, and why only this
    ///
    /// `HEAD` and `GET` are the two methods a probe can meaningfully issue: it reads no body and
    /// discards the response, so anything else (`PROPFIND`, `CONNECT`) would either need a body or
    /// is not a request this client can frame. The schema's enumeration is derived from this list,
    /// so a value it advertises is a value that works — the alternative, advertising `PROPFIND`
    /// and silently probing with `HEAD`, is exactly the "accepted and ignored" failure ADR-0006
    /// removed elsewhere.
    ///
    /// # Errors
    ///
    /// Returns a message naming the method and the two that are supported.
    pub fn parse(raw: &str) -> Result<Self, CheckError> {
        match raw.trim().to_ascii_uppercase().as_str() {
            "HEAD" => Ok(Self::Head),
            "GET" => Ok(Self::Get),
            other => Err(CheckError::InvalidUrl(format!(
                "{other:?} is not a probe method; this build issues HEAD or GET"
            ))),
        }
    }

    /// The canonical spelling, which is what the JSON Schema advertises.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Head => "HEAD",
            Self::Get => "GET",
        }
    }

    /// Every method this build can issue, in schema order.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[Self::Head, Self::Get]
    }

    fn as_netune(self) -> Method {
        match self {
            Self::Head => Method::HEAD,
            Self::Get => Method::GET,
        }
    }
}

/// Performs the HTTP probe for `tcp_check_url`.
pub struct HttpChecker {
    client: Client<TlsRouterConnector<TcpConnector>>,
    method: HttpMethod,
    timeout: Duration,
}

impl fmt::Debug for HttpChecker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpChecker")
            .field("method", &self.method)
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl HttpChecker {
    pub fn new(method: HttpMethod, timeout: Duration) -> Self {
        let connector = TcpConnector::new().with_connect_timeout(Some(timeout));
        let connector = TlsRouterConnector::new(connector);
        let config = ClientConfig {
            max_redirects: 0,
            ..ClientConfig::default()
        };
        Self {
            client: Client::new(connector, Pool::default(), config),
            method,
            timeout,
        }
    }

    /// Requests `url` from `addr` and returns the time to the response head.
    pub async fn check(&self, url: &CheckUrl, addr: IpAddr) -> Result<TimeSpan, CheckError> {
        let authority = format!("{addr}:{}", url.port());
        let target = match url.scheme() {
            Scheme::Http => Target::plain(authority),
            Scheme::Https => Target::tls(authority, url.host().to_owned()),
        };
        let head = RequestHead::new(self.method.as_netune(), url.path())
            .with_header("host", url.host_header());

        let started = Instant::now();
        let response = tokio::time::timeout(self.timeout, self.client.request(&target, head, None))
            .await
            .map_err(|_| CheckError::Timeout)?
            .map_err(|err| CheckError::Request(err.to_string()))?;
        let elapsed = started.elapsed();
        drop(response);
        Ok(TimeSpan::from_nanos(elapsed.as_nanos() as i64))
    }
}

/// Measures a bare TCP handshake through netune's connector, so the probe
/// shares the DNS, confinement and timeout behaviour of the data path.
pub struct TcpChecker {
    connector: TcpConnector,
    timeout: Duration,
}

impl fmt::Debug for TcpChecker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TcpChecker")
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl TcpChecker {
    pub fn new(timeout: Duration) -> Self {
        Self {
            connector: TcpConnector::new().with_connect_timeout(Some(timeout)),
            timeout,
        }
    }

    pub async fn check(&self, addr: SocketAddr) -> Result<TimeSpan, CheckError> {
        let target = Target::plain(addr.to_string());
        let recorder = Arc::new(Mutex::new(Recorder::start(64)));

        let started = Instant::now();
        let established =
            tokio::time::timeout(self.timeout, self.connector.connect(&target, &recorder))
                .await
                .map_err(|_| CheckError::Timeout)?
                .map_err(|err| CheckError::Request(err.to_string()))?;
        let elapsed = started.elapsed();
        drop(established);
        Ok(TimeSpan::from_nanos(elapsed.as_nanos() as i64))
    }
}

/// Measures a DNS query/answer round trip over UDP through netune's datagram
/// connector, so the probe shares the data path's resolution, confinement and
/// socket options.
///
/// This is what the `udp-dns` configuration row has always meant and never had:
/// before netune gained a datagram path there was nothing to probe with, so the
/// row was dead. A QUIC-only node (hysteria2, tuic) cannot be health-checked over
/// TCP at all, and a node whose TCP handshake succeeds can still drop UDP, so a
/// TCP check cannot stand in for this one.
pub struct UdpDnsChecker {
    connector: UdpConnector,
    timeout: Duration,
}

impl fmt::Debug for UdpDnsChecker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UdpDnsChecker")
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl UdpDnsChecker {
    pub fn new(timeout: Duration) -> Self {
        Self {
            connector: UdpConnector::new().with_connect_timeout(Some(timeout)),
            timeout,
        }
    }

    /// Probes `addr` by sending one DNS query and waiting for a reply.
    ///
    /// The reply is not parsed beyond its header: this measures reachability and
    /// latency, not an answer. Reading the 12-byte header is enough to tell a DNS
    /// server from a host that echoes, and it does not pull a DNS codec into the
    /// outbound crate — `daer-dns` depends on `daer-routing`, so importing it here
    /// would drag the routing and geodata crates into every outbound build for the
    /// sake of one probe.
    ///
    /// # Errors
    ///
    /// [`CheckError::Timeout`] when no reply arrives in time, and
    /// [`CheckError::Request`] when the transport fails or the peer answers
    /// something that cannot be a DNS response.
    pub async fn check(&self, addr: SocketAddr) -> Result<TimeSpan, CheckError> {
        let recorder = Arc::new(Mutex::new(Recorder::start(64)));
        let started = Instant::now();

        let session = timeout(
            self.timeout,
            self.connector.connect(&addr.to_string(), &recorder),
        )
        .await
        .map_err(|_| CheckError::Timeout)?
        .map_err(|err| CheckError::Request(err.to_string()))?;

        let query = dns_probe_query();
        timeout(self.timeout, session.datagrams.send(&query))
            .await
            .map_err(|_| CheckError::Timeout)?
            .map_err(|err| CheckError::Request(err.to_string()))?;

        // A DNS/UDP reply is at most 512 bytes without EDNS, but a server that
        // ignores the limit may send more; size from the session so the kernel
        // cannot truncate a reply into a false negative.
        let mut buffer = vec![0u8; session.datagrams.max_datagram_size().clamp(512, 4096)];
        let received = timeout(self.timeout, session.datagrams.recv(&mut buffer))
            .await
            .map_err(|_| CheckError::Timeout)?
            .map_err(|err| CheckError::Request(err.to_string()))?;

        let elapsed = started.elapsed();
        drop(session);

        if !is_dns_response(&buffer[..received]) {
            return Err(CheckError::Request(format!(
                "{addr} answered {} bytes that are not a DNS response",
                received
            )));
        }
        Ok(TimeSpan::from_nanos(elapsed.as_nanos() as i64))
    }
}

/// The probe query: `A` for `example.com`, ID 0, recursion desired.
///
/// A fixed, well-known name so the probe cannot be distinguished from ordinary
/// traffic by a node under test, and so no answer is ever needed from a cache
/// that happens to be warm.
fn dns_probe_query() -> Vec<u8> {
    let mut query = Vec::with_capacity(29);
    query.extend_from_slice(&0u16.to_be_bytes()); // ID
    query.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: RD
    query.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    query.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    query.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    query.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    for label in ["example", "com"] {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0); // root
    query.extend_from_slice(&1u16.to_be_bytes()); // QTYPE A
    query.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
    query
}

/// Whether `datagram` can be a DNS response: it has a header, and the QR bit says
/// "response".
///
/// Deliberately shallow. The probe's question is "did a DNS-speaking host answer
/// in time", and a full parse would be a codec this crate does not own.
fn is_dns_response(datagram: &[u8]) -> bool {
    const HEADER_LEN: usize = 12;
    // QR is the top bit of byte 2.
    datagram.len() >= HEADER_LEN && datagram[2] & 0x80 != 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, UdpSocket};

    #[test]
    fn parses_check_urls() {
        let url = CheckUrl::parse("http://cp.cloudflare.com").expect("parses");
        assert_eq!(url.scheme(), Scheme::Http);
        assert_eq!(url.host(), "cp.cloudflare.com");
        assert_eq!(url.port(), 80);
        assert_eq!(url.path(), "/");
        assert_eq!(url.host_header(), "cp.cloudflare.com");

        let url = CheckUrl::parse("https://example.com:8443/generate_204").expect("parses");
        assert_eq!(url.scheme(), Scheme::Https);
        assert_eq!(url.port(), 8443);
        assert_eq!(url.path(), "/generate_204");
        assert_eq!(url.host_header(), "example.com:8443");

        let url = CheckUrl::parse("https://[2001:db8::1]:443/").expect("parses");
        assert_eq!(url.host(), "2001:db8::1");
        assert_eq!(url.port(), 443);
    }

    #[test]
    fn rejects_unusable_check_urls() {
        assert!(CheckUrl::parse("cp.cloudflare.com").is_err());
        assert!(CheckUrl::parse("ftp://example.com").is_err());
        assert!(CheckUrl::parse("http://:80").is_err());
        assert!(CheckUrl::parse("http://example.com:notaport").is_err());
    }

    #[tokio::test]
    async fn http_check_measures_a_real_request() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("binds");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accepts");
            let mut buffer = [0u8; 1024];
            let _ = stream.read(&mut buffer).await;
            let _ = stream
                .write_all(b"HTTP/1.1 204 No Content\r\ncontent-length: 0\r\n\r\n")
                .await;
            let _ = stream.shutdown().await;
        });

        let url = CheckUrl::parse(&format!("http://example.com:{}/", addr.port())).expect("parses");
        let checker = HttpChecker::new(HttpMethod::Head, Duration::from_secs(2));
        let latency = checker.check(&url, addr.ip()).await.expect("checks");
        assert!(latency.as_nanos() > 0);
    }

    #[tokio::test]
    async fn http_check_times_out() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("binds");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.expect("accepts");
            tokio::time::sleep(Duration::from_secs(30)).await;
        });

        let url = CheckUrl::parse(&format!("http://example.com:{}/", addr.port())).expect("parses");
        let checker = HttpChecker::new(HttpMethod::Head, Duration::from_millis(100));
        let error = checker.check(&url, addr.ip()).await.expect_err("times out");
        assert_eq!(error, CheckError::Timeout);
    }

    #[tokio::test]
    async fn udp_dns_check_measures_a_query_round_trip() {
        // A minimal DNS server: read one query, answer it as a response with the
        // same ID, so the probe's header check is exercised on the happy path.
        let server = UdpSocket::bind("127.0.0.1:0").await.expect("binds");
        let addr = server.local_addr().expect("addr");
        tokio::spawn(async move {
            let mut buffer = [0u8; 512];
            let (received, from) = server.recv_from(&mut buffer).await.expect("recv");
            let mut reply = buffer[..received].to_vec();
            reply[2] |= 0x80; // QR = response
            let _ = server.send_to(&reply, from).await;
        });

        let checker = UdpDnsChecker::new(Duration::from_secs(2));
        let latency = checker.check(addr).await.expect("checks");
        assert!(latency.as_nanos() > 0);
    }

    #[tokio::test]
    async fn udp_dns_check_times_out_when_nothing_answers() {
        // Bind but never reply: the deadline must fire rather than hang the
        // health check forever.
        let server = UdpSocket::bind("127.0.0.1:0").await.expect("binds");
        let addr = server.local_addr().expect("addr");
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(30)).await;
        });

        let checker = UdpDnsChecker::new(Duration::from_millis(100));
        let error = checker.check(addr).await.expect_err("times out");
        assert_eq!(error, CheckError::Timeout);
    }

    #[tokio::test]
    async fn udp_dns_check_refuses_a_non_dns_reply() {
        // A host that echoes the query verbatim is not a DNS server: the QR bit
        // is clear, so the answer must be rejected rather than counted as a
        // healthy node.
        let server = UdpSocket::bind("127.0.0.1:0").await.expect("binds");
        let addr = server.local_addr().expect("addr");
        tokio::spawn(async move {
            let mut buffer = [0u8; 512];
            let (received, from) = server.recv_from(&mut buffer).await.expect("recv");
            let _ = server.send_to(&buffer[..received], from).await;
        });

        let checker = UdpDnsChecker::new(Duration::from_secs(2));
        let error = checker
            .check(addr)
            .await
            .expect_err("echo is not a response");
        assert!(
            matches!(&error, CheckError::Request(message) if message.contains("not a DNS response")),
            "{error}"
        );
    }

    #[test]
    fn the_probe_query_is_a_well_formed_a_question() {
        let query = dns_probe_query();
        assert_eq!(query.len(), 29);
        assert_eq!(&query[0..2], &[0, 0], "ID 0");
        assert_eq!(&query[2..4], &[0x01, 0x00], "RD set, QR clear");
        assert_eq!(&query[4..6], &[0, 1], "one question");
        assert_eq!(&query[12..13], &[7], "first label length");
        assert_eq!(&query[13..20], b"example");
        assert_eq!(&query[20..21], &[3]);
        assert_eq!(&query[21..24], b"com");
        assert_eq!(query[24], 0, "root label");
        assert_eq!(&query[25..27], &[0, 1], "QTYPE A");
        assert_eq!(&query[27..29], &[0, 1], "QCLASS IN");
    }

    #[test]
    fn a_response_is_recognised_by_its_qr_bit_only() {
        // Header present, QR set.
        assert!(is_dns_response(&[0, 0, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]));
        // QR clear: a query, not a response.
        assert!(!is_dns_response(&[
            0, 0, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0
        ]));
        // Too short to hold a header.
        assert!(!is_dns_response(&[0, 0, 0x81]));
        assert!(!is_dns_response(&[]));
    }

    #[tokio::test]
    async fn tcp_check_measures_a_handshake() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("binds");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.expect("accepts");
        });

        let checker = TcpChecker::new(Duration::from_secs(2));
        let latency = checker.check(addr).await.expect("checks");
        assert!(latency.as_nanos() > 0);
    }

    #[tokio::test]
    async fn tcp_check_reports_a_refused_connection() {
        // Bind then drop to get a port that is almost certainly closed.
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("binds");
        let addr = listener.local_addr().expect("addr");
        drop(listener);

        let checker = TcpChecker::new(Duration::from_millis(500));
        assert!(checker.check(addr).await.is_err());
    }
}
