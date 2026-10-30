// SPDX-License-Identifier: AGPL-3.0-only

//! The server side: accept queries, answer them.
//!
//! ```text
//!   client ──udp──▶ [socket] ──▶ Resolver::resolve ──▶ [socket] ──udp──▶ client
//!          ──tcp──▶ [socket] ──▶       │                    └──tcp──▶
//!                                     └─ AsIs ─▶ no reply at all
//! ```
//!
//! # Why this is daer's and not netune's
//!
//! netune supplies a *client* resolver for its own dialing. A transparent proxy has to
//! answer arbitrary clients, so the server role — the socket, the framing, the decision to
//! stay silent — is this crate's ([ADR-0002](../../../docs/adr/0002-netune-boundary.md)).
//!
//! # `AsIs` means silence
//!
//! `[dns.request]` can decide `asis`: "let the client's own resolver do it". A datagram
//! server expresses that by **not replying** — the client's resolver, not this process, is
//! what should answer. Sending a refusal instead would be a different decision, and one the
//! operator did not make.
//!
//! # UDP and TCP differ in more than framing
//!
//! * a UDP reply is one datagram capped at the client's advertised EDNS size (512 bytes
//!   without EDNS), so a large answer must set `TC` rather than be truncated silently —
//!   a silently truncated answer parses as a valid, wrong answer;
//! * a TCP connection may carry several queries in sequence, so the loop reads until the
//!   peer stops writing or a query limit is reached.
//!
//! Both are stated in code rather than left to the reader, because "the answer is
//! truncated" and "the answer is wrong" are indistinguishable to a client that did not get
//! the `TC` bit.

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use crate::resolver::{Resolution, Resolver, ResolverError};
use crate::wire::{self, Message, ResponseCode};

/// A DNS datagram payload ceiling without EDNS0 (RFC 1035 §2.3.4).
pub const UDP_PLAIN_LIMIT: usize = 512;

/// The largest payload this server will ever put in one datagram.
///
/// 4096 is the common EDNS0 buffer size; a client that advertises more is likely to
/// fragment anyway, so a bigger reply is better answered over TCP.
pub const UDP_MAX_LIMIT: usize = 4096;

/// How long one exchange may take, from the client's point of view.
///
/// A client that has not been answered in this long has already retried: holding the slot
/// longer turns one slow query into two.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// How many queries one TCP connection may carry before it is closed.
///
/// A connection is not a query stream a client is entitled to hold forever; the bound
/// keeps one client from pinning a task indefinitely.
pub const TCP_QUERIES_PER_CONNECTION: usize = 32;

/// Why the server could not be started.
#[derive(Debug)]
pub enum ServerError {
    /// A socket could not be bound.
    Bind {
        address: SocketAddr,
        source: io::Error,
    },
    /// Accepting failed in a way that ends the loop.
    Accept(io::Error),
}

impl fmt::Display for ServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bind { address, source } => write!(f, "cannot bind {address}: {source}"),
            Self::Accept(error) => write!(f, "accept failed: {error}"),
        }
    }
}

impl std::error::Error for ServerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Bind { source, .. } => Some(source),
            Self::Accept(error) => Some(error),
        }
    }
}

/// The advertised EDNS0 payload size, or the plain limit.
///
/// Read from the OPT record when the client sent one. A client that advertises a size above
/// [`UDP_MAX_LIMIT`] gets [`UDP_MAX_LIMIT`]: honouring a larger claim risks fragmentation,
/// and fragmentation on DNS is a reliability problem, not a throughput win.
#[must_use]
pub fn udp_payload_limit(query: &Message) -> usize {
    query
        .additionals
        .iter()
        .find(|record| record.is_opt())
        .map_or(UDP_PLAIN_LIMIT, |record| {
            // For OPT, the class field carries the sender's UDP payload size.
            usize::from(record.class).clamp(UDP_PLAIN_LIMIT, UDP_MAX_LIMIT)
        })
}

/// Encodes `answer` for a UDP client, setting `TC` if it does not fit.
///
/// Returns `None` only when even the truncated header cannot be encoded, which cannot
/// happen for a message this crate built.
#[must_use]
pub fn encode_datagram(answer: &Message, limit: usize) -> Option<Vec<u8>> {
    let encoded = wire::encode(answer);
    if encoded.len() <= limit {
        return Some(encoded);
    }

    // Too large: send the header and question with TC set, so the client retries over TCP.
    // A silently shortened answer would parse as a valid but *wrong* answer.
    let mut truncated = answer.clone();
    truncated.flags = wire::Flags(answer.flags.0 | 0x0200);
    truncated.answers.clear();
    truncated.authorities.clear();
    truncated.additionals.retain(|record| record.is_opt());
    Some(wire::encode(&truncated))
}

/// Serves UDP queries until `shutdown` resolves.
///
/// # Errors
///
/// Returns [`ServerError`] when the socket cannot be bound or accepting fails.
pub async fn serve_udp(
    resolver: Arc<Resolver>,
    address: SocketAddr,
    shutdown: impl Future<Output = ()>,
) -> Result<(), ServerError> {
    let socket = UdpSocket::bind(address)
        .await
        .map_err(|source| ServerError::Bind { address, source })?;
    tracing::info!(address = %address, "dns udp server listening");
    serve_udp_on(socket, resolver, shutdown).await
}

/// Serves UDP queries on an already-bound socket.
///
/// Split from [`serve_udp`] so a test can bind port 0 and learn the port before serving.
///
/// # Errors
///
/// Returns [`ServerError::Accept`] when a receive fails for a reason other than a
/// transient one.
pub async fn serve_udp_on(
    socket: UdpSocket,
    resolver: Arc<Resolver>,
    shutdown: impl Future<Output = ()>,
) -> Result<(), ServerError> {
    let socket = Arc::new(socket);
    let mut buffer = vec![0u8; 65_535];
    tokio::pin!(shutdown);

    loop {
        let (read, peer) = tokio::select! {
            () = &mut shutdown => {
                tracing::info!("dns udp server stopping");
                return Ok(());
            }
            received = socket.recv_from(&mut buffer) => match received {
                Ok(pair) => pair,
                Err(error) if is_transient(&error) => {
                    tracing::debug!(%error, "transient udp receive error");
                    continue;
                }
                Err(error) => return Err(ServerError::Accept(error)),
            },
        };

        let Ok(query) = wire::parse(&buffer[..read]) else {
            // A malformed datagram has no id to answer to; dropping it is the only
            // correct response.
            tracing::debug!(peer = %peer, bytes = read, "dropped a malformed dns datagram");
            continue;
        };

        let limit = udp_payload_limit(&query);
        let resolver = Arc::clone(&resolver);
        let socket = Arc::clone(&socket);
        tokio::spawn(async move {
            match tokio::time::timeout(REQUEST_TIMEOUT, resolver.resolve(&query)).await {
                Ok(Ok(Resolution::Answer(answer))) => {
                    if let Some(bytes) = encode_datagram(&answer, limit)
                        && let Err(error) = socket.send_to(&bytes, peer).await
                    {
                        tracing::debug!(%error, peer = %peer, "udp send failed");
                    }
                }
                Ok(Ok(Resolution::AsIs)) => {
                    // Silence is the correct expression of `asis` on a datagram socket.
                    tracing::trace!(peer = %peer, "asis: no reply");
                }
                Ok(Err(error)) => {
                    tracing::debug!(%error, peer = %peer, "dns resolution failed");
                }
                Err(_) => {
                    tracing::debug!(peer = %peer, "dns resolution timed out");
                }
            }
        });
    }
}

/// Serves TCP queries until `shutdown` resolves.
///
/// # Errors
///
/// Returns [`ServerError`] when the listener cannot be bound or accepting fails.
pub async fn serve_tcp(
    resolver: Arc<Resolver>,
    address: SocketAddr,
    shutdown: impl Future<Output = ()>,
) -> Result<(), ServerError> {
    let listener = TcpListener::bind(address)
        .await
        .map_err(|source| ServerError::Bind { address, source })?;
    tracing::info!(address = %address, "dns tcp server listening");
    serve_tcp_on(listener, resolver, shutdown).await
}

/// Serves TCP queries on an already-bound listener.
///
/// # Errors
///
/// Returns [`ServerError::Accept`] when accepting fails.
pub async fn serve_tcp_on(
    listener: TcpListener,
    resolver: Arc<Resolver>,
    shutdown: impl Future<Output = ()>,
) -> Result<(), ServerError> {
    tokio::pin!(shutdown);
    loop {
        let (stream, peer) = tokio::select! {
            () = &mut shutdown => {
                tracing::info!("dns tcp server stopping");
                return Ok(());
            }
            accepted = listener.accept() => match accepted {
                Ok(pair) => pair,
                Err(error) if is_transient(&error) => {
                    tracing::debug!(%error, "transient tcp accept error");
                    continue;
                }
                Err(error) => return Err(ServerError::Accept(error)),
            },
        };

        let resolver = Arc::clone(&resolver);
        tokio::spawn(async move {
            if let Err(error) = handle_tcp_connection(stream, peer, resolver).await {
                tracing::debug!(%error, peer = %peer, "dns tcp connection ended");
            }
        });
    }
}

/// Serves one TCP connection: a sequence of length-prefixed queries.
async fn handle_tcp_connection(
    mut stream: TcpStream,
    peer: SocketAddr,
    resolver: Arc<Resolver>,
) -> io::Result<()> {
    stream.set_nodelay(true)?;
    for _ in 0..TCP_QUERIES_PER_CONNECTION {
        let mut length = [0u8; 2];
        match stream.read_exact(&mut length).await {
            Ok(_) => {}
            // The peer closed cleanly between queries: a normal end.
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(error) => return Err(error),
        }
        let length = usize::from(u16::from_be_bytes(length));
        let mut body = vec![0u8; length];
        stream.read_exact(&mut body).await?;

        let Ok(query) = wire::parse(&body) else {
            // Without a parseable query there is no id to echo; closing is the honest
            // response, and the client will retry.
            tracing::debug!(%peer, "dropped a malformed dns query over tcp");
            return Ok(());
        };

        let answer = match tokio::time::timeout(REQUEST_TIMEOUT, resolver.resolve(&query)).await {
            Ok(Ok(Resolution::Answer(answer))) => answer,
            Ok(Ok(Resolution::AsIs)) => {
                // On TCP, `asis` also means silence: the connection stays open in case the
                // client asks something else, but no reply is written.
                tracing::trace!(%peer, "asis: no reply");
                continue;
            }
            Ok(Err(error)) => {
                tracing::debug!(%error, %peer, "dns resolution failed");
                Message::reply_to(&query, ResponseCode::SERVFAIL)
            }
            Err(_) => {
                tracing::debug!(%peer, "dns resolution timed out");
                Message::reply_to(&query, ResponseCode::SERVFAIL)
            }
        };

        let encoded = wire::encode(&answer);
        let Ok(length) = u16::try_from(encoded.len()) else {
            // A reply over 64 KiB cannot be framed; SERVFAIL is the only answer that fits.
            let fallback = wire::encode(&Message::reply_to(&query, ResponseCode::SERVFAIL));
            stream
                .write_all(&(fallback.len() as u16).to_be_bytes())
                .await?;
            stream.write_all(&fallback).await?;
            continue;
        };
        stream.write_all(&length.to_be_bytes()).await?;
        stream.write_all(&encoded).await?;
    }
    Ok(())
}

/// True for errors that mean "try again", not "the socket is broken".
fn is_transient(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock
            | io::ErrorKind::Interrupted
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionReset
    ) || matches!(
        error.raw_os_error(),
        Some(libc::ENOBUFS) | Some(libc::ENOMEM) | Some(libc::EMFILE) | Some(libc::ENFILE)
    )
}

/// What a resolution failure becomes for the client.
///
/// Exposed because it is a contract: an unserviceable query still gets an answer, so a
/// client does not retry into the same failure.
#[must_use]
pub fn failure_reply(query: &Message, error: &ResolverError) -> Message {
    let code = match error {
        ResolverError::Unserviceable(code) => *code,
        // A configuration or transport problem is a service failure from the client's
        // point of view: it cannot be fixed by retrying with different content.
        _ => ResponseCode::SERVFAIL,
    };
    Message::reply_to(query, code)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{Flags, Name, Question, Record, RecordType};
    use std::net::Ipv4Addr;

    fn query(edns_size: Option<u16>) -> Message {
        let mut query = Message {
            id: 0x1234,
            flags: Flags(0x0100),
            questions: vec![Question::internet(
                Name::parse("example.com").expect("name"),
                RecordType::A,
            )],
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        };
        if let Some(size) = edns_size {
            query.additionals.push(Record {
                name: Name::root(),
                rtype: RecordType::OPT,
                class: size,
                ttl: 0,
                rdata: Vec::new(),
            });
        }
        query
    }

    fn answer(records: usize) -> Message {
        let name = Name::parse("example.com").expect("name");
        Message {
            id: 0x1234,
            flags: Flags(0x8180),
            questions: vec![Question::internet(name.clone(), RecordType::A)],
            answers: (0..records)
                .map(|index| Record {
                    name: name.clone(),
                    rtype: RecordType::A,
                    class: Question::CLASS_IN,
                    ttl: 60,
                    rdata: vec![93, 184, 216, index as u8],
                })
                .collect(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        }
    }

    #[test]
    fn the_plain_limit_applies_without_edns() {
        let query = query(None);
        assert_eq!(udp_payload_limit(&query), UDP_PLAIN_LIMIT);
    }

    #[test]
    fn an_edns_size_is_honoured_up_to_the_maximum() {
        assert_eq!(udp_payload_limit(&query(Some(1232))), 1232);
        // Below 512 is not a real EDNS size; the floor protects the client.
        assert_eq!(udp_payload_limit(&query(Some(100))), UDP_PLAIN_LIMIT);
        // Above the maximum would fragment; cap it.
        assert_eq!(udp_payload_limit(&query(Some(9000))), UDP_MAX_LIMIT);
    }

    #[test]
    fn a_small_answer_is_sent_whole() {
        let encoded = encode_datagram(&answer(2), UDP_PLAIN_LIMIT).expect("encodes");
        let parsed = wire::parse(&encoded).expect("parses");
        assert_eq!(parsed.answers.len(), 2);
        assert_eq!(parsed.flags.0 & 0x0200, 0, "not truncated");
    }

    #[test]
    fn an_oversized_answer_sets_tc_instead_of_being_cut() {
        // A silently shortened answer parses as a valid, wrong answer; TC tells the client
        // to retry over TCP.
        let encoded = encode_datagram(&answer(60), UDP_PLAIN_LIMIT).expect("encodes");
        assert!(encoded.len() <= UDP_PLAIN_LIMIT);
        let parsed = wire::parse(&encoded).expect("parses");
        assert_eq!(parsed.flags.0 & 0x0200, 0x0200, "TC must be set");
        assert!(parsed.answers.is_empty());
        assert_eq!(
            parsed.questions.len(),
            1,
            "the question must survive so the client can match the reply"
        );
        assert_eq!(parsed.id, 0x1234);
    }

    #[test]
    fn transient_errors_are_not_fatal() {
        for kind in [
            io::ErrorKind::WouldBlock,
            io::ErrorKind::Interrupted,
            io::ErrorKind::ConnectionReset,
        ] {
            assert!(is_transient(&io::Error::from(kind)));
        }
        assert!(!is_transient(&io::Error::from(
            io::ErrorKind::PermissionDenied
        )));
    }

    #[test]
    fn a_failure_reply_keeps_the_question_and_sets_a_code() {
        let query = query(None);
        let reply = failure_reply(&query, &ResolverError::Unserviceable(ResponseCode::FORMERR));
        assert_eq!(reply.id, query.id);
        assert_eq!(reply.response_code(), ResponseCode::FORMERR);
        assert_eq!(reply.questions, query.questions);
    }

    /// A resolver whose upstream is a fake that answers immediately.
    fn resolver() -> Arc<Resolver> {
        use crate::resolver::{ExchangeFuture, Upstream};
        use std::sync::atomic::AtomicUsize;

        #[derive(Debug)]
        struct Echo(AtomicUsize);
        impl Upstream for Echo {
            fn exchange<'a>(&'a self, _query: &'a Message) -> ExchangeFuture<'a> {
                Box::pin(async move {
                    self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    Ok(answer(1))
                })
            }
        }

        let config = daer_config::toml_config::load_str(
            r#"
[dns]
upstream = ["local:tcp://127.0.0.1:1"]

[dns.request]
rules = ["qname(suffix: asis) -> asis", "qname(suffix: reject) -> reject"]
fallback = "local"
"#,
        )
        .expect("config loads");
        Arc::new(
            Resolver::new(
                &config,
                [(
                    "local".to_owned(),
                    Arc::new(Echo(AtomicUsize::new(0))) as Arc<dyn Upstream>,
                )],
            )
            .expect("builds"),
        )
    }

    async fn udp_server() -> SocketAddr {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("binds");
        let address = socket.local_addr().expect("addr");
        let resolver = resolver();
        tokio::spawn(async move {
            let _ = serve_udp_on(socket, resolver, std::future::pending()).await;
        });
        address
    }

    async fn ask_udp(address: SocketAddr, request: &Message) -> Vec<u8> {
        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("binds");
        client
            .send_to(&wire::encode(request), address)
            .await
            .expect("sends");
        let mut buffer = vec![0u8; 4096];
        let (read, _) = tokio::time::timeout(Duration::from_secs(3), client.recv_from(&mut buffer))
            .await
            .expect("a reply must arrive")
            .expect("receives");
        buffer.truncate(read);
        buffer
    }

    #[tokio::test]
    async fn a_udp_query_is_answered() {
        let address = udp_server().await;
        let reply = wire::parse(&ask_udp(address, &query(None)).await).expect("parses");
        assert_eq!(reply.id, 0x1234);
        assert!(reply.is_response());
        assert_eq!(reply.response_code(), ResponseCode::NOERROR);
        assert_eq!(reply.answers.len(), 1);
    }

    #[tokio::test]
    async fn a_rejected_query_is_answered_refused() {
        let address = udp_server().await;
        let mut request = query(None);
        request.questions = vec![Question::internet(
            Name::parse("x.reject").expect("name"),
            RecordType::A,
        )];
        let reply = wire::parse(&ask_udp(address, &request).await).expect("parses");
        assert_eq!(reply.response_code(), ResponseCode::REFUSED);
    }

    #[tokio::test]
    async fn an_asis_query_gets_no_reply() {
        // Silence is the decision: the client's own resolver is what should answer.
        let address = udp_server().await;
        let mut request = query(None);
        request.questions = vec![Question::internet(
            Name::parse("x.asis").expect("name"),
            RecordType::A,
        )];

        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("binds");
        client
            .send_to(&wire::encode(&request), address)
            .await
            .expect("sends");
        let mut buffer = vec![0u8; 512];
        let result =
            tokio::time::timeout(Duration::from_millis(300), client.recv_from(&mut buffer)).await;
        assert!(result.is_err(), "asis must not produce a reply");
    }

    #[tokio::test]
    async fn a_malformed_datagram_is_dropped_without_a_crash() {
        let address = udp_server().await;
        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("binds");
        client
            .send_to(b"not a dns message", address)
            .await
            .expect("sends");
        let mut buffer = vec![0u8; 512];
        let result =
            tokio::time::timeout(Duration::from_millis(300), client.recv_from(&mut buffer)).await;
        assert!(result.is_err(), "a malformed datagram has no id to answer");

        // The server is still working: a valid query is answered afterwards.
        let reply = wire::parse(&ask_udp(address, &query(None)).await).expect("parses");
        assert_eq!(reply.response_code(), ResponseCode::NOERROR);
    }

    #[tokio::test]
    async fn a_tcp_connection_carries_several_queries() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("binds");
        let address = listener.local_addr().expect("addr");
        let resolver = resolver();
        tokio::spawn(async move {
            let _ = serve_tcp_on(listener, resolver, std::future::pending()).await;
        });

        let mut stream = TcpStream::connect(address).await.expect("connects");
        for id in [1u16, 2, 3] {
            let mut request = query(None);
            request.id = id;
            let encoded = wire::encode(&request);
            stream
                .write_all(&(encoded.len() as u16).to_be_bytes())
                .await
                .expect("writes length");
            stream.write_all(&encoded).await.expect("writes body");

            let mut length = [0u8; 2];
            stream.read_exact(&mut length).await.expect("reads length");
            let mut body = vec![0u8; usize::from(u16::from_be_bytes(length))];
            stream.read_exact(&mut body).await.expect("reads body");
            let reply = wire::parse(&body).expect("parses");
            assert_eq!(reply.id, id, "each reply carries its own query's id");
            assert_eq!(reply.answers.len(), 1);
        }
    }

    #[tokio::test]
    async fn closing_a_tcp_connection_ends_only_that_connection() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("binds");
        let address = listener.local_addr().expect("addr");
        let resolver = resolver();
        tokio::spawn(async move {
            let _ = serve_tcp_on(listener, resolver, std::future::pending()).await;
        });

        // First connection: open and abandon without a query.
        let aborted = TcpStream::connect(address).await.expect("connects");
        drop(aborted);

        // Second connection still works.
        let mut stream = TcpStream::connect(address).await.expect("connects");
        let encoded = wire::encode(&query(None));
        stream
            .write_all(&(encoded.len() as u16).to_be_bytes())
            .await
            .expect("writes");
        stream.write_all(&encoded).await.expect("writes");
        let mut length = [0u8; 2];
        stream.read_exact(&mut length).await.expect("reads");
        assert!(u16::from_be_bytes(length) > 0);
    }
}
