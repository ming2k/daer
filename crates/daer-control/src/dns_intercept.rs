// SPDX-License-Identifier: AGPL-3.0-only

//! In-process transparent `:53` interception into [`daer_dns::Resolver`] (ADR-0054).
//!
//! When `[dns]` interception is active, `:53` UDP and TCP flows arriving at the control
//! plane are answered by `daer-dns::Resolver` without requiring `[dns].bind` or host
//! `/etc/resolv.conf` modifications. Queries whose `[dns.request]` policy evaluates to
//! `asis` are handed back to normal `[routing]` without consuming stream bytes.

use std::fmt;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use daer_dns::Resolver;
use daer_outbound::Upstream;
use daer_relay::relay::DatagramLeg;
use daer_relay::{Accepted, FlowFacts, RelayError};
use netune::{DatagramConnector, DatagramTransport, EstablishedDatagrams, NetError};
use netune_trace::TraceCollector;
use tokio::net::TcpStream;
use tokio::sync::{Mutex, mpsc};

/// Port intercepted for transparent DNS resolution.
pub const DNS_PORT: u16 = 53;

/// Maximum time spent peeking the first TCP DNS query for an `asis` check.
const TCP_PEEK_BUDGET: Duration = Duration::from_millis(50);

/// Interval between TCP peek retries while waiting for the first query bytes.
const TCP_PEEK_INTERVAL: Duration = Duration::from_millis(2);

/// Maximum size of a single DNS-over-TCP message peeked for `asis` detection.
const MAX_TCP_PEEK_BYTES: usize = 2 + daer_dns::UDP_MAX_LIMIT;

/// Bounded queue depth for replies produced by one intercepted UDP DNS session.
const SESSION_REPLY_CAPACITY: usize = 64;

/// Duplex buffer size for an intercepted TCP DNS stream.
const TCP_DUPLEX_BUFFER: usize = 65_536;

/// Attempts to intercept a UDP `:53` flow into `resolver`.
///
/// Returns `None` when the initial datagram parses as a DNS query whose `[dns.request]`
/// policy evaluates to `asis`, allowing the caller to fall through to normal `[routing]`.
#[must_use]
pub fn try_intercept_datagram(
    facts: FlowFacts,
    payload: &[u8],
    resolver: &Arc<Resolver>,
) -> Option<DatagramLeg> {
    if let Ok(query) = daer_dns::wire::parse(payload)
        && resolver.is_asis(&query)
    {
        return None;
    }

    Some(DatagramLeg {
        target: facts.destination.to_string(),
        connector: Arc::new(DnsDatagramConnector {
            resolver: Arc::clone(resolver),
            peer: facts.source,
        }),
    })
}

/// Attempts to intercept a TCP `:53` flow into `resolver`.
///
/// Peeks the first length-prefixed query without consuming bytes from `flow.stream`.
/// Returns `Ok(None)` when `[dns.request]` evaluates that query to `asis`, leaving
/// `flow.stream` intact for normal outbound dialing.
///
/// # Errors
///
/// Currently infallible (`Ok(...)`), returning `Result` to match `Router::resolve`.
pub async fn try_intercept_tcp(
    flow: &Accepted,
    resolver: &Arc<Resolver>,
) -> Result<Option<Upstream>, RelayError> {
    if peek_is_asis(&flow.stream, resolver).await {
        return Ok(None);
    }

    let (client_half, server_half) = tokio::io::duplex(TCP_DUPLEX_BUFFER);
    let resolver = Arc::clone(resolver);
    let peer = flow.source;
    tokio::spawn(async move {
        if let Err(error) = daer_dns::serve_tcp_stream(server_half, peer, resolver).await {
            daer_observe::debug!(
                daer_observe::EventCode::DnsTcpConnectionEnded,
                %error,
                peer = %peer,
                "intercepted dns tcp stream ended"
            );
        }
    });

    Ok(Some(Box::new(client_half)))
}

/// Peeks the first length-prefixed DNS query on `stream` without consuming it.
async fn peek_is_asis(stream: &TcpStream, resolver: &Resolver) -> bool {
    let deadline = Instant::now() + TCP_PEEK_BUDGET;
    let mut buffer = vec![0u8; MAX_TCP_PEEK_BYTES];

    loop {
        match stream.peek(&mut buffer).await {
            Ok(0) => return false,
            Ok(read) if read >= 2 => {
                let length = usize::from(u16::from_be_bytes([buffer[0], buffer[1]]));
                if length == 0 || 2 + length > buffer.len() {
                    return false;
                }
                if read >= 2 + length {
                    return daer_dns::wire::parse(&buffer[2..2 + length])
                        .is_ok_and(|query| resolver.is_asis(&query));
                }
            }
            Ok(_) => {}
            Err(_) => return false,
        }

        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(TCP_PEEK_INTERVAL).await;
    }
}

/// In-process [`DatagramConnector`] that answers UDP `:53` queries via [`Resolver`].
struct DnsDatagramConnector {
    resolver: Arc<Resolver>,
    peer: SocketAddr,
}

impl fmt::Debug for DnsDatagramConnector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DnsDatagramConnector")
            .field("peer", &self.peer)
            .finish_non_exhaustive()
    }
}

impl DatagramConnector for DnsDatagramConnector {
    fn connect<'a>(
        &'a self,
        _authority: &'a str,
        _recorder: &'a TraceCollector,
    ) -> Pin<Box<dyn Future<Output = Result<EstablishedDatagrams, NetError>> + Send + 'a>> {
        let session = DnsDatagramSession::new(Arc::clone(&self.resolver), self.peer);
        Box::pin(async move {
            Ok(EstablishedDatagrams {
                datagrams: Box::new(session),
                local_port: None,
            })
        })
    }
}

/// One client `(peer, destination)` UDP `:53` session answered by [`Resolver`].
struct DnsDatagramSession {
    resolver: Arc<Resolver>,
    peer: SocketAddr,
    tx: mpsc::Sender<Vec<u8>>,
    rx: Mutex<mpsc::Receiver<Vec<u8>>>,
}

impl DnsDatagramSession {
    fn new(resolver: Arc<Resolver>, peer: SocketAddr) -> Self {
        let (tx, rx) = mpsc::channel(SESSION_REPLY_CAPACITY);
        Self {
            resolver,
            peer,
            tx,
            rx: Mutex::new(rx),
        }
    }
}

impl DatagramTransport for DnsDatagramSession {
    fn send<'a>(
        &'a self,
        payload: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Result<usize, io::Error>> + Send + 'a>> {
        Box::pin(async move {
            if let Some(reply) =
                daer_dns::resolve_datagram(&self.resolver, payload, self.peer).await
            {
                // Drop excess replies if a peer floods faster than the reply pump drains;
                // UDP is best-effort and must never stall the ingress loop.
                let _ = self.tx.try_send(reply);
            }
            Ok(payload.len())
        })
    }

    fn recv<'a>(
        &'a self,
        buffer: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = Result<usize, io::Error>> + Send + 'a>> {
        Box::pin(async move {
            let Some(reply) = self.rx.lock().await.recv().await else {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "dns datagram session closed",
                ));
            };
            if reply.len() > buffer.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "dns reply exceeds datagram buffer",
                ));
            }
            buffer[..reply.len()].copy_from_slice(&reply);
            Ok(reply.len())
        })
    }

    fn max_datagram_size(&self) -> usize {
        daer_dns::UDP_MAX_LIMIT
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use daer_dns::wire::{Flags, Message, Name, Question, RecordType};
    use std::net::{Ipv4Addr, SocketAddrV4};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn test_resolver() -> Arc<Resolver> {
        let config = daer_config::toml_config::load_str(
            r#"
[dns]
upstream = ["unused:udp://127.0.0.1:53"]

[dns.request]
rules = ["qname(asis.test) -> asis", "qname(blocked.test) -> reject"]
default = "unused"

[dns.fake-ip]
enabled = true
"#,
        )
        .expect("config loads");
        Arc::new(Resolver::from_config(&config).expect("resolver builds"))
    }

    fn dns_query_bytes(domain: &str) -> Vec<u8> {
        let msg = Message {
            id: 0x4242,
            flags: Flags(0x0100),
            questions: vec![Question::internet(
                Name::parse(domain).expect("name"),
                RecordType::A,
            )],
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        };
        daer_dns::wire::encode(&msg)
    }

    fn sample_facts(dst_port: u16) -> FlowFacts {
        FlowFacts {
            flow_id: daer_observe::FlowId::new(1),
            source: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 54321)),
            destination: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), dst_port)),
        }
    }

    #[tokio::test]
    async fn udp_intercept_answers_fake_ip_and_yields_on_asis() {
        let resolver = test_resolver();
        let facts = sample_facts(53);

        // `asis.test` must NOT be hijacked: returns None so Router falls through.
        let asis_payload = dns_query_bytes("asis.test");
        assert!(try_intercept_datagram(facts, &asis_payload, &resolver).is_none());

        // `example.com` is hijacked and answered with a Fake-IP via DnsDatagramConnector.
        let query_payload = dns_query_bytes("example.com");
        let leg = try_intercept_datagram(facts, &query_payload, &resolver)
            .expect("non-asis query is intercepted");
        let collector = TraceCollector::start(0);
        let established = leg
            .connector
            .connect(&leg.target, &collector)
            .await
            .expect("in-process connector never fails");

        let sent = established
            .datagrams
            .send(&query_payload)
            .await
            .expect("send succeeds");
        assert_eq!(sent, query_payload.len());

        let mut buf = vec![0u8; 4096];
        let n = established
            .datagrams
            .recv(&mut buf)
            .await
            .expect("recv succeeds");
        let reply = daer_dns::wire::parse(&buf[..n]).expect("valid dns reply");
        assert_eq!(reply.id, 0x4242);
        assert_eq!(reply.answers.len(), 1);
    }

    #[tokio::test]
    async fn tcp_intercept_yields_on_asis_without_consuming_and_answers_otherwise() {
        let resolver = test_resolver();
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr");

        // Case 1: `asis.test` returns None and leaves every byte in the TcpStream.
        let asis_query = dns_query_bytes("asis.test");
        let mut client = TcpStream::connect(addr).await.expect("connect");
        let (server_stream, peer) = listener.accept().await.expect("accept");
        let mut framed = Vec::with_capacity(2 + asis_query.len());
        framed.extend_from_slice(&(asis_query.len() as u16).to_be_bytes());
        framed.extend_from_slice(&asis_query);
        client.write_all(&framed).await.expect("write");

        let accepted = Accepted {
            stream: server_stream,
            source: peer,
            destination: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 53)),
            flow_id: daer_observe::FlowId::new(2),
        };
        let intercepted = try_intercept_tcp(&accepted, &resolver).await.expect("ok");
        assert!(intercepted.is_none(), "asis must fall through");

        // Verify all bytes are still intact in `accepted.stream`.
        let mut read_back = vec![0u8; framed.len()];
        let mut stream = accepted.stream;
        stream.read_exact(&mut read_back).await.expect("unconsumed");
        assert_eq!(read_back, framed);

        // Case 2: `blocked.test` is intercepted and answered with REFUSED over duplex.
        let blocked_query = dns_query_bytes("blocked.test");
        let mut client2 = TcpStream::connect(addr).await.expect("connect2");
        let (server_stream2, peer2) = listener.accept().await.expect("accept2");
        let mut framed2 = Vec::with_capacity(2 + blocked_query.len());
        framed2.extend_from_slice(&(blocked_query.len() as u16).to_be_bytes());
        framed2.extend_from_slice(&blocked_query);
        client2.write_all(&framed2).await.expect("write2");
        client2.shutdown().await.expect("shutdown2");

        let accepted2 = Accepted {
            stream: server_stream2,
            source: peer2,
            destination: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 53)),
            flow_id: daer_observe::FlowId::new(3),
        };
        let mut upstream = try_intercept_tcp(&accepted2, &resolver)
            .await
            .expect("ok")
            .expect("non-asis tcp query must be intercepted");

        // Bridge accepted2.stream <-> upstream just like daer-relay::splice does.
        let mut s2 = accepted2.stream;
        let splice = tokio::spawn(async move {
            let _ = tokio::io::copy_bidirectional(&mut s2, &mut upstream).await;
        });

        let mut len_buf = [0u8; 2];
        client2.read_exact(&mut len_buf).await.expect("reply len");
        let reply_len = usize::from(u16::from_be_bytes(len_buf));
        let mut reply_buf = vec![0u8; reply_len];
        client2
            .read_exact(&mut reply_buf)
            .await
            .expect("reply body");
        let reply = daer_dns::wire::parse(&reply_buf).expect("valid dns reply");
        assert_eq!(reply.id, 0x4242);
        assert_eq!(reply.flags.0 & 0x000f, daer_dns::ResponseCode::REFUSED.0);
        let _ = splice.await;
    }
}
