// SPDX-License-Identifier: AGPL-3.0-only

//! End to end: a UDP client asks the server, which asks a real TCP upstream.
//!
//! Nothing here is a stub except the origin, and the origin is a real DNS-over-TCP server
//! built from `daer_dns::wire`. The path exercised is the one a deployment takes: socket →
//! resolver → request routing → cache → transport → response routing → socket.
//!
//! The properties asserted are the ones whose absence would be silent in production:
//! a second identical query does not reach the upstream, a rejected name never does, and an
//! `asis` flow produces no reply at all.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use daer_dns::wire::{self, Flags, Message, Name, Question, Record, RecordType, ResponseCode};
use daer_dns::{Resolver, serve_tcp_on, serve_udp_on};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

/// A real DNS-over-TCP origin that counts how often it is asked.
async fn origin() -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("binds");
    let address = listener.local_addr().expect("addr");
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&calls);

    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let counter = Arc::clone(&counter);
            tokio::spawn(async move {
                let mut length = [0u8; 2];
                if stream.read_exact(&mut length).await.is_err() {
                    return;
                }
                let mut body = vec![0u8; usize::from(u16::from_be_bytes(length))];
                if stream.read_exact(&mut body).await.is_err() {
                    return;
                }
                let Ok(query) = wire::parse(&body) else {
                    return;
                };
                counter.fetch_add(1, Ordering::Relaxed);

                let question = query.questions.first().cloned().expect("a question");
                let reply = Message {
                    id: query.id,
                    flags: Flags(0x8180),
                    questions: vec![question.clone()],
                    answers: vec![Record {
                        name: question.name.clone(),
                        rtype: RecordType::A,
                        class: Question::CLASS_IN,
                        ttl: 60,
                        rdata: vec![93, 184, 216, 34],
                    }],
                    authorities: Vec::new(),
                    additionals: Vec::new(),
                };
                let encoded = wire::encode(&reply);
                let _ = stream
                    .write_all(&(encoded.len() as u16).to_be_bytes())
                    .await;
                let _ = stream.write_all(&encoded).await;
            });
        }
    });
    (address, calls)
}

/// Builds a resolver against `origin` and serves it on a fresh UDP port.
async fn server(origin: SocketAddr) -> (SocketAddr, Arc<Resolver>) {
    let config = daer_config::toml_config::load_str(&format!(
        r#"
[dns]
upstream = ["origin:tcp://{origin}"]

[dns.request]
rules = [
    "qname(suffix: blocked.example) -> reject",
    "qname(suffix: local.example) -> asis",
]
fallback = "origin"
"#
    ))
    .expect("config loads");

    let resolver = Arc::new(Resolver::from_config(&config).expect("resolver builds"));
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("binds");
    let address = socket.local_addr().expect("addr");
    let served = Arc::clone(&resolver);
    tokio::spawn(async move {
        let _ = serve_udp_on(socket, served, std::future::pending()).await;
    });
    (address, resolver)
}

fn query(id: u16, name: &str) -> Message {
    Message {
        id,
        flags: Flags(0x0100),
        questions: vec![Question::internet(
            Name::parse(name).expect("name"),
            RecordType::A,
        )],
        answers: Vec::new(),
        authorities: Vec::new(),
        additionals: Vec::new(),
    }
}

async fn ask(address: SocketAddr, request: &Message) -> Option<Message> {
    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("binds");
    client
        .send_to(&wire::encode(request), address)
        .await
        .expect("sends");
    let mut buffer = vec![0u8; 4096];
    match tokio::time::timeout(Duration::from_secs(3), client.recv_from(&mut buffer)).await {
        Err(_) => None,
        Ok(Ok((read, _))) => Some(wire::parse(&buffer[..read]).expect("the reply parses")),
        Ok(Err(error)) => panic!("receive failed: {error}"),
    }
}

#[tokio::test]
async fn a_query_is_answered_through_the_whole_stack() {
    let (origin_address, origin_calls) = origin().await;
    let (address, _resolver) = server(origin_address).await;

    let reply = ask(address, &query(0x1234, "www.example.com"))
        .await
        .expect("a reply");
    assert_eq!(reply.id, 0x1234);
    assert!(reply.is_response());
    assert_eq!(reply.response_code(), ResponseCode::NOERROR);
    assert_eq!(reply.answers.len(), 1);
    assert_eq!(origin_calls.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn a_second_identical_query_is_answered_from_the_cache() {
    let (origin_address, origin_calls) = origin().await;
    let (address, resolver) = server(origin_address).await;

    let first = ask(address, &query(1, "cached.example.com"))
        .await
        .expect("a reply");
    let second = ask(address, &query(2, "cached.example.com"))
        .await
        .expect("a reply");

    assert_eq!(
        origin_calls.load(Ordering::Relaxed),
        1,
        "the second answer came from the cache"
    );
    assert_eq!(second.id, 2, "the reply echoes the second client's id");
    assert_eq!(
        second.answer_addresses(),
        first.answer_addresses(),
        "the same addresses"
    );
    // The TTL counts down: it is the remaining lifetime, never the original. Serving 60
    // again would let a downstream cache hold the answer past its expiry.
    assert!(
        second.answers[0].ttl <= first.answers[0].ttl,
        "cached ttl {} must not exceed the original {}",
        second.answers[0].ttl,
        first.answers[0].ttl
    );
    assert!(second.answers[0].ttl > 0);
    let stats = resolver.stats().snapshot();
    assert_eq!(stats.hits, 1);
    assert_eq!(stats.misses, 1);
}

#[tokio::test]
async fn a_rejected_name_never_reaches_the_upstream() {
    let (origin_address, origin_calls) = origin().await;
    let (address, _resolver) = server(origin_address).await;

    let reply = ask(address, &query(3, "tracker.blocked.example"))
        .await
        .expect("a reply");
    assert_eq!(reply.response_code(), ResponseCode::REFUSED);
    assert_eq!(origin_calls.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn an_asis_name_gets_no_reply_at_all() {
    let (origin_address, origin_calls) = origin().await;
    let (address, resolver) = server(origin_address).await;

    assert!(
        ask(address, &query(4, "nas.local.example")).await.is_none(),
        "asis must produce silence, not a refusal"
    );
    assert_eq!(origin_calls.load(Ordering::Relaxed), 0);
    assert_eq!(resolver.stats().snapshot().as_is, 1);
}

#[tokio::test]
async fn a_tcp_client_gets_the_same_answers() {
    // The TCP path shares the resolver, so it must not be a second implementation of it.
    let (origin_address, origin_calls) = origin().await;
    let config = daer_config::toml_config::load_str(&format!(
        r#"
[dns]
upstream = ["origin:tcp://{origin_address}"]

[dns.request]
rules = []
fallback = "origin"
"#
    ))
    .expect("config loads");
    let resolver = Arc::new(Resolver::from_config(&config).expect("builds"));

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("binds");
    let address = listener.local_addr().expect("addr");
    let served = Arc::clone(&resolver);
    tokio::spawn(async move {
        let _ = serve_tcp_on(listener, served, std::future::pending()).await;
    });

    let mut stream = tokio::net::TcpStream::connect(address)
        .await
        .expect("connects");
    for id in [10u16, 11] {
        let encoded = wire::encode(&query(id, "tcp.example.com"));
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
        assert_eq!(reply.id, id);
        assert_eq!(reply.response_code(), ResponseCode::NOERROR);
        assert_eq!(reply.answers.len(), 1);
    }
    assert_eq!(
        origin_calls.load(Ordering::Relaxed),
        1,
        "the second query over the same connection was a cache hit"
    );
}

#[tokio::test]
async fn an_upstream_that_is_down_becomes_servfail_not_silence() {
    // Bind and drop, so the port is closed: a real failure, at the socket level.
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("binds");
    let dead = listener.local_addr().expect("addr");
    drop(listener);

    let config = daer_config::toml_config::load_str(&format!(
        r#"
[dns]
upstream = ["origin:tcp://{dead}"]

[dns.request]
rules = []
fallback = "origin"
"#
    ))
    .expect("config loads");
    let resolver = Arc::new(Resolver::from_config(&config).expect("builds"));
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("binds");
    let address = socket.local_addr().expect("addr");
    let served = Arc::clone(&resolver);
    tokio::spawn(async move {
        let _ = serve_udp_on(socket, served, std::future::pending()).await;
    });

    let reply = ask(address, &query(20, "down.example.com"))
        .await
        .expect("a SERVFAIL is still a reply");
    assert_eq!(reply.response_code(), ResponseCode::SERVFAIL);
    assert_eq!(resolver.stats().snapshot().upstream_errors, 1);
}
