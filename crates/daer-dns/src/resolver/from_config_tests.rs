use super::*;
use crate::wire::{Flags, Name, Question, RecordType};
use std::net::Ipv4Addr;
use tokio::net::TcpListener;

/// A one-shot DNS-over-TCP server answering one query.
async fn tcp_server() -> std::net::SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("binds");
    let address = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accepts");
        let mut length = [0u8; 2];
        tokio::io::AsyncReadExt::read_exact(&mut stream, &mut length)
            .await
            .expect("length");
        let mut body = vec![0u8; usize::from(u16::from_be_bytes(length))];
        tokio::io::AsyncReadExt::read_exact(&mut stream, &mut body)
            .await
            .expect("body");
        let query = crate::wire::parse(&body).expect("query");
        let reply = crate::wire::Message {
            id: query.id,
            flags: Flags(0x8180),
            questions: query.questions.clone(),
            answers: vec![crate::wire::Record {
                name: Name::parse("example.com").expect("name"),
                rtype: RecordType::A,
                class: Question::CLASS_IN,
                ttl: 60,
                rdata: vec![93, 184, 216, 34],
            }],
            authorities: Vec::new(),
            additionals: Vec::new(),
        };
        let encoded = crate::wire::encode(&reply);
        tokio::io::AsyncWriteExt::write_all(&mut stream, &(encoded.len() as u16).to_be_bytes())
            .await
            .expect("length");
        tokio::io::AsyncWriteExt::write_all(&mut stream, &encoded)
            .await
            .expect("body");
    });
    address
}

#[tokio::test]
async fn a_tcp_upstream_declared_in_the_config_answers() {
    // The whole point of `from_config`: the configuration names a transport and the
    // resolver speaks it, with no hand-wiring.
    let address = tcp_server().await;
    let config = daer_config::toml_config::load_str(&format!(
        r#"
[dns]
upstream = ["local:tcp://{address}"]

[dns.request]
rules = []
default = "local"
"#
    ))
    .expect("config loads");

    let resolver = Resolver::from_config(&config).expect("builds");
    let query = Message {
        id: 5,
        flags: Flags(0x0100),
        questions: vec![Question::internet(
            Name::parse("example.com").expect("name"),
            RecordType::A,
        )],
        answers: Vec::new(),
        authorities: Vec::new(),
        additionals: Vec::new(),
    };

    let answer = match resolver.resolve_test(&query).await.expect("resolves") {
        Resolution::Answer(message) => message,
        Resolution::AsIs => panic!("the fallback is an upstream, not asis"),
    };
    assert_eq!(answer.response_code(), ResponseCode::NOERROR);
    assert_eq!(answer.answer_addresses().len(), 1);
    assert_eq!(resolver.stats().snapshot().upstream_calls, 1);
}

#[tokio::test]
async fn every_documented_protocol_builds_a_real_transport() {
    // The regression this guards: `udp`, `tls` and `https` were documented, parsed, and
    // then silently registered as transports that refused every query. Building must
    // succeed for all four, and a query must actually reach the wire.
    for entry in [
        "google:udp://127.0.0.1:1",
        "google:tcp://127.0.0.1:1",
        "google:tls://127.0.0.1:1",
        "google:https://127.0.0.1:1",
    ] {
        let config = daer_config::toml_config::load_str(&format!(
            r#"
[dns]
upstream = ["{entry}"]

[dns.request]
rules = []
default = "google"
"#
        ))
        .expect("config loads");
        let resolver = Resolver::from_config(&config)
            .unwrap_or_else(|error| panic!("{entry} must build: {error}"));
        drop(resolver);
    }
}

#[tokio::test]
async fn a_udp_upstream_is_actually_contacted() {
    // The service answers SERVFAIL when the upstream cannot be reached, and the
    // upstream-call counter proves the transport tried rather than short-circuited.
    let config = daer_config::toml_config::load_str(
        r#"
[dns]
upstream = ["google:udp://127.0.0.1:1"]

[dns.request]
rules = []
default = "google"
"#,
    )
    .expect("config loads");

    let resolver = Resolver::from_config(&config).expect("builds");
    let query = Message {
        id: 5,
        flags: Flags(0x0100),
        questions: vec![Question::internet(
            Name::parse("example.com").expect("name"),
            RecordType::A,
        )],
        answers: Vec::new(),
        authorities: Vec::new(),
        additionals: Vec::new(),
    };
    let answer = match resolver.resolve_test(&query).await.expect("resolves") {
        Resolution::Answer(message) => message,
        Resolution::AsIs => panic!("expected SERVFAIL"),
    };
    assert_eq!(answer.response_code(), ResponseCode::SERVFAIL);
    assert_eq!(resolver.stats().snapshot().upstream_errors, 1);
}

#[test]
fn a_malformed_upstream_entry_fails_the_build() {
    let config = daer_config::toml_config::load_str(
        r#"
[dns]
upstream = ["nonsense"]
"#,
    )
    .expect("config loads");

    let error = Resolver::from_config(&config).expect_err("must reject");
    assert!(error.to_string().contains("dns.upstream"), "{error}");
}
