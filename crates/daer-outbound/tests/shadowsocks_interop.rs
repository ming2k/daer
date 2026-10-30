// SPDX-License-Identifier: AGPL-3.0-only

//! Shadowsocks against an independently written server.
//!
//! The server in `shadowsocks_server.rs` shares only the primitive AEAD operations with the
//! client: its own KDF, its own nonces, its own framing parser. A mistake in the client's
//! framing, nonce order or key derivation therefore fails here instead of cancelling out.

#[path = "shadowsocks_server.rs"]
mod server;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use daer_outbound::shadowsocks::ShadowSocksConnector;
use daer_outbound::{DialerOptions, NodeDialer, Protocol};
use netune_trace::Recorder;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn options() -> DialerOptions {
    DialerOptions::new(None, Duration::from_secs(5))
}

#[tokio::test]
async fn a_client_interoperates_with_an_independent_server() {
    let (address, observed) = server::serve(server::Method::Aes256Gcm, "correct horse").await;
    let link = server::link("aes-256-gcm", "correct horse", address);

    let connector = ShadowSocksConnector::from_link(&link, options()).expect("link parses");
    let recorder = Arc::new(Mutex::new(Recorder::start(16)));
    let established = connector
        .connect("example.com:443", &recorder)
        .await
        .expect("handshake succeeds");

    // The server saw the exact target the client was told to reach.
    let seen = observed.await.expect("the server reported");
    assert_eq!(seen.target, "example.com:443");
    assert!(
        seen.first_payload.is_empty(),
        "the client sent no payload, so the frame is only the address"
    );

    // The server's echo proves both directions decrypt: this is the assertion that would
    // fail if the client's receive nonce or salt handling were wrong.
    let mut stream = established.stream;
    let mut buffer = vec![0u8; 5];
    stream
        .read_exact(&mut buffer)
        .await
        .expect("reads the echo");
    assert_eq!(&buffer, b"hello");
}

#[tokio::test]
async fn every_supported_cipher_interoperates() {
    for (method, name) in [
        (server::Method::Aes128Gcm, "aes-128-gcm"),
        (server::Method::Aes256Gcm, "aes-256-gcm"),
        (server::Method::ChaCha20Poly1305, "chacha20-ietf-poly1305"),
    ] {
        let (address, observed) = server::serve(method, "pw").await;
        let link = server::link(name, "pw", address);
        let connector = ShadowSocksConnector::from_link(&link, options()).expect("parses");
        let recorder = Arc::new(Mutex::new(Recorder::start(16)));
        let established = connector
            .connect("1.2.3.4:8388", &recorder)
            .await
            .unwrap_or_else(|error| panic!("{name}: {error}"));

        let seen = observed.await.expect("reported");
        assert_eq!(seen.target, "1.2.3.4:8388", "{name}");
        let mut stream = established.stream;
        let mut buffer = vec![0u8; 5];
        stream.read_exact(&mut buffer).await.expect("reads");
        assert_eq!(&buffer, b"hello", "{name}");
    }
}

#[tokio::test]
async fn a_node_dialer_speaks_shadowsocks() {
    // The path the data path takes: a node link, not a connector built by hand.
    let (address, _observed) = server::serve(server::Method::Aes128Gcm, "secret").await;
    let link = server::link("aes-128-gcm", "secret", address);

    let dialer = NodeDialer::from_link(&link, options()).expect("the link is accepted");
    assert_eq!(dialer.protocol(), Protocol::ShadowSocks);

    let established = dialer
        .connect("example.com:80")
        .await
        .expect("connects through the node");
    let mut stream = established.stream;
    let mut buffer = vec![0u8; 5];
    stream
        .read_exact(&mut buffer)
        .await
        .expect("reads the echo");
    assert_eq!(&buffer, b"hello");
}

#[tokio::test]
async fn an_ipv6_target_is_encoded_and_accepted() {
    let (address, observed) = server::serve(server::Method::Aes256Gcm, "pw").await;
    let link = server::link("aes-256-gcm", "pw", address);
    let connector = ShadowSocksConnector::from_link(&link, options()).expect("parses");
    let recorder = Arc::new(Mutex::new(Recorder::start(16)));
    connector
        .connect("[2001:db8::1]:53", &recorder)
        .await
        .expect("connects");

    let seen = observed.await.expect("reported");
    assert_eq!(seen.target, "[2001:db8::1]:53");
}

#[tokio::test]
async fn a_wrong_password_fails_the_handshake() {
    // The server decrypts with a different password; the client must not pretend to succeed.
    let (address, _observed) = server::serve(server::Method::Aes256Gcm, "server-password").await;
    let link = server::link("aes-256-gcm", "client-password", address);

    let connector = ShadowSocksConnector::from_link(&link, options()).expect("parses");
    let recorder = Arc::new(Mutex::new(Recorder::start(16)));
    // The client's own writes succeed; the failure appears when the server's salt never
    // arrives, because the server cannot decrypt the address frame and therefore closes.
    let result = connector.connect("example.com:443", &recorder).await;
    match result {
        Err(_) => {}
        Ok(mut established) => {
            let mut buffer = [0u8; 1];
            let read =
                tokio::time::timeout(Duration::from_secs(2), established.stream.read(&mut buffer))
                    .await
                    .expect("the read must not hang");
            assert!(
                read.is_err() || read.is_ok_and(|count| count == 0),
                "a wrong password must not yield usable data"
            );
        }
    }
}

#[tokio::test]
async fn a_legacy_cipher_link_is_rejected_before_dialing() {
    let (address, _observed) = server::serve(server::Method::Aes256Gcm, "pw").await;
    let link = server::link("aes-256-cfb", "pw", address);
    let error = NodeDialer::from_link(&link, options()).expect_err("must be rejected");
    assert!(error.to_string().contains("no authentication"), "{error}");
}

#[tokio::test]
async fn several_payloads_in_sequence_stay_in_sync() {
    // Two writes mean four records; a nonce that reset per write would decrypt the second
    // chunk as garbage.
    let (address, _observed) = server::serve(server::Method::ChaCha20Poly1305, "pw").await;
    let link = server::link("chacha20-ietf-poly1305", "pw", address);
    let connector = ShadowSocksConnector::from_link(&link, options()).expect("parses");
    let recorder = Arc::new(Mutex::new(Recorder::start(16)));
    let established = connector
        .connect("example.com:443", &recorder)
        .await
        .expect("connects");

    let mut stream = established.stream;
    let mut hello = vec![0u8; 5];
    stream
        .read_exact(&mut hello)
        .await
        .expect("reads the greeting");
    assert_eq!(&hello, b"hello");

    for payload in [b"second".to_vec(), b"third".to_vec()] {
        stream.write_all(&payload).await.expect("writes");
        let mut echoed = vec![0u8; payload.len()];
        stream
            .read_exact(&mut echoed)
            .await
            .unwrap_or_else(|error| panic!("echo of {payload:?}: {error}"));
        assert_eq!(echoed, payload);
    }
}
