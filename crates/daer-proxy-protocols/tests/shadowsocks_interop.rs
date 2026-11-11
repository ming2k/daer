// SPDX-License-Identifier: AGPL-3.0-only

//! Shadowsocks against an independently written server.
//!
//! The server in `shadowsocks_server.rs` shares only the primitive AEAD operations with the
//! client: its own KDF, its own nonces, its own framing parser. A mistake in the client's
//! framing, nonce order or key derivation therefore fails here instead of cancelling out.

#[path = "shadowsocks_server.rs"]
mod server;

#[path = "shadowsocks_2022_server.rs"]
mod server2022;

use std::time::Duration;

use daer_proxy_protocols::shadowsocks::ShadowSocksConnector;
use daer_proxy_protocols::{DialerOptions, ProxyDialer, ProxyProtocol};
use netune_trace::TraceCollector;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn options() -> DialerOptions {
    DialerOptions::new(None, Duration::from_secs(5))
}

#[tokio::test]
async fn a_client_interoperates_with_an_independent_server() {
    let (address, observed) = server::serve(server::Method::Aes256Gcm, "correct horse").await;
    let link = server::link("aes-256-gcm", "correct horse", address);

    let connector = ShadowSocksConnector::from_link(&link, options()).expect("link parses");
    let recorder = TraceCollector::start(16);
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
        let recorder = TraceCollector::start(16);
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

    let dialer = ProxyDialer::from_link(&link, options()).expect("the link is accepted");
    assert_eq!(dialer.protocol(), ProxyProtocol::ShadowSocks);

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
    let recorder = TraceCollector::start(16);
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
    let recorder = TraceCollector::start(16);
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
    let error = ProxyDialer::from_link(&link, options()).expect_err("must be rejected");
    // The message must name the cipher *and* why: `daer-config` rejects a legacy method at load
    // with "insecure legacy cipher", and the dialer surfaces that text verbatim rather than
    // replacing it with a generic failure.
    let message = error.to_string();
    assert!(message.contains("aes-256-cfb"), "{message}");
    assert!(
        message.contains("legacy")
            || message.contains("AEAD")
            || message.contains("authentication"),
        "{message}"
    );
}

#[tokio::test]
async fn several_payloads_in_sequence_stay_in_sync() {
    // Two writes mean four records; a nonce that reset per write would decrypt the second
    // chunk as garbage.
    let (address, _observed) = server::serve(server::Method::ChaCha20Poly1305, "pw").await;
    let link = server::link("chacha20-ietf-poly1305", "pw", address);
    let connector = ShadowSocksConnector::from_link(&link, options()).expect("parses");
    let recorder = TraceCollector::start(16);
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

#[tokio::test]
async fn ss2022_all_ciphers_interoperate_with_echo() {
    let key16 = "3L69X4PF2eSL/JSLkoWnXg=="; // 16 bytes base64
    let key32 = "4wYfDniq4N6kMqFajRO03PPZLfPkl469eNYY9Wz0E78="; // 32 bytes base64

    for (method, method_name, b64_key) in [
        (
            server2022::Method2022::Aes128Gcm,
            "2022-blake3-aes-128-gcm",
            key16,
        ),
        (
            server2022::Method2022::Aes256Gcm,
            "2022-blake3-aes-256-gcm",
            key32,
        ),
        (
            server2022::Method2022::ChaCha20Poly1305,
            "2022-blake3-chacha20-poly1305",
            key32,
        ),
    ] {
        let psk = daer_proxy_protocols::shadowsocks::decode_base64_bytes(b64_key).unwrap();
        let (server_addr, observed) =
            server2022::serve_2022(method, psk, server2022::ServerBehavior::default()).await;

        let link = format!("ss://{method_name}:{b64_key}@{server_addr}#test22");
        let connector = ShadowSocksConnector::from_link(&link, options()).expect("link parses");
        let recorder = TraceCollector::start(16);

        let established = connector
            .connect("example.com:443", &recorder)
            .await
            .unwrap_or_else(|e| panic!("{method_name} connect failed: {e}"));

        let seen = observed.await.expect("server recorded handshake");
        assert_eq!(seen.target, "example.com:443", "{method_name}");
        assert!(seen.payload.is_empty(), "{method_name}");
        assert!(
            (1..=900).contains(&seen.padding_len),
            "{method_name}: SIP022 mandatory padding check failed (got {})",
            seen.padding_len
        );

        let mut stream = established.stream;
        let mut greeting = vec![0u8; 5];
        stream
            .read_exact(&mut greeting)
            .await
            .expect("reads server greeting");
        assert_eq!(&greeting, b"hello", "{method_name}");

        // Multi-chunk round trip echo test
        for msg in [
            b"message_one".as_slice(),
            b"message_two",
            b"final_round_trip",
        ] {
            stream.write_all(msg).await.expect("writes message");
            let mut echo = vec![0u8; msg.len()];
            stream.read_exact(&mut echo).await.expect("reads echo");
            assert_eq!(&echo, msg, "{method_name}");
        }
    }
}

#[tokio::test]
async fn ss2022_clock_skew_is_rejected() {
    let key16 = "3L69X4PF2eSL/JSLkoWnXg==";
    let psk = daer_proxy_protocols::shadowsocks::decode_base64_bytes(key16).unwrap();
    let (server_addr, _observed) = server2022::serve_2022(
        server2022::Method2022::Aes128Gcm,
        psk,
        server2022::ServerBehavior {
            clock_skew_secs: 100, // 100s skew exceeds 30s threshold
            tamper_request_salt: false,
        },
    )
    .await;

    let link = format!("ss://2022-blake3-aes-128-gcm:{key16}@{server_addr}");
    let connector = ShadowSocksConnector::from_link(&link, options()).expect("link parses");
    let recorder = TraceCollector::start(16);

    let mut established = connector
        .connect("example.com:443", &recorder)
        .await
        .expect("initial send succeeds");
    let mut buf = [0u8; 10];
    let err = established
        .stream
        .read(&mut buf)
        .await
        .expect_err("must reject large clock skew on receive");
    let err_str = err.to_string();
    assert!(err_str.contains("clock skew"), "{err_str}");
}

#[tokio::test]
async fn ss2022_salt_mismatch_is_rejected() {
    let key16 = "3L69X4PF2eSL/JSLkoWnXg==";
    let psk = daer_proxy_protocols::shadowsocks::decode_base64_bytes(key16).unwrap();
    let (server_addr, _observed) = server2022::serve_2022(
        server2022::Method2022::Aes128Gcm,
        psk,
        server2022::ServerBehavior {
            clock_skew_secs: 0,
            tamper_request_salt: true, // Tampered Request Salt
        },
    )
    .await;

    let link = format!("ss://2022-blake3-aes-128-gcm:{key16}@{server_addr}");
    let connector = ShadowSocksConnector::from_link(&link, options()).expect("link parses");
    let recorder = TraceCollector::start(16);

    let mut established = connector
        .connect("example.com:443", &recorder)
        .await
        .expect("initial send succeeds");
    let mut buf = [0u8; 10];
    let err = established
        .stream
        .read(&mut buf)
        .await
        .expect_err("must reject request salt mismatch on receive");
    let err_str = err.to_string();
    assert!(err_str.contains("salt"), "{err_str}");
}

#[tokio::test]
async fn ss2022_node_dialer_speaks_shadowsocks_2022() {
    let key16 = "3L69X4PF2eSL/JSLkoWnXg==";
    let psk = daer_proxy_protocols::shadowsocks::decode_base64_bytes(key16).unwrap();
    let (server_addr, _observed) = server2022::serve_2022(
        server2022::Method2022::Aes128Gcm,
        psk,
        server2022::ServerBehavior::default(),
    )
    .await;

    let link = format!("ss://2022-blake3-aes-128-gcm:{key16}@{server_addr}#ss22");
    let dialer = ProxyDialer::from_link(&link, options()).expect("the link is accepted");
    assert_eq!(dialer.protocol(), ProxyProtocol::ShadowSocks);

    let established = dialer
        .connect("example.com:80")
        .await
        .expect("connects through the 2022 node");
    let mut stream = established.stream;
    let mut buffer = vec![0u8; 5];
    stream
        .read_exact(&mut buffer)
        .await
        .expect("reads the echo");
    assert_eq!(&buffer, b"hello");
}

#[tokio::test]
async fn ss2022_udp_datagram_echo_round_trip() {
    let key16 = "3L69X4PF2eSL/JSLkoWnXg==";
    let key32 = "4wYfDniq4N6kMqFajRO03PPZLfPkl469eNYY9Wz0E78=";

    for (method, method_name, b64_key) in [
        (
            server2022::Method2022::Aes128Gcm,
            "2022-blake3-aes-128-gcm",
            key16,
        ),
        (
            server2022::Method2022::ChaCha20Poly1305,
            "2022-blake3-chacha20-poly1305",
            key32,
        ),
    ] {
        let psk = daer_proxy_protocols::shadowsocks::decode_base64_bytes(b64_key).unwrap();
        let (server_addr, mut rx) = server2022::serve_2022_udp(method, psk).await;

        let link = format!("ss://{method_name}:{b64_key}@{server_addr}");
        let connector = ShadowSocksConnector::from_link(&link, options()).expect("link parses");
        let recorder = TraceCollector::start(16);

        let established = connector
            .connect_datagram("1.2.3.4:443", &recorder)
            .await
            .expect("datagram connects");

        let session = established.datagrams;
        let test_payload = b"ping_2022_udp";
        let sent = session.send(test_payload).await.expect("sends datagram");
        assert_eq!(sent, test_payload.len());

        let server_received = rx.recv().await.expect("server received packet");
        assert_eq!(&server_received, test_payload);

        let mut recv_buf = vec![0u8; 1024];
        let n = session.recv(&mut recv_buf).await.expect("receives echo");
        assert_eq!(&recv_buf[..n], test_payload);
    }
}
