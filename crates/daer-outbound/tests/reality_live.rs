// SPDX-License-Identifier: AGPL-3.0-only

//! Vision and REALITY against a live node — the end-to-end evidence.
//!
//! ```sh
//! DAER_REALITY_LINK='vless://…?security=reality&flow=xtls-rprx-vision&pbk=…' \
//!     cargo test -p daer-outbound --test reality_live -- --nocapture --include-ignored
//! ```
//!
//! Ignored by default: it needs the network and a node. `tests/vision_lab.rs` is the same
//! question against a local `xray run`, which is what to reach for when this fails and the
//! reason is not obvious.
//!
//! The test asserts the *observable* steps rather than "it works", so a failure names the
//! layer:
//!
//! 1. the link parses into the parts REALITY needs,
//! 2. the TLS 1.3 handshake completes **and the node proves itself** (a forwarded flow
//!    completes a handshake too, against the impersonated site),
//! 3. a request written into the tunnel comes back as that destination's reply.
//!
//! # When step 2 fails with "the peer is not the REALITY node"
//!
//! That message means the handshake completed but the certificate is not the node's: REALITY
//! **forwards** a flow it cannot authenticate to the impersonated site, so the client ends up
//! talking to `apple.com`. The cause is always on the node side of the link — a rotated `pbk`, a
//! `sid` the node no longer accepts, or a clock skew large enough to invalidate the timestamp —
//! and never a fault in this crate. It is worth confirming before touching code: run the same
//! link with `sid` removed, and with `flow` removed. If all three report this message, the node
//! is not authenticating this client at all, and the link has to be reissued.
//!
//! The distinction matters because the message is the *only* signal: a forwarded flow produces a
//! valid TLS 1.3 handshake and a real HTTP reply, so every layer below this one reports success.
//! `verify.rs` is what turns that into an explicit failure, and this note is how to read it.

use std::time::Duration;

use daer_outbound::{DialerOptions, NodeDialer};

/// The node, from the environment so no credential is in the repository.
fn link() -> String {
    std::env::var("DAER_REALITY_LINK").expect(
        "DAER_REALITY_LINK must hold the vless:// link; \
         see the module docs for the invocation",
    )
}

fn options() -> DialerOptions {
    DialerOptions::new(None, Duration::from_secs(10))
}

#[test]
fn the_link_parses_into_what_reality_needs() {
    // Skipped without the env var: a unit-shaped test that needs a credential would fail
    // every `cargo test` on a machine that has none.
    let Ok(link) = std::env::var("DAER_REALITY_LINK") else {
        return;
    };
    let dialer = NodeDialer::from_link(&link, options()).expect("the link must parse");
    println!("parsed: {dialer:?}");
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "needs the network and DAER_REALITY_LINK"]
async fn a_reality_node_completes_a_handshake_and_carries_bytes() {
    let dialer = NodeDialer::from_link(&link(), options()).expect("the link must parse");

    // `example.com:80` is the destination asked of the *node*: the VLESS header carries it,
    // so the node dials it on our behalf. A plain HTTP/1.1 request then proves the tunnel
    // carries bytes both ways.
    let established =
        tokio::time::timeout(Duration::from_secs(20), dialer.connect("example.com:80"))
            .await
            .expect("the connect must not hang")
            .expect("the session must be established and the node must authenticate itself");
    println!("established");

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = established.stream;
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
        .await
        .expect("the request must be written");

    let mut reply = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(20), stream.read_to_end(&mut reply))
        .await
        .expect("the reply must not hang")
        .expect("the reply must be readable");
    println!("read {read} bytes");
    let head = String::from_utf8_lossy(&reply[..reply.len().min(120)]).to_string();
    println!("{head}");

    assert!(read > 0, "the tunnel carried nothing back");
    // The reply must start with the response itself. A Vision-framed reply that still
    // carries its block header means the unpadder did not run — the stream would "work"
    // for a reader that ignored the prefix and fail for every real client.
    assert!(
        reply.starts_with(b"HTTP/1."),
        "the reply is not a bare HTTP response: {:?}",
        String::from_utf8_lossy(&reply[..reply.len().min(64)])
    );
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "needs the network and DAER_REALITY_LINK"]
async fn a_reality_node_carries_udp_datagrams() {
    let dialer = NodeDialer::from_link(&link(), options()).expect("the link must parse");
    let datagram_connector = dialer
        .datagram()
        .expect("reality node must support datagrams");

    let recorder = std::sync::Arc::new(std::sync::Mutex::new(netune_trace::Recorder::start(16)));
    let established = tokio::time::timeout(
        Duration::from_secs(20),
        datagram_connector.connect("8.8.8.8:53", &recorder),
    )
    .await
    .expect("connect must not hang")
    .expect("session must establish");

    // Standard DNS query for google.com (A record, query id 0x1234)
    let dns_query = [
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, b'g', b'o',
        b'o', b'g', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
    ];

    let sent = established
        .datagrams
        .send(&dns_query)
        .await
        .expect("datagram must send");
    assert_eq!(sent, dns_query.len());

    let mut buf = [0u8; 1024];
    let received = tokio::time::timeout(
        Duration::from_secs(10),
        established.datagrams.recv(&mut buf),
    )
    .await
    .expect("recv must not hang")
    .expect("recv must succeed");

    assert!(
        received >= 12,
        "DNS response must have at least 12-byte header"
    );
    assert_eq!(&buf[0..2], &[0x12, 0x34], "DNS ID must match");
    println!("received {received} bytes UDP DNS reply from 8.8.8.8:53 via REALITY node");
}
