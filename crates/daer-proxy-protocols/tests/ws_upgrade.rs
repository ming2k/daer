// SPDX-License-Identifier: AGPL-3.0-only

//! The `ws` upgrade's bytes, asserted against a recording server.
//!
//! # Why this exists next to `layer_matrix.rs`
//!
//! `layer_matrix` proves the upgrade works against a real `xray`; this test proves *what daer
//! writes*. When the two disagree the difference is either in daer's request or in the fixture, and
//! a failure that only says "the node answered 400" cannot tell them apart. Here the server records
//! exactly what arrived, so a rejection has a cause.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use daer_proxy_protocols::transport::{TransportLayer, WsParams};
use netune::Connector as _;
use netune::{Target, TcpConnector};
use netune_trace::TraceCollector;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

/// Starts a server that reads until it sees `\r\n\r\n`, records the bytes, and answers `101`.
async fn recording_server() -> (std::net::SocketAddr, Arc<Mutex<Vec<u8>>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("binds");
    let address = listener.local_addr().expect("has an address");
    let observed = Arc::new(Mutex::new(Vec::new()));
    let record = Arc::clone(&observed);
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accepts");
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 512];
        loop {
            let read = stream.read(&mut chunk).await.expect("reads");
            if read == 0 {
                return;
            }
            buffer.extend_from_slice(&chunk[..read]);
            if buffer.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        record.lock().expect("lock").extend_from_slice(&buffer);
        let key = buffer
            .windows(b"Sec-WebSocket-Key: ".len())
            .position(|window| window == b"Sec-WebSocket-Key: ")
            .map(|start| {
                let rest = &buffer[start + b"Sec-WebSocket-Key: ".len()..];
                let end = rest
                    .windows(2)
                    .position(|window| window == b"\r\n")
                    .unwrap_or(rest.len());
                String::from_utf8_lossy(&rest[..end]).into_owned()
            })
            .unwrap_or_default();
        let accept = netune_ws::compute_accept_key(&key);
        let response = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
             Sec-WebSocket-Accept: {accept}\r\n\r\n"
        );
        stream.write_all(response.as_bytes()).await.expect("writes");
        // Keep the connection open so the client's write does not race a close.
        let _ = stream.read(&mut chunk).await;
    });
    (address, observed)
}

#[tokio::test]
async fn the_upgrade_request_carries_the_reference_fields() {
    let (address, observed) = recording_server().await;
    let tcp = TcpConnector::new();
    let recorder = TraceCollector::start(16);
    let established = tcp
        .connect(&Target::plain(address.to_string()), &recorder)
        .await
        .expect("dials");

    let layer = TransportLayer::Ws(WsParams {
        path: "/ray".to_owned(),
        host: Some("lab.example.com".to_owned()),
        headers: vec![("X-Custom".to_owned(), "value".to_owned())],
    });
    layer
        .wrap(
            established.stream,
            "node.example.com",
            None,
            &recorder,
            Duration::from_secs(5),
        )
        .await
        .expect("upgrades");

    let bytes = observed.lock().expect("lock").clone();
    let request = String::from_utf8_lossy(&bytes);
    assert!(
        request.starts_with("GET /ray HTTP/1.1\r\n"),
        "the request line is what a node parses first:\n{request}"
    );
    assert!(
        request.contains("\r\nHost: lab.example.com\r\n"),
        "the explicit host wins over the node's address:\n{request}"
    );
    assert!(request.contains("\r\nUpgrade: websocket\r\n"), "{request}");
    assert!(request.contains("\r\nConnection: Upgrade\r\n"), "{request}");
    assert!(
        request.contains("\r\nSec-WebSocket-Version: 13\r\n"),
        "{request}"
    );
    assert!(request.contains("\r\nX-Custom: value\r\n"), "{request}");
    assert!(
        request.contains("\r\nSec-WebSocket-Key: "),
        "RFC 6455 requires the key:\n{request}"
    );
    assert!(
        request.ends_with("\r\n\r\n"),
        "the head must terminate:\n{request}"
    );
}
