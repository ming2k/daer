// SPDX-License-Identifier: AGPL-3.0-only

//! The relay over real TCP sockets.
//!
//! The unit tests drive `splice` over `tokio::io::duplex`, which proves the byte
//! accounting and the half-close wiring. This one uses real sockets, because the
//! failure this module exists to prevent — a proxy that hangs after the client
//! finishes writing — only shows up against a real peer.

use std::net::{Ipv4Addr, SocketAddr};

use daer_control::splice;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// An echo server that answers once and then closes its write half.
async fn echo_once() -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("binds");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accepts");
        let mut buffer = vec![0u8; 1024];
        let read = stream.read(&mut buffer).await.expect("reads");
        stream.write_all(&buffer[..read]).await.expect("writes");
        // Echo and half-close: the client still has to be able to read this.
        stream.shutdown().await.expect("shutdown");
        // Drain whatever the client sends afterwards, to prove EOF reached us.
        let mut sink = Vec::new();
        let _ = stream.read_to_end(&mut sink).await;
    });
    addr
}

#[tokio::test]
async fn relays_a_real_connection_and_propagates_eof() {
    let upstream_addr = echo_once().await;
    let upstream = TcpStream::connect(upstream_addr).await.expect("connects");

    // Stand in for the ingress side: a connected pair, one half given to the relay.
    let (client, relay_client) = tokio::io::duplex(64);

    let relay = tokio::spawn(splice(relay_client, upstream));

    let mut client = client;
    client.write_all(b"ping").await.expect("writes");
    // The upstream echoes and half-closes, so the client must see both the bytes
    // and then EOF rather than a reset.
    let mut echoed = [0u8; 4];
    client.read_exact(&mut echoed).await.expect("reads echo");
    assert_eq!(&echoed, b"ping");
    let mut extra = [0u8; 1];
    assert_eq!(
        client.read(&mut extra).await.expect("reads eof"),
        0,
        "the upstream's half-close must reach the client"
    );

    // The client's own half-close must reach the upstream, which is why the echo
    // task drains to EOF instead of returning immediately.
    client.shutdown().await.expect("shutdown");
    drop(client);

    let relayed = relay.await.expect("joins").expect("relays");
    assert_eq!(relayed.to_upstream, 4);
    assert_eq!(relayed.to_client, 4);
    assert!(!relayed.is_empty());
}

#[tokio::test]
async fn a_closed_upstream_ends_the_relay_without_hanging() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("binds");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accepts");
        drop(stream);
    });

    let upstream = TcpStream::connect(addr).await.expect("connects");
    let (client, relay_client) = tokio::io::duplex(8);
    drop(client);

    let relayed = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        splice(relay_client, upstream),
    )
    .await
    .expect("the relay must not hang");

    match relayed {
        Ok(relayed) => assert_eq!(relayed.total(), 0),
        Err(error) => assert_ne!(error.kind(), std::io::ErrorKind::TimedOut),
    }
}
