// SPDX-License-Identifier: AGPL-3.0-only

//! AnyTLS protocol interop and session multiplexing tests.
//!
//! Falsifiers:
//! - An incorrect password hash in the client auth flight fails independent server verification.
//! - A stream open failure or rejected SYNACK propagates as an error to the caller.
//! - Multiplexed Push and Fin frames carry exact stream IDs and payload framing.

use std::time::Duration;

use bytes::{Bytes, BytesMut};
use daer_outbound::anytls::frame::{Command, Frame};
use daer_outbound::anytls::session::AnyTlsSession;
use daer_outbound::{DialerOptions, NodeDialer, Protocol};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn options() -> DialerOptions {
    DialerOptions::new(None, Duration::from_millis(500))
}

#[tokio::test]
async fn anytls_link_parses_into_node_dialer() {
    let link = "anytls://my-password@node.example.com:443?sni=sni.example.com&allowInsecure=1&idle_sessions=2#hk";
    let dialer = NodeDialer::from_link(link, options()).expect("parses anytls link");
    assert_eq!(dialer.protocol(), Protocol::AnyTls);
    assert_eq!(dialer.describe(), Protocol::AnyTls);
    assert!(dialer.datagram().is_some());
}

#[tokio::test]
async fn anytls_unreachable_node_reports_connect_failure() {
    // Port is closed, dialing must fail cleanly
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("binds");
    let port = listener.local_addr().expect("addr").port();
    drop(listener);

    let link = format!("anytls://pw@localhost:{port}?sni=localhost");
    let dialer = NodeDialer::from_link(&link, options()).expect("parses");
    match dialer.connect("example.com:80").await {
        Ok(_) => panic!("a closed port must not yield a session"),
        Err(error) => {
            let message = error.to_string().to_lowercase();
            assert!(
                message.contains("connect")
                    || message.contains("timeout")
                    || message.contains("tls"),
                "unexpected error message: {error}"
            );
        }
    }
}

#[tokio::test]
async fn anytls_session_full_duplex_multiplexing_and_echo() {
    let (mut client_transport, mut server_transport) = tokio::io::duplex(64 * 1024);

    // Send auth before AnyTlsSession begins, matching AnyTlsConnector::get_or_dial_session
    daer_outbound::anytls::auth::send_authentication(&mut client_transport, "test-secret", 0)
        .await
        .expect("auth sent");

    let session = AnyTlsSession::new(Box::new(client_transport));

    let server_task = tokio::spawn(async move {
        // 1. Read authentication flight
        let mut auth_hash = [0u8; 32];
        server_transport
            .read_exact(&mut auth_hash)
            .await
            .expect("reads auth hash");
        let expected_hash: [u8; 32] = Sha256::digest(b"test-secret").into();
        assert_eq!(
            auth_hash, expected_hash,
            "falsifier: client must present sha256(password)"
        );

        let mut padding_len_bytes = [0u8; 2];
        server_transport
            .read_exact(&mut padding_len_bytes)
            .await
            .expect("reads padding len");
        let padding_len = u16::from_be_bytes(padding_len_bytes) as usize;
        if padding_len > 0 {
            let mut padding = vec![0u8; padding_len];
            server_transport
                .read_exact(&mut padding)
                .await
                .expect("reads padding");
        }

        // 2. Read Syn frame (Command::Syn, stream_id = 1)
        let mut buf = BytesMut::with_capacity(4096);
        let syn_frame = loop {
            if let Some(frame) = Frame::decode(&mut buf).expect("decodes") {
                break frame;
            }
            server_transport
                .read_buf(&mut buf)
                .await
                .expect("reads syn");
        };
        assert_eq!(syn_frame.cmd, Command::Syn);
        assert_eq!(syn_frame.stream_id, 1);

        // 3. Read initial Push frame carrying SOCKS5 destination
        let dest_frame = loop {
            if let Some(frame) = Frame::decode(&mut buf).expect("decodes") {
                break frame;
            }
            server_transport
                .read_buf(&mut buf)
                .await
                .expect("reads dest");
        };
        assert_eq!(dest_frame.cmd, Command::Push);
        assert_eq!(dest_frame.stream_id, 1);
        // SOCKS5 address type 3 (domain)
        assert_eq!(dest_frame.data[0], 3);

        // 4. Send SynAck confirmation (empty payload = success)
        let synack = Frame::control(Command::SynAck, 1);
        server_transport
            .write_all(&synack.encode())
            .await
            .expect("writes synack");

        // 5. Read client request Push frame
        let req_frame = loop {
            if let Some(frame) = Frame::decode(&mut buf).expect("decodes") {
                break frame;
            }
            server_transport
                .read_buf(&mut buf)
                .await
                .expect("reads request data");
        };
        assert_eq!(req_frame.cmd, Command::Push);
        assert_eq!(req_frame.stream_id, 1);
        assert_eq!(
            req_frame.data,
            Bytes::from_static(b"GET / HTTP/1.1\r\n\r\n")
        );

        // 6. Reply with response Push frame
        let resp_data = Bytes::from_static(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK");
        let resp_frame = Frame::push(1, resp_data);
        server_transport
            .write_all(&resp_frame.encode())
            .await
            .expect("writes response");

        // 7. Read client Fin frame
        let fin_frame = loop {
            if let Some(frame) = Frame::decode(&mut buf).expect("decodes") {
                break frame;
            }
            server_transport
                .read_buf(&mut buf)
                .await
                .expect("reads fin");
        };
        assert_eq!(fin_frame.cmd, Command::Fin);
        assert_eq!(fin_frame.stream_id, 1);
    });

    // Write initial auth flight as AnyTlsConnector would
    // The duplex client_transport was wrapped in AnyTlsSession, so send auth through it first:
    // Notice AnyTlsSession expects auth to already be transmitted before frames.
    // In our duplex test, AnyTlsSession is reading/writing directly, so client opens a stream:
    let mut virtual_stream = session
        .open_stream("example.com:80")
        .await
        .expect("stream opened");

    // Send payload
    virtual_stream
        .write_all(b"GET / HTTP/1.1\r\n\r\n")
        .await
        .expect("writes request");

    // Read echo
    let mut resp = vec![0u8; 40];
    virtual_stream
        .read_exact(&mut resp)
        .await
        .expect("reads response");
    assert_eq!(&resp, b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK");

    // Close stream
    virtual_stream.shutdown().await.expect("shuts down stream");

    // Wait for server assertions to complete
    server_task.await.expect("server finished without panic");
}

#[tokio::test]
async fn anytls_server_rejection_propagates_to_open_stream() {
    let (client_transport, mut server_transport) = tokio::io::duplex(4096);
    let session = AnyTlsSession::new(Box::new(client_transport));

    tokio::spawn(async move {
        let mut buf = BytesMut::with_capacity(1024);
        // Drain syn and destination
        for _ in 0..2 {
            loop {
                if Frame::decode(&mut buf).expect("decodes").is_some() {
                    break;
                }
                server_transport.read_buf(&mut buf).await.expect("reads");
            }
        }
        // Send SynAck with rejection error message
        let error_msg = Bytes::from_static(b"connection refused by destination");
        let synack_err = Frame::new(Command::SynAck, 1, error_msg);
        server_transport
            .write_all(&synack_err.encode())
            .await
            .expect("writes err");
    });

    let result = session.open_stream("unreachable.local:80").await;
    match result {
        Ok(_) => panic!("falsifier: rejected synack must fail stream opening"),
        Err(err) => {
            assert!(
                err.to_string()
                    .contains("connection refused by destination"),
                "error message must carry server rejection reason, got: {err}"
            );
        }
    }
}
