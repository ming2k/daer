// SPDX-License-Identifier: AGPL-3.0-only

//! Does the hand-rolled ClientHello pass for a real TLS 1.3 server?
//!
//! REALITY's failure mode is ambiguous by design: when the authentication tag does not
//! open, the node **forwards the connection to the impersonated site**, so the client sees
//! a certificate for `apple.com` instead of an error. A `decode_error` alert from a REALITY
//! node could therefore come from the node *or* from the site behind it, and the two need
//! different fixes.
//!
//! This probe removes the ambiguity: it sends the same ClientHello to a public TLS 1.3
//! server with no REALITY involved. If that server answers with a ServerHello, the hello is
//! well-formed and the problem is the REALITY tag. If it answers with an alert, the hello
//! is malformed and REALITY was never the issue.
//!
//! Ignored by default: it needs the network.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test(flavor = "current_thread")]
#[ignore = "needs the network"]
async fn a_plain_tls13_server_answers_our_client_hello() {
    let host = std::env::var("DAER_PROBE_HOST").unwrap_or_else(|_| "cloudflare.com".to_owned());
    let address = format!("{host}:443");
    println!("probing {address}");

    let stream = tokio::net::TcpStream::connect(&address)
        .await
        .expect("connects");
    let (mut read, mut write) = stream.into_split();

    // The hello this repository generates, byte for byte, through the same accessor the
    // REALITY connector uses. `session_id` is all zeroes here: a plain server ignores it,
    // and the point of the probe is to test everything *else*.
    let hello = daer_outbound::probe_client_hello(&host).expect("builds");
    let mut record = vec![0x16, 0x03, 0x01];
    record.extend_from_slice(&(hello.len() as u16).to_be_bytes());
    record.extend_from_slice(&hello);
    write.write_all(&record).await.expect("writes");
    write.flush().await.expect("flushes");

    let mut header = [0u8; 5];
    let read_n = tokio::time::timeout(Duration::from_secs(10), read.read_exact(&mut header))
        .await
        .expect("must not hang")
        .expect("must read a record header");
    assert_eq!(read_n, 5);

    let content_type = header[0];
    let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
    let mut body = vec![0u8; length];
    read.read_exact(&mut body).await.expect("reads the body");

    println!(
        "record type {content_type} version {:#06x} length {length}",
        u16::from_be_bytes([header[1], header[2]])
    );

    if content_type == 22 {
        println!(
            "ServerHello: handshake type {}",
            body.first().copied().unwrap_or(0)
        );
        assert_eq!(body.first().copied(), Some(2), "expected a ServerHello");
    } else if content_type == 21 {
        let level = body[0];
        let description = body[1];
        panic!(
            "the server rejected the ClientHello with alert({level}, {description}) \
             ({}); the hello is malformed, not the REALITY tag",
            alert_name(description)
        );
    } else {
        panic!("unexpected content type {content_type}");
    }
}

fn alert_name(description: u8) -> &'static str {
    match description {
        0 => "close_notify",
        10 => "unexpected_message",
        20 => "bad_record_mac",
        22 => "record_overflow",
        40 => "handshake_failure",
        42 => "bad_certificate",
        47 => "illegal_parameter",
        50 => "decode_error",
        70 => "protocol_version",
        71 => "insufficient_security",
        80 => "internal_error",
        109 => "missing_extension",
        110 => "unsupported_extension",
        _ => "unknown",
    }
}
