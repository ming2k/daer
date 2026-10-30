// SPDX-License-Identifier: AGPL-3.0-only

//! Hysteria 2 protocol interop and framing tests.

use std::time::Duration;

use daer_outbound::hysteria2::varint::{decode_varint_slice, encode_varint};
use daer_outbound::{DialerOptions, NodeDialer, Protocol};

fn options() -> DialerOptions {
    DialerOptions::new(None, Duration::from_millis(500))
}

#[test]
fn hysteria2_link_parses_into_node_dialer() {
    let link = "hysteria2://my-secret-token@hy2.example.com:443?sni=sni.example.com&insecure=1&upmbps=50&downmbps=100&obfs=salamander#hk-hy2";
    let dialer = NodeDialer::from_link(link, options()).expect("parses hysteria2 link");
    assert_eq!(dialer.protocol(), Protocol::Hysteria2);
    assert_eq!(dialer.describe(), Protocol::Hysteria2);
    assert!(dialer.datagram().is_some());

    // Also test hy2:// alias
    let alias_link = "hy2://my-secret-token@hy2.example.com:443?sni=sni.example.com#hk-hy2";
    let dialer_alias = NodeDialer::from_link(alias_link, options()).expect("parses hy2 alias link");
    assert_eq!(dialer_alias.protocol(), Protocol::Hysteria2);
}

#[tokio::test]
async fn hysteria2_unreachable_node_reports_connect_failure() {
    // Port is closed, dialing must fail cleanly
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("binds");
    let port = socket.local_addr().expect("addr").port();
    drop(socket);

    let link = format!("hysteria2://pw@127.0.0.1:{port}?sni=localhost&insecure=1");
    let dialer = NodeDialer::from_link(&link, options()).expect("parses");
    match dialer.connect("example.com:80").await {
        Ok(_) => panic!("a closed UDP port must not yield a session"),
        Err(error) => {
            let message = error.to_string().to_lowercase();
            assert!(
                message.contains("connect") || message.contains("time") || message.contains("quic"),
                "unexpected error message: {error}"
            );
        }
    }
}

#[test]
fn hysteria2_tcp_request_framing_varint() {
    let mut frame = Vec::new();
    encode_varint(0x401, &mut frame);
    assert_eq!(frame, &[0x44, 0x01], "RFC 9000 varint 0x401 is 2 bytes");

    let dest = "example.com:80";
    encode_varint(dest.len() as u64, &mut frame);
    frame.extend_from_slice(dest.as_bytes());

    let (frame_type, consumed_1) = decode_varint_slice(&frame).expect("decodes type");
    assert_eq!(frame_type, 0x401);
    let (addr_len, consumed_2) =
        decode_varint_slice(&frame[consumed_1..]).expect("decodes addr len");
    assert_eq!(addr_len, dest.len() as u64);
    assert_eq!(
        &frame[consumed_1 + consumed_2..consumed_1 + consumed_2 + addr_len as usize],
        dest.as_bytes()
    );
}
