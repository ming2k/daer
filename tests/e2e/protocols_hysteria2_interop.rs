// SPDX-License-Identifier: AGPL-3.0-only

//! Hysteria 2 protocol interop and framing tests.
//!
//! # What these tests are for
//!
//! The defect ADR-0029 exists to fix was not a crash: `obfs` was parsed, stored, printed by
//! `Debug`, asserted by a test — and never reached the wire, because `make_endpoint` handed Quinn
//! a plain socket. A test that only checks "the link parsed" is exactly what let that survive, so
//! every assertion below either checks a *byte* the peer would see or checks that a value the
//! configuration accepted reached the code that acts on it.

use std::time::Duration;

use daer_proxy_protocols::hysteria2::obfs::{Obfs, deobfuscate_salamander, obfuscate_salamander};
use daer_proxy_protocols::hysteria2::varint::{decode_varint_slice, encode_varint};
use daer_proxy_protocols::{DialerOptions, ProxyDialer, ProxyProtocol};

fn options() -> DialerOptions {
    DialerOptions::new(None, Duration::from_millis(500))
}

#[test]
fn hysteria2_link_parses_into_node_dialer() {
    // The obfuscation carries a password now: `obfs=salamander` without one is a load error,
    // because a pre-shared key with no key is a node that cannot authenticate.
    let link = "hysteria2://my-secret-token@hy2.example.com:443?sni=sni.example.com&insecure=1&upmbps=50&downmbps=100&obfs=salamander&obfs-password=cry_me_a_r1ver#hk-hy2";
    let dialer = ProxyDialer::from_link(link, options()).expect("parses hysteria2 link");
    assert_eq!(dialer.protocol(), ProxyProtocol::Hysteria2);
    assert!(dialer.datagram_connector().is_some());

    // Also test hy2:// alias
    let alias_link = "hy2://my-secret-token@hy2.example.com:443?sni=sni.example.com#hk-hy2";
    let dialer_alias =
        ProxyDialer::from_link(alias_link, options()).expect("parses hy2 alias link");
    assert_eq!(dialer_alias.protocol(), ProxyProtocol::Hysteria2);
}

#[test]
fn an_obfuscation_without_a_password_is_refused_at_load() {
    // The reference's server discards every packet from a client whose key it does not share, and
    // the symptom is a handshake timeout. Naming the missing key at load time is the difference
    // between a five-second fix and an afternoon.
    let error = ProxyDialer::from_link(
        "hysteria2://pw@hy2.example.com:443?obfs=salamander",
        options(),
    )
    .expect_err("salamander needs a password");
    assert!(error.to_string().contains("obfs-password"), "{error}");

    // And a password with no obfuscation has no meaning of its own.
    let error = ProxyDialer::from_link(
        "hysteria2://pw@hy2.example.com:443?obfs-password=cry_me_a_r1ver",
        options(),
    )
    .expect_err("a password without obfs is a typo");
    assert!(error.to_string().contains("without obfs"), "{error}");
}

#[test]
fn an_obfuscation_this_build_does_not_implement_is_named() {
    let error = ProxyDialer::from_link(
        "hysteria2://pw@hy2.example.com:443?obfs=whirlpool&obfs-password=cry_me_a_r1ver",
        options(),
    )
    .expect_err("whirlpool is not implemented");
    let message = error.to_string();
    assert!(message.contains("whirlpool"), "{message}");
    assert!(message.contains("salamander"), "{message}");
}

#[test]
fn a_port_set_reaches_the_connector_so_hopping_has_something_to_hop_over() {
    // Port hopping is a socket layer over the *port set* the node names, so the set has to survive
    // the link parse intact and in normalised form.
    let dialer = ProxyDialer::from_link(
        "hy2://pw@hy2.example.com:443,20000-20002?hop-interval=30s",
        options(),
    )
    .expect("parses");
    let ProxyDialer::Hysteria2(connector) = &dialer else {
        panic!("expected a hysteria2 connector, got {dialer:?}");
    };
    assert_eq!(
        connector.ports().ports(),
        vec![443, 20000, 20001, 20002],
        "the set is sorted and merged, which is what the hop layer samples from"
    );
    assert!(
        connector.hopping().is_enabled(),
        "hop-interval must reach the port-hopping schedule"
    );
}

#[test]
fn a_hop_interval_below_the_references_floor_is_refused() {
    // A one-second hop schedule exhausts the server's port table faster than it releases entries,
    // and looks like a working node whose connections the server drops.
    let error = ProxyDialer::from_link("hy2://pw@hy2.example.com:443?hop-interval=1s", options())
        .expect_err("1s is under the floor");
    assert!(error.to_string().contains("5s"), "{error}");
}

#[tokio::test]
async fn hysteria2_unreachable_node_reports_connect_failure() {
    // Port is closed, dialing must fail cleanly
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("binds");
    let port = socket.local_addr().expect("addr").port();
    drop(socket);

    let link = format!("hysteria2://pw@127.0.0.1:{port}?sni=localhost&insecure=1");
    let dialer = ProxyDialer::from_link(&link, options()).expect("parses");
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

#[test]
fn salamander_matches_the_references_wire_format() {
    // `[salt 8][payload ^ BLAKE2b-256(psk ‖ salt)]`, from `extras/obfs/salamander.go`. The test
    // recomputes the key from the salt the encoder emitted, because the salt is random and pinning
    // one would only test the test.
    let password = b"average_password";
    let payload = b"a QUIC Initial packet, shaped like nothing in particular";
    let oblique = obfuscate_salamander(password, payload);

    assert_eq!(
        oblique.len(),
        8 + payload.len(),
        "8 bytes of salt, then the payload"
    );
    let salt = &oblique[..8];
    use blake2::Digest as _;
    let mut hasher = blake2::Blake2b::<blake2::digest::consts::U32>::new();
    hasher.update(password);
    hasher.update(salt);
    let key: [u8; 32] = hasher.finalize().into();
    for (index, byte) in oblique[8..].iter().enumerate() {
        assert_eq!(*byte, payload[index] ^ key[index % 32], "byte {index}");
    }

    // And it round-trips, which is what a node must be able to do.
    assert_eq!(
        deobfuscate_salamander(password, &oblique).as_deref(),
        Some(&payload[..])
    );
}

#[test]
fn the_gecko_layer_is_implemented_and_reachable() {
    // The name has to reach a real layer: an `obfs => type` that parsed but built nothing is the
    // defect ADR-0029 fixed, and `Obfs::from_config` is where a `gecko` node either becomes a
    // layer or is refused by name.
    let gecko = daer_config::Hysteria2Obfs::Gecko {
        password: "gecko_password".to_owned(),
        min_packet_size: 512,
        max_packet_size: 1200,
    };
    assert_eq!(Obfs::from_config(&gecko).expect("builds").kind(), "gecko");

    let salamander = daer_config::Hysteria2Obfs::Salamander {
        password: "salamander_password".to_owned(),
    };
    assert_eq!(
        Obfs::from_config(&salamander).expect("builds").kind(),
        "salamander"
    );
}
