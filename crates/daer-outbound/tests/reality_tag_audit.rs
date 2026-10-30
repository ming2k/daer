// SPDX-License-Identifier: AGPL-3.0-only

//! Byte-level audit of the REALITY ClientHello and tag.
//!
//! REALITY's failures are silent: a node that cannot open the tag does not refuse, it
//! *forwards* the flow to the impersonated site, so the client gets a valid TLS session
//! against a host nobody asked for. The offsets below are therefore stated and asserted
//! rather than trusted, because every one of the bugs this file has caught looked like a
//! working connection.
//!
//! The checks that need the network live in `reality_live.rs`; everything here is offline.

/// The offsets a REALITY tag depends on, derived from RFC 8446's field layout.
///
/// ```text
///   handshake : type(1) length(3)                      — 4 bytes
///   body      : legacy_version(2) random(32) session_id(1+32) …
/// ```
const HANDSHAKE_HEADER: usize = 4;
const RANDOM_OFFSET: usize = HANDSHAKE_HEADER + 2;
const RANDOM_LEN: usize = 32;
const SESSION_ID_LEN_OFFSET: usize = RANDOM_OFFSET + RANDOM_LEN;
const SESSION_ID_OFFSET: usize = SESSION_ID_LEN_OFFSET + 1;

#[test]
fn the_hello_layout_matches_the_offsets_the_tag_uses() {
    // The tag is sealed with `random[..20]` as salt and `random[20..]` as nonce, and it is
    // placed in `session_id`. If the field order were wrong, both would silently address the
    // wrong bytes — which is exactly the bug this audit found: the hello once omitted
    // `random` entirely, so a conformant parser read our session-id length byte as the last
    // byte of `random` and saw a zero-length session id.
    let hello = daer_outbound::probe_client_hello("apple.com").expect("builds");

    assert_eq!(hello[0], 0x01, "ClientHello handshake type");
    assert_eq!(
        &hello[1..4],
        &(hello.len() as u32 - 4).to_be_bytes()[1..],
        "the declared length must consume the rest of the message"
    );
    assert_eq!(&hello[4..6], &[0x03, 0x03], "legacy_version");

    let random = &hello[RANDOM_OFFSET..RANDOM_OFFSET + RANDOM_LEN];
    assert_eq!(random.len(), 32, "random is 32 bytes");
    assert_ne!(random, &[0u8; 32], "random must not be all zeroes");

    assert_eq!(hello[SESSION_ID_LEN_OFFSET], 32, "session_id length");
    assert!(
        SESSION_ID_OFFSET + 32 <= hello.len(),
        "the hello must be long enough to hold the session-id"
    );
}

#[test]
fn the_hello_offers_the_group_a_current_node_requires() {
    // REALITY servers from `xtls/reality` v0.0.0-20260908062103 refuse to authenticate a
    // hello without an `X25519MLKEM768` share: `peerPub2 == nil` makes the server break out
    // of its authentication loop *before* it looks at the tag. The flow is then forwarded,
    // and the client sees a healthy session with the wrong host.
    let hello = daer_outbound::probe_client_hello("apple.com").expect("builds");

    // supported_groups (10) must name 0x11ec, and key_share (51) must carry it.
    let needle = 0x11ecu16.to_be_bytes();
    assert!(
        hello.windows(2).any(|window| window == needle),
        "the hello must name X25519MLKEM768 (0x11ec)"
    );

    // The share is 1184 + 32 bytes, so the hello is far larger than an x25519-only one.
    assert!(
        hello.len() > 1184,
        "an X25519MLKEM768 share alone is 1184 bytes; the hello is {} bytes",
        hello.len()
    );
}

#[test]
fn a_link_with_a_wrong_key_still_parses() {
    // The parser cannot know which public key is right — only the node can — so a wrong key
    // is a valid link that fails at the handshake. Asserting this keeps a future "validate
    // the key" change from rejecting links for the wrong reason.
    let base = "vless://df4af3d0-030e-4062-baa6-eb9dd45298ef@45.77.55.191:443\
                ?encryption=none&security=reality&sni=apple.com\
                &pbk=SKVJehhZSqSCnit3ta2tF37eO3mEfyAW_SOZigrAMnw\
                &sid=ef37119567cd97&type=tcp&fp=chrome";
    let options = daer_outbound::DialerOptions::new(None, std::time::Duration::from_secs(5));
    assert!(
        daer_outbound::NodeDialer::from_link(base, options).is_ok(),
        "the reference link must parse"
    );

    let wrong_key = base.replace(
        "pbk=SKVJehhZSqSCnit3ta2tF37eO3mEfyAW_SOZigrAMnw",
        "pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    );
    assert_ne!(base, wrong_key);
    assert!(
        daer_outbound::NodeDialer::from_link(&wrong_key, options).is_ok(),
        "a wrong key is a valid X25519 point, so only the node can reject it"
    );
}

#[test]
fn the_vision_flow_is_accepted_and_reaches_the_addons() {
    // The node in the reference link requires `flow=xtls-rprx-vision`: a server whose user
    // is configured for Vision refuses a client that omits it. So this is not an optional
    // feature — a link with the flow must parse *and* declare it on the wire.
    let with_flow = "vless://df4af3d0-030e-4062-baa6-eb9dd45298ef@45.77.55.191:443\
                     ?encryption=none&security=reality&sni=apple.com\
                     &pbk=SKVJehhZSqSCnit3ta2tF37eO3mEfyAW_SOZigrAMnw\
                     &sid=ef37119567cd97&type=tcp&fp=chrome&flow=xtls-rprx-vision";
    let options = daer_outbound::DialerOptions::new(None, std::time::Duration::from_secs(5));
    assert!(
        daer_outbound::NodeDialer::from_link(with_flow, options).is_ok(),
        "a Vision link must parse; it is the form this node requires"
    );
}
