// SPDX-License-Identifier: AGPL-3.0-only

//! The sniffer's budget is a security property, not a performance hint: the buffer comes from
//! the network, so every declared length is hostile.
//!
//! The unit tests cover the TLS and HTTP parsers' own length checks. This file exercises the
//! *composition*: a QUIC Initial whose varint token or packet length claims more than
//! [`MAX_SNIFF_LEN`], and a deterministic corpus of arbitrary bytes passed to both entry
//! points. The falsifier is a `NeedMore` whose `want` exceeds the budget: a caller that obeys
//! the API would then buffer without limit, which is the exact failure the constant exists to
//! prevent.

use daer_sniff::{MAX_SNIFF_LEN, Malformed, Sniffed, sniff, sniff_quic};

/// A fixed-seed sequence; reproducibility matters more than statistical quality.
fn next(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    *state
}

fn assert_bounded(result: &Sniffed, what: &str) {
    if let Sniffed::NeedMore { want: Some(want) } = result {
        assert!(
            *want <= MAX_SNIFF_LEN + 128,
            "{what} asked the caller to buffer {want} bytes, beyond the {MAX_SNIFF_LEN}-byte \
             budget (the +128 allows the HTTP parser's read-ahead hint)"
        );
    }
}

#[test]
fn a_quic_token_length_beyond_the_budget_is_malformed() {
    // Long header, QUIC v1 Initial, no DCID, no SCID, then an 8-byte varint token length of
    // 2^62-1. A parser that returns `NeedMore { want: 2^62 }` hands the caller an unbounded
    // allocation request.
    let mut packet = vec![0xC0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00];
    packet.extend_from_slice(&[0xff; 8]);
    assert_eq!(
        sniff_quic(&packet),
        Sniffed::Malformed(Malformed::Oversized),
        "the token length must be rejected before the caller buffers it"
    );
    assert_eq!(
        sniff(&packet),
        Sniffed::Malformed(Malformed::Oversized),
        "the top-level entry point must enforce the same budget"
    );
}

#[test]
fn a_quic_packet_length_beyond_the_budget_is_malformed() {
    // Same header, a zero-length token, then the packet-length varint claims 2^62-1 bytes.
    let mut packet = vec![0xC0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00];
    packet.extend_from_slice(&[0xff; 8]);
    assert_eq!(
        sniff_quic(&packet),
        Sniffed::Malformed(Malformed::Oversized),
        "a packet length larger than the sniff budget is malformed, not a read request"
    );
}

#[test]
fn arbitrary_bytes_never_ask_for_more_than_the_budget() {
    let mut state = 0xda_e0_5e_ed_00_00_00_01;
    for iteration in 0..4096 {
        // Lengths up to 512 exercise prefixes, TLS record headers, HTTP request lines and
        // QUIC long headers without making the corpus slow.
        let length = (next(&mut state) as usize) % 513;
        let mut buffer = vec![0u8; length];
        for byte in &mut buffer {
            *byte = (next(&mut state) & 0xff) as u8;
        }

        // Half the corpus starts with a byte that reaches the QUIC/TLS branches, so the run
        // is not dominated by the `None` fast path.
        if iteration % 2 == 0 && !buffer.is_empty() {
            buffer[0] = 0xC0;
        }

        let result = sniff(&buffer);
        assert_bounded(&result, "sniff");
        let quic = sniff_quic(&buffer);
        assert_bounded(&quic, "sniff_quic");

        for result in [result, quic] {
            if let Sniffed::Domain { name, .. } = result {
                assert!(
                    !name.is_empty() && name.len() <= MAX_SNIFF_LEN,
                    "a recovered name must be non-empty and within the budget"
                );
            }
        }
    }
}
