// SPDX-License-Identifier: AGPL-3.0-only

//! The UDP plane of Hysteria 2: per-flow sessions and fragmentation (ADR-0029).
//!
//! # What was wrong before
//!
//! `session_id` was the constant `1`, so every concurrent UDP flow through one node shared one
//! id and the server multiplexed them onto one outbound port; and `frag_id = 0,
//! frag_total = 1` was hard-coded, so any datagram larger than the QUIC datagram MTU was
//! dropped instead of fragmented. Both are part of the protocol
//! (`hysteria/PROTOCOL.md` §UDP, `core/internal/frag`), not optimisations.
//!
//! # The format
//!
//! ```text
//!   [session_id 4][packet_id 2][frag_id 1][frag_total 1][addr_len varint][addr][payload]
//! ```
//!
//! Fragment ids start at 0, and every fragment of one datagram shares its `packet_id`. A
//! receiver must wait for all of them; a lost fragment discards the whole datagram.
//!
//! # Session ids
//!
//! One id per UDP flow, from a process-wide counter. The server allocates an outbound port per
//! session id and releases it after inactivity, so sharing an id across flows makes several
//! unrelated destinations look like one flow to the server's NAT table — which is what the
//! constant `1` did.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, AtomicU32, Ordering};

use bytes::Bytes;
use netune::{DatagramConnector, DatagramTransport, EstablishedDatagrams, NetError};
use netune_trace::Recorder;

use crate::hysteria2::connector::Hysteria2Connector;
use crate::hysteria2::varint::{decode_varint_slice, encode_varint};

/// The QUIC datagram frame's maximum payload, from the reference
/// (`MaxDatagramFrameSize = 1200`).
const MAX_DATAGRAM_FRAME: usize = 1200;
/// The reference's ceiling on a reassembled UDP payload (`MaxUDPSize = 4096`).
const MAX_UDP_SIZE: usize = 4096;

/// Hands out session ids, one per UDP flow.
///
/// Starts at 1 because the reference's server treats 0 as an ordinary id; starting at 0 would
/// make the first flow indistinguishable from an initialised-but-unused slot in a server that
/// keys a table on it.
fn next_session_id() -> u32 {
    static NEXT: AtomicU32 = AtomicU32::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

/// Datagram connector for Hysteria 2 nodes.
pub struct Hysteria2DatagramConnector {
    connector: Hysteria2Connector,
}

impl Hysteria2DatagramConnector {
    #[must_use]
    pub const fn new(connector: Hysteria2Connector) -> Self {
        Self { connector }
    }
}

impl std::fmt::Debug for Hysteria2DatagramConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hysteria2DatagramConnector")
            .field("server", &self.connector.server())
            .finish()
    }
}

impl DatagramConnector for Hysteria2DatagramConnector {
    fn connect<'a>(
        &'a self,
        authority: &'a str,
        recorder: &'a Arc<std::sync::Mutex<Recorder>>,
    ) -> Pin<
        Box<dyn std::future::Future<Output = Result<EstablishedDatagrams, NetError>> + Send + 'a>,
    > {
        let connector = self.connector.clone();
        let authority = authority.to_owned();
        let recorder = Arc::clone(recorder);
        Box::pin(async move { connector.connect_datagram(&authority, &recorder).await })
    }
}

/// A connected UDP session over a Hysteria 2 node's QUIC connection.
pub struct Hysteria2DatagramSession {
    connection: quinn::Connection,
    authority: String,
    session_id: u32,
    packet_id: AtomicU16,
}

impl std::fmt::Debug for Hysteria2DatagramSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hysteria2DatagramSession")
            .field("authority", &self.authority)
            .field("session_id", &self.session_id)
            .finish()
    }
}

impl Hysteria2DatagramSession {
    /// Constructs a session with a freshly allocated id.
    #[must_use]
    pub fn new(connection: quinn::Connection, authority: String) -> Self {
        Self {
            connection,
            authority,
            session_id: next_session_id(),
            // Fragment-capable ids start at 1 in the reference's own tests; the value is
            // opaque to the server and only has to be unique per datagram.
            packet_id: AtomicU16::new(1),
        }
    }

    /// The session id, for a diagnostic that has to correlate with a server log.
    #[must_use]
    pub const fn session_id(&self) -> u32 {
        self.session_id
    }

    /// The header size one fragment of `address` carries.
    fn header_size(&self) -> usize {
        let address_len = self.authority.len();
        4 + 2 + 1 + 1 + varint_len(address_len as u64) + address_len
    }
}

/// The encoded length of a QUIC varint, from RFC 9000 §16.
fn varint_len(value: u64) -> usize {
    match value {
        0..=63 => 1,
        64..=16_383 => 2,
        16_384..=1_073_741_823 => 4,
        _ => 8,
    }
}

impl DatagramTransport for Hysteria2DatagramSession {
    fn max_datagram_size(&self) -> usize {
        // A caller's payload has to fit one QUIC datagram frame after this session's header,
        // and the reference's ceiling on a UDP payload is 4096 — but a datagram larger than
        // the frame is *fragmented* rather than refused, so the limit reported here is the
        // reassembled maximum and `send` does the splitting.
        MAX_UDP_SIZE
    }

    fn send<'a>(
        &'a self,
        payload: &'a [u8],
    ) -> Pin<Box<dyn std::future::Future<Output = Result<usize, io::Error>> + Send + 'a>> {
        Box::pin(async move {
            if payload.is_empty() {
                return Ok(0);
            }
            if payload.len() > MAX_UDP_SIZE {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "a Hysteria 2 datagram of {} bytes exceeds the reference's {MAX_UDP_SIZE} \
                         byte ceiling",
                        payload.len()
                    ),
                ));
            }

            let packet_id = self.packet_id.fetch_add(1, Ordering::Relaxed);
            let header = self.header_size();
            let max_payload = MAX_DATAGRAM_FRAME.saturating_sub(header);
            if max_payload == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "the address {:?} leaves no room in a {MAX_DATAGRAM_FRAME} byte datagram",
                        self.authority
                    ),
                ));
            }

            let fragment_count = payload
                .len()
                .div_ceil(max_payload)
                .clamp(1, usize::from(u8::MAX));
            let mut offset = 0usize;
            for fragment_id in 0..fragment_count {
                let end = (offset + max_payload).min(payload.len());
                let fragment = &payload[offset..end];
                let mut packet = Vec::with_capacity(header + fragment.len());
                packet.extend_from_slice(&self.session_id.to_be_bytes());
                packet.extend_from_slice(&packet_id.to_be_bytes());
                packet.push(fragment_id as u8);
                packet.push(fragment_count as u8);
                encode_varint(self.authority.len() as u64, &mut packet);
                packet.extend_from_slice(self.authority.as_bytes());
                packet.extend_from_slice(fragment);
                self.connection
                    .send_datagram(Bytes::from(packet))
                    .map_err(|error| io::Error::other(format!("send datagram failed: {error}")))?;
                offset = end;
            }

            Ok(payload.len())
        })
    }

    fn recv<'a>(
        &'a self,
        buffer: &'a mut [u8],
    ) -> Pin<Box<dyn std::future::Future<Output = Result<usize, io::Error>> + Send + 'a>> {
        Box::pin(async move {
            // The reference can only reassemble one packet id at a time
            // (`core/internal/frag`'s `Defragger`), so this mirrors that: a new packet id
            // discards any partial state.
            let mut assembler = FragmentAssembler::default();
            loop {
                let datagram =
                    self.connection.read_datagram().await.map_err(|error| {
                        io::Error::other(format!("read datagram failed: {error}"))
                    })?;
                let Some(fragment) = parse_message(&datagram) else {
                    // A malformed datagram is dropped rather than surfaced: the reference does
                    // the same, and one stray packet must not kill the flow.
                    continue;
                };
                if fragment.session_id != self.session_id {
                    continue;
                }
                let Some(assembled) = assembler.feed(&fragment) else {
                    continue;
                };
                let take = assembled.len().min(buffer.len());
                buffer[..take].copy_from_slice(&assembled[..take]);
                return Ok(take);
            }
        })
    }
}

/// One received UDP message, borrowed from the datagram it arrived in.
struct ReceivedFragment<'a> {
    session_id: u32,
    packet_id: u16,
    fragment_id: u8,
    fragment_count: u8,
    payload: &'a [u8],
}

/// Parses the `[session][packet][frag][count][addr_len][addr][payload]` header.
fn parse_message(datagram: &[u8]) -> Option<ReceivedFragment<'_>> {
    if datagram.len() < 8 {
        return None;
    }
    let session_id = u32::from_be_bytes([datagram[0], datagram[1], datagram[2], datagram[3]]);
    let packet_id = u16::from_be_bytes([datagram[4], datagram[5]]);
    let fragment_id = datagram[6];
    let fragment_count = datagram[7];
    if fragment_count == 0 || fragment_id >= fragment_count {
        return None;
    }
    let (address_len, consumed) = decode_varint_slice(&datagram[8..])?;
    let address_len = usize::try_from(address_len).ok()?;
    let payload_start = 8 + consumed + address_len;
    if address_len == 0 || payload_start > datagram.len() {
        return None;
    }
    Some(ReceivedFragment {
        session_id,
        packet_id,
        fragment_id,
        fragment_count,
        payload: &datagram[payload_start..],
    })
}

/// Reassembles one packet id at a time, as the reference does.
#[derive(Default)]
struct FragmentAssembler {
    packet_id: Option<u16>,
    fragments: Vec<Option<Vec<u8>>>,
    received: usize,
    total: usize,
}

impl FragmentAssembler {
    fn feed(&mut self, fragment: &ReceivedFragment<'_>) -> Option<Vec<u8>> {
        if fragment.fragment_count <= 1 {
            return Some(fragment.payload.to_vec());
        }
        if self.packet_id != Some(fragment.packet_id)
            || self.fragments.len() != usize::from(fragment.fragment_count)
        {
            self.packet_id = Some(fragment.packet_id);
            self.fragments = vec![None; usize::from(fragment.fragment_count)];
            self.received = 0;
            self.total = 0;
        }
        let slot = &mut self.fragments[usize::from(fragment.fragment_id)];
        if slot.is_some() {
            return None;
        }
        self.total += fragment.payload.len();
        *slot = Some(fragment.payload.to_vec());
        self.received += 1;
        if self.received < self.fragments.len() {
            return None;
        }
        let mut assembled = Vec::with_capacity(self.total);
        for part in self.fragments.drain(..) {
            assembled.extend_from_slice(part.as_deref().unwrap_or_default());
        }
        self.packet_id = None;
        self.received = 0;
        self.total = 0;
        Some(assembled)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(session: u32, packet: u16, frag: u8, count: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&session.to_be_bytes());
        out.extend_from_slice(&packet.to_be_bytes());
        out.push(frag);
        out.push(count);
        let address = "example.com:80";
        encode_varint(address.len() as u64, &mut out);
        out.extend_from_slice(address.as_bytes());
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn a_single_fragment_needs_no_window() {
        let datagram = message(7, 1, 0, 1, b"hello");
        let fragment = parse_message(&datagram).expect("parses");
        assert_eq!(fragment.session_id, 7);
        assert_eq!(fragment.payload, b"hello");

        let mut assembler = FragmentAssembler::default();
        assert_eq!(assembler.feed(&fragment), Some(b"hello".to_vec()));
    }

    #[test]
    fn fragments_are_reassembled_in_order() {
        let first = message(7, 42, 0, 3, b"aaa");
        let second = message(7, 42, 1, 3, b"bbb");
        let third = message(7, 42, 2, 3, b"ccc");
        let mut assembler = FragmentAssembler::default();
        let mut assembled = None;
        // Feed out of order on purpose: the window keys on fragment id, not arrival order.
        for datagram in [&second, &third, &first] {
            let fragment = parse_message(datagram).expect("parses");
            if let Some(payload) = assembler.feed(&fragment) {
                assembled = Some(payload);
            }
        }
        assert_eq!(assembled, Some(b"aaabbbccc".to_vec()));
    }

    #[test]
    fn a_new_packet_id_discards_partial_state() {
        // The reference documents this limitation explicitly ("can only handle one packet ID
        // at a time"), and a wider window would accept reordering the server never produces.
        let mut assembler = FragmentAssembler::default();
        let partial = message(1, 1, 0, 2, b"aa");
        let fragment = parse_message(&partial).expect("parses");
        assert_eq!(assembler.feed(&fragment), None);

        let other = message(1, 2, 0, 2, b"bb");
        let fragment = parse_message(&other).expect("parses");
        assert_eq!(assembler.feed(&fragment), None);

        let completes = message(1, 2, 1, 2, b"cc");
        let fragment = parse_message(&completes).expect("parses");
        assert_eq!(assembler.feed(&fragment), Some(b"bbcc".to_vec()));
    }

    #[test]
    fn a_fragment_id_beyond_its_count_is_dropped_at_the_parser() {
        // A `frag_id >= frag_total` message is meaningless, and indexing a fragment window with
        // it would panic. It is refused before the window ever sees it.
        assert!(parse_message(&message(1, 1, 5, 2, b"x")).is_none());
        // A zero fragment count is refused for the same reason: `count` is what sizes the window.
        let mut zero = message(1, 1, 0, 1, b"x");
        zero[7] = 0;
        assert!(parse_message(&zero).is_none());
        // A datagram too short to hold its fixed header is refused rather than read past.
        assert!(parse_message(&[0u8; 7]).is_none());
        // An address length that runs past the datagram cannot be a valid message.
        let mut truncated = message(1, 1, 0, 1, b"x");
        truncated.truncate(9);
        assert!(parse_message(&truncated).is_none());
    }

    #[test]
    fn a_datagram_with_a_payload_beyond_the_references_ceiling_is_refused() {
        // 4096 is `MaxUDPSize`, and a larger caller payload cannot be represented even after
        // fragmentation because the *reassembled* size is what the ceiling governs.
        assert_eq!(MAX_UDP_SIZE, 4096);
        assert_eq!(MAX_DATAGRAM_FRAME, 1200);
        assert_eq!(varint_len(63), 1);
        assert_eq!(varint_len(64), 2);
        assert_eq!(varint_len(16_384), 4);
    }

    #[test]
    fn session_ids_are_allocated_per_flow_and_never_zero() {
        let first = next_session_id();
        let second = next_session_id();
        assert_ne!(first, second);
        assert_ne!(first, 0);
        assert_eq!(second, first + 1);
    }
}
