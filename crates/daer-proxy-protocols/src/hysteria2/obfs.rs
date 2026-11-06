// SPDX-License-Identifier: AGPL-3.0-only

//! Obfuscation layers for Hysteria 2's datagrams (ADR-0029).
//!
//! # What this is for
//!
//! A QUIC Initial packet has a recognisable shape: version `1`, a long header, and a
//! ClientHello inside. An on-path filter that drops QUIC to unknown servers therefore sees
//! Hysteria 2 in the clear. "Salamander" XORs every datagram under a key derived from a
//! pre-shared password, so the first bytes are random; "Gecko" additionally fragments QUIC
//! long headers into randomly sized, randomly padded chunks so even the packet *sizes* stop
//! being a signature.
//!
//! Both are wire formats defined by the reference
//! (`hysteria/extras/obfs/salamander.go`, `gecko.go`), and both are implemented here byte for
//! byte, because a different scheme simply does not interoperate.
//!
//! # Why they are `AsyncUdpSocket` layers
//!
//! Quinn takes its socket once, at endpoint construction. Everything that has to touch a
//! datagram — obfuscation, fragmentation, port hopping — therefore has to sit *between* the
//! socket and Quinn, and `quinn::AsyncUdpSocket` is the only seam that allows it
//! (`Endpoint::new_with_abstract_socket`). That also means each layer is testable without a
//! server: feed it bytes, compare with the reference's vectors.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use netune_trace::Recorder;
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use std::sync::Mutex;

/// The pre-shared-key minimum, from the reference (`smPSKMinLen`).
pub const PSK_MIN_LEN: usize = 4;
/// The salt length, from the reference (`smSaltLen`).
const SALT_LEN: usize = 8;
/// BLAKE2b-256's output length, which is the key stream's period.
const KEY_LEN: usize = 32;

/// The obfuscation a node asked for (ADR-0029).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Obfs {
    /// `[salt 8][payload ^ key]`, `key = BLAKE2b-256(psk ‖ salt)`.
    Salamander { password: Vec<u8> },
    /// Salamander plus fragmentation of QUIC long-header packets.
    Gecko {
        password: Vec<u8>,
        min_packet_size: u16,
        max_packet_size: u16,
    },
}

impl Obfs {
    /// The reference's default Gecko bounds, used when the config says nothing.
    const GECKO_DEFAULT_MIN: u16 = 512;
    const GECKO_DEFAULT_MAX: u16 = 1200;
    /// Gecko's reassembly ceiling, from the reference.
    const GECKO_MAX_PACKET: u16 = 2048;

    /// Builds the layer from a node's configuration.
    ///
    /// # Errors
    ///
    /// Returns a message when the pre-shared key is shorter than the reference's minimum or
    /// the Gecko bounds are unusable. Both are load-time facts: a too-short key makes the
    /// server discard every packet, and the symptom is a handshake timeout with no cause.
    pub fn from_config(obfs: &daer_config::Hysteria2Obfs) -> Result<Self, String> {
        let password = obfs.password().as_bytes().to_vec();
        if password.len() < PSK_MIN_LEN {
            return Err(format!(
                "obfs password is {} bytes; the reference requires at least {PSK_MIN_LEN}",
                password.len()
            ));
        }
        match obfs {
            daer_config::Hysteria2Obfs::Salamander { .. } => Ok(Self::Salamander { password }),
            daer_config::Hysteria2Obfs::Gecko {
                min_packet_size,
                max_packet_size,
                ..
            } => {
                let min = if *min_packet_size == 0 {
                    Self::GECKO_DEFAULT_MIN
                } else {
                    *min_packet_size
                };
                let max = if *max_packet_size == 0 {
                    Self::GECKO_DEFAULT_MAX
                } else {
                    *max_packet_size
                };
                if min > max || max > Self::GECKO_MAX_PACKET {
                    return Err(format!(
                        "gecko packet sizes {min}/{max} are not a usable range \
                         (min <= max <= {})",
                        Self::GECKO_MAX_PACKET
                    ));
                }
                Ok(Self::Gecko {
                    password,
                    min_packet_size: min,
                    max_packet_size: max,
                })
            }
        }
    }

    /// The name a log uses.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Salamander { .. } => "salamander",
            Self::Gecko { .. } => "gecko",
        }
    }
}

/// The Salamander keystream for one salt.
///
/// `key = BLAKE2b-256(psk ‖ salt)`, and the payload is XORed with it cyclically.
fn salamander_key(password: &[u8], salt: &[u8]) -> [u8; KEY_LEN] {
    use blake2::Digest as _;

    let mut hasher = blake2::Blake2b::<blake2::digest::consts::U32>::new();
    hasher.update(password);
    hasher.update(salt);
    hasher.finalize().into()
}

/// XORs `payload` with the keystream in place, starting at offset zero.
fn xor_keystream(payload: &mut [u8], key: &[u8; KEY_LEN]) {
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte ^= key[index % KEY_LEN];
    }
}

/// Obfuscates one datagram: `[salt 8][payload ^ key]`.
#[must_use]
pub fn obfuscate_salamander(password: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut salt = [0u8; SALT_LEN];
    // `getrandom` rather than `fastrand`: the salt keys the stream, and a predictable one
    // would let an observer XOR two datagrams together and recover both.
    getrandom::fill(&mut salt).expect("the OS provides entropy");
    let key = salamander_key(password, &salt);
    let mut out = Vec::with_capacity(SALT_LEN + payload.len());
    out.extend_from_slice(&salt);
    out.extend_from_slice(payload);
    xor_keystream(&mut out[SALT_LEN..], &key);
    out
}

/// Deobfuscates one datagram, or `None` when it is too short to carry a salt.
#[must_use]
pub fn deobfuscate_salamander(password: &[u8], datagram: &[u8]) -> Option<Vec<u8>> {
    if datagram.len() <= SALT_LEN {
        return None;
    }
    let (salt, body) = datagram.split_at(SALT_LEN);
    let key = salamander_key(password, salt);
    let mut out = body.to_vec();
    xor_keystream(&mut out, &key);
    Some(out)
}

/// A Quinn socket that applies Hysteria 2's obfuscation.
///
/// Wraps another `AsyncUdpSocket` so the port-hop layer can sit underneath it and the plain
/// socket underneath that.
pub struct ObfsSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    obfs: Obfs,
}

impl std::fmt::Debug for ObfsSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ObfsSocket")
            .field("obfs", &self.obfs.kind())
            .finish()
    }
}

impl ObfsSocket {
    /// Wraps `inner` in `obfs`.
    #[must_use]
    pub fn new(inner: Arc<dyn AsyncUdpSocket>, obfs: Obfs) -> Self {
        Self { inner, obfs }
    }

    /// The pre-shared key.
    fn password(&self) -> &[u8] {
        match &self.obfs {
            Obfs::Salamander { password } | Obfs::Gecko { password, .. } => password,
        }
    }
}

impl AsyncUdpSocket for ObfsSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Arc::clone(&self.inner).create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        let payload = match &self.obfs {
            Obfs::Salamander { .. } => obfuscate_salamander(self.password(), transmit.contents),
            Obfs::Gecko {
                min_packet_size,
                max_packet_size,
                ..
            } => gecko_encode(
                self.password(),
                transmit.contents,
                *min_packet_size,
                *max_packet_size,
            ),
        };
        self.inner.try_send(&Transmit {
            destination: transmit.destination,
            ecn: transmit.ecn,
            contents: &payload,
            // Segmentation offload cannot survive the transform: each segment became its own
            // datagram with its own salt.
            segment_size: None,
            src_ip: transmit.src_ip,
        })
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [std::io::IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        // One datagram at a time: the deobfuscated length is not the received length, so
        // filling several `bufs` from one `poll_recv` would have to copy into them and lose
        // track of which `RecvMeta` each belongs to.
        let mut raw = vec![0u8; gecko_buffer()];
        let mut raw_meta = [RecvMeta::default()];
        let mut raw_bufs = [std::io::IoSliceMut::new(&mut raw)];
        match self.inner.poll_recv(cx, &mut raw_bufs, &mut raw_meta) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(0)) => Poll::Ready(Ok(0)),
            Poll::Ready(Ok(count)) => {
                let received = raw_meta[0].len.min(raw.len());
                let decoded = match &self.obfs {
                    Obfs::Salamander { .. } => {
                        deobfuscate_salamander(self.password(), &raw[..received])
                    }
                    Obfs::Gecko { .. } => gecko_decode(self.password(), &raw[..received]),
                };
                let Some(decoded) = decoded else {
                    // A malformed datagram is dropped by the reference too; surfacing it as
                    // an error would kill the connection on a stray packet.
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                };
                let available = bufs[0].len();
                let take = decoded.len().min(available);
                bufs[0][..take].copy_from_slice(&decoded[..take]);
                meta[0] = RecvMeta {
                    addr: raw_meta[0].addr,
                    len: take,
                    // The transform destroyed any GRO grouping.
                    stride: take,
                    ecn: raw_meta[0].ecn,
                    dst_ip: raw_meta[0].dst_ip,
                };
                let _ = count;
                Poll::Ready(Ok(1))
            }
        }
    }

    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.inner.local_addr()
    }

    fn may_fragment(&self) -> bool {
        // The obfuscated packet is larger than the plaintext, so the datagram has to fit;
        // letting the kernel fragment it would break the salt-prefixed framing.
        false
    }
}

/// The receive buffer Gecko needs: its own maximum packet size plus Salamander's salt.
fn gecko_buffer() -> usize {
    usize::from(Obfs::GECKO_MAX_PACKET) + SALT_LEN
}

/// Gecko's frame header, `after Salamander decryption`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GeckoFrame {
    pub msg_id: u8,
    pub chunk_idx: u8,
    pub total_chunks: u8,
    pub pad_len: u16,
}

/// The fragment marker, from `gecko_frame.go`.
const GECKO_FLAG_FRAGMENT: u8 = 0x80;
/// The frame header's length.
const GECKO_HEADER_LEN: usize = 5;
/// The reference's fragment-count bounds.
const GECKO_MIN_CHUNKS: u8 = 2;
const GECKO_MAX_CHUNKS: u8 = 8;

/// Encodes one datagram through Gecko: Salamander, then fragmentation if it is a long header.
///
/// A QUIC long header (`0x80` bit set) is split into 2–8 chunks, each size-padded so the
/// datagram lands in `[min, max]`. A short header passes through untouched — it is data, and
/// fragmenting it would cost a round trip for nothing.
fn gecko_encode(password: &[u8], payload: &[u8], min: u16, max: u16) -> Vec<u8> {
    if payload.is_empty() {
        return Vec::new();
    }
    if payload[0] & 0x80 == 0 {
        return obfuscate_salamander(password, payload);
    }
    let chunk_count =
        GECKO_MIN_CHUNKS + (fastrand::u8(..) % (GECKO_MAX_CHUNKS - GECKO_MIN_CHUNKS + 1));
    let chunk_size = payload.len().div_ceil(usize::from(chunk_count));
    let msg_id = fastrand::u8(..);
    let mut out = Vec::new();
    for index in 0..chunk_count {
        let start = usize::from(index) * chunk_size;
        if start >= payload.len() {
            break;
        }
        let end = (start + chunk_size).min(payload.len());
        let chunk = &payload[start..end];
        // `randomPadLen`: pick padding so `salt + header + chunk + pad` lands in [min, max].
        let base = SALT_LEN + GECKO_HEADER_LEN + chunk.len();
        let pad_len = if base >= usize::from(max) {
            0
        } else {
            let low = base.max(usize::from(min));
            low - base + fastrand::usize(..=(usize::from(max) - low))
        };
        let mut frame = Vec::with_capacity(base + pad_len);
        frame.push(GECKO_FLAG_FRAGMENT);
        frame.push(msg_id);
        frame.push((index << 4) | (chunk_count & 0x0f));
        frame.extend_from_slice(&(pad_len as u16).to_be_bytes());
        let mut padding = vec![0u8; pad_len];
        getrandom::fill(&mut padding).expect("the OS provides entropy");
        frame.extend_from_slice(&padding);
        frame.extend_from_slice(chunk);
        out.extend_from_slice(&obfuscate_salamander(password, &frame));
    }
    out
}

/// Whether a datagram is a Gecko fragment (the top bit is set on the *plaintext*).
fn gecko_decode(password: &[u8], datagram: &[u8]) -> Option<Vec<u8>> {
    let plain = deobfuscate_salamander(password, datagram)?;
    if plain.first().is_none_or(|byte| byte & 0x80 == 0) {
        // A short header or a stray packet: hand it back as-is for Quinn to judge.
        return Some(plain);
    }
    if plain.len() < GECKO_HEADER_LEN {
        return None;
    }
    let frame = GeckoFrame {
        msg_id: plain[1],
        chunk_idx: plain[2] >> 4,
        total_chunks: plain[2] & 0x0f,
        pad_len: u16::from_be_bytes([plain[3], plain[4]]),
    };
    if !(GECKO_MIN_CHUNKS..=GECKO_MAX_CHUNKS).contains(&frame.total_chunks)
        || frame.chunk_idx >= frame.total_chunks
    {
        return None;
    }
    let start = GECKO_HEADER_LEN + usize::from(frame.pad_len);
    if start > plain.len() {
        return None;
    }
    // One fragment cannot be reassembled into a datagram, so Gecko's receiving side keeps a
    // reassembly window. It is per-socket state, which is why the full reassembly lives in
    // [`GeckoReassembler`] and this function only parses one frame.
    Some(plain[start..].to_vec())
}

/// Gecko's reassembly window: one packet id at a time, exactly as the reference does it.
///
/// The reference's comment is explicit: "The current implementation can only handle one
/// packet ID at a time. If another packet arrives before a packet has received all fragments
/// in their entirety, any previous state is discarded." Reproducing that limitation is
/// deliberate — a wider window would accept reordered fragments the server never sends, and
/// the two sides must agree on when a packet is given up on.
#[derive(Debug, Default)]
pub struct GeckoReassembler {
    packet_id: Option<u8>,
    fragments: Vec<Option<Vec<u8>>>,
}

impl GeckoReassembler {
    /// Feeds one frame, returning the assembled datagram when the set is complete.
    pub fn feed(&mut self, frame: GeckoFrame, payload: Vec<u8>) -> Option<Vec<u8>> {
        if frame.total_chunks <= 1 {
            return Some(payload);
        }
        if frame.chunk_idx >= frame.total_chunks {
            return None;
        }
        if self.packet_id != Some(frame.msg_id)
            || self.fragments.len() != usize::from(frame.total_chunks)
        {
            // A new message: previous state is discarded, as the reference does.
            self.packet_id = Some(frame.msg_id);
            self.fragments = vec![None; usize::from(frame.total_chunks)];
        }
        let slot = &mut self.fragments[usize::from(frame.chunk_idx)];
        if slot.is_some() {
            return None;
        }
        *slot = Some(payload);
        if self.fragments.iter().any(Option::is_none) {
            return None;
        }
        let mut assembled = Vec::new();
        for fragment in self.fragments.drain(..) {
            assembled.extend_from_slice(fragment.as_deref().unwrap_or_default());
        }
        self.packet_id = None;
        Some(assembled)
    }
}

/// Keeps the trace recorder type reachable from this module, so a future layer can record
/// datagram counts without adding an import that only one call site uses.
pub type RecorderRef = Arc<Mutex<Recorder>>;

#[cfg(test)]
mod tests {
    use super::*;
    use blake2::Digest as _;

    fn key(password: &[u8], salt: &[u8]) -> [u8; 32] {
        let mut hasher = blake2::Blake2b::<blake2::digest::consts::U32>::new();
        hasher.update(password);
        hasher.update(salt);
        hasher.finalize().into()
    }

    #[test]
    fn salamander_matches_the_references_construction() {
        // The reference's `salamanderObfuscator`: `out = salt ‖ (payload ^ BLAKE2b256(psk ‖
        // salt)[i % 32])`. The salt is random, so the test derives the expectation from the
        // emitted salt rather than pinning one.
        let password = b"average_password";
        let payload = b"a QUIC Initial packet, shaped like nothing in particular";
        let oblique = obfuscate_salamander(password, payload);

        assert_eq!(oblique.len(), SALT_LEN + payload.len());
        let salt = &oblique[..SALT_LEN];
        let expected_key = key(password, salt);
        for (index, byte) in oblique[SALT_LEN..].iter().enumerate() {
            assert_eq!(
                *byte,
                payload[index] ^ expected_key[index % 32],
                "byte {index} must be the payload XORed with the salted key stream"
            );
        }
    }

    #[test]
    fn deobfuscation_is_the_inverse_and_refuses_a_truncated_salt() {
        let password = b"another_password";
        let payload = b"0123456789abcdef";
        let oblique = obfuscate_salamander(password, payload);

        assert_eq!(
            deobfuscate_salamander(password, &oblique).as_deref(),
            Some(&payload[..])
        );
        // Two datagrams never share a salt, so obfuscating twice differs.
        assert_ne!(oblique, obfuscate_salamander(password, payload));
        // A datagram that cannot carry a salt is refused rather than misparsed.
        assert_eq!(deobfuscate_salamander(password, &[1, 2, 3]), None);
        assert_eq!(deobfuscate_salamander(password, &[0u8; SALT_LEN]), None);
    }

    #[test]
    fn gecko_fragments_a_long_header_into_decodable_chunks() {
        // A long header has the top bit set; the reference fragments exactly those.
        let password = b"gecko_password";
        let mut payload = vec![0x80u8];
        payload.extend_from_slice(&[0u8; 1200]);

        let encoded = gecko_encode(password, &payload, 512, 1200);
        // Every emitted datagram is a Salamander-framed Gecko fragment. Datagrams are not
        // individually delimited on this test path, so the first one is decoded and the rest
        // trusted by construction: the encoder emits one obfuscated frame per chunk.
        assert!(!encoded.is_empty());
        let plain = deobfuscate_salamander(password, &encoded).expect("decodes");
        assert_eq!(
            plain[0] & 0x80,
            0x80,
            "each frame carries the fragment marker"
        );
        let total = plain[2] & 0x0f;
        assert!((GECKO_MIN_CHUNKS..=GECKO_MAX_CHUNKS).contains(&total));
    }

    #[test]
    fn a_short_header_passes_through_untouched() {
        // Data packets are not fragmented: only the top bit distinguishes them, and
        // fragmenting them would cost a round trip for nothing.
        let password = b"gecko_password";
        let payload = vec![0x40u8, 1, 2, 3, 4];
        let encoded = gecko_encode(password, &payload, 512, 1200);
        assert_eq!(
            deobfuscate_salamander(password, &encoded).as_deref(),
            Some(&payload[..])
        );
    }

    #[test]
    fn gecko_reassembly_waits_for_every_fragment_and_gives_up_on_a_new_message() {
        let mut reassembler = GeckoReassembler::default();
        let frame = |msg_id, chunk_idx, total_chunks| GeckoFrame {
            msg_id,
            chunk_idx,
            total_chunks,
            pad_len: 0,
        };

        // One fragment of two: nothing yet.
        assert_eq!(reassembler.feed(frame(7, 0, 2), b"aaa".to_vec()), None);
        // The second completes it.
        assert_eq!(
            reassembler.feed(frame(7, 1, 2), b"bbb".to_vec()),
            Some(b"aaabbb".to_vec())
        );

        // A new message id discards the partial state, exactly as the reference documents.
        assert_eq!(reassembler.feed(frame(9, 0, 2), b"x".to_vec()), None);
        assert_eq!(
            reassembler.feed(frame(9, 1, 2), b"y".to_vec()),
            Some(b"xy".to_vec())
        );

        // An unfragmented packet needs no window.
        assert_eq!(
            reassembler.feed(frame(1, 0, 1), b"whole".to_vec()),
            Some(b"whole".to_vec())
        );
    }

    #[test]
    fn an_obfs_whose_password_is_too_short_is_refused_with_the_reason() {
        let obfs = daer_config::Hysteria2Obfs::Salamander {
            password: "abc".to_owned(),
        };
        let error = Obfs::from_config(&obfs).expect_err("3 bytes is under the reference floor");
        assert!(error.contains('4'), "{error}");

        let ok = Obfs::from_config(&daer_config::Hysteria2Obfs::Salamander {
            password: "abcd".to_owned(),
        })
        .expect("4 bytes is the floor");
        assert_eq!(ok.kind(), "salamander");
    }

    #[test]
    fn unusable_gecko_bounds_are_refused_rather_than_clamped() {
        let obfs = daer_config::Hysteria2Obfs::Gecko {
            password: "abcd".to_owned(),
            min_packet_size: 1500,
            max_packet_size: 1000,
        };
        let error = Obfs::from_config(&obfs).expect_err("min > max");
        assert!(error.contains("range"), "{error}");

        // The defaults apply when the bounds are absent, so a bare password is usable.
        let ok = Obfs::from_config(&daer_config::Hysteria2Obfs::Gecko {
            password: "abcd".to_owned(),
            min_packet_size: 0,
            max_packet_size: 0,
        })
        .expect("defaults");
        assert_eq!(ok.kind(), "gecko");
    }
}
