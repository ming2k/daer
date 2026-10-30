// SPDX-License-Identifier: AGPL-3.0-only

//! XTLS Vision (`flow=xtls-rprx-vision`) for a REALITY session.
//!
//! # Why this is mandatory, not an optimisation
//!
//! A node whose user is configured with Vision **rejects a client that omits the flow**:
//! the server compares the client's declared flow against the account's and refuses the
//! session outright when they differ. So for such a node "skip Vision" is not a degradation,
//! it is a connection that never carries a byte.
//!
//! # The wire format
//!
//! Vision frames the tunnel's payload as a sequence of blocks. Every block is
//!
//! ```text
//!   [uuid 16]  [command 1] [content_len 2] [padding_len 2] [content…] [padding…]
//!    ^ only on the very first block of each direction
//! ```
//!
//! and the command says what follows the block:
//!
//! | Command | Value | Meaning |
//! | --- | --- | --- |
//! | Continue | `0x00` | another block follows |
//! | End | `0x01` | the block is the last; the rest of the stream is raw |
//! | Direct | `0x02` | as `End`, and the peer may splice at the socket |
//!
//! The padding exists to hide the length signature of the TLS handshake that follows: a
//! fixed-size `ClientHello` inside a fixed-size record is a fingerprint, and filling the
//! record to a random length removes it.
//!
//! # What the receiver does with an unrecognised first block
//!
//! It passes the bytes through untouched. That is the compatibility rule that lets a Vision
//! client talk to a node whose user is *not* configured for Vision, and it is why this
//! implementation has to be exact: a malformed block is not an error the peer reports, it is
//! silently treated as payload, which corrupts the stream in a way that looks like the inner
//! protocol misbehaving.
//!
//! # Scope
//!
//! Only what a client needs: pad the uplink, unpad the downlink, and stop padding when the
//! inner stream reveals itself. The splice optimisation (`Direct` at the socket) is
//! deliberately absent — it needs the raw file descriptor on both legs, and the tunnel is
//! correct without it.

use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// The command byte of a block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Command {
    /// Another block follows this one.
    Continue = 0x00,
    /// This is the last block; the remaining bytes are raw.
    End = 0x01,
    /// As [`Command::End`], and the peer may splice at the socket.
    Direct = 0x02,
}

impl Command {
    fn from_byte(byte: u8) -> Option<Self> {
        Some(match byte {
            0x00 => Self::Continue,
            0x01 => Self::End,
            0x02 => Self::Direct,
            _ => return None,
        })
    }
}

/// The first three bytes of a TLS 1.3 application-data record.
const TLS_APPLICATION_DATA: [u8; 3] = [0x17, 0x03, 0x03];

/// How many chunks the writer inspects looking for the inner TLS handshake.
///
/// The reference implementation uses eight. Once the budget is spent it stops padding, so a
/// stream that never reveals itself as TLS (a plaintext protocol inside the tunnel, for
/// example) does not stay padded forever.
const FILTER_BUDGET: u8 = 8;

/// The state that decides how long to keep padding.
///
/// Shared between the read and write halves because the decision depends on both: the
/// downlink's `ServerHello` is what proves the inner stream is TLS 1.3, and the uplink's
/// writer is what acts on that verdict. The reference implementation keeps one per
/// connection for exactly this reason.
#[derive(Debug)]
pub(crate) struct TrafficState {
    /// Chunks still to be inspected for the inner TLS handshake.
    filter_budget: u8,
    /// True once any TLS record has been seen inside the tunnel.
    is_tls: bool,
    /// True once a TLS 1.2-or-later `ServerHello` has been seen, which is the signal that
    /// the inner stream is worth padding for.
    is_tls12_or_above: bool,
    /// True when the inner stream is TLS 1.3, which is what the `Direct` command is for.
    enable_xtls: bool,
}

impl Default for TrafficState {
    fn default() -> Self {
        Self::new()
    }
}

impl TrafficState {
    pub(crate) fn new() -> Self {
        Self {
            filter_budget: FILTER_BUDGET,
            is_tls: false,
            is_tls12_or_above: false,
            enable_xtls: false,
        }
    }

    /// Inspects one chunk of inner traffic and records what it reveals.
    fn observe(&mut self, chunk: &[u8]) {
        if self.filter_budget == 0 {
            return;
        }
        self.filter_budget -= 1;

        // A TLS record header is five bytes: type, version, length.
        if chunk.len() < 6 {
            return;
        }
        let kind = chunk[0];
        let version = u16::from_be_bytes([chunk[1], chunk[2]]);
        // `0x16 0x03 0x03` with handshake type 2 is a ServerHello.
        if kind == 0x16 && version == 0x0303 && chunk[5] == 0x02 {
            self.is_tls12_or_above = true;
            self.is_tls = true;
            // A TLS 1.3 ServerHello advertises `supported_versions` = 0x0304. Searching the
            // whole record rather than parsing the extension mirrors the reference: the
            // question is only "is this 1.3", and a false positive costs a splice decision,
            // not correctness.
            if chunk
                .windows(6)
                .any(|window| window == [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04])
            {
                self.enable_xtls = true;
            }
        } else if kind == 0x16 && chunk[1] == 0x03 && chunk[5] == 0x01 {
            // A ClientHello: the inner stream is TLS, but 1.2 versus 1.3 is not yet known.
            self.is_tls = true;
        }
    }

    /// Whether the writer has learnt all it will learn.
    ///
    /// The reference finishes padding one packet early ("for compatibility with earlier
    /// vision receiver"), which is `NumberOfPacketToFilter <= 1`.
    const fn budget_spent(&self) -> bool {
        self.filter_budget <= 1
    }

    /// Marks the padding as finished after the opening block.
    ///
    /// The reference stops padding once it has seen enough to conclude the inner stream is
    /// not TLS ("for compatibility with earlier vision receiver, we finish padding 1 packet
    /// early": `NumberOfPacketToFilter <= 1`). The opening block is what the header was
    /// hidden behind, so by the time the real payload arrives there is nothing left to
    /// hide — and a block that says `Continue` leaves the peer unpadding bytes that are
    /// plaintext, which is exactly how a request ends up being read as another block header.
    ///
    /// A TLS-in-TLS stream reaches the same point on the same block: its first payload is
    /// the inner `ClientHello`, which is not application data, so the reference's
    /// application-data branch does not fire either.
    fn finish_padding_after_opening(&mut self) {
        self.filter_budget = 1;
    }
}

/// Pads the uplink.
#[derive(Debug)]
struct WriteSide {
    uuid: [u8; 16],
    /// The uuid is written once, on the first block of the direction.
    uuid_pending: bool,
    /// True while blocks are still being emitted.
    padding: bool,
}

impl WriteSide {
    const fn new(uuid: [u8; 16]) -> Self {
        Self {
            uuid,
            uuid_pending: true,
            padding: true,
        }
    }

    /// Frames `payload` as one block.
    ///
    /// `long_padding` asks for enough padding to bring the block to a random size in a wide
    /// band, which is what hides a handshake's length signature. A short block that is not
    /// asking for that gets a small random amount instead.
    fn frame(&mut self, payload: &[u8], command: Command, long_padding: bool) -> Vec<u8> {
        let content_len = payload.len();
        let padding_len = padding_for(content_len, long_padding);

        let mut out = Vec::with_capacity(16 + 5 + content_len + padding_len);
        if self.uuid_pending {
            out.extend_from_slice(&self.uuid);
            self.uuid_pending = false;
        }
        out.push(command as u8);
        out.extend_from_slice(&(content_len as u16).to_be_bytes());
        out.extend_from_slice(&(padding_len as u16).to_be_bytes());
        out.extend_from_slice(payload);
        out.resize(out.len() + padding_len, 0);
        out
    }
}

/// The reference implementation's `buf.Size`, which bounds a padded block.
///
/// `XtlsPadding` clamps with `buf.Size - 21 - contentLen`, so this number decides the
/// maximum padding. Using anything smaller silently caps every block below what the
/// reference produces, which changes the size distribution the padding exists to blur.
const BUF_SIZE: usize = 8192;

/// How much padding to add, following `XtlsPadding` exactly.
///
/// The reference derives it from `testseed = {900, 500, 900, 256}`:
///
/// ```text
///   if contentLen < testseed[0] && longPadding {
///       paddingLen = rand(testseed[1]) + testseed[2] - contentLen   // ≈ 900..1400 - len
///   } else {
///       paddingLen = rand(testseed[3])                              // 0..255
///   }
///   paddingLen = min(paddingLen, buf.Size - 21 - contentLen)
/// ```
fn padding_for(content_len: usize, long_padding: bool) -> usize {
    let (seed0, seed1, seed2, seed3): (usize, usize, usize, usize) = (900, 500, 900, 256);
    let padding_len = if long_padding && content_len < seed0 {
        // `rand` is inclusive of neither bound; the offset makes the band sit near 900.
        usize::from(fastrand::u16(0..seed1 as u16)) + seed2 - content_len
    } else {
        usize::from(fastrand::u16(0..seed3 as u16))
    };
    // Clamped exactly as the reference does, so a large block cannot overflow the ceiling.
    padding_len.min(BUF_SIZE.saturating_sub(21).saturating_sub(content_len))
}

/// Where the unpadder is in a block.
#[derive(Debug, Clone, Copy)]
enum Phase {
    /// Skipping the VLESS response header (`version || addon_len`) that precedes the first
    /// downlink block.
    ///
    /// `EncodeResponseHeader` writes these two bytes to the same writer the Vision writer
    /// then wraps, so the server's first block does **not** start at offset zero of the
    /// stream. A reader that expects the uuid there concludes "not a Vision stream" and
    /// hands the caller the raw framed bytes — which is exactly what happened, and why the
    /// first bytes of a working reply still looked like a uuid.
    ResponseHeader { remaining: usize },
    /// Waiting for the first block, which is the only one that carries the uuid.
    Initial,
    /// Reading a block header.
    Header,
    /// Passing `remaining` bytes of content through.
    Content { remaining: usize },
    /// Discarding `remaining` bytes of padding.
    Padding { remaining: usize },
    /// Padding is over: every remaining byte is payload.
    Raw,
}

/// Removes the padding from the downlink.
#[derive(Debug)]
struct ReadSide {
    uuid: [u8; 16],
    phase: Phase,
    /// The command of the block being read.
    command: Command,
    /// The padding length declared by the block header, consumed after its content.
    block_padding: usize,
    /// Bytes received but not yet consumed by the state machine.
    raw: Vec<u8>,
    /// Bytes ready to be handed to the caller.
    ready: Vec<u8>,
}

impl ReadSide {
    fn new(uuid: [u8; 16]) -> Self {
        Self {
            uuid,
            phase: Phase::Initial,
            command: Command::End,
            block_padding: 0,
            raw: Vec::new(),
            ready: Vec::new(),
        }
    }

    /// Feeds `bytes` through the state machine.
    fn push(&mut self, bytes: &[u8]) {
        self.raw.extend_from_slice(bytes);
        loop {
            match self.phase {
                Phase::ResponseHeader { remaining } => {
                    if self.raw.is_empty() {
                        return;
                    }
                    let take = remaining.min(self.raw.len());
                    self.raw.drain(..take);
                    let left = remaining - take;
                    self.phase = if left > 0 {
                        Phase::ResponseHeader { remaining: left }
                    } else {
                        Phase::Initial
                    };
                }
                Phase::Initial => {
                    if self.raw.len() < 16 {
                        return;
                    }
                    if self.raw[..16] == self.uuid {
                        self.raw.drain(..16);
                        self.phase = Phase::Header;
                    } else {
                        // Not a Vision stream: pass it through. This is the compatibility
                        // rule, and it is why a malformed block corrupts rather than errors.
                        self.phase = Phase::Raw;
                    }
                }
                Phase::Header => {
                    if self.raw.len() < 5 {
                        return;
                    }
                    let command = self.raw[0];
                    let content_len = usize::from(u16::from_be_bytes([self.raw[1], self.raw[2]]));
                    let padding_len = usize::from(u16::from_be_bytes([self.raw[3], self.raw[4]]));
                    self.raw.drain(..5);
                    self.block_padding = padding_len;
                    self.command = match Command::from_byte(command) {
                        Some(command) => command,
                        // An unknown command is not recoverable: the reference treats the
                        // stream as payload from here on, and so do we.
                        None => {
                            self.phase = Phase::Raw;
                            continue;
                        }
                    };
                    self.phase = if content_len > 0 {
                        Phase::Content {
                            remaining: content_len,
                        }
                    } else if padding_len > 0 {
                        Phase::Padding {
                            remaining: padding_len,
                        }
                    } else {
                        self.finish_block()
                    };
                }
                Phase::Content { remaining } => {
                    if self.raw.is_empty() {
                        return;
                    }
                    let take = remaining.min(self.raw.len());
                    self.ready.extend(self.raw.drain(..take));
                    let left = remaining - take;
                    self.phase = if left > 0 {
                        Phase::Content { remaining: left }
                    } else {
                        // The content is done; the header's padding length decides what
                        // follows, which is why it is kept rather than recomputed.
                        Phase::Padding {
                            remaining: self.block_padding,
                        }
                    };
                }
                Phase::Padding { remaining } => {
                    if remaining == 0 {
                        self.phase = self.finish_block();
                        continue;
                    }
                    if self.raw.is_empty() {
                        return;
                    }
                    let take = remaining.min(self.raw.len());
                    self.raw.drain(..take);
                    let left = remaining - take;
                    self.phase = if left > 0 {
                        Phase::Padding { remaining: left }
                    } else {
                        self.finish_block()
                    };
                }
                Phase::Raw => {
                    if self.raw.is_empty() {
                        return;
                    }
                    let raw = std::mem::take(&mut self.raw);
                    self.ready.extend_from_slice(&raw);
                    return;
                }
            }
        }
    }

    /// The next phase after a block's bytes are consumed.
    fn finish_block(&mut self) -> Phase {
        match self.command {
            Command::Continue => Phase::Header,
            Command::End | Command::Direct => Phase::Raw,
        }
    }
}

/// A tunnel whose payload is Vision-framed.
pub(crate) struct VisionStream<S> {
    inner: S,
    read: ReadSide,
    write: WriteSide,
    state: TrafficState,
}

impl<S> std::fmt::Debug for VisionStream<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VisionStream")
            .field("phase", &self.read.phase)
            .field("padding", &self.write.padding)
            .finish_non_exhaustive()
    }
}

impl<S> VisionStream<S> {
    /// Wraps a handshaken tunnel.
    ///
    /// `uuid` is the VLESS user id, which Vision repeats at the head of each direction.
    /// Wraps a tunnel whose downlink begins with the VLESS response header.
    ///
    /// The node's reply is `version(1) || addon_len(1)` and then its first Vision block, so
    /// the uuid is two bytes in rather than at offset zero.
    pub(crate) fn new_answering(inner: S, uuid: [u8; 16]) -> Self {
        let mut read = ReadSide::new(uuid);
        read.phase = Phase::ResponseHeader { remaining: 2 };
        Self {
            inner,
            read,
            write: WriteSide::new(uuid),
            state: TrafficState::new(),
        }
    }

    /// Writes `bytes` to the tunnel **without** framing them again.
    ///
    /// The VLESS header is not a Vision block, and the opening block already is one; a
    /// caller that hands the two to [`AsyncWrite::poll_write`] gets them wrapped a second
    /// time and the peer reads block bytes as a VLESS version. This writes the bytes
    /// through, which is what the reference gets from building its buffer before the
    /// VisionWriter exists.
    pub(crate) async fn write_through(&mut self, bytes: &[u8]) -> std::io::Result<()>
    where
        S: AsyncWrite + Unpin,
    {
        tokio::io::AsyncWriteExt::write_all(&mut self.inner, bytes).await
    }

    /// The empty, long-padded block that must follow the VLESS request header.
    ///
    /// The reference emits this from its `len(mb) == 1 && mb[0] == nil` branch, with the
    /// comment "we do a long padding to hide vless header". It carries **no content**: its
    /// only job is to occupy a large, randomly sized block so the request header that
    /// precedes it has no distinguishable length.
    ///
    /// It is not optional. A client that sends the header and then a payload immediately
    /// gives the peer a short header followed by a short block, which is the length
    /// signature the scheme exists to remove — and the reference node's reader is written
    /// against the reference writer, so it expects this block first.
    pub(crate) fn opening_block(&mut self) -> Vec<u8> {
        // `Continue`, not `End`: the stream is not finished, and the next write appends.
        // Framed through the writer's state so the uuid is consumed here — this *is* the
        // first block of the direction — and the next block does not repeat it.
        let framed = self.write.frame(&[], Command::Continue, true);
        self.state.finish_padding_after_opening();
        framed
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for VisionStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            if !self.read.ready.is_empty() {
                let take = self.read.ready.len().min(buf.remaining());
                buf.put_slice(&self.read.ready[..take]);
                self.read.ready.drain(..take);
                return Poll::Ready(Ok(()));
            }
            if buf.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }

            let mut chunk = [0u8; 4096];
            let mut read_buf = ReadBuf::new(&mut chunk);
            match Pin::new(&mut self.inner).poll_read(cx, &mut read_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {
                    let filled = read_buf.filled().len();
                    if filled == 0 {
                        // EOF: hand over whatever the unpadder is still holding, then end.
                        let raw = std::mem::take(&mut self.read.raw);
                        self.read.ready.extend_from_slice(&raw);
                        if !self.read.ready.is_empty() {
                            continue;
                        }
                        return Poll::Ready(Ok(()));
                    }
                    let bytes = chunk[..filled].to_vec();
                    self.state.observe(&bytes);
                    self.read.push(&bytes);
                }
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for VisionStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if !self.write.padding {
            return Pin::new(&mut self.inner).poll_write(cx, buf);
        }

        // Observe *first*: the budget and the "is the inside TLS" verdict both feed the
        // command decision below, so inspecting after the decision would leave the first
        // block always `Continue` and the stream never terminated.
        self.state.observe(buf);

        // The command says what the peer does after this block. `Continue` keeps the
        // receiver unpadding; `End` tells it the rest of the stream is raw.
        let mut command = Command::Continue;
        if self.state.is_tls
            && buf.len() >= 6
            && buf[..3] == TLS_APPLICATION_DATA
            && is_complete_record(buf)
        {
            command = if self.state.enable_xtls {
                Command::Direct
            } else {
                Command::End
            };
            self.write.padding = false;
        } else if !self.state.is_tls12_or_above && self.state.budget_spent() {
            command = Command::End;
            self.write.padding = false;
        }

        // `frame` needs `&mut self.write` and `&self.state` at once; reading the flag it uses
        // into a local keeps the borrows disjoint.
        let long_padding = self.state.is_tls;
        let framed = self.write.frame(buf, command, long_padding);
        match Pin::new(&mut self.inner).poll_write(cx, &framed) {
            // The report is about the caller's bytes, not the framed length: a caller that
            // asked to write 100 bytes must be told 100, or it retries the remainder of a
            // block that has already gone out and the peer sees it twice.
            Poll::Ready(Ok(_written)) => Poll::Ready(Ok(buf.len())),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Whether `bytes` holds a whole number of TLS records, all of them application data.
fn is_complete_record(bytes: &[u8]) -> bool {
    let mut offset = 0;
    while offset < bytes.len() {
        if bytes.len() - offset < 5 {
            return false;
        }
        if bytes[offset] != 0x17 || bytes[offset + 1] != 0x03 || bytes[offset + 2] != 0x03 {
            return false;
        }
        let length = usize::from(u16::from_be_bytes([bytes[offset + 3], bytes[offset + 4]]));
        offset += 5 + length;
    }
    offset == bytes.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: [u8; 16] = [
        0xdf, 0x4a, 0xf3, 0xd0, 0x03, 0x0e, 0x40, 0x62, 0xba, 0xa6, 0xeb, 0x9d, 0xd4, 0x52, 0x98,
        0xef,
    ];

    /// Frames one block by hand, the way a peer would.
    fn block(uuid: Option<[u8; 16]>, command: Command, content: &[u8], padding: usize) -> Vec<u8> {
        let mut out = Vec::new();
        if let Some(uuid) = uuid {
            out.extend_from_slice(&uuid);
        }
        out.push(command as u8);
        out.extend_from_slice(&(content.len() as u16).to_be_bytes());
        out.extend_from_slice(&(padding as u16).to_be_bytes());
        out.extend_from_slice(content);
        out.resize(out.len() + padding, 0);
        out
    }

    #[test]
    fn a_first_block_carries_the_uuid_and_its_content_survives() {
        let mut read = ReadSide::new(UUID);
        read.push(&block(Some(UUID), Command::End, b"hello", 32));
        assert_eq!(read.ready, b"hello");
        assert!(matches!(read.phase, Phase::Raw), "End ends the padding");
    }

    #[test]
    fn padding_is_discarded_not_echoed() {
        let mut read = ReadSide::new(UUID);
        read.push(&block(Some(UUID), Command::End, b"abc", 64));
        assert_eq!(
            read.ready, b"abc",
            "the zero padding must not reach the caller"
        );
    }

    #[test]
    fn the_downlink_response_header_is_skipped_before_the_uuid() {
        // The node writes `version || addon_len` to the same writer its Vision writer wraps,
        // so its first block is two bytes in. A reader that expects the uuid at offset zero
        // falls back to raw passthrough and the caller sees the framing as data — which is
        // what happened: a working reply began with the uuid instead of with `HTTP/`.
        let content = b"HTTP/1.1 200 OK\r\n\r\n";
        let mut wire = vec![0x00, 0x00]; // VLESS response version + addon length
        wire.extend_from_slice(&UUID);
        wire.push(0x01); // End
        wire.extend_from_slice(&(content.len() as u16).to_be_bytes());
        wire.extend_from_slice(&0u16.to_be_bytes());
        wire.extend_from_slice(content);

        let mut read = ReadSide::new(UUID);
        read.phase = Phase::ResponseHeader { remaining: 2 };
        read.push(&wire);
        assert_eq!(read.ready, content, "the response header must be dropped");
    }

    #[test]
    fn the_payload_block_after_the_opening_one_ends_the_padding() {
        // The reference stops padding one packet early, so the first real payload says
        // `End`. A block that says `Continue` leaves the peer unpadding plaintext, and the
        // request is then read as another block header.
        let mut stream = VisionStream::new_answering((), UUID);
        let _ = stream.opening_block();
        assert!(
            stream.state.budget_spent(),
            "the opening block must consume the padding budget"
        );
    }

    #[test]
    fn a_stream_that_is_not_vision_passes_through_untouched() {
        // A node whose user is not configured for Vision sends no uuid. The bytes must reach
        // the caller unchanged: this is the compatibility rule the format relies on.
        let mut read = ReadSide::new(UUID);
        read.push(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n");
        assert_eq!(read.ready, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n");
    }

    #[test]
    fn a_block_split_across_reads_is_reassembled() {
        // Records arrive in pieces; a header cut in half must not be misread.
        let framed = block(Some(UUID), Command::End, b"0123456789", 16);
        let mut read = ReadSide::new(UUID);
        for byte in &framed[..21] {
            read.push(std::slice::from_ref(byte));
        }
        assert!(read.ready.is_empty(), "nothing is ready mid-header");
        for byte in &framed[21..25] {
            read.push(std::slice::from_ref(byte));
        }
        assert_eq!(read.ready, b"0123", "content flows as it arrives");
        read.push(&framed[25..]);
        assert_eq!(read.ready, b"0123456789");
    }

    #[test]
    fn a_continue_block_is_followed_by_another_block() {
        let mut read = ReadSide::new(UUID);
        let mut stream = block(Some(UUID), Command::Continue, b"one", 8);
        stream.extend_from_slice(&block(None, Command::End, b"two", 8));
        read.push(&stream);
        assert_eq!(read.ready, b"onetwo");
        assert!(matches!(read.phase, Phase::Raw));
    }

    #[test]
    fn payload_after_an_end_block_is_raw() {
        let mut read = ReadSide::new(UUID);
        let mut stream = block(Some(UUID), Command::End, b"one", 0);
        stream.extend_from_slice(b"GET /");
        read.push(&stream);
        assert_eq!(read.ready, b"oneGET /");
    }

    #[test]
    fn the_writer_prefixes_the_uuid_exactly_once() {
        // The first block carries the uuid; every later one starts with its command byte, so it
        // must not repeat it. Asserting `second[..16] != UUID` would be a coin flip — the second
        // block is `[command][content_len][padding_len][payload][padding]`, so a particular
        // payload and padding length can spell the uuid by accident, and the test failed exactly
        // once in a full-workspace run because of it.
        //
        // What is actually invariant: the uuid appears at offset 0 of the first block, and the
        // second block's *length prefix* describes its own payload — which is how the reader
        // tells the two apart.
        let mut write = WriteSide::new(UUID);
        let first = write.frame(b"a", Command::Continue, false);
        let second = write.frame(b"b", Command::Continue, false);
        assert_eq!(&first[..16], &UUID, "the first block carries the uuid");

        // The second block has no uuid, so its first byte is the command and its next four are
        // the length prefixes. Reading it as a block must recover the payload.
        assert_eq!(second[0], Command::Continue as u8);
        let content_len = u16::from_be_bytes([second[1], second[2]]);
        assert_eq!(content_len, 1, "the second block carries one payload byte");
        assert_eq!(
            &second[5..6],
            b"b",
            "the payload follows the two length prefixes"
        );
    }

    #[test]
    fn a_framed_block_round_trips_through_the_reader() {
        // The property that matters: whatever the writer emits, the reader returns the
        // payload and nothing else.
        let mut write = WriteSide::new(UUID);
        let framed = write.frame(b"payload bytes", Command::End, false);

        let mut read = ReadSide::new(UUID);
        read.push(&framed);
        assert_eq!(read.ready, b"payload bytes");
    }

    #[test]
    fn a_complete_tls_application_record_is_recognised() {
        let record = [0x17, 0x03, 0x03, 0x00, 0x02, 0xaa, 0xbb];
        assert!(is_complete_record(&record));
        // One byte short of the declared length is not complete.
        assert!(!is_complete_record(&[0x17, 0x03, 0x03, 0x00, 0x02, 0xaa]));
        // A handshake record is not application data.
        assert!(!is_complete_record(&[
            0x16, 0x03, 0x01, 0x00, 0x02, 0xaa, 0xbb
        ]));
    }

    #[test]
    fn a_server_hello_teaches_the_state_that_the_inside_is_tls13() {
        let mut state = TrafficState::new();
        let mut hello = vec![0x16, 0x03, 0x03, 0x00, 0x20, 0x02];
        hello.extend_from_slice(&[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]);
        hello.resize(40, 0);
        state.observe(&hello);
        assert!(state.is_tls, "a ServerHello means TLS");
        assert!(state.is_tls12_or_above);
        assert!(
            state.enable_xtls,
            "supported_versions = 1.3 enables direct copy"
        );
    }

    #[test]
    fn an_unknown_command_degrades_to_raw_rather_than_corrupting() {
        let mut read = ReadSide::new(UUID);
        let mut stream = Vec::new();
        stream.extend_from_slice(&UUID);
        stream.extend_from_slice(&[0x7f, 0, 0, 0, 0]); // command 0x7f
        stream.extend_from_slice(b"tail");
        read.push(&stream);
        assert_eq!(read.ready, b"tail");
    }
}
