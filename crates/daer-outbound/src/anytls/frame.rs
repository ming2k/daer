// SPDX-License-Identifier: AGPL-3.0-only

//! AnyTLS frame definition and binary codec.
//!
//! A frame consists of a 7-byte header followed by variable-length data:
//! ```text
//! +----------+-------------------+------------------+---------------------+
//! | cmd (1B) |  stream_id (4B)   | data_length (2B) |     data (N B)      |
//! +----------+-------------------+------------------+---------------------+
//! ```
//! All integers are big-endian (network byte order).

use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::fmt;

/// The 7-byte header overhead size for each AnyTLS frame.
pub const HEADER_OVERHEAD_SIZE: usize = 7;

/// Maximum payload size in a single frame (u16::MAX).
pub const MAX_FRAME_PAYLOAD_SIZE: usize = u16::MAX as usize;

/// Command types in AnyTLS frames.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// Waste bytes for traffic padding and timing obfuscation.
    Waste = 0,
    /// Open a new multiplexed stream.
    Syn = 1,
    /// Push data payload to a stream.
    Push = 2,
    /// Close a stream (EOF).
    Fin = 3,
    /// Client settings.
    Settings = 4,
    /// Alert / error notification.
    Alert = 5,
    /// Dynamic padding scheme update.
    UpdatePaddingScheme = 6,
    /// Server acknowledges stream open.
    SynAck = 7,
    /// Keep-alive heartbeat ping.
    HeartRequest = 8,
    /// Keep-alive heartbeat pong.
    HeartResponse = 9,
    /// Server settings.
    ServerSettings = 10,
    /// Unknown or unrecognised command opcode.
    Unknown(u8),
}

impl From<u8> for Command {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::Waste,
            1 => Self::Syn,
            2 => Self::Push,
            3 => Self::Fin,
            4 => Self::Settings,
            5 => Self::Alert,
            6 => Self::UpdatePaddingScheme,
            7 => Self::SynAck,
            8 => Self::HeartRequest,
            9 => Self::HeartResponse,
            10 => Self::ServerSettings,
            other => Self::Unknown(other),
        }
    }
}

impl From<Command> for u8 {
    fn from(cmd: Command) -> Self {
        match cmd {
            Command::Waste => 0,
            Command::Syn => 1,
            Command::Push => 2,
            Command::Fin => 3,
            Command::Settings => 4,
            Command::Alert => 5,
            Command::UpdatePaddingScheme => 6,
            Command::SynAck => 7,
            Command::HeartRequest => 8,
            Command::HeartResponse => 9,
            Command::ServerSettings => 10,
            Command::Unknown(val) => val,
        }
    }
}

/// An AnyTLS protocol frame.
#[derive(Clone, PartialEq, Eq)]
pub struct Frame {
    pub cmd: Command,
    pub stream_id: u32,
    pub data: Bytes,
}

impl fmt::Debug for Frame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Frame")
            .field("cmd", &self.cmd)
            .field("stream_id", &self.stream_id)
            .field("data_len", &self.data.len())
            .finish()
    }
}

impl Frame {
    /// Constructs a new frame with data.
    pub fn new(cmd: Command, stream_id: u32, data: Bytes) -> Self {
        Self {
            cmd,
            stream_id,
            data,
        }
    }

    /// Constructs a control frame (no payload).
    pub fn control(cmd: Command, stream_id: u32) -> Self {
        Self::new(cmd, stream_id, Bytes::new())
    }

    /// Constructs a `Syn` frame to open a stream.
    pub fn syn(stream_id: u32) -> Self {
        Self::control(Command::Syn, stream_id)
    }

    /// Constructs a `Fin` frame to close a stream.
    pub fn fin(stream_id: u32) -> Self {
        Self::control(Command::Fin, stream_id)
    }

    /// Constructs a `Push` data frame.
    pub fn push(stream_id: u32, data: Bytes) -> Self {
        Self::new(Command::Push, stream_id, data)
    }

    /// Constructs a `HeartRequest` ping on stream 0.
    pub fn heart_request() -> Self {
        Self::control(Command::HeartRequest, 0)
    }

    /// Constructs a `HeartResponse` pong on stream 0.
    pub fn heart_response() -> Self {
        Self::control(Command::HeartResponse, 0)
    }

    /// Constructs a `Waste` padding frame.
    pub fn waste(stream_id: u32, len: usize) -> Self {
        Self::new(Command::Waste, stream_id, Bytes::from(vec![0u8; len]))
    }

    /// Returns the total wire size of this frame (header + payload).
    pub fn wire_size(&self) -> usize {
        HEADER_OVERHEAD_SIZE + self.data.len()
    }

    /// Encodes this frame into a byte vector.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.wire_size());
        self.encode_buf(&mut out);
        out
    }

    /// Appends the encoded frame into an existing buffer.
    pub fn encode_buf<B: BufMut>(&self, dst: &mut B) {
        dst.put_u8(self.cmd.into());
        dst.put_u32(self.stream_id);
        dst.put_u16(self.data.len() as u16);
        dst.put_slice(&self.data);
    }

    /// Decodes a frame from `src` if enough bytes are available.
    ///
    /// Consumes the frame bytes on success. Returns `Ok(None)` if more bytes are needed.
    pub fn decode(src: &mut BytesMut) -> Result<Option<Self>, String> {
        if src.len() < HEADER_OVERHEAD_SIZE {
            return Ok(None);
        }

        let cmd = Command::from(src[0]);
        let stream_id = u32::from_be_bytes([src[1], src[2], src[3], src[4]]);
        let length = u16::from_be_bytes([src[5], src[6]]) as usize;

        let total = HEADER_OVERHEAD_SIZE + length;
        if src.len() < total {
            // Need more data
            return Ok(None);
        }

        // Consume header
        src.advance(HEADER_OVERHEAD_SIZE);
        // Extract payload
        let data = src.split_to(length).freeze();

        Ok(Some(Self {
            cmd,
            stream_id,
            data,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_encoding_and_decoding_roundtrip() {
        let payload = Bytes::from_static(b"hello world in anytls");
        let frame = Frame::push(42, payload.clone());

        let encoded = frame.encode();
        assert_eq!(encoded.len(), HEADER_OVERHEAD_SIZE + payload.len());
        assert_eq!(encoded[0], 2); // Push
        assert_eq!(&encoded[1..5], &42u32.to_be_bytes());
        assert_eq!(&encoded[5..7], &(payload.len() as u16).to_be_bytes());
        assert_eq!(&encoded[7..], &payload[..]);

        let mut buf = BytesMut::from(&encoded[..]);
        let decoded = Frame::decode(&mut buf)
            .expect("decodes")
            .expect("full frame");
        assert_eq!(decoded.cmd, Command::Push);
        assert_eq!(decoded.stream_id, 42);
        assert_eq!(decoded.data, payload);
        assert!(buf.is_empty());
    }

    #[test]
    fn control_frames_have_zero_payload() {
        let syn = Frame::syn(1);
        assert_eq!(syn.wire_size(), HEADER_OVERHEAD_SIZE);
        let mut buf = BytesMut::from(&syn.encode()[..]);
        let decoded = Frame::decode(&mut buf)
            .expect("decodes")
            .expect("full frame");
        assert_eq!(decoded.cmd, Command::Syn);
        assert_eq!(decoded.stream_id, 1);
        assert!(decoded.data.is_empty());
    }

    #[test]
    fn partial_frame_waits_for_complete_payload() {
        let payload = Bytes::from_static(b"0123456789");
        let frame = Frame::push(10, payload);
        let encoded = frame.encode();

        // Feed only 5 bytes (partial header)
        let mut buf = BytesMut::from(&encoded[..5]);
        assert_eq!(Frame::decode(&mut buf).expect("ok"), None);
        assert_eq!(buf.len(), 5);

        // Feed remaining header and partial payload
        buf.extend_from_slice(&encoded[5..10]);
        assert_eq!(Frame::decode(&mut buf).expect("ok"), None);

        // Feed rest of payload
        buf.extend_from_slice(&encoded[10..]);
        let decoded = Frame::decode(&mut buf).expect("ok").expect("completed");
        assert_eq!(decoded.stream_id, 10);
        assert_eq!(decoded.data, Bytes::from_static(b"0123456789"));
        assert!(buf.is_empty());
    }
}
