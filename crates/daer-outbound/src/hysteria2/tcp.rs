// SPDX-License-Identifier: AGPL-3.0-only

//! Hysteria 2 TCP stream establishment.

use tokio::io::AsyncWriteExt;

use crate::error::OutboundError;
use crate::hysteria2::stream::QuicBiStream;
use crate::hysteria2::varint::{decode_varint, encode_varint};

/// Frame type for TCP request in Hysteria 2.
pub const FRAME_TYPE_TCP_REQUEST: u64 = 0x401;

/// Opens a TCP proxy tunnel over a new QUIC bidirectional stream.
pub async fn open_tcp_stream(
    conn: &quinn::Connection,
    authority: &str,
) -> Result<QuicBiStream, OutboundError> {
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| OutboundError::Connect(format!("quic open bi stream: {e}")))?;

    // Frame type 0x401
    let mut req = Vec::with_capacity(64);
    encode_varint(FRAME_TYPE_TCP_REQUEST, &mut req);

    // Destination address: varint len + bytes
    let addr_bytes = authority.as_bytes();
    encode_varint(addr_bytes.len() as u64, &mut req);
    req.extend_from_slice(addr_bytes);

    // Random padding: varint len + bytes
    let pad_len = fastrand::u8(..32) as usize;
    encode_varint(pad_len as u64, &mut req);
    req.resize(req.len() + pad_len, 0);

    send.write_all(&req)
        .await
        .map_err(|e| OutboundError::Connect(format!("write hysteria2 tcp req: {e}")))?;
    send.flush()
        .await
        .map_err(|e| OutboundError::Connect(format!("flush hysteria2 tcp req: {e}")))?;

    // Read response: 1-byte status
    let mut status = [0u8; 1];
    recv.read_exact(&mut status)
        .await
        .map_err(|e| OutboundError::Connect(format!("read hysteria2 tcp resp status: {e}")))?;

    // Read message length and message
    let msg_len = decode_varint(&mut recv)
        .await
        .map_err(|e| OutboundError::Connect(format!("decode hysteria2 tcp resp msg len: {e}")))?;
    let mut msg = vec![0u8; msg_len as usize];
    if msg_len > 0 {
        recv.read_exact(&mut msg)
            .await
            .map_err(|e| OutboundError::Connect(format!("read hysteria2 tcp resp msg: {e}")))?;
    }

    // Read padding length and skip padding
    let pad_len = decode_varint(&mut recv)
        .await
        .map_err(|e| OutboundError::Connect(format!("decode hysteria2 tcp resp pad len: {e}")))?;
    if pad_len > 0 {
        let mut pad_buf = vec![0u8; pad_len as usize];
        recv.read_exact(&mut pad_buf)
            .await
            .map_err(|e| OutboundError::Connect(format!("read hysteria2 tcp resp pad: {e}")))?;
    }

    if status[0] != 0 {
        let err_msg = String::from_utf8_lossy(&msg);
        return Err(OutboundError::Connect(format!(
            "hysteria2 server refused tcp connection: status {} ({err_msg})",
            status[0]
        )));
    }

    Ok(QuicBiStream::new(send, recv))
}
