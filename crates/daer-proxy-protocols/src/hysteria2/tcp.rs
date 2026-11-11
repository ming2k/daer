// SPDX-License-Identifier: AGPL-3.0-only

//! Hysteria 2 TCP stream establishment.

use netune_quic::owned::{Connection, RecvStream};

use crate::error::ProxyProtocolError;
use crate::hysteria2::stream::{QuicBiStream, wrap};
use crate::hysteria2::varint::encode_varint;

/// Frame type for TCP request in Hysteria 2.
pub const FRAME_TYPE_TCP_REQUEST: u64 = 0x401;

/// Opens a TCP proxy tunnel over a new QUIC bidirectional stream.
pub async fn open_tcp_stream(
    conn: &Connection,
    authority: &str,
) -> Result<QuicBiStream, ProxyProtocolError> {
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| ProxyProtocolError::Connect(format!("quic open bi stream: {e}")))?;

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
        .map_err(|e| ProxyProtocolError::Connect(format!("write hysteria2 tcp req: {e}")))?;

    // Read response: 1-byte status
    let mut status = [0u8; 1];
    read_exact(&mut recv, &mut status)
        .await
        .map_err(|e| ProxyProtocolError::Connect(format!("read hysteria2 tcp resp status: {e}")))?;

    // Read message length and message
    let msg_len = read_varint(&mut recv).await.map_err(|e| {
        ProxyProtocolError::Connect(format!("decode hysteria2 tcp resp msg len: {e}"))
    })?;
    let mut msg = vec![0u8; msg_len as usize];
    if msg_len > 0 {
        read_exact(&mut recv, &mut msg).await.map_err(|e| {
            ProxyProtocolError::Connect(format!("read hysteria2 tcp resp msg: {e}"))
        })?;
    }

    // Read padding length and skip padding
    let pad_len = read_varint(&mut recv).await.map_err(|e| {
        ProxyProtocolError::Connect(format!("decode hysteria2 tcp resp pad len: {e}"))
    })?;
    if pad_len > 0 {
        let mut pad_buf = vec![0u8; pad_len as usize];
        read_exact(&mut recv, &mut pad_buf).await.map_err(|e| {
            ProxyProtocolError::Connect(format!("read hysteria2 tcp resp pad: {e}"))
        })?;
    }

    if status[0] != 0 {
        let err_msg = String::from_utf8_lossy(&msg);
        return Err(ProxyProtocolError::Connect(format!(
            "hysteria2 server refused tcp connection: status {} ({err_msg})",
            status[0]
        )));
    }

    Ok(wrap(send, recv))
}

/// Fills `buffer` from a QUIC receive stream.
async fn read_exact(recv: &mut RecvStream, buffer: &mut [u8]) -> std::io::Result<()> {
    let mut filled = 0;
    while filled < buffer.len() {
        let Some(bytes) = recv
            .read(buffer.len() - filled)
            .await
            .map_err(std::io::Error::other)?
        else {
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
        };
        if bytes.is_empty() {
            continue;
        }
        let take = bytes.len().min(buffer.len() - filled);
        buffer[filled..filled + take].copy_from_slice(&bytes[..take]);
        filled += take;
    }
    Ok(())
}

/// Reads one QUIC variable-length integer from a receive stream (RFC 9000 §16).
async fn read_varint(recv: &mut RecvStream) -> std::io::Result<u64> {
    let mut first = [0u8; 1];
    read_exact(recv, &mut first).await?;
    let prefix = first[0] >> 6;
    let initial = u64::from(first[0] & 0x3f);
    match prefix {
        0 => Ok(initial),
        1 => {
            let mut rest = [0u8; 1];
            read_exact(recv, &mut rest).await?;
            Ok((initial << 8) | u64::from(rest[0]))
        }
        2 => {
            let mut rest = [0u8; 3];
            read_exact(recv, &mut rest).await?;
            let mut value = initial;
            for byte in rest {
                value = (value << 8) | u64::from(byte);
            }
            Ok(value)
        }
        3 => {
            let mut rest = [0u8; 7];
            read_exact(recv, &mut rest).await?;
            let mut value = initial;
            for byte in rest {
                value = (value << 8) | u64::from(byte);
            }
            Ok(value)
        }
        _ => unreachable!(),
    }
}
