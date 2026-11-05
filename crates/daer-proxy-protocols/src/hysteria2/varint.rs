// SPDX-License-Identifier: AGPL-3.0-only

//! QUIC variable-length integer encoding and decoding (RFC 9000 §16).

use std::io;
use tokio::io::{AsyncRead, AsyncReadExt};

/// Encodes `val` as a QUIC variable-length integer into `out`.
pub fn encode_varint(val: u64, out: &mut Vec<u8>) {
    if val < 64 {
        out.push(val as u8);
    } else if val < 16384 {
        let v = (val as u16) | 0x4000;
        out.extend_from_slice(&v.to_be_bytes());
    } else if val < 1073741824 {
        let v = (val as u32) | 0x80000000;
        out.extend_from_slice(&v.to_be_bytes());
    } else {
        let v = val | 0xc000000000000000;
        out.extend_from_slice(&v.to_be_bytes());
    }
}

/// Decodes a QUIC variable-length integer from an async reader.
pub async fn decode_varint<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<u64> {
    let mut first = [0u8; 1];
    reader.read_exact(&mut first).await?;
    let prefix = first[0] >> 6;
    let initial = (first[0] & 0x3f) as u64;

    match prefix {
        0 => Ok(initial),
        1 => {
            let mut second = [0u8; 1];
            reader.read_exact(&mut second).await?;
            Ok((initial << 8) | (second[0] as u64))
        }
        2 => {
            let mut rest = [0u8; 3];
            reader.read_exact(&mut rest).await?;
            let mut val = initial;
            for byte in rest {
                val = (val << 8) | (byte as u64);
            }
            Ok(val)
        }
        3 => {
            let mut rest = [0u8; 7];
            reader.read_exact(&mut rest).await?;
            let mut val = initial;
            for byte in rest {
                val = (val << 8) | (byte as u64);
            }
            Ok(val)
        }
        _ => unreachable!(),
    }
}

/// Decodes a QUIC variable-length integer from a byte slice.
///
/// Returns `Some((value, bytes_consumed))` or `None` if `slice` has insufficient bytes.
pub fn decode_varint_slice(slice: &[u8]) -> Option<(u64, usize)> {
    if slice.is_empty() {
        return None;
    }
    let prefix = slice[0] >> 6;
    let initial = (slice[0] & 0x3f) as u64;

    match prefix {
        0 => Some((initial, 1)),
        1 => {
            if slice.len() < 2 {
                return None;
            }
            Some(((initial << 8) | (slice[1] as u64), 2))
        }
        2 => {
            if slice.len() < 4 {
                return None;
            }
            let mut val = initial;
            for &byte in &slice[1..4] {
                val = (val << 8) | (byte as u64);
            }
            Some((val, 4))
        }
        3 => {
            if slice.len() < 8 {
                return None;
            }
            let mut val = initial;
            for &byte in &slice[1..8] {
                val = (val << 8) | (byte as u64);
            }
            Some((val, 8))
        }
        _ => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_roundtrip_all_ranges() {
        let test_cases = [
            0u64,
            1,
            25,
            63,
            64,
            1025,
            16383,
            16384,
            1073741823,
            1073741824,
            4611686018427387903,
        ];
        for &val in &test_cases {
            let mut encoded = Vec::new();
            encode_varint(val, &mut encoded);
            let (decoded, consumed) = decode_varint_slice(&encoded).expect("decodes");
            assert_eq!(decoded, val);
            assert_eq!(consumed, encoded.len());
        }
    }

    #[test]
    fn hysteria2_tcp_frame_type_is_varint_0x401() {
        let mut encoded = Vec::new();
        encode_varint(0x401, &mut encoded);
        assert_eq!(encoded, &[0x44, 0x01]);
    }
}
