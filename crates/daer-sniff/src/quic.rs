// SPDX-License-Identifier: AGPL-3.0-only

//! QUIC Initial packet sniffing: recovers SNI from QUIC ClientHello (RFC 9000 & 9001).

use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes_gcm::Aes128Gcm;
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{Aead, Payload};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::{Malformed, Protocol, Sniffed, client_hello_sni};

/// Salt for QUIC version 1 (RFC 9001 §5.2) and draft-29.
const QUIC_V1_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

/// Salt for QUIC version 2 (RFC 9369 §5.2).
const QUIC_V2_SALT: [u8; 20] = [
    0x0d, 0x3e, 0x90, 0xea, 0x0c, 0x3e, 0x32, 0xe0, 0x76, 0x4f, 0x1d, 0x21, 0xf6, 0xbe, 0x98, 0xee,
    0xf1, 0x9d, 0x8d, 0x8e,
];

const QUIC_V1: u32 = 0x0000_0001;
const QUIC_V2: u32 = 0x6b33_3e36;
const QUIC_DRAFT29: u32 = 0xff00_001d;

/// Decodes a QUIC variable-length integer (RFC 9000 §16).
///
/// Returns `(value, bytes_consumed)`.
fn read_varint(slice: &[u8]) -> Result<(u64, usize), Malformed> {
    let first = *slice.first().ok_or(Malformed::BadLength)?;
    let prefix = first >> 6;
    let len = 1 << prefix;
    if slice.len() < len {
        return Err(Malformed::BadLength);
    }
    let mut val = u64::from(first & 0x3f);
    for &b in &slice[1..len] {
        val = (val << 8) | u64::from(b);
    }
    Ok((val, len))
}

/// Expands a QUIC HKDF label (RFC 9001 §5.1).
fn hkdf_expand_label(
    hkdf: &Hkdf<Sha256>,
    label: &[u8],
    context: &[u8],
    out: &mut [u8],
) -> Result<(), Malformed> {
    let mut info = Vec::with_capacity(2 + 1 + 6 + label.len() + 1 + context.len());
    let length = u16::try_from(out.len()).map_err(|_| Malformed::BadLength)?;
    info.extend_from_slice(&length.to_be_bytes());
    let full_label_len = 6 + label.len();
    let full_label_len = u8::try_from(full_label_len).map_err(|_| Malformed::BadLength)?;
    info.push(full_label_len);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label);
    let context_len = u8::try_from(context.len()).map_err(|_| Malformed::BadLength)?;
    info.push(context_len);
    info.extend_from_slice(context);
    hkdf.expand(&info, out).map_err(|_| Malformed::BadLength)
}

/// Sniffs a QUIC Initial packet for a TLS ClientHello carrying an SNI.
pub fn sniff_quic(buffer: &[u8]) -> Sniffed {
    if buffer.len() < 5 {
        return Sniffed::NeedMore { want: Some(5) };
    }

    let first = buffer[0];
    // Long header: bit 7 must be 1.
    if (first & 0x80) == 0 {
        return Sniffed::None;
    }

    let version = u32::from_be_bytes([buffer[1], buffer[2], buffer[3], buffer[4]]);
    if version == 0 {
        // Version Negotiation packet, not Initial.
        return Sniffed::None;
    }

    let (is_initial, salt) = match version {
        QUIC_V1 | QUIC_DRAFT29 => {
            let pkt_type = (first >> 4) & 0x03;
            (pkt_type == 0x00, &QUIC_V1_SALT)
        }
        QUIC_V2 => {
            let pkt_type = (first >> 4) & 0x03;
            (pkt_type == 0x01, &QUIC_V2_SALT)
        }
        _ => return Sniffed::None,
    };

    if !is_initial {
        return Sniffed::None;
    }

    // DCID length at offset 5.
    let mut offset = 5;
    let dcid_len = match buffer.get(offset) {
        Some(&len) => len as usize,
        None => {
            return Sniffed::NeedMore {
                want: Some(offset + 1),
            };
        }
    };
    offset += 1;

    let dcid = match buffer.get(offset..offset + dcid_len) {
        Some(dcid) => dcid,
        None => {
            return Sniffed::NeedMore {
                want: Some(offset + dcid_len),
            };
        }
    };
    offset += dcid_len;

    // SCID length.
    let scid_len = match buffer.get(offset) {
        Some(&len) => len as usize,
        None => {
            return Sniffed::NeedMore {
                want: Some(offset + 1),
            };
        }
    };
    offset += 1;
    if buffer.len() < offset + scid_len {
        return Sniffed::NeedMore {
            want: Some(offset + scid_len),
        };
    }
    offset += scid_len;

    // Token length (varint) and token.
    let (token_len, varint_len) = match read_varint(&buffer[offset..]) {
        Ok(res) => res,
        Err(_) => {
            return Sniffed::NeedMore {
                want: Some(offset + 1),
            };
        }
    };
    offset += varint_len;
    let token_len = token_len as usize;
    if buffer.len() < offset + token_len {
        return Sniffed::NeedMore {
            want: Some(offset + token_len),
        };
    }
    offset += token_len;

    // Length field (varint): describes the remaining bytes (Packet Number + Payload + AEAD Tag).
    let (packet_len, varint_len) = match read_varint(&buffer[offset..]) {
        Ok(res) => res,
        Err(_) => {
            return Sniffed::NeedMore {
                want: Some(offset + 1),
            };
        }
    };
    offset += varint_len;
    let packet_len = packet_len as usize;
    let pn_offset = offset;
    let total_expected = pn_offset + packet_len;

    if buffer.len() < total_expected {
        return Sniffed::NeedMore {
            want: Some(total_expected),
        };
    }

    let packet_data = &buffer[..total_expected];

    // Derive Initial secrets.
    let hkdf_initial = Hkdf::<Sha256>::new(Some(salt), dcid);
    let mut client_initial_secret = [0u8; 32];
    if hkdf_expand_label(&hkdf_initial, b"client in", &[], &mut client_initial_secret).is_err() {
        return Sniffed::Malformed(Malformed::BadLength);
    }
    let hkdf_client =
        Hkdf::<Sha256>::from_prk(&client_initial_secret).map_err(|_| Malformed::BadLength);
    let Ok(hkdf_client) = hkdf_client else {
        return Sniffed::Malformed(Malformed::BadLength);
    };

    let mut key = [0u8; 16];
    let mut iv = [0u8; 12];
    let mut hp = [0u8; 16];

    if hkdf_expand_label(&hkdf_client, b"quic key", &[], &mut key).is_err()
        || hkdf_expand_label(&hkdf_client, b"quic iv", &[], &mut iv).is_err()
        || hkdf_expand_label(&hkdf_client, b"quic hp", &[], &mut hp).is_err()
    {
        return Sniffed::Malformed(Malformed::BadLength);
    }

    // Header protection sample is 16 bytes, starting 4 bytes after pn_offset.
    let sample_offset = pn_offset + 4;
    if packet_data.len() < sample_offset + 16 {
        return Sniffed::Malformed(Malformed::BadLength);
    }
    let sample = &packet_data[sample_offset..sample_offset + 16];

    let cipher_hp = match Aes128::new_from_slice(&hp) {
        Ok(c) => c,
        Err(_) => return Sniffed::Malformed(Malformed::BadLength),
    };
    let mut mask = [0u8; 16];
    mask.copy_from_slice(sample);
    cipher_hp.encrypt_block(GenericArray::from_mut_slice(&mut mask));

    let mut unmasked = packet_data.to_vec();
    // Unmask first byte: lower 4 bits.
    unmasked[0] ^= mask[0] & 0x0f;
    let pn_len = (unmasked[0] & 0x03) as usize + 1;

    if packet_data.len() < pn_offset + pn_len {
        return Sniffed::Malformed(Malformed::BadLength);
    }

    for i in 0..pn_len {
        unmasked[pn_offset + i] ^= mask[1 + i];
    }

    let mut pn: u64 = 0;
    for i in 0..pn_len {
        pn = (pn << 8) | u64::from(unmasked[pn_offset + i]);
    }

    let payload_offset = pn_offset + pn_len;
    if total_expected < payload_offset + 16 {
        // Needs at least a 16-byte AEAD tag.
        return Sniffed::Malformed(Malformed::BadLength);
    }
    let aad = &unmasked[..payload_offset];
    let ciphertext = &unmasked[payload_offset..total_expected];

    let mut nonce = iv;
    let pn_bytes = pn.to_be_bytes();
    for i in 0..8 {
        nonce[4 + i] ^= pn_bytes[i];
    }

    let cipher_payload = match Aes128Gcm::new_from_slice(&key) {
        Ok(c) => c,
        Err(_) => return Sniffed::Malformed(Malformed::BadLength),
    };

    let plaintext = match cipher_payload.decrypt(
        GenericArray::from_slice(&nonce),
        Payload {
            msg: ciphertext,
            aad,
        },
    ) {
        Ok(pt) => pt,
        Err(_) => return Sniffed::Malformed(Malformed::BadLength),
    };

    // Parse frames in plaintext to find CRYPTO frame.
    let mut cursor = 0;
    while cursor < plaintext.len() {
        let (frame_type, vlen) = match read_varint(&plaintext[cursor..]) {
            Ok(v) => v,
            Err(_) => break,
        };
        cursor += vlen;

        match frame_type {
            0x00 => {
                // PADDING
                continue;
            }
            0x01 => {
                // PING
                continue;
            }
            0x02 | 0x03 => {
                // ACK: largest_ack, ack_delay, ack_range_count, first_ack_range...
                let (_, l) = match read_varint(&plaintext[cursor..]) {
                    Ok(v) => v,
                    Err(_) => break,
                };
                cursor += l;
                let (_, l) = match read_varint(&plaintext[cursor..]) {
                    Ok(v) => v,
                    Err(_) => break,
                };
                cursor += l;
                let (ranges, l) = match read_varint(&plaintext[cursor..]) {
                    Ok(v) => v,
                    Err(_) => break,
                };
                cursor += l;
                let (_, l) = match read_varint(&plaintext[cursor..]) {
                    Ok(v) => v,
                    Err(_) => break,
                };
                cursor += l;
                for _ in 0..ranges {
                    let (_, l) = match read_varint(&plaintext[cursor..]) {
                        Ok(v) => v,
                        Err(_) => break,
                    };
                    cursor += l;
                    let (_, l) = match read_varint(&plaintext[cursor..]) {
                        Ok(v) => v,
                        Err(_) => break,
                    };
                    cursor += l;
                }
                if frame_type == 0x03 {
                    // ECN counts: ECT0, ECT1, ECN-CE
                    for _ in 0..3 {
                        let (_, l) = match read_varint(&plaintext[cursor..]) {
                            Ok(v) => v,
                            Err(_) => break,
                        };
                        cursor += l;
                    }
                }
            }
            0x06 => {
                // CRYPTO frame
                let (crypto_offset, l) = match read_varint(&plaintext[cursor..]) {
                    Ok(v) => v,
                    Err(_) => break,
                };
                cursor += l;
                let (crypto_len, l) = match read_varint(&plaintext[cursor..]) {
                    Ok(v) => v,
                    Err(_) => break,
                };
                cursor += l;
                let crypto_len = crypto_len as usize;
                if cursor + crypto_len > plaintext.len() {
                    break;
                }
                let crypto_data = &plaintext[cursor..cursor + crypto_len];

                // ClientHello should start at offset 0.
                if crypto_offset == 0 && crypto_data.len() >= 4 && crypto_data[0] == 0x01 {
                    // TLS ClientHello: 1 byte handshake type (0x01), 3 bytes length.
                    match client_hello_sni(&crypto_data[4..]) {
                        Ok(Some(name)) => {
                            return Sniffed::Domain {
                                name,
                                protocol: Protocol::Quic,
                            };
                        }
                        Ok(None) => return Sniffed::None,
                        Err(e) => return Sniffed::Malformed(e),
                    }
                }
                cursor += crypto_len;
            }
            _ => {
                // Unknown or other frame; skip
                break;
            }
        }
    }

    Sniffed::None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn rfc9001_appendix_a_keys() {
        // RFC 9001 §A.1 Client Initial
        let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        let hkdf_initial = Hkdf::<Sha256>::new(Some(&QUIC_V1_SALT), &dcid);
        let mut client_initial_secret = [0u8; 32];
        hkdf_expand_label(&hkdf_initial, b"client in", &[], &mut client_initial_secret)
            .expect("expand client in");

        assert_eq!(
            to_hex(&client_initial_secret),
            "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea"
        );

        let hkdf_client = Hkdf::<Sha256>::from_prk(&client_initial_secret).expect("from prk");
        let mut key = [0u8; 16];
        let mut iv = [0u8; 12];
        let mut hp = [0u8; 16];

        hkdf_expand_label(&hkdf_client, b"quic key", &[], &mut key).expect("key");
        hkdf_expand_label(&hkdf_client, b"quic iv", &[], &mut iv).expect("iv");
        hkdf_expand_label(&hkdf_client, b"quic hp", &[], &mut hp).expect("hp");

        assert_eq!(to_hex(&key), "1f369613dd76d5467730efcbe3b1a22d");
        assert_eq!(to_hex(&iv), "fa044b2f42a3fd3b46fb255c");
        assert_eq!(to_hex(&hp), "9f50449e04a0e810283a1e9933adedd2");
    }

    #[test]
    fn rfc9001_appendix_a_sniffs_example_com() {
        // RFC 9001 §A.2 Client Initial packet
        let hex_str = concat!(
            "c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11",
            "d242b123dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f399",
            "1c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c",
            "8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df6212",
            "30c83711b39343fa028cea7f7fb5ff89eac2308249a02252155e2347b63d58c5",
            "457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c208",
            "4dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec",
            "4e15daf8500a6ef69ec4e3feb6b1d98e610ac8b7ec3faf6ad760b7bad1db4ba3",
            "485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db",
            "059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c",
            "7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f8",
            "9937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556",
            "be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c74",
            "68449a13d8e3b95811a198f3491de3e7fe942b330407abf82a4ed7c1b311663a",
            "c69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00",
            "f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632",
            "291d6a418211cc2962e20fe47feb3edf330f2c603a9d48c0fcb5699dbfe58964",
            "25c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd",
            "14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ff",
            "ef132eef2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198",
            "e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009dd",
            "c324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73",
            "203a4a13e96f5432ec0fd4a1ee65accdd5e3904df54c1da510b0ff20dcc0c77f",
            "cb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450e",
            "fc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03ade",
            "a2e1fbc5aa463d08ca19896d2bf59a071b851e6c239052172f296bfb5e724047",
            "90a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2",
            "162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f4",
            "40591f355e12d439ff150aab7613499dbd49adabc8676eef023b15b65bfc5ca0",
            "6948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e",
            "8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0",
            "be79e2fb8f5d5fbbe2e30ecadd220723c8c0aea8078cdfcb3868263ff8f09400",
            "54da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab",
            "760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9",
            "f96f3ca9ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f5aa731b4",
            "056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd4684064",
            "7e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241",
            "e221af44860018ab0856972e194cd934"
        );
        let mut pkt = Vec::new();
        for i in (0..hex_str.len()).step_by(2) {
            pkt.push(u8::from_str_radix(&hex_str[i..i + 2], 16).unwrap());
        }

        let sniffed = sniff_quic(&pkt);
        assert_eq!(
            sniffed,
            Sniffed::Domain {
                name: "example.com".to_owned(),
                protocol: Protocol::Quic,
            }
        );
    }
}
