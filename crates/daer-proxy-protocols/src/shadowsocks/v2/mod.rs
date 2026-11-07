// SPDX-License-Identifier: AGPL-3.0-only

//! Shadowsocks 2022 (SIP022) implementation.

pub mod crypto;
pub mod datagram;
pub mod stream;

pub use crypto::{
    BLAKE3_KEY_DERIVE_CONTEXT, Nonce12, Opener2022, Sealer2022, decrypt_header_block,
    derive_tcp_session_key, derive_udp_session_key, encrypt_header_block,
};
pub use datagram::ShadowSocks2022DatagramSession;
pub use stream::{Handshake2022Error, ShadowSocks2022Stream, send_client_handshake};
