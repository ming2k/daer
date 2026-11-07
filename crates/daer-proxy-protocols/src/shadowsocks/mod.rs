// SPDX-License-Identifier: AGPL-3.0-only

//! Shadowsocks implementation supporting both 2017 AEAD (SIP004 / SIP007)
//! and Shadowsocks 2022 (SIP022).

pub mod cipher;
pub mod connector;
pub mod link;
pub mod v1;
pub mod v2;

pub use cipher::{Cipher, CipherError, DecryptError, ShadowSocksError};
pub use connector::{
    ShadowSocksConnector, ShadowSocksDatagramConnector, decode_base64, encode_address,
    split_authority,
};
pub use link::{Link, decode_base64_bytes, decode_base64_string, is_shadowsocks};
pub use v1::{Opener, SaltReplayFilter, Sealer, ShadowSocksStream};
pub use v2::ShadowSocks2022Stream;
