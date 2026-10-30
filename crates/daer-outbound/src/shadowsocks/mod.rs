// SPDX-License-Identifier: AGPL-3.0-only

//! Shadowsocks AEAD: the crypto and the stream.

pub mod connector;
pub mod crypto;
pub mod stream;

pub use connector::{Link, ShadowSocksConnector, encode_address, split_authority};
pub use crypto::{Cipher, CipherError, DecryptError, Opener, SaltReplayFilter, Sealer};
pub use stream::{ShadowSocksError, ShadowSocksStream};
