// SPDX-License-Identifier: AGPL-3.0-only

//! Shadowsocks 2017 AEAD (SIP004 / SIP007) implementation.

pub mod crypto;
pub mod datagram;
pub mod stream;

pub use crypto::{Opener, SaltReplayFilter, Sealer, master_key, subkey};
pub use datagram::ShadowSocksDatagramSession;
pub use stream::{ShadowSocksStream, read_salt, write_salt};
