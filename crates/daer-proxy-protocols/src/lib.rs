// SPDX-License-Identifier: AGPL-3.0-only

//! Proxy protocol implementations (Shadowsocks, Trojan, REALITY, Hysteria 2, AnyTLS) for daer.
//!
//! Decoupled from outbound governance per ADR-0017.

pub mod anytls;
pub mod dialer;
pub mod error;
pub mod fragment;
pub mod hysteria2;
pub mod options;
pub mod reality;
pub mod shadowsocks;
pub mod trojan;

pub use anytls::AnyTlsConnector;
pub use dialer::ProxyDialer;
pub use error::ProxyProtocolError;
pub use fragment::{Fragment, FragmentingIo, Range};
pub use hysteria2::Hysteria2Connector;
pub use options::DialerOptions;
pub use reality::RealityConnector;
pub use shadowsocks::{
    Cipher, CipherError, SaltReplayFilter, ShadowSocksConnector, ShadowSocksError,
    ShadowSocksStream,
};
pub use trojan::TrojanConnector;

/// Supported proxy protocol identities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProxyProtocol {
    ShadowSocks,
    Trojan,
    AnyTls,
    Hysteria2,
    Reality,
}

impl ProxyProtocol {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ShadowSocks => "ss",
            Self::Trojan => "trojan",
            Self::AnyTls => "anytls",
            Self::Hysteria2 => "hysteria2",
            Self::Reality => "vless",
        }
    }
}

/// The stream half of an established connection.
pub type Upstream = Box<dyn netune::Transport>;

/// Builds the ClientHello this crate sends, for the wire-level probe in tests.
#[doc(hidden)]
pub fn probe_client_hello(server_name: &str) -> Result<Vec<u8>, String> {
    reality::probe::client_hello(server_name)
}

pub use netune::{
    DatagramConnector, DatagramTransport, Established, EstablishedDatagrams, SocketConfig,
    Transport,
};
