// SPDX-License-Identifier: AGPL-3.0-only

//! Proxy protocol implementations for daer.
//!
//! Decoupled from outbound governance per [ADR-0017](../../docs/adr/0017-proxy-protocols-crate-boundary.md),
//! and layered per [ADR-0028](../../docs/adr/0028-protocol-layering.md).
//!
//! # The layering
//!
//! A proxy protocol is not one thing. It is a stack of orthogonal layers, and each layer is
//! a type:
//!
//! ```text
//!   node ──▶ Transport (tcp | ws)          ──▶ raw byte stream
//!         ──▶ Security  (none | tls | reality) ──▶ opaque byte stream
//!         ──▶ Protocol  (vless | vmess)        ──▶ framed byte stream
//!         ──▶ Flow      (none | vision)        ──▶ padded byte stream
//! ```
//!
//! The composition order is fixed by the protocols themselves and performed in exactly one
//! place per protocol ([`vless::connector`], `vmess::connector`). Before ADR-0028 this crate
//! had no seam at all: REALITY *was* a kind of VLESS, so a standard-TLS VLESS node had no
//! code path, Vision was reachable only through REALITY, and the next security layer would
//! have had to be bolted onto a second protocol.
//!
//! # What is where
//!
//! | Module | Owns |
//! | --- | --- |
//! | [`transport`] | the `ws` upgrade; `tcp` is nothing to do |
//! | [`server`] | the stream to a node's own server, the seam a detour replaces |
//! | [`security`] | a handshake, a certificate policy, an ALPN offer |
//! | [`vless`] | the request header, the response header, and Vision |
//! | [`vmess`] | VMess AEAD: KDF, AuthID, header seal, chunk stream |
//! | [`hysteria2`] | QUIC + HTTP/3 auth + the datagram plane and its socket layers |
//! | [`shadowsocks`] | SIP004 AEAD crypto and framing |
//! | [`trojan`] | the trojan request header |
//! | [`anytls`] | the multiplexed session and its frames |
//! | [`reality`] | the TLS 1.3 client and the certificate verdict, and nothing else |
//!
//! # One entry point
//!
//! [`ProxyDialer::from_link`] and `ProxyDialer::from_node` are the whole public surface for
//! constructing a session. Everything below them is reachable only from a parsed node, which
//! is what keeps a configuration from reaching a handshake it did not ask for.

pub mod anytls;
pub mod dialer;
pub mod error;
pub mod fragment;
pub mod hysteria2;
pub mod options;
pub mod reality;
pub mod security;
pub mod server;
pub mod shadowsocks;
pub mod transport;
mod transport_ws;
pub mod trojan;
pub mod vless;
pub mod vmess;

pub use anytls::AnyTlsConnector;
pub use dialer::ProxyDialer;
pub use error::ProxyProtocolError;
pub use fragment::{Fragment, FragmentingIo, Range};
pub use hysteria2::Hysteria2Connector;
pub use options::DialerOptions;
pub use security::Security;
pub use server::{DirectServerDialer, ServerConnector, ServerDialer};
pub use shadowsocks::{
    Cipher, CipherError, SaltReplayFilter, ShadowSocksConnector, ShadowSocksError,
    ShadowSocksStream,
};
pub use transport::TransportLayer;
pub use trojan::TrojanConnector;
pub use vless::Flow;
pub use vless::VlessConnector;
// vmess connector lands with the rest of the module

/// Supported proxy protocol identities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProxyProtocol {
    ShadowSocks,
    Trojan,
    AnyTls,
    Hysteria2,
    /// VLESS with any of the three security layers. The identity is the protocol, not the
    /// handshake: `vless` over TLS and `vless` over REALITY are the same protocol
    /// (ADR-0028).
    Vless,
    Vmess,
}

impl ProxyProtocol {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ShadowSocks => "ss",
            Self::Trojan => "trojan",
            Self::AnyTls => "anytls",
            Self::Hysteria2 => "hysteria2",
            Self::Vless => "vless",
            Self::Vmess => "vmess",
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
