// SPDX-License-Identifier: AGPL-3.0-only

//! Hysteria 2 proxy protocol over QUIC and HTTP/3.

pub mod auth;
pub mod connector;
pub mod datagram;
pub mod stream;
pub mod tcp;
pub mod varint;

pub use connector::Hysteria2Connector;
pub use datagram::Hysteria2DatagramConnector;
pub use stream::QuicBiStream;
