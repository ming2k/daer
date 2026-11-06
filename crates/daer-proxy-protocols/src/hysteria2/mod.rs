// SPDX-License-Identifier: AGPL-3.0-only

//! Hysteria 2 over QUIC and HTTP/3 (ADR-0029).

pub mod auth;
pub mod brutal;
pub mod connector;
pub mod datagram;
pub mod hop;
pub mod obfs;
pub mod port_set;
pub mod stream;
pub mod tcp;
pub mod varint;

pub use auth::AuthOutcome;
pub use connector::Hysteria2Connector;
pub use datagram::{Hysteria2DatagramConnector, Hysteria2DatagramSession};
pub use obfs::Obfs;
pub use port_set::PortSet;
pub use stream::QuicBiStream;
