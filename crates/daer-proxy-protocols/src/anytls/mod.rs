// SPDX-License-Identifier: AGPL-3.0-only

//! AnyTLS protocol implementation: TLS-based session multiplexing and traffic obfuscation.

pub mod auth;
pub mod connector;
pub mod datagram;
pub mod frame;
pub mod session;
pub mod stream;

pub use connector::AnyTlsConnector;
pub use datagram::AnyTlsDatagramConnector;
pub use frame::{Command, Frame};
pub use session::AnyTlsSession;
pub use stream::AnyTlsStream;
