// SPDX-License-Identifier: AGPL-3.0-only

//! Moving bytes between the accepted flow and the outbound leg.
//!
//! * [`stream`] splices two TCP streams and forwards half-close, which is the whole
//!   difference between a proxy and a proxy that hangs.
//! * [`datagram`] owns the session table a UDP relay needs: one socket, many peers,
//!   each with its own outbound session, and a reply that goes back to the right one.

pub mod datagram;
pub mod stream;

pub use datagram::{
    DatagramLeg, DatagramRouter, DatagramService, DatagramSnapshot, DatagramStats, OpenDatagram,
    RelayOptions, serve_datagrams,
};
pub use stream::{Relayed, splice};
