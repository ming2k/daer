// SPDX-License-Identifier: AGPL-3.0-only

//! Transparent ingress: the sockets the datapath hands redirected flows to.
//!
//! * [`tcp`] accepts a redirected stream; the kernel has already restored the original
//!   destination onto the accepted socket.
//! * [`udp`] receives datagrams that each carry their own original destination as control
//!   data, because a wildcard UDP socket has no per-flow state to restore.
//!
//! Both apply the same self-connect rule, so "someone connected to the transparent port
//! directly" is refused identically for either family.

pub mod tcp;
pub mod udp;

pub use tcp::{Accepted, FlowFacts, TransparentListener, bind_shared, is_self_connect, unmap};
pub use udp::{Datagram, DatagramFamily, DatagramIngress, TransparentDatagramListener};
