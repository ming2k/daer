// SPDX-License-Identifier: AGPL-3.0-only

//! Outbound dialers for daer.
//!
//! Replaces `component/outbound/dialer`. This milestone ports the parts that do
//! not depend on a proxy protocol implementation yet:
//!
//! * [`latency`] — `LatenciesN` / moving average, the numbers policies rank on.
//! * [`alive`] — [`AliveDialerSet`], the per-network alive set with the
//!   tolerance rule from `alive_dialer_set.go`.
//! * [`dialer`] / [`group`] — per-node measured state and the group that selects
//!   from it.
//! * [`direct`] — the direct dialer, with `SO_MARK` applied before `connect(2)`.
//! * [`filter`] — `group { filter: name(...) && subtag(...) }` and the
//!   `add_latency` annotation.
//! * [`check`] — node connectivity checks. The HTTP and TCP probes are built on
//!   [`netune`](https://github.com/ming2k/netune), which supplies the HTTP/1.1
//!   client, TLS (with fingerprint profiles), DNS and connect timeouts that daer
//!   previously took from Go's `net/http`.
//!
//! * [`subscription`] — fetching, decoding (plain / base64 / SIP008) and caching a
//!   node list, so `[[subscription]]` produces nodes instead of an empty group.
//!
//! Protocol dialers for `vmess` / `vless` and the QUIC families are not implemented;
//! `docs/dev/roadmap.md` records that with the reason each is blocked on, rather than
//! listing them as "next up".

mod alive;
mod check;
mod dialer;
mod direct;
mod error;
mod filter;
pub mod fragment;
mod group;
mod latency;
mod node_dialer;
mod property;
mod reality;
pub mod shadowsocks;
pub mod subscription;
pub mod trojan;

pub use alive::{AliveDialerSet, DialerId, NotifyOutcome};
pub use check::{CheckError, CheckUrl, HttpChecker, HttpMethod, TcpChecker, UdpDnsChecker};
pub use dialer::Dialer;
pub use direct::DirectDialer;
pub use error::OutboundError;
pub use filter::{Annotation, FilterError, FilterSet};
pub use group::DialerGroup;
pub use latency::{LatenciesN, MovingAverage};
pub use node_dialer::{DialerOptions, NodeDialer};
pub use property::{GroupPolicy, Property, Protocol, Security, parse_group_policy};
pub use shadowsocks::{Cipher, CipherError, SaltReplayFilter, ShadowSocksError, ShadowSocksStream};
pub use trojan::TrojanConnector;

/// The stream half of an established connection.
///
/// Re-exported so a consumer of this crate can name the type it receives without
/// depending on the transport crate itself.
pub type Upstream = Box<dyn netune::Transport>;

/// Builds the ClientHello this crate sends, for the wire-level probe in
/// `tests/client_hello_probe.rs`.
///
/// REALITY's mistakes are ambiguous — a tag the node cannot open makes it forward the flow
/// to the impersonated site, so the client sees that site's answer rather than an error.
/// Separating "the hello is malformed" from "the tag is wrong" needs the hello on its own,
/// which is why this exists. It exposes no key material and no constructor: it returns the
/// bytes only.
#[doc(hidden)]
pub fn probe_client_hello(server_name: &str) -> Result<Vec<u8>, String> {
    reality::probe::client_hello(server_name)
}

/// The datagram half, re-exported for the same reason as [`Upstream`].
///
/// `daer-control` routes a datagram flow but may not import netune directly
/// (ADR-0002), so the connector a route hands back is named here, in daer's own
/// vocabulary, rather than making the control plane depend on the network stack.
pub use netune::{
    DatagramConnector, DatagramTransport, Established, EstablishedDatagrams, Preset, SocketConfig,
    UdpConnector,
};
pub use netune_trace::Recorder;

pub use daer_common::SelectionPolicy;
pub use daer_config::TimeSpan;
