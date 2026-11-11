// SPDX-License-Identifier: AGPL-3.0-only

//! Outbound dialers and governance for daer.
//!
//! Owns:
//! * [`latency`] — `LatenciesN` / moving average, the numbers policies rank on.
//! * [`alive`] — [`AliveDialerSet`], the per-network alive set with tolerance rules.
//! * [`dialer`] / [`group`] — per-node measured state and the group that selects from it.
//! * [`direct`] — the direct dialer, with `SO_MARK` applied before `connect(2)`.
//! * [`filter`] — `group { filter: name(...) && subtag(...) }` and `add_latency`.
//! * [`check`] — node connectivity probes (HTTP HEAD/GET, TCP, UDP DNS).
//! * [`subscription`] — fetching, decoding, validating, and caching node lists.
//! * [`node_dialer`] — dispatches nodes to direct, system proxies, or proxy protocols.
//!
//! Proxy protocol implementations and cryptography engines are housed in `daer-proxy-protocols`
//! per ADR-0017.

mod alive;
mod check;
mod dialer;
mod direct;
mod error;
mod filter;
mod group;
mod latency;
mod node_dialer;
mod observe;
mod property;
pub mod subscription;

pub use alive::{AliveDialerSet, DialerId, NotifyOutcome};
pub use check::{CheckError, CheckUrl, HttpChecker, HttpMethod, Scheme, TcpChecker, UdpDnsChecker};
pub use dialer::Dialer;
pub use direct::DirectDialer;
pub use error::OutboundError;
pub use filter::{Annotation, FilterError, FilterSet};
pub use group::DialerGroup;
pub use latency::{LatenciesN, MovingAverage};
pub use node_dialer::{DialerOptions, NodeDialer};
pub use property::{GroupPolicy, Property, Protocol, Security, parse_group_policy};

/// The ClientHello fragmentation plan, re-exported because [`DialerOptions`] carries one.
///
/// `decide` turns `[global.tls]` into a `Fragment` before it builds dialer options, and it
/// must be able to name the type it is constructing. Nothing else from
/// `daer-proxy-protocols` is re-exported here: a protocol type reachable through the
/// governance crate would announce a boundary this crate does not own (ADR-0017).
pub use daer_proxy_protocols::fragment;

/// The stream half of an established connection.
pub type Upstream = Box<dyn netune::Transport>;

pub use netune::{
    DatagramConnector, DatagramTransport, Established, EstablishedDatagrams, Preset, SocketConfig,
    UdpConnector,
};
pub use netune_trace::{TraceCollector, TraceSink};
pub use observe::{
    DialId, DialObserver, DialObserverSink, LogObserver, ObservedDialer, ObserverSlot,
};

pub use daer_common::SelectionPolicy;
pub use daer_config::TimeSpan;
