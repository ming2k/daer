// SPDX-License-Identifier: AGPL-3.0-only

//! The userspace data path: transparent ingress, byte relaying, flow ownership.
//!
//! # What this crate is, and what it deliberately is not
//!
//! It answers exactly two questions per flow — *how do I get the bytes* and *where do they
//! go* — and nothing about *which* outbound that should be. Routing policy, node selection,
//! health measurement and subscription discovery live in `daer-control`; proxy protocols
//! live in `daer-proxy-protocols`. Neither appears in this crate's dependency graph.
//!
//! ```text
//!   inbound::TransparentListener ──▶ serve::serve ──▶ relay::splice ──▶ upstream stream
//!   inbound::TransparentDatagramListener ─▶ relay::serve_datagrams ─▶ upstream datagrams
//!                                              │
//!                                     Decider (daer-control)
//! ```
//!
//! # Why the seam is a trait, not a call
//!
//! [`serve::Decide`] and [`relay::datagram::DatagramRouter`] are traits because the loop and
//! the session table are the parts that are easy to get wrong (resource exhaustion, a
//! panicking handler, a reply delivered to the wrong peer), and they must be testable
//! without `CAP_NET_ADMIN`, without a proxy protocol, and without a routing configuration.
//! Production implements them in `daer-control`.
//!
//! # Why this crate is the stable half
//!
//! Accepting a redirected flow, forwarding half-close, keying a UDP session by
//! `(client, destination)`, reaping an idle peer: none of it changes when a protocol is
//! added or a routing concept is invented. Keeping it separate means a change to either of
//! those does not recompile or re-review the data path, and the data path's own tests do not
//! need a network stack to run.
//!
//! # Design rules
//!
//! * **No lock crosses an `.await`.** A flow owns its state.
//! * **Cancellation is dropping.** A relay ends when its future is dropped, so there is no
//!   shutdown flag to observe and no task to leak.
//! * **The kernel is the authority on destinations.** The original destination is the
//!   accepted socket's local address (TCP) or the ancillary message (UDP); it is never
//!   guessed or re-derived.
//! * **Nothing is swallowed.** A socket option that cannot be set is an error, not a
//!   warning: a listener without `IP_TRANSPARENT` silently accepts nothing.
//!
//! # Reporting
//!
//! Every hop has one place that reports it, so a question has exactly one place to look. The
//! field names are stable — they are what a log query filters on.
//!
//! | Question | Where | Level | Fields |
//! | --- | --- | --- | --- |
//! | What happened to the bytes? | [`serve::serve`] | `debug` | `destination to_upstream to_client elapsed_ms` |
//! | Why was a flow dropped? | [`serve::serve`] | `debug` | `reject` |
//! | Are we out of file descriptors? | [`serve::serve`] | `warn` | `error` (then a backoff, never a teardown) |
//! | Is anything leaking? | [`serve::Metrics::snapshot`] | on demand | `accepted rejected failed exhausted panicked` |
//! | Is a reload safe to finish? | [`supervise::Supervisor::in_flight`] | on demand | count of live flows |
//! | Did stopping a loop drop traffic? | [`serve::serve`] | `info` | `in_flight` — the flows keep running |
//! | Which datagram sessions are live? | [`relay::serve_datagrams`] | `debug` | `sessions reaped` |

pub mod error;
pub mod inbound;
pub mod relay;
pub mod serve;
pub mod supervise;

#[cfg(test)]
mod testkit;

pub use error::{DialFailure, Reject, RelayError};
pub use inbound::tcp::{
    Accepted, FlowFacts, TransparentListener, bind_shared, is_self_connect, unmap,
};
pub use inbound::udp::{Datagram, DatagramFamily, DatagramIngress, TransparentDatagramListener};
pub use relay::datagram::{
    DatagramLeg, DatagramRouter, DatagramService, DatagramSnapshot, DatagramStats, OpenDatagram,
    RelayOptions, serve_datagrams,
};
pub use relay::stream::{Relayed, splice};
pub use serve::{
    Decide, Ingress, Metrics, ServeStats, ShutdownReason, Stopped, is_resource_exhausted,
    serve as serve_ingress, serve_parallel,
};
pub use supervise::Supervisor;
