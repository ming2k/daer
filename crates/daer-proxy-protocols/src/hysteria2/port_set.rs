// SPDX-License-Identifier: AGPL-3.0-only

//! The port set a Hysteria 2 node is reached on (ADR-0029).
//!
//! # Why this is not `u16`
//!
//! A reference `hysteria2://` link accepts a *union*: `443`, `443,8443`, `20000-30000`,
//! `all`. The union is what makes port hopping possible — the hop layer draws from it — and
//! it is also how a node behind a cloud provider's load balancer is spelled, where only one
//! port in a published range is actually forwarded.
//!
//! The type is re-exported from `daer-config` so there is one parser: a second one is a
//! second place for the normalisation rules (`8443-443` swaps, `all` is `0-65535`, overlaps
//! merge) to drift, and the hop layer samples uniformly from the result.

pub use daer_config::PortSet;
