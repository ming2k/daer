// SPDX-License-Identifier: AGPL-3.0-only

//! REALITY: the client-side authentication layer for `vless` nodes.
//!
//! See [ADR-0010](../../../docs/adr/0010-reality-client-ownership.md) for why this lives
//! here rather than in `netune`, and why the TLS 1.3 client below is scoped to this
//! module alone.
//!
//! Nothing in this module is exported from the crate root: the only constructor is the
//! `vless://…?security=reality` link, so a configuration cannot reach the TLS 1.3 client
//! by any other route.

pub(crate) mod connector;
pub(crate) mod hybrid;
pub(crate) mod probe;
pub(crate) mod tls13;
pub(crate) mod verify;
pub(crate) mod vision;
