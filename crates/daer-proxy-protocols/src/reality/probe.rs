// SPDX-License-Identifier: AGPL-3.0-only

//! Wire-level probes, used by tests to attribute a REALITY failure to the right layer.
//!
//! REALITY answers a bad tag by forwarding the flow to the impersonated site, so a client
//! cannot tell "my ClientHello is malformed" from "my tag is wrong" by reading the error:
//! both end as a certificate for the wrong host, or as an alert relayed from that host.
//!
//! These functions expose the hello itself — bytes only, no keys, no constructor — so a
//! test can offer it to an ordinary TLS 1.3 server and see whether the server accepts it.

use super::tls13;

/// The ClientHello this crate would send to `server_name`, with a zero session-id.
///
/// A zero tag is deliberate: a plain TLS server ignores the field, so the hello is judged
/// on its framing and extensions alone — which is exactly the question the probe asks.
///
/// # Errors
///
/// Returns a message when the hello cannot be built, which is currently impossible and
/// would be a bug rather than a configuration error.
pub(crate) fn client_hello(server_name: &str) -> Result<Vec<u8>, String> {
    tls13::stream::probe_client_hello(server_name)
}
