// SPDX-License-Identifier: AGPL-3.0-only

//! Hysteria 2's HTTP/3 authentication, and what the answer means (ADR-0029).
//!
//! # The exchange
//!
//! ```text
//!   POST https://hysteria/auth
//!   Hysteria-Auth: <password>
//!   Hysteria-CC-RX: <bytes per second, 0 = unknown>
//!   Hysteria-Padding: <random hex>
//!   Content-Length: 0
//! ```
//!
//! A `233 HyOK` answer authorises the connection. Anything else is a failure *or* the
//! server's masquerade page — the protocol deliberately makes those indistinguishable to a
//! prober, so a client cannot tell "wrong password" from "not a Hysteria server". The error
//! message says so rather than guessing.
//!
//! # What the answer carries, and why reading it matters
//!
//! | Header | Meaning |
//! | --- | --- |
//! | `Hysteria-UDP` | may this node relay UDP at all? |
//! | `Hysteria-CC-RX` | the rate the server will take: a number, `0` for unlimited, or `auto` |
//!
//! Both were discarded before ADR-0029. `Hysteria-UDP: false` made a datagram flow fail later
//! at the relay with nothing to attribute it to, and `Hysteria-CC-RX` is the number Brutal
//! needs to pin a window at all.

use netune_http3::H3Client;
use netune_trace::TraceCollector;

use crate::error::ProxyProtocolError;

const AUTH_URL: &str = "https://hysteria/auth";
const HOST: &str = "hysteria";
const STATUS_AUTH_SUCCESS: u16 = 233;

/// What the server said about the connection it just authorised.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthOutcome {
    /// `Hysteria-UDP`: whether the server will relay UDP.
    pub udp_enabled: bool,
    /// `Hysteria-CC-RX`: the rate the server will take, in bytes per second.
    ///
    /// `None` means the server did not say, which the protocol spells `auto`: the client must
    /// use congestion control instead of pinning a rate.
    pub server_rx: Option<u64>,
}

/// The HTTP/3 connection the authentication opened, driven by `netune_http3::H3Client`.
pub type H3Session = H3Client;

/// Authenticates this client over the QUIC connection using HTTP/3.
///
/// Returns the session handle with the outcome: the caller must keep it alive, because it is what
/// keeps the HTTP/3 connection (and with it the server's stream dispatcher) alive.
pub async fn authenticate(
    conn: &netune_quic::owned::Connection,
    password: &str,
    rx_bps: u64,
    collector: &TraceCollector,
) -> Result<(AuthOutcome, H3Session), ProxyProtocolError> {
    let trace = collector.is_enabled().then(|| collector.clone());
    let mut h3 = H3Client::new(conn, trace)
        .await
        .map_err(|error| ProxyProtocolError::Connect(format!("h3 handshake failed: {error}")))?;

    // A random padding length, from the reference's `authRequestPadding` range. It exists to
    // stop a prober fingerprinting the request by its size.
    let pad_len = 16 + (fastrand::u8(..) % 32);
    let mut padding = String::with_capacity(usize::from(pad_len) * 2);
    for _ in 0..pad_len {
        use std::fmt::Write as _;
        let _ = write!(&mut padding, "{:02x}", fastrand::u8(..));
    }

    let request = http::Request::builder()
        .method("POST")
        .uri(AUTH_URL)
        .header("Host", HOST)
        .header("Hysteria-Auth", password)
        .header("Hysteria-CC-RX", rx_bps.to_string())
        .header("Hysteria-Padding", padding)
        .header("Content-Length", "0")
        .body(bytes::Bytes::new())
        .map_err(|error| ProxyProtocolError::Connect(format!("build the auth request: {error}")))?;

    let stream = h3
        .send(request)
        .await
        .map_err(|error| ProxyProtocolError::Connect(format!("send auth request: {error}")))?;

    let response = stream.head().clone();
    let status = response.status().as_u16();
    if status != STATUS_AUTH_SUCCESS {
        return Err(ProxyProtocolError::Connect(format!(
            "hysteria2 authentication failed: the server answered {status}. A non-233 answer \
             is either a rejected credential or the server's masquerade page — the protocol \
             makes the two indistinguishable to a prober, so check the password and the SNI \
             rather than expecting a distinct error"
        )));
    }

    let udp_enabled = header_bool(&response, "hysteria-udp");
    let server_rx = header_rx(&response);
    Ok((
        AuthOutcome {
            udp_enabled,
            server_rx,
        },
        h3,
    ))
}

/// Reads a boolean header, defaulting to `true`.
///
/// The default is `true` because the reference's server sends `Hysteria-UDP` on every
/// successful answer; a server that omits it is not saying "no", and refusing every datagram
/// on an absent header would break UDP against a proxy that simply did not repeat the default.
fn header_bool(response: &http::Response<()>, name: &str) -> bool {
    response
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.eq_ignore_ascii_case("true"))
        .unwrap_or(true)
}

/// Reads `Hysteria-CC-RX` into a rate in bytes per second.
///
/// Missing, `auto`, or a non-integer is `None`, which tells the caller to use congestion
/// control rather than pin a rate.
fn header_rx(response: &http::Response<()>) -> Option<u64> {
    let value = response.headers().get("hysteria-cc-rx")?.to_str().ok()?;
    let value = value.trim();
    if value.eq_ignore_ascii_case("auto") {
        return None;
    }
    value.parse::<u64>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_udp_header_defaults_to_true() {
        let response = http::Response::builder().body(()).unwrap();
        assert!(header_bool(&response, "hysteria-udp"));
    }

    #[test]
    fn an_explicit_false_udp_header_is_read() {
        let response = http::Response::builder()
            .header("hysteria-udp", "false")
            .body(())
            .unwrap();
        assert!(!header_bool(&response, "hysteria-udp"));
    }

    #[test]
    fn an_explicit_true_udp_header_is_read() {
        let response = http::Response::builder()
            .header("hysteria-udp", "TRUE")
            .body(())
            .unwrap();
        assert!(header_bool(&response, "hysteria-udp"));
    }

    #[test]
    fn a_numeric_cc_rx_is_parsed() {
        let response = http::Response::builder()
            .header("hysteria-cc-rx", "12500000")
            .body(())
            .unwrap();
        assert_eq!(header_rx(&response), Some(12_500_000));
    }

    #[test]
    fn an_auto_cc_rx_is_none() {
        let response = http::Response::builder()
            .header("hysteria-cc-rx", "auto")
            .body(())
            .unwrap();
        assert_eq!(header_rx(&response), None);
    }

    #[test]
    fn a_missing_cc_rx_is_none() {
        let response = http::Response::builder().body(()).unwrap();
        assert_eq!(header_rx(&response), None);
    }
}
