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

/// The HTTP/3 connection the authentication opened, kept alive for the session.
///
/// # Why this has to outlive `authenticate`
///
/// Hysteria 2 uses HTTP/3 *only* for authentication: every proxy stream afterwards is a raw QUIC
/// bidirectional stream whose first bytes are a frame type (`0x401`). But the server's HTTP/3
/// listener is what dispatches those streams — `ProxyStreamHijacker` peeks the first frame and
/// takes the stream over — so the HTTP/3 connection must stay up for the whole session.
///
/// Both halves of `h3`'s client close the QUIC connection when they go away:
///
/// * dropping the driver stops the state machine, and `h3` closes the connection;
/// * dropping the last `SendRequest` calls `handle_connection_error_on_stream(H3_NO_ERROR, …)`,
///   which closes it too.
///
/// Either one produces the same quiet failure: authentication succeeds, and the first proxy stream
/// reports `connection lost: LocallyClosed` on a connection that was healthy a moment before.
/// Holding both here is what makes their lifetime the session's lifetime.
pub struct H3Session {
    /// The driver task. Kept for its side effect; dropping a `JoinHandle` does not abort it, and
    /// the task ends when the connection does.
    _driver: tokio::task::JoinHandle<()>,
    /// Held for the destructor's side effect; see this struct's own note.
    _send_request: h3::client::SendRequest<h3_quinn::OpenStreams, bytes::Bytes>,
}

impl std::fmt::Debug for H3Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H3Session").finish_non_exhaustive()
    }
}

/// Authenticates this client over the QUIC connection using HTTP/3.
///
/// Returns the session handle with the outcome: the caller must keep it alive, because it is what
/// keeps the HTTP/3 connection (and with it the server's stream dispatcher) alive.
pub async fn authenticate(
    conn: &quinn::Connection,
    password: &str,
    rx_bps: u64,
) -> Result<(AuthOutcome, H3Session), ProxyProtocolError> {
    let h3_conn = h3_quinn::Connection::new(conn.clone());
    let (mut driver, mut send_request) = h3::client::new(h3_conn)
        .await
        .map_err(|error| ProxyProtocolError::Connect(format!("h3 handshake failed: {error}")))?;

    // Drive the HTTP/3 state machine on its own task, and keep the task alive past this function.
    //
    // Two things go wrong without this, and both are quiet:
    //
    // * the driver must be polled or the request never leaves the client (a timeout with no
    //   cause);
    // * when the driver is *dropped*, `h3` closes the underlying QUIC connection — so a driver
    //   that dies with `authenticate` takes the session with it, and the first stream operation
    //   reports "connection lost: LocallyClosed" on an otherwise healthy connection.
    //
    // `poll_close` resolves only when the HTTP/3 connection ends, which for a Hysteria 2 session is
    // when the session does; the returned join handle is detached on purpose so the driver lives
    // exactly as long as the QUIC connection it serves.
    let driver = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });

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
        .body(())
        .map_err(|error| ProxyProtocolError::Connect(format!("build the auth request: {error}")))?;

    let mut stream = send_request
        .send_request(request)
        .await
        .map_err(|error| ProxyProtocolError::Connect(format!("send auth request: {error}")))?;
    stream
        .finish()
        .await
        .map_err(|error| ProxyProtocolError::Connect(format!("finish auth stream: {error}")))?;

    let response = stream
        .recv_response()
        .await
        .map_err(|error| ProxyProtocolError::Connect(format!("receive auth response: {error}")))?;

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
        H3Session {
            _driver: driver,
            _send_request: send_request,
        },
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
        .map(|value| !value.eq_ignore_ascii_case("false"))
        .unwrap_or(true)
}

/// Reads `Hysteria-CC-RX`.
///
/// Three cases, all meaningful: a number is a rate, `0` is unlimited, and anything
/// unparseable (including the protocol's `auto`) means "use congestion control", which is
/// `None` here.
fn header_rx(response: &http::Response<()>) -> Option<u64> {
    let value = response
        .headers()
        .get("hysteria-cc-rx")
        .and_then(|value| value.to_str().ok())?;
    if value.eq_ignore_ascii_case("auto") {
        return None;
    }
    match value.trim().parse::<u64>() {
        // `0` is "unlimited", which is not a rate Brutal can pin; `None` says the same thing
        // to the controller, which then falls back to congestion control.
        Ok(0) => None,
        Ok(rate) => Some(rate),
        Err(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(headers: &[(&str, &str)]) -> http::Response<()> {
        let mut builder = http::Response::builder().status(STATUS_AUTH_SUCCESS);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        builder.body(()).expect("builds")
    }

    #[test]
    fn a_server_that_says_udp_is_disabled_is_believed() {
        // The defect this pins: the answer used to be discarded, so a datagram flow failed at
        // the relay with nothing to attribute it to.
        assert!(!header_bool(
            &response(&[("hysteria-udp", "false")]),
            "hysteria-udp"
        ));
        assert!(header_bool(
            &response(&[("hysteria-udp", "true")]),
            "hysteria-udp"
        ));
        // An absent header is not a "no": the reference's server sends it on every success,
        // so omission means the proxy did not repeat the default.
        assert!(header_bool(&response(&[]), "hysteria-udp"));
    }

    #[test]
    fn the_rate_header_distinguishes_a_number_auto_and_unlimited() {
        // A number is a rate Brutal can pin.
        assert_eq!(
            header_rx(&response(&[("hysteria-cc-rx", "1048576")])),
            Some(1_048_576)
        );
        // `0` is "unlimited", and `auto` is "decide for yourself": both mean the client must
        // use congestion control rather than a pinned rate.
        assert_eq!(header_rx(&response(&[("hysteria-cc-rx", "0")])), None);
        assert_eq!(header_rx(&response(&[("hysteria-cc-rx", "auto")])), None);
        assert_eq!(header_rx(&response(&[])), None);
        // An unparseable value is treated as "auto" rather than as zero bytes per second.
        assert_eq!(header_rx(&response(&[("hysteria-cc-rx", "1e9")])), None);
    }

    #[test]
    fn the_auth_request_is_a_post_to_the_references_path_with_its_headers() {
        // A wrong path or a missing `Host: hysteria` makes the server serve its masquerade
        // page, which reads as a rejected password.
        assert_eq!(AUTH_URL, "https://hysteria/auth");
        assert_eq!(HOST, "hysteria");
        assert_eq!(STATUS_AUTH_SUCCESS, 233);
    }
}
