// SPDX-License-Identifier: AGPL-3.0-only

//! Hysteria 2 HTTP/3 authentication over QUIC.
//!
//! After the QUIC handshake succeeds (with ALPN `h3`), the client performs
//! an HTTP/3 `POST https://hysteria/auth` request. A status of 233 indicates
//! successful authentication; any other status or response represents failure
//! or server masquerading.

use crate::error::OutboundError;

const AUTH_URL: &str = "https://hysteria/auth";
const STATUS_AUTH_SUCCESS: u16 = 233;

/// Authenticates this client over the QUIC connection using HTTP/3.
pub async fn authenticate(
    conn: &quinn::Connection,
    password: &str,
    rx_bps: u64,
) -> Result<(), OutboundError> {
    let h3_conn = h3_quinn::Connection::new(conn.clone());
    let (mut driver, mut send_request) = h3::client::new(h3_conn)
        .await
        .map_err(|e| OutboundError::Connect(format!("h3 handshake failed: {e}")))?;

    // Drive HTTP/3 state machine in background
    tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });

    // Random padding hex string to thwart fingerprinting
    let pad_len = 16 + (fastrand::u8(..) % 32);
    let mut pad = String::with_capacity(pad_len as usize * 2);
    for _ in 0..pad_len {
        use std::fmt::Write;
        let _ = write!(&mut pad, "{:02x}", fastrand::u8(..));
    }

    let req = http::Request::builder()
        .method("POST")
        .uri(AUTH_URL)
        .header("Host", "hysteria")
        .header("Hysteria-Auth", password)
        .header("Hysteria-CC-RX", rx_bps.to_string())
        .header("Hysteria-Padding", pad)
        .header("Content-Length", "0")
        .body(())
        .map_err(|e| OutboundError::Connect(format!("build auth request: {e}")))?;

    let mut send_stream = send_request
        .send_request(req)
        .await
        .map_err(|e| OutboundError::Connect(format!("send auth request: {e}")))?;

    send_stream
        .finish()
        .await
        .map_err(|e| OutboundError::Connect(format!("finish auth stream: {e}")))?;

    let resp = send_stream
        .recv_response()
        .await
        .map_err(|e| OutboundError::Connect(format!("recv auth response: {e}")))?;

    if resp.status().as_u16() != STATUS_AUTH_SUCCESS {
        return Err(OutboundError::Connect(format!(
            "hysteria2 authentication failed: server status {}",
            resp.status()
        )));
    }

    Ok(())
}
