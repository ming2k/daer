// SPDX-License-Identifier: AGPL-3.0-only

//! The transport layer: what carries the security layer's record stream (ADR-0028).
//!
//! # The order, which is the opposite of what it looks like
//!
//! `transportSettings: { network = "ws", security = "tls" }` means **TLS wraps WebSocket**, not
//! the other way round. The upgrade request is a plaintext HTTP request sent *inside* the TLS
//! tunnel (`wss://`), which is what Xray's own transport dialer does: it builds a
//! `websocket.Dialer` whose `TLSClientConfig` is the stream's TLS config, so the handshake happens
//! first and the `GET … Upgrade: websocket` follows through it.
//!
//! ```text
//!   tcp ──▶ Security (tls | reality) ──▶ Transport (ws) ──▶ Protocol (vless | vmess)
//! ```
//!
//! Getting this backwards is not subtle on the wire — a node configured for `wss` answers a
//! plaintext `GET` with `400 Bad Request` — but it is easy to get backwards from the configuration
//! names alone, which is why the order is stated here and asserted by `tests/layer_matrix.rs`.
//!
//! # What the layer owns
//!
//! Only the upgrade: the request line, `Host`, the key and the extra headers. The frame codec, the
//! ping/pong heartbeats and the close handshake are netune's (`WsStream`), because RFC 6455 is a
//! general protocol with nothing proxy-specific in it — [ADR-0002](../../../docs/adr/0002-netune-boundary.md)'s
//! split exactly.
//!
//! # What is not here
//!
//! `grpc`, `httpupgrade`, `xhttp`, `kcp`, `quic`. Each is a real transport with real framing, and
//! each is refused by name at load time rather than silently treated as TCP. A node that connects
//! and then sends nonsense costs more to diagnose than one that refuses to load.

use std::time::Duration;

use bytes::BytesMut;
use netune::{Transport, WsHandshake, WsStream};
use netune_trace::TraceCollector;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::error::ProxyProtocolError;
use crate::transport_ws::WsByteStream;

/// The transport above a protocol's security layer (ADR-0028).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum TransportLayer {
    /// A raw stream: nothing to do.
    #[default]
    Tcp,
    Ws(WsParams),
}

/// WebSocket framing above the security layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsParams {
    /// Request path, e.g. `/ray`.
    pub path: String,
    /// `Host` header; `None` uses the node's SNI, then its hostname.
    pub host: Option<String>,
    /// Extra request headers, in the order they are written.
    pub headers: Vec<(String, String)>,
}

impl TransportLayer {
    /// The name a log or a diagnostic uses.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Ws(_) => "ws",
        }
    }

    /// The `Host` a `ws` upgrade presents: the explicit header, else the SNI, else the node's host.
    ///
    /// The reference resolves it in that order, and a CDN-fronted node depends on it: the TLS SNI
    /// and the WebSocket `Host` are frequently the *CDN's* name while the node's own address is an
    /// IP literal the CDN routes by path.
    #[must_use]
    fn host_for<'a>(&'a self, node_host: &'a str, sni: Option<&'a str>) -> &'a str {
        match self {
            Self::Ws(params) => params.host.as_deref().or(sni).unwrap_or(node_host),
            Self::Tcp => node_host,
        }
    }

    /// Applies this layer to the stream the security layer produced.
    ///
    /// The `tcp` arm returns the stream unchanged, so a node with no transport pays nothing; the
    /// `ws` arm upgrades it. Both return `Box<dyn Transport>`, which is what the protocol layer
    /// above needs and what keeps the six concrete type combinations from being named anywhere.
    ///
    /// # Errors
    ///
    /// Returns a message when the upgrade is refused, times out, or the node answers with
    /// something that is not `101 Switching Protocols`.
    pub async fn wrap(
        &self,
        stream: Box<dyn Transport>,
        node_host: &str,
        sni: Option<&str>,
        recorder: &TraceCollector,
        timeout: Duration,
    ) -> Result<Box<dyn Transport>, ProxyProtocolError> {
        match self {
            Self::Tcp => Ok(stream),
            Self::Ws(params) => {
                let host = self.host_for(node_host, sni).to_owned();
                let upgraded = upgrade(stream, params, &host, recorder, timeout).await?;
                Ok(Box::new(upgraded))
            }
        }
    }
}

/// Performs the RFC 6455 upgrade on an already-established (and already secured) stream.
///
/// netune's `WsStream` takes the connected transport and a residual buffer, so the request/response
/// exchange happens here rather than inside netune's HTTP client — which would add a request body,
/// a redirect policy and a pool this connection must not have.
async fn upgrade<S>(
    mut stream: S,
    params: &WsParams,
    host: &str,
    _recorder: &TraceCollector,
    timeout: Duration,
) -> Result<WsByteStream<S>, ProxyProtocolError>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let key = netune_ws::generate_key();
    let path = if params.path.is_empty() {
        "/"
    } else {
        &params.path
    };
    let mut request = format!(
        "GET {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: {key}\r\n\
         Sec-WebSocket-Version: 13\r\n"
    );
    for (name, value) in &params.headers {
        request.push_str(name);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");

    tokio::time::timeout(timeout, stream.write_all(request.as_bytes()))
        .await
        .map_err(|_| ProxyProtocolError::Timeout)?
        .map_err(|error| {
            ProxyProtocolError::Connect(format!("write the WebSocket upgrade request: {error}"))
        })?;
    tokio::time::timeout(timeout, stream.flush())
        .await
        .map_err(|_| ProxyProtocolError::Timeout)?
        .map_err(|error| {
            ProxyProtocolError::Connect(format!("flush the WebSocket upgrade request: {error}"))
        })?;

    // Read the response head, keeping whatever followed it: a server may write its first frame in
    // the same segment as `101 Switching Protocols`, and dropping those bytes loses the start of
    // the tunnel.
    let mut buffer = BytesMut::with_capacity(2048);
    let head_end = loop {
        let mut chunk = [0u8; 1024];
        let read = tokio::time::timeout(timeout, stream.read(&mut chunk))
            .await
            .map_err(|_| ProxyProtocolError::Timeout)?
            .map_err(|error| {
                ProxyProtocolError::Connect(format!("read the WebSocket upgrade response: {error}"))
            })?;
        if read == 0 {
            return Err(ProxyProtocolError::Connect(
                "the node closed before answering the WebSocket upgrade".to_owned(),
            ));
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(index) = find_head_end(&buffer) {
            break index;
        }
        if buffer.len() > 16 * 1024 {
            return Err(ProxyProtocolError::Connect(
                "the WebSocket upgrade response head is over 16 KiB; the node is not answering an \
                 upgrade"
                    .to_owned(),
            ));
        }
    };

    let head = String::from_utf8_lossy(&buffer[..head_end]).into_owned();
    let residual = BytesMut::from(&buffer[head_end..]);

    let mut lines = head.split("\r\n");
    let status = lines.next().unwrap_or_default();
    let accepted = status
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        == Some(101);
    if !accepted {
        return Err(ProxyProtocolError::Connect(format!(
            "the node answered the WebSocket upgrade with {status:?}, not 101 Switching \
             Protocols. A 400 or 404 here is what a `wss` node answers a request that did not \
             arrive inside TLS, or a path the node does not serve"
        )));
    }

    let mut accept = None;
    for line in lines {
        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("sec-websocket-accept")
        {
            accept = Some(value.trim().to_owned());
        }
    }
    let accept = accept.ok_or_else(|| {
        ProxyProtocolError::Connect(
            "the WebSocket upgrade response has no Sec-WebSocket-Accept header".to_owned(),
        )
    })?;
    netune_ws::verify_handshake(&key, &accept).map_err(|error| {
        ProxyProtocolError::Connect(format!(
            "the node's Sec-WebSocket-Accept does not match the key: {error}"
        ))
    })?;

    // netune's `WsStream` is message-oriented; a proxy transport is a byte stream in binary frames,
    // so the adapter bridges the two (`transport_ws.rs`).
    Ok(WsByteStream::new(WsStream::new(
        stream,
        residual,
        None,
        WsHandshake::default().limits,
    )))
}

/// The offset just past the blank line that ends an HTTP head.
fn find_head_end(buffer: &[u8]) -> Option<usize> {
    buffer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_host_header_falls_back_from_explicit_to_sni_to_the_node() {
        // A CDN-fronted node depends on this order: the TLS SNI and the WebSocket `Host` are
        // frequently the CDN's name while the node's own address is an IP literal.
        let ws = TransportLayer::Ws(WsParams {
            path: "/ray".to_owned(),
            host: Some("cdn.example.com".to_owned()),
            headers: Vec::new(),
        });
        assert_eq!(
            ws.host_for("1.2.3.4", Some("sni.example")),
            "cdn.example.com"
        );

        let ws = TransportLayer::Ws(WsParams {
            path: "/ray".to_owned(),
            host: None,
            headers: Vec::new(),
        });
        assert_eq!(ws.host_for("1.2.3.4", Some("sni.example")), "sni.example");
        assert_eq!(ws.host_for("1.2.3.4", None), "1.2.3.4");
    }

    #[test]
    fn a_head_end_is_found_only_at_a_blank_line() {
        assert_eq!(find_head_end(b"HTTP/1.1 101\r\n\r\nrest"), Some(16));
        assert_eq!(find_head_end(b"HTTP/1.1 101\r\nA: b\r\n"), None);
        // A `\r\n\r\n` inside a value is still the head end by RFC 7230's rules — the first blank
        // line terminates the head — so this asserts a plain scan rather than a header-aware
        // parser.
        assert_eq!(find_head_end(b"\r\n\r\n"), Some(4));
    }
}
