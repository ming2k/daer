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
//!
//! # The one product-fingerprint layer
//!
//! The WebSocket upgrade's header *set and order* are daer's product data; the HTTP grammar is
//! not. `netune-http1::write_request_head` serializes the exact caller-supplied headers with no
//! synthetic `User-Agent` or `Content-Length`, and `Http1Reader` parses the response. All
//! WebSocket frames, ping/pong and close handling are netune-ws. ADR-0002 records this as a
//! fingerprint decision, not a second HTTP implementation.

use std::time::Duration;

use netune::{Method, Transport, WsHandshake, WsStream};
use netune_http1::{Http1Reader, Limits, RequestHead, write_request_head};
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
/// The *request* is deliberately serialized here: it is the node's HTTP fingerprint (the exact
/// header set and order, with no synthetic `User-Agent` or `Content-Length`). The *response* is
/// parsed by netune-http1, so framing, header-count and head-size limits are netune's rather than
/// a second hand-written HTTP parser.
async fn upgrade<S>(
    mut stream: S,
    params: &WsParams,
    host: &str,
    recorder: &TraceCollector,
    timeout: Duration,
) -> Result<WsByteStream<S>, ProxyProtocolError>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let key = netune_ws::generate_key();
    let path = if params.path.is_empty() {
        "/"
    } else {
        &params.path
    };
    // The exact header set and order are the node-visible fingerprint; netune-http1 owns the
    // request-line/header grammar, while this list is the product data. `write_request_head`
    // deliberately adds no `Content-Length` or `User-Agent`.
    let mut head = RequestHead::new(Method::GET, path)
        .with_raw_header("Host", host)
        .with_raw_header("Upgrade", "websocket")
        .with_raw_header("Connection", "Upgrade")
        .with_raw_header("Sec-WebSocket-Key", key.as_str())
        .with_raw_header("Sec-WebSocket-Version", "13");
    for (name, value) in &params.headers {
        head = head.with_raw_header(name.as_str(), value.as_str());
    }
    tokio::time::timeout(timeout, write_request_head(&mut stream, &head))
        .await
        .map_err(|_| ProxyProtocolError::Timeout)?
        .map_err(|error| {
            ProxyProtocolError::Connect(format!("write the WebSocket upgrade request: {error}"))
        })?;

    // The reader keeps any bytes that followed the head: a server may write its first frame in the
    // same segment as `101 Switching Protocols`, and dropping them loses the start of the tunnel.
    // The 16 KiB ceiling matches the old hand-written parser and is tighter than netune's default.
    let limits = Limits {
        max_head_bytes: 16 * 1024,
        ..Limits::default()
    };
    let mut reader = Http1Reader::with_limits(stream, limits);
    let response = tokio::time::timeout(timeout, reader.read_response_head(&Method::GET))
        .await
        .map_err(|_| ProxyProtocolError::Timeout)?
        .map_err(|error| {
            ProxyProtocolError::Connect(format!("read the WebSocket upgrade response: {error}"))
        })?;
    if response.status != http::StatusCode::SWITCHING_PROTOCOLS {
        return Err(ProxyProtocolError::Connect(format!(
            "the node answered the WebSocket upgrade with {}, not 101 Switching Protocols. \
             A 400 or 404 here is what a `wss` node answers a request that did not arrive \
             inside TLS, or a path the node does not serve",
            response.status
        )));
    }

    let accept = response
        .headers
        .get("sec-websocket-accept")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| {
            ProxyProtocolError::Connect(
                "the WebSocket upgrade response has no valid Sec-WebSocket-Accept header"
                    .to_owned(),
            )
        })?;
    netune_ws::verify_handshake(&key, accept).map_err(|error| {
        ProxyProtocolError::Connect(format!(
            "the node's Sec-WebSocket-Accept does not match the key: {error}"
        ))
    })?;

    let (stream, residual) = reader.into_inner();
    // netune's `WsStream` is message-oriented; a proxy transport is a byte stream in binary frames,
    // so the adapter bridges the two (`transport_ws.rs`). Frame and ping/pong tracing stays in
    // netune's collector.
    Ok(WsByteStream::new(WsStream::new(
        stream,
        residual,
        Some(recorder.clone()),
        WsHandshake::default().limits,
    )))
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
}
