// SPDX-License-Identifier: AGPL-3.0-only

//! REALITY as a *security layer* (ADR-0028), not as a kind of VLESS.
//!
//! # What moved and why
//!
//! Before ADR-0028 the only way to reach the TLS 1.3 client below was
//! `RealityConnector::from_link`, which also built the VLESS header and the Vision writer.
//! That made REALITY inseparable from VLESS, so a `vless://…?security=tls` node had no code
//! path at all. The handshake is now [`RealitySecurity::wrap`]: a byte stream in, an opaque
//! byte stream out, and no opinion about what is inside.
//!
//! The scope rule of [ADR-0010](../../../docs/adr/0010-reality-client-ownership.md) is
//! preserved and is now stronger, because it is the *only* thing this module can do:
//! [`Tls13Connection`] is `pub(crate)` with no public constructor, and
//! [`RealitySecurity::wrap`] is the single caller.
//!
//! # What the layer checks
//!
//! REALITY answers a flow it cannot authenticate by **forwarding it to the impersonated
//! site**, which completes a valid TLS 1.3 handshake against a host nobody named. The
//! client's obligation is therefore not "verify the chain" (there is no chain) but "verify
//! that the certificate's signature is an HMAC under the auth key", which only the node can
//! produce. [`verify`](crate::reality::verify) is that check, and it runs before the layer
//! returns.

use std::time::{Duration, SystemTime};

use tokio::io::{AsyncRead, AsyncWrite};

use crate::error::ProxyProtocolError;
use crate::reality::tls13::RealityAuth;
use crate::reality::tls13::stream::Tls13Connection;
use crate::security::Opaque;

/// The parameters of a REALITY security layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealityParams {
    /// The impersonated site. Never an address: REALITY impersonates a *named* site.
    pub server_name: String,
    /// The server's X25519 public key.
    pub public_key: [u8; 32],
    /// Short id, at most 8 bytes.
    pub short_id: Vec<u8>,
    /// ALPN to offer in the handshake. A REALITY node forwards an unauthenticated flow to
    /// the impersonated site, so offering an ALPN the site does not speak is one of the ways
    /// a flow fails to blend in.
    pub alpn: Vec<Vec<u8>>,
}

/// REALITY: the client-side authentication layer for a stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealitySecurity {
    params: RealityParams,
}

impl RealitySecurity {
    /// Builds the layer from already-decoded parameters.
    #[must_use]
    pub const fn new(params: RealityParams) -> Self {
        Self { params }
    }

    /// The impersonated site, for a diagnostic that has to name what went wrong.
    #[must_use]
    pub fn server_name(&self) -> &str {
        &self.params.server_name
    }

    /// The ALPN this layer will offer.
    #[must_use]
    pub fn alpn(&self) -> &[Vec<u8>] {
        &self.params.alpn
    }

    /// Wraps `stream` in a REALITY handshake.
    ///
    /// `deadline` bounds the whole handshake, not each write: a node that accepts the
    /// connection and then trickles bytes must fail like a node that refuses it.
    pub async fn wrap<S>(&self, stream: S, deadline: Duration) -> Result<Opaque, ProxyProtocolError>
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let auth = RealityAuth::new(
            &self.params.public_key,
            &self.params.short_id,
            SystemTime::now(),
        )
        .map_err(ProxyProtocolError::UnsupportedLink)?;

        let handshake =
            Tls13Connection::handshake(stream, &self.params.server_name, &auth, &self.params.alpn);
        let connection = tokio::time::timeout(deadline, handshake)
            .await
            .map_err(|_| ProxyProtocolError::Timeout)?
            .map_err(|error| {
                ProxyProtocolError::Connect(format!(
                    "REALITY handshake impersonating {} failed: {error}",
                    self.params.server_name
                ))
            })?;

        // The raw-read switch is what Vision's `Direct` command toggles. It lives on the
        // TLS 1.3 connection rather than on a wrapper trait, so it travels beside the stream
        // instead of inside a trait object (see `Opaque`'s documentation).
        let raw_read = connection.raw_read_switch();
        Ok(Opaque {
            stream: Box::new(connection),
            raw_read: Some(raw_read),
            alpn: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_short_id_longer_than_eight_bytes_is_refused_at_wrap_time() {
        // The layer does not silently truncate: REALITY's tag carries at most 8 bytes, and a
        // truncated id authenticates to nothing while looking configured.
        let security = RealitySecurity::new(RealityParams {
            server_name: "www.example.com".to_owned(),
            public_key: [1u8; 32],
            short_id: vec![0u8; 9],
            alpn: Vec::new(),
        });
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let error = runtime.block_on(async {
            let (client, _server) = tokio::io::duplex(64);
            security
                .wrap(client, Duration::from_millis(50))
                .await
                .expect_err("9 bytes is not a short-id")
        });
        assert!(error.to_string().contains("8"), "{error}");
    }
}
