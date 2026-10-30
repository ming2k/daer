// SPDX-License-Identifier: AGPL-3.0-only

//! Hysteria 2 UDP datagram session over QUIC datagrams (RFC 9221).

use std::fmt;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};

use bytes::Bytes;
use netune::{DatagramConnector, DatagramTransport, EstablishedDatagrams, NetError};
use netune_trace::Recorder;

use crate::hysteria2::connector::Hysteria2Connector;
use crate::hysteria2::varint::{decode_varint_slice, encode_varint};

/// Datagram connector for Hysteria 2 nodes.
pub struct Hysteria2DatagramConnector {
    connector: Hysteria2Connector,
}

impl Hysteria2DatagramConnector {
    #[must_use]
    pub const fn new(connector: Hysteria2Connector) -> Self {
        Self { connector }
    }
}

impl fmt::Debug for Hysteria2DatagramConnector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Hysteria2DatagramConnector")
            .field("server", &self.connector.server())
            .finish()
    }
}

impl DatagramConnector for Hysteria2DatagramConnector {
    fn connect<'a>(
        &'a self,
        authority: &'a str,
        recorder: &'a Arc<std::sync::Mutex<Recorder>>,
    ) -> Pin<
        Box<dyn std::future::Future<Output = Result<EstablishedDatagrams, NetError>> + Send + 'a>,
    > {
        let connector = self.connector.clone();
        let authority = authority.to_owned();
        let recorder = Arc::clone(recorder);
        Box::pin(async move { connector.connect_datagram(&authority, &recorder).await })
    }
}

/// A connected datagram session over Hysteria 2's QUIC connection.
pub struct Hysteria2DatagramSession {
    connection: quinn::Connection,
    authority: String,
    session_id: u32,
    packet_id: AtomicU16,
}

impl fmt::Debug for Hysteria2DatagramSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Hysteria2DatagramSession")
            .field("authority", &self.authority)
            .field("session_id", &self.session_id)
            .finish()
    }
}

impl Hysteria2DatagramSession {
    /// Constructs a new Hysteria 2 datagram session.
    pub fn new(connection: quinn::Connection, authority: String, session_id: u32) -> Self {
        Self {
            connection,
            authority,
            session_id,
            packet_id: AtomicU16::new(1),
        }
    }
}

impl DatagramTransport for Hysteria2DatagramSession {
    fn max_datagram_size(&self) -> usize {
        // Safe bound considering QUIC datagram MTU overheads
        1280
    }

    fn send<'a>(
        &'a self,
        payload: &'a [u8],
    ) -> Pin<Box<dyn std::future::Future<Output = Result<usize, io::Error>> + Send + 'a>> {
        Box::pin(async move {
            let pid = self.packet_id.fetch_add(1, Ordering::Relaxed);
            let addr_bytes = self.authority.as_bytes();

            let mut packet = Vec::with_capacity(8 + 8 + addr_bytes.len() + payload.len());
            packet.extend_from_slice(&self.session_id.to_be_bytes());
            packet.extend_from_slice(&pid.to_be_bytes());
            packet.push(0); // frag_id = 0
            packet.push(1); // frag_total = 1
            encode_varint(addr_bytes.len() as u64, &mut packet);
            packet.extend_from_slice(addr_bytes);
            packet.extend_from_slice(payload);

            self.connection
                .send_datagram(Bytes::from(packet))
                .map_err(|e| io::Error::other(format!("send datagram failed: {e}")))?;

            Ok(payload.len())
        })
    }

    fn recv<'a>(
        &'a self,
        buffer: &'a mut [u8],
    ) -> Pin<Box<dyn std::future::Future<Output = Result<usize, io::Error>> + Send + 'a>> {
        Box::pin(async move {
            loop {
                let datagram = self
                    .connection
                    .read_datagram()
                    .await
                    .map_err(|e| io::Error::other(format!("read datagram failed: {e}")))?;

                if datagram.len() < 8 {
                    continue;
                }

                let session_id =
                    u32::from_be_bytes([datagram[0], datagram[1], datagram[2], datagram[3]]);
                if session_id != self.session_id {
                    continue;
                }

                let rest = &datagram[8..];
                let Some((addr_len, varint_bytes)) = decode_varint_slice(rest) else {
                    continue;
                };

                let header_len = varint_bytes + addr_len as usize;
                if rest.len() < header_len {
                    continue;
                }

                let payload = &rest[header_len..];
                if payload.len() > buffer.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "receive buffer too small for datagram payload",
                    ));
                }

                buffer[..payload.len()].copy_from_slice(payload);
                return Ok(payload.len());
            }
        })
    }
}
