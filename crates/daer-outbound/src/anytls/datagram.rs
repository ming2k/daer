// SPDX-License-Identifier: AGPL-3.0-only

//! Datagram session for AnyTLS using UDP-over-TCP (UoT) encapsulation.

use std::fmt;
use std::io;
use std::pin::Pin;
use std::sync::Arc;

use netune::{DatagramConnector, DatagramTransport, EstablishedDatagrams, NetError};
use netune_trace::Recorder;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::anytls::connector::AnyTlsConnector;

/// SOCKS5 Address Type constants for UOT header decoding.
const ATYP_IPV4: u8 = 1;
const ATYP_DOMAIN: u8 = 3;
const ATYP_IPV6: u8 = 4;

/// Magic destination address for UDP-over-TCP v2 tunnels.
pub const UOT_MAGIC_ADDRESS: &str = "sp.v2.udp-over-tcp.arpa:53";

/// Datagram connector for AnyTLS nodes.
pub struct AnyTlsDatagramConnector {
    connector: AnyTlsConnector,
}

impl AnyTlsDatagramConnector {
    #[must_use]
    pub const fn new(connector: AnyTlsConnector) -> Self {
        Self { connector }
    }
}

impl fmt::Debug for AnyTlsDatagramConnector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AnyTlsDatagramConnector")
            .field("server", &self.connector.server())
            .finish()
    }
}

impl DatagramConnector for AnyTlsDatagramConnector {
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

/// A datagram session carried over an AnyTLS virtual stream.
pub struct AnyTlsDatagramSession<R, W> {
    reader: tokio::sync::Mutex<R>,
    writer: tokio::sync::Mutex<W>,
    target_addr: Vec<u8>,
}

impl<R, W> fmt::Debug for AnyTlsDatagramSession<R, W> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AnyTlsDatagramSession")
            .finish_non_exhaustive()
    }
}

impl<R, W> AnyTlsDatagramSession<R, W> {
    pub fn new(reader: R, writer: W, target_addr: Vec<u8>) -> Self {
        Self {
            reader: tokio::sync::Mutex::new(reader),
            writer: tokio::sync::Mutex::new(writer),
            target_addr,
        }
    }
}

impl<R, W> DatagramTransport for AnyTlsDatagramSession<R, W>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    fn max_datagram_size(&self) -> usize {
        65507
    }

    fn send<'a>(
        &'a self,
        payload: &'a [u8],
    ) -> Pin<Box<dyn std::future::Future<Output = Result<usize, io::Error>> + Send + 'a>> {
        Box::pin(async move {
            let total_len = self.target_addr.len() + payload.len();
            let len = u16::try_from(total_len).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "datagram packet exceeds u16::MAX",
                )
            })?;

            let mut writer = self.writer.lock().await;
            writer.write_all(&len.to_be_bytes()).await?;
            writer.write_all(&self.target_addr).await?;
            writer.write_all(payload).await?;
            writer.flush().await?;
            Ok(payload.len())
        })
    }

    fn recv<'a>(
        &'a self,
        buffer: &'a mut [u8],
    ) -> Pin<Box<dyn std::future::Future<Output = Result<usize, io::Error>> + Send + 'a>> {
        Box::pin(async move {
            let mut reader = self.reader.lock().await;

            // Read 2-byte total length
            let mut len_buf = [0u8; 2];
            reader.read_exact(&mut len_buf).await?;
            let total_len = u16::from_be_bytes(len_buf) as usize;

            // Parse address header
            let mut atyp_buf = [0u8; 1];
            reader.read_exact(&mut atyp_buf).await?;
            let addr_len = match atyp_buf[0] {
                ATYP_IPV4 => {
                    // 4 bytes IPv4 + 2 bytes port
                    let mut skip = [0u8; 6];
                    reader.read_exact(&mut skip).await?;
                    1 + 6
                }
                ATYP_IPV6 => {
                    // 16 bytes IPv6 + 2 bytes port
                    let mut skip = [0u8; 18];
                    reader.read_exact(&mut skip).await?;
                    1 + 18
                }
                ATYP_DOMAIN => {
                    // 1 byte domain length
                    let mut domain_len = [0u8; 1];
                    reader.read_exact(&mut domain_len).await?;
                    let mut domain_and_port = vec![0u8; domain_len[0] as usize + 2];
                    reader.read_exact(&mut domain_and_port).await?;
                    1 + 1 + domain_and_port.len()
                }
                other => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("unknown address type in uot datagram: {other}"),
                    ));
                }
            };

            if total_len < addr_len {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "uot packet length smaller than address header",
                ));
            }

            let payload_len = total_len - addr_len;
            if payload_len > buffer.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "receive buffer too small for datagram payload",
                ));
            }

            reader.read_exact(&mut buffer[..payload_len]).await?;
            Ok(payload_len)
        })
    }
}
