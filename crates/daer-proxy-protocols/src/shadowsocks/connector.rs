// SPDX-License-Identifier: AGPL-3.0-only

//! The shadowsocks `Connector`: link parsing, the handshake, and the framed stream.

use std::fmt;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use netune::{
    Connector, DatagramConnector, Established, EstablishedDatagrams, NetError, SocketConfig,
    Target, TcpConnector, Transport,
};
use netune_trace::TraceCollector;
use tokio::io::AsyncWriteExt;

use super::link::{Link, decode_base64_bytes, decode_base64_string};
use super::v1::{Sealer, ShadowSocksDatagramSession, ShadowSocksStream, master_key, write_salt};
use super::v2::{
    ShadowSocks2022DatagramSession, send_client_handshake as send_client_handshake_2022,
};
use super::{Cipher, ShadowSocksError};
use crate::error::ProxyProtocolError;
use crate::options::DialerOptions;

/// The address types shadowsocks encodes in its handshake.
pub mod atyp {
    pub const IPV4: u8 = 1;
    pub const DOMAIN: u8 = 3;
    pub const IPV6: u8 = 4;
}

/// Decodes standard or URL-safe base64, with or without padding.
pub fn decode_base64(text: &str) -> Result<String, String> {
    decode_base64_string(text)
}

/// The shadowsocks client connector.
#[derive(Debug, Clone)]
pub struct ShadowSocksConnector {
    cipher: Cipher,
    master: Vec<u8>,
    server: String,
    connector: TcpConnector,
    timeout: Duration,
    so_mark: Option<u32>,
}

impl ShadowSocksConnector {
    /// Builds a connector directly from typed parameters.
    pub fn new(
        server: &str,
        port: u16,
        method: &str,
        password: &str,
        options: DialerOptions,
    ) -> Result<Self, ProxyProtocolError> {
        let cipher = Cipher::parse(method)
            .map_err(|e| ProxyProtocolError::UnsupportedLink(e.to_string()))?;
        let master = if cipher.is_2022() {
            let psk = decode_base64_bytes(password).map_err(|e| {
                ProxyProtocolError::UnsupportedLink(format!(
                    "shadowsocks 2022: invalid base64 password for '{method}': {e}"
                ))
            })?;
            if psk.len() != cipher.key_len() {
                return Err(ProxyProtocolError::UnsupportedLink(format!(
                    "shadowsocks 2022: '{method}' requires a {}-byte key, but got {}",
                    cipher.key_len(),
                    psk.len()
                )));
            }
            psk
        } else {
            master_key(cipher, password)
        };
        let server = format!("{server}:{port}");
        Ok(Self {
            cipher,
            master,
            server,
            connector: TcpConnector::new()
                .with_socket_config(match options.so_mark {
                    Some(mark) => SocketConfig::default().with_mark(mark),
                    None => SocketConfig::default(),
                })
                .with_connect_timeout(Some(options.timeout)),
            timeout: options.timeout,
            so_mark: options.so_mark,
        })
    }

    /// Builds a connector from a link.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyProtocolError::UnsupportedLink`] for a link this module cannot use.
    pub fn from_link(link: &str, options: DialerOptions) -> Result<Self, ProxyProtocolError> {
        let parsed = Link::parse(link).map_err(ProxyProtocolError::UnsupportedLink)?;
        Ok(Self {
            cipher: parsed.cipher,
            master: parsed.master_key(),
            server: parsed.server,
            connector: TcpConnector::new()
                .with_socket_config(match options.so_mark {
                    Some(mark) => SocketConfig::default().with_mark(mark),
                    None => SocketConfig::default(),
                })
                .with_connect_timeout(Some(options.timeout)),
            timeout: options.timeout,
            so_mark: options.so_mark,
        })
    }

    /// The shadowsocks server this connector dials.
    #[must_use]
    pub fn server(&self) -> &str {
        &self.server
    }

    /// The cipher this connector speaks.
    #[must_use]
    pub const fn cipher(&self) -> Cipher {
        self.cipher
    }

    /// Connects to `authority` (`host:port`) through the shadowsocks server.
    pub async fn connect(
        &self,
        authority: &str,
        recorder: &TraceCollector,
    ) -> Result<Established, ProxyProtocolError> {
        let (host, port) =
            split_authority(authority).map_err(ProxyProtocolError::UnsupportedLink)?;
        let address = encode_address(host, port).map_err(ProxyProtocolError::UnsupportedLink)?;

        let server = Target::plain(&self.server);
        let established =
            tokio::time::timeout(self.timeout, self.connector.connect(&server, recorder))
                .await
                .map_err(|_| ProxyProtocolError::Timeout)?
                .map_err(|error| ProxyProtocolError::Connect(error.to_string()))?;

        let stream = established.stream;
        let local_port = established.local_port;
        let socket = established.socket;

        if self.cipher.is_2022() {
            let ss22_stream =
                send_client_handshake_2022(stream, self.cipher, &self.master, &address, &[])
                    .await
                    .map_err(|e| ProxyProtocolError::Connect(e.to_string()))?;

            Ok(Established {
                stream: Box::new(ss22_stream),
                local_port,
                socket,
                alpn: None,
            })
        } else {
            let mut stream = stream;
            let mut salt = vec![0u8; self.cipher.salt_len()];
            fill_random(&mut salt);
            let mut sealer = Sealer::new(self.cipher, &self.master, &salt);
            let request = sealer.seal_chunk(&address).map_err(|error| {
                ProxyProtocolError::Connect(ShadowSocksError::Crypto(error).to_string())
            })?;

            write_salt(&mut stream, &salt)
                .await
                .map_err(|error| ProxyProtocolError::Connect(error.to_string()))?;
            stream
                .write_all(&request)
                .await
                .map_err(|error| ProxyProtocolError::Connect(error.to_string()))?;

            let mut peer_salt = vec![0u8; self.cipher.salt_len()];
            read_exact(&mut stream, &mut peer_salt)
                .await
                .map_err(|error| ProxyProtocolError::Connect(error.to_string()))?;

            let framed: ShadowSocksStream<Box<dyn Transport>> =
                ShadowSocksStream::with_sealer(stream, self.cipher, sealer, &peer_salt);
            Ok(Established {
                stream: Box::new(framed),
                local_port,
                socket,
                alpn: None,
            })
        }
    }

    /// Returns a [`DatagramConnector`] that carries UDP over this Shadowsocks node.
    #[must_use]
    pub fn datagram_connector(&self) -> Arc<dyn DatagramConnector> {
        Arc::new(ShadowSocksDatagramConnector::new(self.clone()))
    }

    /// Opens a Shadowsocks datagram session to `authority` (`host:port`).
    pub async fn connect_datagram(
        &self,
        authority: &str,
        _recorder: &TraceCollector,
    ) -> Result<EstablishedDatagrams, NetError> {
        let (host, port) = split_authority(authority).map_err(NetError::Protocol)?;
        let addr_bytes = encode_address(host, port).map_err(NetError::Protocol)?;

        let server_addr = tokio::net::lookup_host(&self.server)
            .await
            .map_err(|e| NetError::Resolve(e.to_string()))?
            .next()
            .ok_or_else(|| NetError::Resolve(format!("cannot resolve {}", self.server)))?;

        let bind_addr = if server_addr.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let socket = tokio::net::UdpSocket::bind(bind_addr)
            .await
            .map_err(|e| NetError::Connect(e.to_string()))?;

        if let Some(mark) = self.so_mark {
            #[cfg(unix)]
            // SAFETY: socket is an open UDP socket owned by us; libc::SO_MARK is a valid sockopt on Linux.
            unsafe {
                use std::os::fd::AsRawFd;
                let val = mark as libc::c_int;
                let _ = libc::setsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_MARK,
                    &val as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
            }
        }

        socket
            .connect(server_addr)
            .await
            .map_err(|e| NetError::Connect(e.to_string()))?;

        let local_port = socket.local_addr().ok().map(|a| a.port());
        if self.cipher.is_2022() {
            let session = ShadowSocks2022DatagramSession::new(
                Arc::new(socket),
                self.cipher,
                self.master.clone(),
                addr_bytes,
            );
            Ok(EstablishedDatagrams {
                datagrams: Box::new(session),
                local_port,
            })
        } else {
            let session = ShadowSocksDatagramSession::new(
                Arc::new(socket),
                self.cipher,
                self.master.clone(),
                addr_bytes,
            );
            Ok(EstablishedDatagrams {
                datagrams: Box::new(session),
                local_port,
            })
        }
    }
}

/// Encodes a target address the way shadowsocks expects it.
pub fn encode_address(host: &str, port: u16) -> Result<Vec<u8>, String> {
    if host.is_empty() {
        return Err("empty host".to_owned());
    }
    if port == 0 {
        return Err("port 0 is not a destination".to_owned());
    }
    let mut out = Vec::with_capacity(1 + 1 + host.len() + 2);
    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(address)) => {
            out.push(atyp::IPV4);
            out.extend_from_slice(&address.octets());
        }
        Ok(std::net::IpAddr::V6(address)) => {
            out.push(atyp::IPV6);
            out.extend_from_slice(&address.octets());
        }
        Err(_) => {
            if host.len() > 255 {
                return Err(format!("host {host:?} is longer than 255 bytes"));
            }
            out.push(atyp::DOMAIN);
            out.push(host.len() as u8);
            out.extend_from_slice(host.as_bytes());
        }
    }
    out.extend_from_slice(&port.to_be_bytes());
    Ok(out)
}

/// Splits `authority` into `(host, port)`.
pub fn split_authority(authority: &str) -> Result<(&str, u16), String> {
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .ok_or_else(|| format!("{authority:?} has an unclosed `[`"))?;
        let port = tail
            .strip_prefix(':')
            .ok_or_else(|| format!("{authority:?} has no port"))?;
        let port = port
            .parse()
            .map_err(|_| format!("{authority:?} has an invalid port"))?;
        return Ok((host, port));
    }
    let (host, port) = authority
        .rsplit_once(':')
        .ok_or_else(|| format!("{authority:?} has no port"))?;
    let port = port
        .parse()
        .map_err(|_| format!("{authority:?} has an invalid port"))?;
    Ok((host, port))
}

impl Connector for ShadowSocksConnector {
    fn connect(
        &self,
        target: &Target,
        recorder: &TraceCollector,
    ) -> impl std::future::Future<Output = Result<Established, NetError>> + Send {
        let authority = target.authority.clone();
        let this = self.clone();
        async move {
            this.connect(&authority, recorder)
                .await
                .map_err(|error| NetError::Connect(error.to_string()))
        }
    }
}

/// A connector establishing datagram sessions over Shadowsocks AEAD.
#[derive(Clone)]
pub struct ShadowSocksDatagramConnector {
    connector: ShadowSocksConnector,
}

impl ShadowSocksDatagramConnector {
    #[must_use]
    pub const fn new(connector: ShadowSocksConnector) -> Self {
        Self { connector }
    }
}

impl fmt::Debug for ShadowSocksDatagramConnector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShadowSocksDatagramConnector")
            .field("server", &self.connector.server())
            .finish()
    }
}

impl DatagramConnector for ShadowSocksDatagramConnector {
    fn connect<'a>(
        &'a self,
        authority: &'a str,
        recorder: &'a TraceCollector,
    ) -> Pin<
        Box<dyn std::future::Future<Output = Result<EstablishedDatagrams, NetError>> + Send + 'a>,
    > {
        let connector = self.connector.clone();
        let authority = authority.to_owned();
        Box::pin(async move { connector.connect_datagram(&authority, recorder).await })
    }
}

fn fill_random(buffer: &mut [u8]) {
    getrandom::fill(buffer).expect("OS random failure");
}

async fn read_exact(stream: &mut Box<dyn Transport>, buffer: &mut [u8]) -> std::io::Result<()> {
    use tokio::io::AsyncReadExt as _;
    stream.read_exact(buffer).await.map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_are_encoded_with_the_right_address_type() {
        assert_eq!(
            encode_address("1.2.3.4", 443).expect("encodes"),
            vec![1, 1, 2, 3, 4, 1, 187]
        );

        let v6 = encode_address("2001:db8::1", 53).expect("encodes");
        assert_eq!(v6[0], 4);
        assert_eq!(v6.len(), 1 + 16 + 2);
        assert_eq!(&v6[v6.len() - 2..], &53u16.to_be_bytes());

        let domain = encode_address("example.com", 8388).expect("encodes");
        assert_eq!(domain[0], 3);
        assert_eq!(domain[1], 11);
        assert_eq!(&domain[2..13], b"example.com");
    }

    #[test]
    fn address_encoding_rejects_impossible_targets() {
        assert!(encode_address("", 80).is_err());
        assert!(encode_address("example.com", 0).is_err());
        assert!(encode_address(&"a".repeat(256), 80).is_err());
    }

    #[test]
    fn authorities_split_for_v4_v6_and_names() {
        assert_eq!(
            split_authority("1.2.3.4:443").expect("splits"),
            ("1.2.3.4", 443)
        );
        assert_eq!(
            split_authority("example.com:8388").expect("splits"),
            ("example.com", 8388)
        );
        assert_eq!(
            split_authority("[2001:db8::1]:53").expect("splits"),
            ("2001:db8::1", 53)
        );
        assert!(split_authority("example.com").is_err());
        assert!(split_authority("example.com:").is_err());
        assert!(split_authority("[2001:db8::1").is_err());
    }

    #[test]
    fn a_connector_rejects_a_link_it_cannot_use() {
        let error = ShadowSocksConnector::from_link(
            "ss://bm90LWEtbGluaw@example.com:1",
            DialerOptions::new(None, Duration::from_secs(1)),
        )
        .expect_err("must reject");
        assert!(matches!(error, ProxyProtocolError::UnsupportedLink(_)));
    }

    #[test]
    fn link_detection_is_prefix_based() {
        assert!(super::super::link::is_shadowsocks("ss://x"));
        assert!(super::super::link::is_shadowsocks("  ss://x"));
        assert!(!super::super::link::is_shadowsocks("socks5://x"));
    }
}
