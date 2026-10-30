// SPDX-License-Identifier: AGPL-3.0-only

//! The transparent ingress: a listening socket that accepts flows the datapath
//! redirected into it.
//!
//! # How a flow arrives
//!
//! The kernel program rewrites the destination of a matching packet to the
//! transparent port and restores the *original* destination on the accepted
//! socket. Two consequences shape this module:
//!
//! * the listener must carry `IP_TRANSPARENT` (`IPV6_TRANSPARENT` for v6), and
//!   `SO_REUSEADDR` / `SO_REUSEPORT` so a reload can bind the same port before the
//!   old generation is dropped;
//! * the accepted socket *is* the client's connection to the original destination,
//!   so its two addresses are the flow's two endpoints: [`TcpStream::peer_addr`] is
//!   the **source** (the client) and [`TcpStream::local_addr`] is the **original
//!   destination**, restored by the kernel because `IP_TRANSPARENT` let the socket
//!   own a non-local address. There is no lookup, no `SO_ORIGINAL_DST` and no guess.
//!
//! Getting those two backwards is not a typo a test would catch by accident: it
//! would proxy every flow back to its own client. The names here are `source` and
//! `destination`, never `peer`/`local`, so the mistake cannot be made by habit.
//!
//! # IPv4 and IPv6 are separate listeners
//!
//! A v6 socket created by hand is `IPV6_V6ONLY` (no dual-stack), and a transparent
//! v4 socket cannot accept a v6 flow, so both families get their own listener on
//! the same port. This mirrors what the kernel program expects: it redirects per
//! family.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::os::fd::AsRawFd;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::{TcpListener, TcpStream};

use crate::error::{IngressError, Reject};

/// What the listener knows about an accepted flow.
#[derive(Debug)]
pub struct Accepted {
    pub stream: TcpStream,
    /// Who opened the flow (`peer_addr` of the accepted socket).
    pub source: SocketAddr,
    /// Where the client wanted to go (`local_addr` of the accepted socket, restored
    /// by the kernel for a transparently accepted flow).
    pub destination: SocketAddr,
}

impl Accepted {
    /// The address facts of this flow, without the stream.
    ///
    /// The routing decision only ever looks at addresses (plus the sniffed name),
    /// so a datagram flow can reach the same decision machinery without pretending
    /// to own a `TcpStream`. Keeping this as a method rather than a free function
    /// means a future fact — a mark, an interface index — is added in one place and
    /// both transports inherit it.
    #[must_use]
    pub const fn facts(&self) -> FlowFacts {
        FlowFacts {
            source: self.source,
            destination: self.destination,
        }
    }
}

/// The address facts that decide a flow's route.
///
/// Deliberately separate from [`Accepted`]: a TCP flow owns a stream and a
/// datagram flow owns a session, but both are routed by exactly these two
/// addresses. Widening `Accepted` with an "optional stream" would let a caller
/// hand a datagram flow a transport it can never use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowFacts {
    /// Who opened the flow.
    pub source: SocketAddr,
    /// Where the client wanted to go.
    pub destination: SocketAddr,
}

/// A bound transparent listener.
///
/// Dropping it closes the sockets. Reload keeps the port bound by binding the new
/// listener before dropping the old one, which is what `SO_REUSEPORT` buys.
#[derive(Debug)]
pub struct TransparentListener {
    v4: TcpListener,
    v6: TcpListener,
    port: u16,
    /// Whether a flow whose original destination *is* the transparent port is refused.
    ///
    /// `global.tproxy-port-protect`, default `true`. It is not decoration: with the check off, a
    /// client that connects to the port directly has its own connection served, which turns the
    /// proxy into an open relay into whatever the box can reach. It exists as a switch only
    /// because a debugging session on a box nobody else can reach sometimes wants to drive the
    /// listener by hand.
    protect: bool,
}

impl TransparentListener {
    /// Binds the transparent port for both address families.
    ///
    /// # Errors
    ///
    /// Returns [`IngressError::Socket`] when a socket cannot be created,
    /// configured or bound — most commonly `EPERM` because the process lacks
    /// `CAP_NET_ADMIN`/`CAP_NET_RAW`, or `EADDRINUSE` because another instance
    /// holds the port without `SO_REUSEPORT`.
    pub fn bind(listen_ip: Ipv4Addr, port: u16) -> Result<Self, IngressError> {
        Self::bind_with_protection(listen_ip, port, true)
    }

    /// Binds the transparent port with the self-connect rule made explicit.
    ///
    /// # Errors
    ///
    /// Same as [`Self::bind`].
    pub fn bind_with_protection(
        listen_ip: Ipv4Addr,
        port: u16,
        protect: bool,
    ) -> Result<Self, IngressError> {
        let v4 = bind_family(Domain::IPV4, IpAddr::V4(listen_ip), port)?;
        // Port 0 means "pick one": the v4 listener chose it, and v6 must reuse it
        // so both families serve the same port.
        let port = v4.local_addr().map_err(IngressError::Socket)?.port();
        let v6 = bind_family(Domain::IPV6, IpAddr::V6(Ipv6Addr::UNSPECIFIED), port)?;
        Ok(Self {
            v4,
            v6,
            port,
            protect,
        })
    }

    /// The port both families are bound to.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// The file descriptor of the IPv4 listener.
    ///
    /// Needed because the datapath hands a redirected flow to the listener through a
    /// `SOCKMAP` (`bpf_sk_assign`), which is keyed by family and holds the *socket*, not the
    /// port. Publishing the fd is what makes `assign_listener` succeed; without it the
    /// datapath returns -1 and the flow is silently not redirected.
    ///
    /// The fd is valid for the listener's lifetime and must not be closed by the caller.
    ///
    /// # Errors
    ///
    /// Returns the OS error from `AsRawFd` (currently infallible, kept for symmetry with the
    /// v6 accessor).
    pub fn raw_fd_v4(&self) -> std::os::fd::RawFd {
        std::os::fd::AsRawFd::as_raw_fd(&self.v4)
    }

    /// The file descriptor of the IPv6 listener.
    #[must_use]
    pub fn raw_fd_v6(&self) -> std::os::fd::RawFd {
        std::os::fd::AsRawFd::as_raw_fd(&self.v6)
    }

    /// Accepts the next flow from either family.
    ///
    /// # Errors
    ///
    /// Returns [`IngressError::Rejected`] when the accepted flow is not a
    /// redirected one (see [`Reject`]), and [`IngressError::Accept`] when the
    /// accept itself failed. A rejection leaves the listener usable; the caller is
    /// expected to drop the connection and keep accepting.
    pub async fn accept(&self) -> Result<Accepted, IngressError> {
        let (stream, source) = tokio::select! {
            result = self.v4.accept() => result.map_err(IngressError::Accept)?,
            result = self.v6.accept() => result.map_err(IngressError::Accept)?,
        };
        // The kernel restored the original destination onto the accepted socket, so
        // it is the *local* address; the peer is the client that opened the flow.
        let destination = stream.local_addr().map_err(IngressError::Socket)?;

        if self.protect && is_self_connect(destination, self.port) {
            return Err(Reject::SelfConnect { destination }.into());
        }

        Ok(Accepted {
            stream,
            source: unmap(source),
            destination: unmap(destination),
        })
    }
}

/// The transparent listener is an [`Ingress`](crate::serve::Ingress).
///
/// The trait exists so the accept loop can be tested without privileges (see
/// `serve.rs`); production uses this implementation, which is the same `accept`
/// call the tests exercise through the trait.
impl crate::serve::Ingress for TransparentListener {
    async fn accept(&self) -> Result<Accepted, IngressError> {
        Self::accept(self).await
    }
}

/// True when the flow's destination is the transparent port itself.
///
/// A redirected flow carries the *client's* destination, which is some service on
/// the machine or the network. A flow whose original destination is the
/// transparent port was not redirected at all — the client connected to the port
/// directly — and must not be served: doing so would make the transparent port a
/// network service and a traffic amplifier into the proxy.
///
/// Only the port is compared, deliberately. The destination address of a
/// redirected flow can legitimately be one of our own addresses (that is what
/// proxying a local service looks like), so an address comparison would reject
/// valid flows.
#[must_use]
pub fn is_self_connect(destination: SocketAddr, transparent_port: u16) -> bool {
    destination.port() == transparent_port
}

/// Binds a plain TCP listener with the same socket options the transparent
/// listener uses.
///
/// The options are the point. `SO_REUSEADDR` alone does not let a second listener
/// bind a port that is still being accepted on; `SO_REUSEPORT` does, and that is
/// what makes a reload able to bind the new socket *before* the old one stops
/// accepting. Exposing this separately means the handover can be tested with an
/// ordinary listener, without `CAP_NET_ADMIN`, using the same options production
/// relies on.
///
/// # Errors
///
/// Returns the OS error from socket creation, option setting or binding.
pub fn bind_shared(address: SocketAddr) -> io::Result<std::net::TcpListener> {
    let domain = if address.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    socket.set_reuse_port(true)?;
    socket.bind(&address.into())?;
    socket.listen(1024)?;
    Ok(socket.into())
}

fn bind_family(domain: Domain, ip: IpAddr, port: u16) -> Result<TcpListener, IngressError> {
    let socket =
        Socket::new(domain, Type::STREAM, Some(Protocol::TCP)).map_err(IngressError::Socket)?;
    socket
        .set_reuse_address(true)
        .map_err(IngressError::Socket)?;
    socket.set_reuse_port(true).map_err(IngressError::Socket)?;
    socket.set_nonblocking(true).map_err(IngressError::Socket)?;
    set_transparent(socket.as_raw_fd(), domain).map_err(IngressError::Socket)?;
    socket
        .bind(&SocketAddr::new(ip, port).into())
        .map_err(IngressError::Socket)?;
    socket.listen(1024).map_err(IngressError::Socket)?;
    let listener: std::net::TcpListener = socket.into();
    TcpListener::from_std(listener).map_err(IngressError::Socket)
}

/// Enables transparent acceptance on one socket.
///
/// `IP_TRANSPARENT` and `IPV6_TRANSPARENT` are the same option number in their
/// respective levels, but a v4 socket rejects the v6 one and vice versa. Only the
/// family's own option is set: a dual-stack trick would fail on a `V6ONLY` socket
/// and tell us nothing.
fn set_transparent(fd: std::os::fd::RawFd, domain: Domain) -> io::Result<()> {
    let (level, option) = if domain == Domain::IPV6 {
        (libc::IPPROTO_IPV6, libc::IPV6_TRANSPARENT)
    } else {
        (libc::IPPROTO_IP, libc::IP_TRANSPARENT)
    };
    let enabled: libc::c_int = 1;
    // SAFETY: `fd` is an open socket owned by the caller for the duration of the
    // call, and `enabled` is a live `c_int` of the exact length passed. A failure
    // is reported, never ignored: without these options nothing can be redirected.
    let result = unsafe {
        libc::setsockopt(
            fd,
            level,
            option,
            std::ptr::from_ref(&enabled).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// The address a v6 listener reports for an IPv4-mapped flow.
///
/// A v4-mapped v6 address (`::ffff:a.b.c.d`) is a v4 destination that arrived on
/// the v6 listener; callers that care about routing should see it as v4.
#[must_use]
pub fn unmap(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(IpAddr::V4(v4), v6.port()),
            None => addr,
        },
        SocketAddr::V4(_) => addr,
    }
}

/// Builds the v6 socket address a transparent flow would carry.
///
/// Used by tests and by the reload path, which needs to reason about both
/// families without binding.
#[must_use]
pub fn v6_addr(port: u16) -> SocketAddr {
    SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(ip: [u8; 4], port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port)
    }

    #[test]
    fn a_flow_to_a_real_destination_is_not_a_self_connect() {
        assert!(!is_self_connect(addr([1, 2, 3, 4], 443), 12_345));
        assert!(!is_self_connect(addr([127, 0, 0, 1], 80), 12_345));
    }

    #[test]
    fn a_flow_to_the_transparent_port_is_rejected() {
        // Someone connected straight to the transparent port: no destination to
        // reach, and serving it would turn the port into a service.
        assert!(is_self_connect(addr([192, 168, 1, 2], 12_345), 12_345));
        // Same address, different port: a legitimate local flow.
        assert!(!is_self_connect(addr([192, 168, 1, 2], 22), 12_345));
    }

    #[test]
    fn ipv4_mapped_destinations_unmap_to_ipv4() {
        let mapped = SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 2, 3, 4]),
            443,
            0,
            0,
        ));
        assert_eq!(unmap(mapped), addr([1, 2, 3, 4], 443));

        let plain_v6 = v6_addr(443);
        assert_eq!(unmap(plain_v6), plain_v6);
    }

    #[test]
    fn a_shared_bind_allows_a_second_listener_on_the_same_port() {
        // The reload handover in one assertion: the new listener binds while the
        // old one is still accepting.
        let first = bind_shared(SocketAddr::from(([127, 0, 0, 1], 0))).expect("binds");
        let port = first.local_addr().expect("addr").port();
        let second = bind_shared(SocketAddr::from(([127, 0, 0, 1], port)))
            .expect("a second listener binds the same port");
        assert_eq!(second.local_addr().expect("addr").port(), port);
    }

    #[test]
    fn binding_reports_a_clear_error_without_privileges() {
        // Runs unprivileged in CI: `IP_TRANSPARENT` needs CAP_NET_ADMIN, so the
        // expected outcome is either success (privileged runner) or EPERM with a
        // message naming the layer. Anything else is a bug in this module.
        match TransparentListener::bind(Ipv4Addr::UNSPECIFIED, 0) {
            Ok(listener) => assert_ne!(listener.port(), 0, "an ephemeral port was assigned"),
            Err(IngressError::Socket(error)) => {
                assert!(
                    matches!(
                        error.raw_os_error(),
                        Some(libc::EPERM) | Some(libc::EACCES) | Some(libc::EADDRINUSE)
                    ),
                    "unexpected bind failure: {error}"
                );
            }
            Err(other) => panic!("unexpected error: {other}"),
        }
    }
}
