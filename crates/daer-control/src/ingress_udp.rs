// SPDX-License-Identifier: AGPL-3.0-only

//! The transparent UDP ingress: one socket, one original destination per datagram.
//!
//! # Why this cannot reuse the TCP trick
//!
//! A transparent TCP listener gets the original destination for free: the kernel
//! restores it onto the accepted socket, so `local_addr()` *is* the destination
//! (see [`crate::inbound`]). UDP has no accept, and its socket keeps the wildcard
//! local address it was bound to, so `local_addr()` says nothing about where any
//! particular datagram was going.
//!
//! The kernel offers the answer as per-datagram control data instead: with
//! `IP_RECVORIGDSTADDR` (`IPV6_RECVORIGDSTADDR` for v6) enabled, every `recvmsg`
//! carries an `IP_ORIGDSTADDR` (`IPV6_ORIGDSTADDR`) ancillary message holding the
//! destination that was redirected. That is what this module reads.
//!
//! # Two properties worth stating
//!
//! * **The destination is per datagram, not per socket.** A relay socket bound to a
//!   wildcard port with `IP_TRANSPARENT` receives datagrams for many destinations at
//!   once, and they may differ. Assuming one destination per socket is the classic
//!   way to send a client's traffic to the wrong place.
//! * **A datagram without the control message is refused, never guessed.** If the
//!   kernel did not redirect it, it arrived at the port directly — serving it would
//!   turn the transparent port into an open relay.

use std::io;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{AsRawFd, RawFd};

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;

use crate::error::IngressError;
use crate::inbound::is_self_connect;

/// One received datagram: who sent it, where it was going, and its payload length.
///
/// The payload is left in the caller's buffer; this type is the addressing answer, which
/// is the part the data path has to get right.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Datagram {
    /// The client that sent it.
    pub source: SocketAddr,
    /// The destination the kernel redirected, from the ancillary message.
    pub destination: SocketAddr,
    /// Payload length, excluding any control data.
    pub len: usize,
}

/// A datagram ingress the relay can serve.
///
/// The relay depends on this rather than on [`TransparentDatagramListener`] so its
/// session table can be tested without `CAP_NET_ADMIN`. Production has exactly one
/// implementation, and a plain (non-transparent) socket is not one of them: an ingress
/// that cannot report where a datagram was going cannot route it.
pub trait DatagramIngress: Send + Sync + std::fmt::Debug {
    /// Receives one datagram into `buffer`.
    fn recv<'a>(
        &'a self,
        buffer: &'a mut [u8],
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Datagram, IngressError>> + Send + 'a>,
    >;

    /// Sends one reply datagram to `peer`.
    fn send_to<'a>(
        &'a self,
        payload: &'a [u8],
        peer: SocketAddr,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = io::Result<usize>> + Send + 'a>>;
}

impl DatagramIngress for TransparentDatagramListener {
    fn recv<'a>(
        &'a self,
        buffer: &'a mut [u8],
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Datagram, IngressError>> + Send + 'a>,
    > {
        Box::pin(TransparentDatagramListener::recv(self, buffer))
    }

    fn send_to<'a>(
        &'a self,
        payload: &'a [u8],
        peer: SocketAddr,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = io::Result<usize>> + Send + 'a>> {
        Box::pin(TransparentDatagramListener::send_to(self, payload, peer))
    }
}

/// A bound transparent UDP ingress.
///
/// Dropping it closes the sockets. Like the TCP listener, both address families get
/// their own socket on the same port, because a transparent v4 socket cannot serve a v6
/// flow.
#[derive(Debug)]
pub struct TransparentDatagramListener {
    v4: UdpSocket,
    v6: UdpSocket,
    port: u16,
}

impl TransparentDatagramListener {
    /// Binds the transparent port for both families. A `port` of 0 picks one.
    ///
    /// # Errors
    ///
    /// Returns [`IngressError::Socket`] when a socket cannot be created, configured or
    /// bound — most commonly `EPERM` without `CAP_NET_ADMIN`/`CAP_NET_RAW`.
    pub fn bind(listen_ip: Ipv4Addr, port: u16) -> Result<Self, IngressError> {
        let v4 = bind_family(Domain::IPV4, IpAddr::V4(listen_ip), port)?;
        let port = v4.local_addr().map_err(IngressError::Socket)?.port();
        let v6 = bind_family(Domain::IPV6, IpAddr::V6(Ipv6Addr::UNSPECIFIED), port)?;
        Ok(Self { v4, v6, port })
    }

    /// The port both families are bound to.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// Receives one datagram into `buffer`, reporting its source and original
    /// destination.
    ///
    /// `buffer` must be large enough for the payload; a datagram that does not fit is
    /// truncated by the kernel, so the caller should size it from the relay's
    /// `max_datagram_size`.
    ///
    /// # Errors
    ///
    /// Returns [`IngressError::Rejected`] when the datagram was not redirected (see
    /// [`crate::error::Reject::SelfConnect`]) and [`IngressError::Socket`] when the
    /// receive itself failed. A truncated datagram is *not* an error: it is returned
    /// with its truncated length, which is what UDP semantics require.
    pub async fn recv(&self, buffer: &mut [u8]) -> Result<Datagram, IngressError> {
        loop {
            // Readability is awaited on the socket itself, then `recvmsg` runs once.
            // Two `recvmsg` futures cannot both borrow `buffer`, and a single socket at a
            // time is what the kernel would serialise anyway.
            tokio::select! {
                ready = self.v4.readable() => {
                    ready.map_err(IngressError::Socket)?;
                    match recvmsg_once(self.v4.as_raw_fd(), buffer) {
                        Ok(Some(received)) => return self.accept_datagram(received),
                        // Not redirected, or nothing to read: try the other family.
                        Ok(None) => continue,
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                        Err(error) => return Err(IngressError::Socket(error)),
                    }
                }
                ready = self.v6.readable() => {
                    ready.map_err(IngressError::Socket)?;
                    match recvmsg_once(self.v6.as_raw_fd(), buffer) {
                        Ok(Some(received)) => return self.accept_datagram(received),
                        Ok(None) => continue,
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                        Err(error) => return Err(IngressError::Socket(error)),
                    }
                }
            }
        }
    }

    /// Sends one reply datagram back to `peer`.
    ///
    /// The family is chosen from the peer's address rather than from the socket that
    /// received the datagram, because the two listeners are separate sockets and a v4
    /// socket cannot send to a v6 peer.
    ///
    /// # Errors
    ///
    /// Returns the OS error from the send; a reply that cannot be delivered ends that
    /// peer's session, never the relay.
    pub async fn send_to(&self, payload: &[u8], peer: SocketAddr) -> io::Result<usize> {
        let socket = if peer.is_ipv6() { &self.v6 } else { &self.v4 };
        socket.send_to(payload, peer).await
    }

    /// Turns a decoded datagram into a [`Datagram`], applying the self-connect rule.
    fn accept_datagram(
        &self,
        (source, destination, len): (SocketAddr, SocketAddr, usize),
    ) -> Result<Datagram, IngressError> {
        let destination = unmap(destination);
        if is_self_connect(destination, self.port) {
            return Err(crate::error::Reject::SelfConnect { destination }.into());
        }
        Ok(Datagram {
            source: unmap(source),
            destination,
            len,
        })
    }
}

/// What `recvmsg` produced: the endpoints and payload length, when redirected.
type Received = (SocketAddr, SocketAddr, usize);

/// Receives one datagram and decodes its original-destination control message.
///
/// Returns `Ok(None)` when the datagram carried no original-destination message, which
/// means the kernel did not redirect it.
fn recvmsg_once(fd: RawFd, buffer: &mut [u8]) -> io::Result<Option<Received>> {
    // SAFETY: `sockaddr_storage` is a plain C struct of integers and byte arrays; an
    // all-zero value is a valid (unspecified) address, and `recvmsg` overwrites it.
    let mut source_storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
    let mut control = vec![0u8; control_buffer_len()];

    let mut iov = libc::iovec {
        iov_base: buffer.as_mut_ptr().cast(),
        iov_len: buffer.len(),
    };
    // SAFETY: `msghdr` is a plain C struct; every pointer field is assigned below, and
    // the zeroed value is never read before they are.
    let mut header: libc::msghdr = unsafe { mem::zeroed() };
    header.msg_name = std::ptr::from_mut(&mut source_storage).cast();
    header.msg_namelen = mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    header.msg_iov = std::ptr::from_mut(&mut iov);
    header.msg_iovlen = 1;
    header.msg_control = control.as_mut_ptr().cast();
    header.msg_controllen = control.len() as _;

    // SAFETY: `fd` is a live socket owned by the listener; every pointer in `header`
    // refers to a local that outlives the call, and `control` is `control_buffer_len()`
    // bytes, which covers the largest ancillary message this family can produce.
    let received = unsafe { libc::recvmsg(fd, &mut header, libc::MSG_DONTWAIT) };
    if received < 0 {
        return Err(io::Error::last_os_error());
    }

    let source = socket_addr_from(&source_storage).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "recvmsg returned an address this family cannot describe",
        )
    })?;

    // SAFETY: `header.msg_control` describes the live `control` buffer for the length the
    // kernel reported in `msg_controllen`.
    let destination = unsafe { original_destination(&header) };
    Ok(destination.map(|destination| (source, destination, received as usize)))
}

/// Decodes the `IP_ORIGDSTADDR`/`IPV6_ORIGDSTADDR` ancillary message, if present.
///
/// # Safety
///
/// `header` must describe a control buffer that is live and at least
/// `header.msg_controllen` bytes long, with each message inside it valid.
unsafe fn original_destination(header: &libc::msghdr) -> Option<SocketAddr> {
    // SAFETY: `header` describes a live control buffer for `msg_controllen` bytes, which
    // is the precondition `CMSG_FIRSTHDR` requires (documented on the caller).
    let mut current = unsafe { libc::CMSG_FIRSTHDR(header) };
    while !current.is_null() {
        // SAFETY: `CMSG_FIRSTHDR`/`CMSG_NXTHDR` only return pointers to messages inside
        // the same control buffer, and the caller guarantees that buffer is live.
        let (level, kind, data) = unsafe {
            (
                (*current).cmsg_level,
                (*current).cmsg_type,
                libc::CMSG_DATA(current),
            )
        };
        let is_original_destination = (level == libc::IPPROTO_IP && kind == libc::IP_ORIGDSTADDR)
            || (level == libc::IPPROTO_IPV6 && kind == libc::IPV6_ORIGDSTADDR);
        if is_original_destination {
            // SAFETY: the kernel reported the family's `sockaddr` as this message's
            // payload, and the buffer was sized to hold a `sockaddr_storage`.
            let storage: libc::sockaddr_storage = unsafe { std::ptr::read_unaligned(data.cast()) };
            return socket_addr_from(&storage);
        }
        // SAFETY: `current` is a message inside the caller's live buffer.
        current = unsafe { libc::CMSG_NXTHDR(header, current) };
    }
    None
}

/// Room for the largest original-destination message either family can produce.
fn control_buffer_len() -> usize {
    let size = mem::size_of::<libc::sockaddr_storage>();
    // SAFETY: `CMSG_SPACE` is a pure arithmetic macro over the length.
    unsafe { libc::CMSG_SPACE(size as u32) as usize }
}

/// Reads a `sockaddr_storage` into a `SocketAddr`.
fn socket_addr_from(storage: &libc::sockaddr_storage) -> Option<SocketAddr> {
    match storage.ss_family as libc::c_int {
        libc::AF_INET => {
            // SAFETY: the family says this is a `sockaddr_in`.
            let addr: libc::sockaddr_in =
                unsafe { std::ptr::read_unaligned(std::ptr::from_ref(storage).cast()) };
            let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
            Some(SocketAddr::from((ip, u16::from_be(addr.sin_port))))
        }
        libc::AF_INET6 => {
            // SAFETY: the family says this is a `sockaddr_in6`.
            let addr: libc::sockaddr_in6 =
                unsafe { std::ptr::read_unaligned(std::ptr::from_ref(storage).cast()) };
            let ip = Ipv6Addr::from(addr.sin6_addr.s6_addr);
            Some(SocketAddr::from((ip, u16::from_be(addr.sin6_port))))
        }
        _ => None,
    }
}

/// Binds one family's transparent datagram socket with original-destination reporting.
fn bind_family(domain: Domain, ip: IpAddr, port: u16) -> Result<UdpSocket, IngressError> {
    let socket =
        Socket::new(domain, Type::DGRAM, Some(Protocol::UDP)).map_err(IngressError::Socket)?;
    socket
        .set_reuse_address(true)
        .map_err(IngressError::Socket)?;
    socket.set_reuse_port(true).map_err(IngressError::Socket)?;
    socket.set_nonblocking(true).map_err(IngressError::Socket)?;
    let fd = socket.as_raw_fd();
    set_transparent(fd, domain).map_err(IngressError::Socket)?;
    set_recv_original_destination(fd, domain).map_err(IngressError::Socket)?;
    socket
        .bind(&SocketAddr::new(ip, port).into())
        .map_err(IngressError::Socket)?;
    UdpSocket::from_std(socket.into()).map_err(IngressError::Socket)
}

/// Enables `IP_TRANSPARENT` (`IPV6_TRANSPARENT`) so the socket may own a redirected
/// destination.
fn set_transparent(fd: RawFd, domain: Domain) -> io::Result<()> {
    let (level, option) = if domain == Domain::IPV6 {
        (libc::IPPROTO_IPV6, libc::IPV6_TRANSPARENT)
    } else {
        (libc::IPPROTO_IP, libc::IP_TRANSPARENT)
    };
    set_int_option(fd, level, option, 1)
}

/// Enables per-datagram original-destination reporting.
///
/// Without this the relay cannot know where a datagram was going, and guessing (from the
/// socket's own address) would send a client's traffic somewhere it never asked for.
fn set_recv_original_destination(fd: RawFd, domain: Domain) -> io::Result<()> {
    let (level, option) = if domain == Domain::IPV6 {
        (libc::IPPROTO_IPV6, libc::IPV6_RECVORIGDSTADDR)
    } else {
        (libc::IPPROTO_IP, libc::IP_RECVORIGDSTADDR)
    };
    set_int_option(fd, level, option, 1)
}

fn set_int_option(
    fd: RawFd,
    level: libc::c_int,
    option: libc::c_int,
    value: libc::c_int,
) -> io::Result<()> {
    // SAFETY: `fd` is an open socket owned by the caller for the duration of the call,
    // and `value` is a live `c_int` of the exact length passed.
    let result = unsafe {
        libc::setsockopt(
            fd,
            level,
            option,
            std::ptr::from_ref(&value).cast(),
            mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Strips an IPv4-mapped IPv6 address back to IPv4, so a v6 socket and a v4 socket name
/// the same peer identically.
fn unmap(address: SocketAddr) -> SocketAddr {
    match address {
        SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
            Some(v4) => SocketAddr::from((v4, v6.port())),
            None => address,
        },
        SocketAddr::V4(_) => address,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_control_buffer_covers_the_largest_address() {
        // A `sockaddr_in6` is 28 bytes; the buffer must hold `cmsghdr` plus that.
        assert!(
            control_buffer_len()
                >= mem::size_of::<libc::cmsghdr>() + mem::size_of::<libc::sockaddr_in6>()
        );
    }

    #[test]
    fn addresses_round_trip_through_storage() {
        let v4: SocketAddr = "192.0.2.9:51820".parse().expect("addr");
        // SAFETY: `sockaddr_storage` accepts any zeroed value.
        let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
        let raw = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: v4.port().to_be(),
            sin_addr: libc::in_addr {
                s_addr: match v4.ip() {
                    IpAddr::V4(ip) => u32::from(ip).to_be(),
                    IpAddr::V6(_) => unreachable!(),
                },
            },
            sin_zero: [0; 8],
        };
        // SAFETY: writing a `sockaddr_in` into a `sockaddr_storage` (larger) is in bounds.
        unsafe { std::ptr::write(std::ptr::from_mut(&mut storage).cast(), raw) };
        assert_eq!(socket_addr_from(&storage), Some(v4));
    }

    #[test]
    fn an_ipv6_address_round_trips_through_storage() {
        let v6: SocketAddr = "[2001:db8::1]:443".parse().expect("addr");
        // SAFETY: `sockaddr_storage` accepts any zeroed value.
        let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
        let raw = libc::sockaddr_in6 {
            sin6_family: libc::AF_INET6 as libc::sa_family_t,
            sin6_port: v6.port().to_be(),
            sin6_flowinfo: 0,
            sin6_addr: libc::in6_addr {
                s6_addr: match v6.ip() {
                    IpAddr::V6(ip) => ip.octets(),
                    IpAddr::V4(_) => unreachable!(),
                },
            },
            sin6_scope_id: 0,
        };
        // SAFETY: writing a `sockaddr_in6` into a `sockaddr_storage` is in bounds.
        unsafe { std::ptr::write(std::ptr::from_mut(&mut storage).cast(), raw) };
        assert_eq!(socket_addr_from(&storage), Some(v6));
    }

    /// Builds a control buffer holding one `IP_ORIGDSTADDR` message for `destination`.
    ///
    /// This is how the decode path is proven without `CAP_NET_ADMIN`: the kernel is not
    /// involved, the layout it produces is reproduced exactly (`cmsghdr` + `sockaddr_in`),
    /// and the parser is asked for the address back.
    fn control_with_v4_destination(destination: SocketAddr) -> Vec<u8> {
        let payload = mem::size_of::<libc::sockaddr_in>();
        // SAFETY: `CMSG_SPACE` is pure arithmetic over its argument.
        let space = unsafe { libc::CMSG_SPACE(payload as u32) as usize };
        let mut buffer = vec![0u8; space];
        // SAFETY: `msghdr` is a plain C struct; every pointer field is assigned below, and
        // the zeroed value is never read before they are.
        let mut header: libc::msghdr = unsafe { mem::zeroed() };
        header.msg_control = buffer.as_mut_ptr().cast();
        header.msg_controllen = buffer.len() as _;
        // SAFETY: the header describes `buffer`, which is `CMSG_SPACE(payload)` long.
        unsafe {
            let message = libc::CMSG_FIRSTHDR(&header);
            assert!(!message.is_null());
            (*message).cmsg_level = libc::IPPROTO_IP;
            (*message).cmsg_type = libc::IP_ORIGDSTADDR;
            (*message).cmsg_len = libc::CMSG_LEN(payload as u32) as _;
            let raw = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: destination.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: match destination.ip() {
                        IpAddr::V4(ip) => u32::from(ip).to_be(),
                        IpAddr::V6(_) => unreachable!(),
                    },
                },
                sin_zero: [0; 8],
            };
            std::ptr::write(libc::CMSG_DATA(message).cast(), raw);
        }
        buffer
    }

    /// Runs the decoder over a control buffer, as `recvmsg` would leave it.
    fn decoded(control: &mut [u8]) -> Option<SocketAddr> {
        // SAFETY: `msghdr` is a plain C struct; every pointer field is assigned below, and
        // the zeroed value is never read before they are.
        let mut header: libc::msghdr = unsafe { mem::zeroed() };
        header.msg_control = control.as_mut_ptr().cast();
        header.msg_controllen = control.len() as _;
        // SAFETY: `header` describes `control`, which is live for this call.
        unsafe { original_destination(&header) }
    }

    #[test]
    fn an_ipv4_original_destination_message_is_decoded() {
        let destination: SocketAddr = "198.51.100.4:53".parse().expect("addr");
        let mut control = control_with_v4_destination(destination);
        assert_eq!(decoded(&mut control), Some(destination));
    }

    #[test]
    fn a_control_buffer_without_the_option_yields_nothing() {
        // `IP_RECVORIGDSTADDR` is what makes the kernel attach the message; without it a
        // datagram reaches the port directly and must not be served.
        let mut empty = vec![0u8; 64];
        assert_eq!(decoded(&mut empty), None);
    }

    #[test]
    fn an_unknown_family_is_refused_rather_than_guessed() {
        // SAFETY: `sockaddr_storage` accepts any zeroed value.
        let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
        storage.ss_family = libc::AF_UNIX as libc::sa_family_t;
        assert_eq!(socket_addr_from(&storage), None);
    }

    #[test]
    fn a_mapped_v4_peer_names_the_same_peer_on_both_families() {
        let mapped: SocketAddr = "[::ffff:192.0.2.9]:1234".parse().expect("addr");
        assert_eq!(
            unmap(mapped),
            "192.0.2.9:1234".parse::<SocketAddr>().expect("addr")
        );
    }

    #[test]
    fn binding_reports_a_clear_error_without_privileges() {
        // Unprivileged CI: `IP_TRANSPARENT` needs CAP_NET_ADMIN. Accept either a bound
        // socket (privileged runner) or EPERM naming the layer; anything else is a bug.
        match TransparentDatagramListener::bind(Ipv4Addr::UNSPECIFIED, 0) {
            Ok(listener) => assert_ne!(listener.port(), 0, "an ephemeral port was assigned"),
            Err(IngressError::Socket(error)) => {
                assert!(
                    error.raw_os_error() == Some(libc::EPERM)
                        || error.raw_os_error() == Some(libc::EACCES),
                    "unexpected binding failure: {error}"
                );
            }
            Err(other) => panic!("unexpected error: {other}"),
        }
    }
}
