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

use crate::error::RelayError;
use crate::inbound::is_self_connect;

/// Which address family a datagram flow uses, and whether the datapath can deliver it.
///
/// Exists so "IPv6 UDP is not proxied on the eBPF path" is a value the daemon reports rather
/// than a sentence in a document: the C's `assign_listener` has one family-independent slot for
/// datagrams (`key = &one_key`), so only the IPv4 socket can receive a redirected datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatagramFamily {
    /// Delivered: `listen_socket_map[1]` holds the wildcard IPv4 socket.
    Ipv4,
    /// **Not** delivered on the eBPF path: there is no slot for a v6 datagram socket.
    Ipv6,
}

impl DatagramFamily {
    /// The family of an address.
    #[must_use]
    pub const fn of(address: SocketAddr) -> Self {
        if address.is_ipv6() {
            Self::Ipv6
        } else {
            Self::Ipv4
        }
    }

    /// True when the datapath can assign a redirected datagram of this family.
    #[must_use]
    pub const fn is_deliverable(self) -> bool {
        matches!(self, Self::Ipv4)
    }
}

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
        Box<dyn std::future::Future<Output = Result<Datagram, RelayError>> + Send + 'a>,
    >;

    /// Sends one reply datagram to `peer`, **from** `source`.
    ///
    /// `source` is the original destination the client sent to. A UDP client validates the
    /// source address of a reply against the destination it wrote to (or its socket is
    /// `connect(2)`-ed, in which case the kernel drops anything else and answers with
    /// `ICMP port unreachable`). Replying from the wildcard listener's own address and the
    /// transparent port instead — which is what `send_to(payload, peer)` on the listener
    /// socket does — makes every UDP client discard the answer. That is the difference
    /// between a working DNS/QUIC relay and one that looks like it silently drops traffic.
    fn send_from<'a>(
        &'a self,
        payload: &'a [u8],
        source: SocketAddr,
        peer: SocketAddr,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = io::Result<usize>> + Send + 'a>>;

    /// The socket fd the datapath may assign a redirected datagram to, when there is one.
    ///
    /// `None` for an ingress that is not backed by a real socket: a test double has no fd to
    /// publish, and reporting a wrong one would put a foreign socket in
    /// `listen_socket_map[1]`.
    fn raw_fd(&self) -> Option<RawFd> {
        None
    }
}

impl DatagramIngress for TransparentDatagramListener {
    fn recv<'a>(
        &'a self,
        buffer: &'a mut [u8],
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Datagram, RelayError>> + Send + 'a>,
    > {
        Box::pin(TransparentDatagramListener::recv(self, buffer))
    }

    fn send_from<'a>(
        &'a self,
        payload: &'a [u8],
        source: SocketAddr,
        peer: SocketAddr,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = io::Result<usize>> + Send + 'a>> {
        // The future is already complete: see `TransparentDatagramListener::try_send_from`
        // for why a UDP reply has no backpressure to await.
        Box::pin(std::future::ready(
            TransparentDatagramListener::try_send_from(self, payload, source, peer),
        ))
    }

    fn raw_fd(&self) -> Option<RawFd> {
        Some(TransparentDatagramListener::raw_fd(self))
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
    /// One transparent socket per original destination, for the reply direction.
    ///
    /// Keyed by the destination a client sent to, because that is the source address its
    /// reply must carry. See [`Self::send_from`].
    ///
    /// # Why this is bounded
    ///
    /// A destination socket holds an fd, and the set of destinations is unbounded: a client
    /// that walks a /16 of QUIC servers, or an attacker that sends to one datagram per
    /// address, would otherwise exhaust the process's fd limit. The cache is therefore a
    /// **bounded LRU** ([`REPLY_SOCKET_CACHE`]), evicting the least recently used destination.
    /// An evicted destination is re-bound on its next reply, which costs one `socket(2)` —
    /// far cheaper than an `EMFILE` that stops every flow.
    sources: std::sync::Mutex<ReplySockets>,
}

/// How many reply sockets one ingress keeps.
///
/// Sized for a DNS or QUIC workload (tens of upstreams) with room for a browsing client
/// fanning out to hundreds of destinations, while staying far below a default 1024 fd limit.
pub const REPLY_SOCKET_CACHE: usize = 512;

/// The bounded reply-socket cache, with LRU order kept explicitly.
///
/// `HashMap` alone has no order, and a timestamp per entry would need a second scan to find
/// the eviction victim; a `VecDeque` of keys is what makes eviction O(1) and the ordering
/// exact. The map is the source of truth for liveness, the deque for recency — an entry is
/// removed from both together, which is the invariant [`ReplySockets::get_or_insert`]
/// maintains.
#[derive(Debug, Default)]
struct ReplySockets {
    sockets: std::collections::HashMap<SocketAddr, UdpSocket>,
    /// Most-recently-used last.
    order: std::collections::VecDeque<SocketAddr>,
}

impl ReplySockets {
    /// Returns the socket for `source`, binding it when absent and evicting when full.
    fn get_or_insert(&mut self, source: SocketAddr) -> io::Result<&UdpSocket> {
        self.get_or_insert_with(source, bind_source)
    }

    /// [`Self::get_or_insert`] with the socket builder injected.
    ///
    /// Split so the eviction bookkeeping — the part that prevents an fd leak — is testable
    /// without `CAP_NET_ADMIN`: `bind_source` sets `IP_TRANSPARENT`, which an unprivileged
    /// test cannot do, but the LRU does not care how a socket was made.
    fn get_or_insert_with(
        &mut self,
        source: SocketAddr,
        bind: impl FnOnce(Domain, SocketAddr) -> io::Result<UdpSocket>,
    ) -> io::Result<&UdpSocket> {
        if self.sockets.contains_key(&source) {
            // Touch: move to the back so it is the last candidate for eviction.
            self.order.retain(|key| *key != source);
            self.order.push_back(source);
        } else {
            if self.order.len() >= REPLY_SOCKET_CACHE {
                // Evict the least recently used. `pop_front` and the map removal are the same
                // entry, so the two containers cannot disagree.
                if let Some(victim) = self.order.pop_front() {
                    self.sockets.remove(&victim);
                }
            }
            let family = if source.is_ipv6() {
                Domain::IPV6
            } else {
                Domain::IPV4
            };
            self.sockets.insert(source, bind(family, source)?);
            self.order.push_back(source);
        }
        self.sockets
            .get(&source)
            .ok_or_else(|| io::Error::other("reply socket vanished after insert"))
    }

    /// How many sockets are cached, for a test that asserts the bound.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.sockets.len()
    }
}

impl TransparentDatagramListener {
    /// Binds the transparent port for both families. A `port` of 0 picks one.
    ///
    /// # Errors
    ///
    /// Returns [`RelayError::Socket`] when a socket cannot be created, configured or
    /// bound — most commonly `EPERM` without `CAP_NET_ADMIN`/`CAP_NET_RAW`.
    pub fn bind(listen_ip: Ipv4Addr, port: u16) -> Result<Self, RelayError> {
        let v4 = bind_family(Domain::IPV4, IpAddr::V4(listen_ip), port)?;
        let port = v4.local_addr().map_err(RelayError::Socket)?.port();
        let v6 = bind_family(Domain::IPV6, IpAddr::V6(Ipv6Addr::UNSPECIFIED), port)?;
        Ok(Self {
            v4,
            v6,
            port,
            sources: std::sync::Mutex::new(ReplySockets::default()),
        })
    }

    /// The port both families are bound to.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// The IPv4 socket's fd, for `listen_socket_map` key `1`.
    ///
    /// # The IPv6 limitation this encodes
    ///
    /// The C's `assign_listener` picks the key by family for TCP (`0` v4, `2` v6) but uses the
    /// single family-independent key `1` for every datagram:
    ///
    /// ```c
    /// const __u32 *key = &one_key;
    /// if (l4proto == IPPROTO_TCP)
    ///     key = skb->protocol == bpf_htons(ETH_P_IPV6) ? &two_key : &zero_key;
    /// ```
    ///
    /// There is therefore **one** datagram slot, and it can hold one socket. A v6 datagram
    /// redirected by the eBPF path is assigned to this v4 socket, which cannot receive it.
    ///
    /// The fix belongs in the datapath (a fourth key for `udp6`, or `bpf_sk_lookup_udp`), not
    /// here: guessing a second slot would silently mismatch the object this crate does not own.
    /// Until then the daemon reports it — see [`DatagramFamily::Ipv6`] and the startup warning
    /// in `daer run` — rather than letting v6 UDP look like a network outage.
    pub fn raw_fd(&self) -> std::os::fd::RawFd {
        self.v4.as_raw_fd()
    }

    /// The IPv6 socket's fd, which the datapath has **no slot** for today.
    ///
    /// Returned so the limitation is visible in one place and a future object that gains a
    /// `udp6` key only has to change `Listeners` and this accessor. Nothing publishes it: an
    /// unused fd in a `SOCKMAP` slot the C never looks up would be a lie about what works.
    pub fn raw_fd_v6(&self) -> std::os::fd::RawFd {
        self.v6.as_raw_fd()
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
    /// Returns [`RelayError::Rejected`] when the datagram was not redirected (see
    /// [`crate::error::Reject::SelfConnect`]) and [`RelayError::Socket`] when the
    /// receive itself failed. A truncated datagram is *not* an error: it is returned
    /// with its truncated length, which is what UDP semantics require.
    pub async fn recv(&self, buffer: &mut [u8]) -> Result<Datagram, RelayError> {
        loop {
            // Readability is awaited on the socket itself, then `recvmsg` runs once.
            // Two `recvmsg` futures cannot both borrow `buffer`, and a single socket at a
            // time is what the kernel would serialise anyway.
            tokio::select! {
                ready = self.v4.readable() => {
                    ready.map_err(RelayError::Socket)?;
                    match recvmsg_once(self.v4.as_raw_fd(), buffer) {
                        Ok(Some(received)) => return self.accept_datagram(received),
                        // Not redirected, or nothing to read: try the other family.
                        Ok(None) => continue,
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                        Err(error) => return Err(RelayError::Socket(error)),
                    }
                }
                ready = self.v6.readable() => {
                    ready.map_err(RelayError::Socket)?;
                    match recvmsg_once(self.v6.as_raw_fd(), buffer) {
                        Ok(Some(received)) => return self.accept_datagram(received),
                        Ok(None) => continue,
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                        Err(error) => return Err(RelayError::Socket(error)),
                    }
                }
            }
        }
    }

    /// Sends one reply datagram to `peer` **from** the original destination `source`.
    ///
    /// # Why this cannot use the listener socket
    ///
    /// The listener is bound to the wildcard address and the transparent port. Sending from
    /// it puts `source_ip = <box address>` and `source_port = <tproxy port>` on the wire, so
    /// the client sees a reply from an address it never sent to. A `connect(2)`-ed client
    /// socket has that packet rejected by its own kernel (`ICMP port unreachable`), and an
    /// unconnected one drops it in the application. Every datagram relay therefore needs a
    /// socket that owns the original destination: `IP_TRANSPARENT` is what allows binding a
    /// non-local address.
    ///
    /// # Why this is not `async`
    ///
    /// A UDP `sendto(2)` on a non-blocking socket either queues the datagram or fails; it
    /// never waits for the peer. Wrapping it in a future would suggest a backpressure that
    /// does not exist, and holding the source-socket lock across a real `.await` would
    /// serialise every reply behind the slowest one.
    ///
    /// # Errors
    ///
    /// Returns the OS error from creating, binding or sending. A reply that cannot be
    /// delivered ends that peer's session, never the relay.
    pub fn try_send_from(
        &self,
        payload: &[u8],
        source: SocketAddr,
        peer: SocketAddr,
    ) -> io::Result<usize> {
        let mut sources = self.sources.lock().unwrap_or_else(|e| e.into_inner());
        sources.get_or_insert(source)?.try_send_to(payload, peer)
    }

    /// Turns a decoded datagram into a [`Datagram`], applying the self-connect rule.
    fn accept_datagram(
        &self,
        (source, destination, len): (SocketAddr, SocketAddr, usize),
    ) -> Result<Datagram, RelayError> {
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
fn bind_family(domain: Domain, ip: IpAddr, port: u16) -> Result<UdpSocket, RelayError> {
    let socket =
        Socket::new(domain, Type::DGRAM, Some(Protocol::UDP)).map_err(RelayError::Socket)?;
    socket.set_reuse_address(true).map_err(RelayError::Socket)?;
    socket.set_reuse_port(true).map_err(RelayError::Socket)?;
    socket.set_nonblocking(true).map_err(RelayError::Socket)?;
    let fd = socket.as_raw_fd();
    set_transparent(fd, domain).map_err(RelayError::Socket)?;
    set_recv_original_destination(fd, domain).map_err(RelayError::Socket)?;
    socket
        .bind(&SocketAddr::new(ip, port).into())
        .map_err(RelayError::Socket)?;
    UdpSocket::from_std(socket.into()).map_err(RelayError::Socket)
}

/// Binds a transparent datagram socket that **owns** `source` as its local address.
///
/// This is the reply half of the relay: the socket's local address becomes the packet's
/// source address, so a client sees the reply coming from the destination it sent to
/// rather than from the transparent port. `IP_TRANSPARENT` is what allows binding an
/// address that is not local to the box.
///
/// # Why `reuse_address` and not `reuse_port`
///
/// Two destinations can share a port (`1.1.1.1:53` and `8.8.8.8:53` are distinct
/// `(address, port)` pairs, so `SO_REUSEADDR` is what makes a second bind of the same
/// *port* on a different address legal). `SO_REUSEPORT` would additionally allow two
/// sockets on the *same* address and port, which is never what the reply path wants.
fn bind_source(domain: Domain, source: SocketAddr) -> io::Result<UdpSocket> {
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    let fd = socket.as_raw_fd();
    set_transparent(fd, domain)?;
    socket.bind(&source.into())?;
    UdpSocket::from_std(socket.into())
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

    #[tokio::test]
    async fn the_reply_socket_cache_evicts_instead_of_growing_without_bound() {
        // The falsifier for an fd leak. The first version of `send_from` kept one socket per
        // original destination in a plain `HashMap` and never removed one, so a client walking
        // a range of destinations would exhaust the process's fd limit and take every flow
        // down with `EMFILE`. The bound is what makes the cache a cache.
        //
        // `bind_source` sets `IP_TRANSPARENT`, which needs `CAP_NET_ADMIN`; the eviction
        // bookkeeping is what this asserts, so the socket builder is a plain loopback bind.
        let plain = |domain: Domain, address: SocketAddr| -> io::Result<UdpSocket> {
            let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
            socket.set_nonblocking(true)?;
            socket.bind(&address.into())?;
            UdpSocket::from_std(socket.into())
        };
        let mut cache = ReplySockets::default();
        for port in 0..(REPLY_SOCKET_CACHE + 8) {
            let source: SocketAddr = format!("127.0.0.1:{}", 20_000 + port)
                .parse()
                .expect("addr");
            cache
                .get_or_insert_with(source, plain)
                .expect("loopback binds");
        }
        assert_eq!(
            cache.len(),
            REPLY_SOCKET_CACHE,
            "the cache must stay at its bound, not grow with the destinations seen"
        );
        assert_eq!(
            cache.order.len(),
            cache.len(),
            "the recency queue and the map must never disagree"
        );

        // A source that is still cached is reused rather than re-bound, and becomes the most
        // recently used, so the next eviction takes a different entry.
        let recent: SocketAddr = format!("127.0.0.1:{}", 20_000 + REPLY_SOCKET_CACHE - 1)
            .parse()
            .expect("addr");
        cache.get_or_insert_with(recent, plain).expect("cached");
        assert_eq!(*cache.order.back().expect("non-empty"), recent);
    }

    #[test]
    fn only_ipv4_datagrams_are_deliverable_on_the_ebpf_path() {
        // The falsifier for "v6 UDP silently does not work". The C's `assign_listener` uses one
        // family-independent key for datagrams, so the map holds the v4 socket only; a v6
        // datagram assigned to it cannot be received. Asserting the split here is what keeps
        // the daemon's warning honest instead of a claim in a document.
        assert!(DatagramFamily::Ipv4.is_deliverable());
        assert!(!DatagramFamily::Ipv6.is_deliverable());
        assert_eq!(
            DatagramFamily::of("192.0.2.1:53".parse().expect("addr")),
            DatagramFamily::Ipv4
        );
        assert_eq!(
            DatagramFamily::of("[2001:db8::1]:53".parse().expect("addr")),
            DatagramFamily::Ipv6
        );
    }

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
            Err(RelayError::Socket(error)) => {
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
