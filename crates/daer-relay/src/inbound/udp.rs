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
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket as StdUdpSocket};
use std::os::fd::{AsRawFd, RawFd};
use std::sync::Arc;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;

use crate::error::RelayError;

/// Which address family a datagram flow uses.
///
/// The datapath has one listener slot per family (`1` for UDP4, `3` for UDP6), so both are
/// deliverable. The type stays distinct because the listener and reply socket are family
/// specific even when the relay above them is not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatagramFamily {
    /// `listen_socket_map[1]` holds the wildcard IPv4 socket.
    Ipv4,
    /// `listen_socket_map[3]` holds the wildcard IPv6 socket.
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
        matches!(self, Self::Ipv4 | Self::Ipv6)
    }
}

/// One received datagram: who sent it, where it was going, and its payload length.
///
/// The payload is left in the caller's buffer; this type is the addressing answer, which
/// is the part the data path has to get right.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Datagram {
    /// The run-local correlation ID for the datagram's first session observation.
    pub flow_id: daer_observe::FlowId,
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

    /// The IPv4 socket fd the datapath may assign a redirected datagram to, when there is one.
    ///
    /// `None` for an ingress that is not backed by a real socket: a test double has no fd to
    /// publish, and reporting a wrong one would put a foreign socket in
    /// `listen_socket_map[1]`.
    fn raw_fd(&self) -> Option<RawFd> {
        None
    }

    /// The IPv6 socket fd the datapath may assign a redirected datagram to, when there is one.
    ///
    /// The v6 socket is separate from the v4 one because a transparent v4 socket cannot
    /// receive a v6 flow. `None` follows the same rule as [`Self::raw_fd`].
    fn raw_fd_v6(&self) -> Option<RawFd> {
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

    fn raw_fd_v6(&self) -> Option<RawFd> {
        Some(TransparentDatagramListener::raw_fd_v6(self))
    }
}

/// A bound transparent UDP ingress.
///
/// Where reply sockets are created.
///
/// The relay must not know that daer's ingress lives in a private network namespace. The
/// control plane supplies this seam so a reply socket can be born in the same namespace as
/// the listener that owns the original destination; the default implementation creates it
/// in the caller's namespace for the host-only tests.
pub trait ReplySocketFactory: std::fmt::Debug + Send + Sync {
    /// Binds a transparent reply socket that owns `source`.
    ///
    /// The socket is nonblocking, but it is a `std` socket: the reply path calls
    /// `send_to` directly, so Tokio's readiness state cannot turn the first send into a
    /// spurious `WouldBlock`.
    fn bind(&self, source: SocketAddr) -> io::Result<StdUdpSocket>;
}

/// Dropping it closes the sockets. Like the TCP listener, both address families get
/// their own socket on the same port, because a transparent v4 socket cannot serve a v6
/// flow.
#[derive(Debug)]
pub struct TransparentDatagramListener {
    v4: UdpSocket,
    v6: UdpSocket,
    port: u16,
    /// The daemon's socket mark, applied to the listeners and every reply socket.
    ///
    /// A reply socket that owns an original destination must be excluded from the
    /// datapath's own-egress capture. Without the mark, the reply is seen as a new flow and
    /// redirected again, which is a loop even though every individual `sendto` succeeds.
    socket_mark: Option<u32>,
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
    /// The namespace the reply sockets must be created in, when the listener itself lives in
    /// a private ingress namespace. `None` means the caller's namespace (host tests).
    reply_factory: Option<Arc<dyn ReplySocketFactory>>,
    /// The process-wide ID allocator, shared with the daemon and the TCP listener.
    ids: Arc<daer_observe::Ids>,
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
    sockets: std::collections::HashMap<SocketAddr, StdUdpSocket>,
    /// Most-recently-used last.
    order: std::collections::VecDeque<SocketAddr>,
}

impl ReplySockets {
    /// Returns the socket for `source`, binding it when absent and evicting when full.
    fn get_or_insert(
        &mut self,
        source: SocketAddr,
        socket_mark: Option<u32>,
        factory: Option<&Arc<dyn ReplySocketFactory>>,
    ) -> io::Result<&StdUdpSocket> {
        self.get_or_insert_with(source, |domain, source| match factory {
            Some(factory) => factory.bind(source),
            None => bind_source(domain, source, socket_mark),
        })
    }

    /// [`Self::get_or_insert`] with the socket builder injected.
    ///
    /// Split so the eviction bookkeeping — the part that prevents an fd leak — is testable
    /// without `CAP_NET_ADMIN`: `bind_source` sets `IP_TRANSPARENT`, which an unprivileged
    /// test cannot do, but the LRU does not care how a socket was made.
    fn get_or_insert_with(
        &mut self,
        source: SocketAddr,
        bind: impl FnOnce(Domain, SocketAddr) -> io::Result<StdUdpSocket>,
    ) -> io::Result<&StdUdpSocket> {
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
    /// Binds the transparent port for both families ephemerally.
    ///
    /// # Errors
    ///
    /// Returns [`RelayError::Socket`] when a socket cannot be created, configured or
    /// bound — most commonly `EPERM` without `CAP_NET_ADMIN`/`CAP_NET_RAW`.
    pub fn bind(listen_ip: Ipv4Addr) -> Result<Self, RelayError> {
        Self::bind_with_options(listen_ip, None)
    }

    /// Binds the transparent datagram port ephemerally with the daemon's socket mark.
    ///
    /// The mark is applied to the wildcard listeners and to every reply socket bound by
    /// [`Self::try_send_from`]. It is not decoration: the datapath treats its own marked
    /// egress as bypass, and an unmarked reply socket would send a reply that the datapath
    /// then tries to proxy again.
    ///
    /// # Errors
    ///
    /// Same as [`Self::bind`], plus `SO_MARK`'s `EPERM` without `CAP_NET_ADMIN`.
    pub fn bind_with_options(
        listen_ip: Ipv4Addr,
        socket_mark: Option<u32>,
    ) -> Result<Self, RelayError> {
        let v4 = bind_family(Domain::IPV4, IpAddr::V4(listen_ip), 0, socket_mark)?;
        let port = v4.local_addr().map_err(RelayError::Socket)?.port();
        let v6 = bind_family(
            Domain::IPV6,
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            port,
            socket_mark,
        )?;
        Ok(Self {
            v4,
            v6,
            port,
            socket_mark,
            sources: std::sync::Mutex::new(ReplySockets::default()),
            reply_factory: None,
            ids: Arc::new(daer_observe::Ids::new()),
        })
    }

    /// Shares the daemon's ID allocator, so TCP and UDP flows live in one ID namespace.
    #[must_use]
    pub fn with_ids(mut self, ids: Arc<daer_observe::Ids>) -> Self {
        self.ids = ids;
        self
    }

    /// Creates reply sockets in the ingress namespace instead of the caller's.
    ///
    /// The UDP outbound leg lives in the host namespace, but the reply must leave from the
    /// original destination and cross the same namespace boundary as a TCP listener reply.
    /// Keeping this as a constructor seam lets `daer-relay` stay independent of
    /// `daer-control` while the daemon supplies the namespace.
    #[must_use]
    pub fn with_reply_factory(mut self, factory: Arc<dyn ReplySocketFactory>) -> Self {
        self.reply_factory = Some(factory);
        self
    }

    /// The port both families are bound to.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// The IPv4 socket's fd, for `listen_socket_map` key `1`.
    pub fn raw_fd(&self) -> std::os::fd::RawFd {
        self.v4.as_raw_fd()
    }

    /// The IPv6 socket's fd, for `listen_socket_map` key `3`.
    ///
    /// It is a separate socket, not a dual-stack v4 socket: a transparent v4 socket cannot
    /// receive a v6 flow, and `bpf_sk_assign` must be handed a socket in the flow's family.
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
    /// Returns [`RelayError::Socket`] when the receive itself failed. A truncated datagram
    /// is *not* an error: it is returned with its truncated length, which is what UDP semantics
    /// require.
    pub async fn recv(&self, buffer: &mut [u8]) -> Result<Datagram, RelayError> {
        loop {
            // Readability is awaited on the socket itself, then `recvmsg` runs once.
            // Two `recvmsg` futures cannot both borrow `buffer`, and a single socket at a
            // time is what the kernel would serialise anyway.
            tokio::select! {
                ready = self.v4.readable() => {
                    ready.map_err(RelayError::Socket)?;
                    // `try_io` clears the readiness flag when the syscall reports
                    // `WouldBlock`. Calling `recvmsg` directly after `readable()` and then
                    // looping on `WouldBlock` leaves the flag set and turns a cancelled
                    // relay into a 100% CPU spin on `recvmsg(EAGAIN)`.
                    match self
                        .v4
                        .try_io(tokio::io::Interest::READABLE, || {
                            recvmsg_once(self.v4.as_raw_fd(), buffer)
                        })
                    {
                        Ok(Some(received)) => return self.accept_datagram(received),
                        // Not redirected, or nothing to read: try the other family.
                        Ok(None) => continue,
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                        Err(error) => return Err(RelayError::Socket(error)),
                    }
                }
                ready = self.v6.readable() => {
                    ready.map_err(RelayError::Socket)?;
                    match self
                        .v6
                        .try_io(tokio::io::Interest::READABLE, || {
                            recvmsg_once(self.v6.as_raw_fd(), buffer)
                        })
                    {
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
        let socket =
            sources.get_or_insert(source, self.socket_mark, self.reply_factory.as_ref())?;
        // A std nonblocking `send_to` executes the syscall; the only `WouldBlock` left is a
        // genuinely transient one (for example the first packet resolving the veth neighbour).
        // Retry a few times without occupying a runtime worker for long.
        for attempt in 0..5 {
            match socket.send_to(payload, peer) {
                Ok(sent) => return Ok(sent),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock && attempt < 4 => {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::from(io::ErrorKind::WouldBlock))
    }

    /// Turns a decoded datagram into a [`Datagram`].
    fn accept_datagram(
        &self,
        (source, destination, len): (SocketAddr, SocketAddr, usize),
    ) -> Result<Datagram, RelayError> {
        let destination = unmap(destination);
        Ok(Datagram {
            flow_id: self.ids.flow(),
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
fn bind_family(
    domain: Domain,
    ip: IpAddr,
    port: u16,
    socket_mark: Option<u32>,
) -> Result<UdpSocket, RelayError> {
    let socket =
        Socket::new(domain, Type::DGRAM, Some(Protocol::UDP)).map_err(RelayError::Socket)?;
    socket.set_reuse_address(true).map_err(RelayError::Socket)?;
    // No SO_REUSEPORT: a redirected datagram is assigned to this exact socket by
    // `bpf_sk_assign`, and reuseport selection can pick a different socket from the
    // assigned one. For the same reason the v6 wildcard is v6-only, otherwise it would
    // collide with the v4 wildcard without reuseport.
    if domain == Domain::IPV6 {
        socket.set_only_v6(true).map_err(RelayError::Socket)?;
    }
    socket.set_nonblocking(true).map_err(RelayError::Socket)?;
    if let Some(mark) = socket_mark {
        #[cfg(target_os = "linux")]
        socket.set_mark(mark).map_err(RelayError::Socket)?;
        #[cfg(not(target_os = "linux"))]
        {
            let _ = mark;
            return Err(RelayError::Socket(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "SO_MARK is only supported on Linux",
            )));
        }
    }
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
/// Binds a transparent reply socket for `source` in the caller's current namespace.
///
/// Public so a [`ReplySocketFactory`] implementation can create the socket on a thread that
/// has entered the private ingress namespace, then return it to the relay.
///
/// # Errors
///
/// Returns the socket creation, `IP_TRANSPARENT`, address-in-use, or binding error.
pub fn bind_reply_socket(source: SocketAddr, socket_mark: Option<u32>) -> io::Result<StdUdpSocket> {
    let domain = if source.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    bind_source(domain, source, socket_mark)
}

fn bind_source(
    domain: Domain,
    source: SocketAddr,
    socket_mark: Option<u32>,
) -> io::Result<StdUdpSocket> {
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    if let Some(mark) = socket_mark {
        #[cfg(target_os = "linux")]
        socket.set_mark(mark)?;
        #[cfg(not(target_os = "linux"))]
        {
            let _ = mark;
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "SO_MARK is only supported on Linux",
            ));
        }
    }
    let fd = socket.as_raw_fd();
    set_transparent(fd, domain)?;
    socket.bind(&source.into())?;
    // This is a std nonblocking socket, not a Tokio socket: the reply path calls the syscall
    // directly, so a first send cannot be lost to an unprimed readiness state. It also avoids
    // blocking a runtime worker while the route/neighbour is resolved.
    Ok(socket.into())
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
mod tests;
