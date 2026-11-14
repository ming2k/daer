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
    let plain = |domain: Domain, address: SocketAddr| -> io::Result<StdUdpSocket> {
        let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
        socket.bind(&address.into())?;
        Ok(socket.into())
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
fn the_reply_socket_factory_is_the_socket_that_sends() {
    // The namespace factory is the seam that keeps reply sockets in `daer0ns`. A
    // regression that bypassed it would call `bind_source` here, which sets
    // `IP_TRANSPARENT` and fails without `CAP_NET_ADMIN`; a factory that returns a plain
    // loopback socket proves the seam is actually used. The send is a direct std syscall,
    // so it is not subject to Tokio's unprimed readiness state.
    #[derive(Debug)]
    struct LoopbackFactory;
    impl ReplySocketFactory for LoopbackFactory {
        fn bind(&self, _source: SocketAddr) -> io::Result<StdUdpSocket> {
            StdUdpSocket::bind(("127.0.0.1", 0))
        }
    }

    let receiver = StdUdpSocket::bind(("127.0.0.1", 0)).expect("receiver binds");
    receiver
        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .expect("read timeout");
    let receiver_addr = receiver.local_addr().expect("receiver address");
    let factory: Arc<dyn ReplySocketFactory> = Arc::new(LoopbackFactory);
    let mut cache = ReplySockets::default();
    let source: SocketAddr = "127.0.0.1:9".parse().expect("source");
    let socket = cache
        .get_or_insert(source, None, Some(&factory))
        .expect("factory binds");

    socket.send_to(b"reply", receiver_addr).expect("sends");
    let mut payload = [0u8; 5];
    let (received, from) = receiver.recv_from(&mut payload).expect("receives");
    assert_eq!(&payload[..received], b"reply");
    assert_ne!(
        from.port(),
        9,
        "the factory socket, not the requested source"
    );
}

#[test]
fn both_datagram_families_are_deliverable_on_the_ebpf_path() {
    // The falsifier for a v6 datagram being assigned to the v4 socket. The C has one
    // listener slot per family (`1` for UDP4, `3` for UDP6); both must be present, or
    // the daemon would attach a datapath that silently drops one family.
    assert!(DatagramFamily::Ipv4.is_deliverable());
    assert!(DatagramFamily::Ipv6.is_deliverable());
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
    match TransparentDatagramListener::bind(Ipv4Addr::UNSPECIFIED) {
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
