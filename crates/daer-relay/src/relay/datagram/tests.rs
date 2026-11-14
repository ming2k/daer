use super::*;
use crate::testkit::DirectRouter;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::AtomicUsize;
use tokio::net::UdpSocket as TokioUdp;

#[test]
fn options_are_bounded_by_default() {
    let options = RelayOptions::default();
    assert!(
        options.max_sessions > 0,
        "an unbounded table is not a default"
    );
    assert_eq!(options.max_datagram_size, 65_507);
    assert!(
        options.idle_timeout > Duration::ZERO,
        "a silent peer must be reaped"
    );
}

#[test]
fn the_reap_interval_is_a_fraction_of_the_idle_timeout_but_never_below_a_second() {
    assert_eq!(
        reap_interval(Duration::from_secs(120)),
        Duration::from_secs(30)
    );
    assert_eq!(
        reap_interval(Duration::from_secs(2)),
        Duration::from_secs(1)
    );
    assert_eq!(
        reap_interval(Duration::from_millis(10)),
        Duration::from_secs(1)
    );
}

#[test]
fn a_refused_datagram_is_per_datagram_but_a_broken_socket_is_not() {
    // The distinction decides whether one ICMP error kills every peer.
    assert!(is_per_datagram_error(&RelayError::Socket(io::Error::from(
        io::ErrorKind::ConnectionRefused
    ))));
    assert!(is_per_datagram_error(&RelayError::Socket(io::Error::from(
        io::ErrorKind::WouldBlock
    ))));
    assert!(!is_per_datagram_error(&RelayError::Socket(
        io::Error::from(io::ErrorKind::BrokenPipe)
    )));
    assert!(!is_per_datagram_error(&RelayError::Socket(
        io::Error::from(io::ErrorKind::PermissionDenied)
    )));
}

#[test]
fn a_touch_makes_a_peer_young_again() {
    let peer = Peer {
        flow_id: daer_observe::FlowId::new(1),
        datagrams: Arc::new(StubDatagrams),
        last_seen_ms: AtomicU64::new(0),
        opened_at: Instant::now() - Duration::from_secs(3600),
    };
    // One hour of silence, then a datagram: the silence collapses to ~0.
    peer.touch();
    let silence = (peer.opened_at.elapsed().as_millis() as u64)
        .saturating_sub(peer.last_seen_ms.load(Ordering::Relaxed));
    assert!(
        silence < 1_000,
        "touch must clear the silence, got {silence}ms"
    );
}

#[tokio::test]
async fn idle_sessions_are_reaped_and_live_ones_survive() {
    let peers: Mutex<HashMap<SessionKey, Arc<Peer>>> = Mutex::new(HashMap::new());
    let destination: SocketAddr = "198.51.100.7:53".parse().expect("addr");
    let old = SessionKey {
        client: "127.0.0.1:1000".parse().expect("addr"),
        destination,
    };
    let fresh = SessionKey {
        client: "127.0.0.1:2000".parse().expect("addr"),
        destination,
    };
    peers.lock().await.insert(
        old,
        Arc::new(Peer {
            flow_id: daer_observe::FlowId::new(1),
            datagrams: Arc::new(StubDatagrams),
            last_seen_ms: AtomicU64::new(0),
            opened_at: Instant::now() - Duration::from_secs(600),
        }),
    );
    peers.lock().await.insert(
        fresh,
        Arc::new(Peer {
            flow_id: daer_observe::FlowId::new(1),
            datagrams: Arc::new(StubDatagrams),
            last_seen_ms: AtomicU64::new(0),
            opened_at: Instant::now(),
        }),
    );

    let options = RelayOptions::default().with_idle_timeout(Duration::from_secs(120));
    let reaped = reap_idle(&peers, &options).await;
    assert_eq!(reaped, 1, "only the silent session may be reaped");
    let table = peers.lock().await;
    assert!(table.contains_key(&fresh));
    assert!(!table.contains_key(&old));
}

/// A loopback ingress standing in for the transparent listener.
///
/// It speaks the same trait as production, so the relay code under test is the real
/// one; only the "where was this datagram going" source differs, which is the part
/// that needs `CAP_NET_ADMIN`.
#[derive(Debug)]
struct LoopbackIngress {
    socket: TokioUdp,
    destination: SocketAddr,
    /// Every `(source, peer)` pair a reply was sent with, so a test can assert the
    /// source address is the original destination rather than the listener's.
    replies: std::sync::Mutex<Vec<(SocketAddr, SocketAddr)>>,
}

impl LoopbackIngress {
    /// Binds a loopback ingress that reports `destination` for every datagram.
    async fn bind(destination: SocketAddr) -> Arc<Self> {
        let socket = TokioUdp::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind");
        Arc::new(Self {
            socket,
            destination,
            replies: std::sync::Mutex::new(Vec::new()),
        })
    }

    /// The address a client should send to.
    fn address(&self) -> SocketAddr {
        self.socket.local_addr().expect("addr")
    }

    /// The `(source, peer)` pairs replies were sent with.
    fn replies(&self) -> Vec<(SocketAddr, SocketAddr)> {
        self.replies
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

/// An ingress that reports a scripted sequence of destinations.
///
/// The real listener reads the destination from an ancillary message, which needs
/// `CAP_NET_ADMIN` to produce. This double replays the same per-datagram answer from a
/// list, which is what lets a single client port be pointed at two origins in a
/// single-namespace test.
#[derive(Debug)]
struct ScriptedIngress {
    socket: TokioUdp,
    destinations: std::sync::Mutex<std::collections::VecDeque<SocketAddr>>,
}

impl ScriptedIngress {
    /// Binds a loopback ingress that reports `destinations` in order, repeating the
    /// last one once the list is exhausted.
    async fn bind(destinations: Vec<SocketAddr>) -> Arc<Self> {
        let socket = TokioUdp::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind");
        Arc::new(Self {
            socket,
            destinations: std::sync::Mutex::new(destinations.into()),
        })
    }

    fn address(&self) -> SocketAddr {
        self.socket.local_addr().expect("addr")
    }

    fn next_destination(&self) -> SocketAddr {
        let mut queue = self.destinations.lock().unwrap_or_else(|e| e.into_inner());
        if queue.len() > 1 {
            queue.pop_front().expect("non-empty")
        } else {
            *queue.front().expect("at least one destination")
        }
    }
}

impl DatagramIngress for ScriptedIngress {
    fn recv<'a>(
        &'a self,
        buffer: &'a mut [u8],
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<crate::inbound::Datagram, RelayError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            let (len, source) = self
                .socket
                .recv_from(buffer)
                .await
                .map_err(RelayError::Socket)?;
            Ok(crate::inbound::Datagram {
                flow_id: daer_observe::FlowId::new(1),
                source,
                destination: self.next_destination(),
                len,
            })
        })
    }

    fn send_from<'a>(
        &'a self,
        payload: &'a [u8],
        _source: SocketAddr,
        peer: SocketAddr,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = io::Result<usize>> + Send + 'a>> {
        // The scripted ingress cannot bind a transparent source address (that is what
        // `CAP_NET_ADMIN` buys in production), so the reply goes out of the loopback
        // socket. The source assertion lives in the `LoopbackIngress` test.
        Box::pin(async move { self.socket.send_to(payload, peer).await })
    }
}

/// Erases a concrete ingress to the trait the relay takes.
fn as_ingress(ingress: &Arc<LoopbackIngress>) -> Arc<dyn DatagramIngress> {
    Arc::clone(ingress) as Arc<dyn DatagramIngress>
}

impl DatagramIngress for LoopbackIngress {
    fn recv<'a>(
        &'a self,
        buffer: &'a mut [u8],
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<crate::inbound::Datagram, RelayError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            let (len, source) = self
                .socket
                .recv_from(buffer)
                .await
                .map_err(RelayError::Socket)?;
            Ok(crate::inbound::Datagram {
                flow_id: daer_observe::FlowId::new(1),
                source,
                destination: self.destination,
                len,
            })
        })
    }

    fn send_from<'a>(
        &'a self,
        payload: &'a [u8],
        source: SocketAddr,
        peer: SocketAddr,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = io::Result<usize>> + Send + 'a>> {
        self.replies
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((source, peer));
        Box::pin(async move { self.socket.send_to(payload, peer).await })
    }
}

/// A transport that discards everything: enough to prove table behaviour without a
/// network.
struct StubDatagrams;

impl DatagramTransport for StubDatagrams {
    fn send<'a>(
        &'a self,
        payload: &'a [u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<usize, io::Error>> + Send + 'a>>
    {
        Box::pin(async move { Ok(payload.len()) })
    }

    fn recv<'a>(
        &'a self,
        _buffer: &'a mut [u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<usize, io::Error>> + Send + 'a>>
    {
        // Never yields a datagram, so the reply pump parks rather than spins.
        Box::pin(std::future::pending())
    }

    fn max_datagram_size(&self) -> usize {
        65_507
    }
}

#[tokio::test]
async fn one_session_per_peer_and_the_table_is_capped() {
    // Two peers, then a third against a two-session ceiling: the third must be
    // refused rather than evicting a live session.
    let destination: SocketAddr = "1.1.1.1:53".parse().expect("addr");
    let ingress = LoopbackIngress::bind(destination).await;
    let ingress_dyn = as_ingress(&ingress);
    let options = RelayOptions::default()
        .with_max_sessions(2)
        .with_idle_timeout(Duration::from_secs(3600));
    let stats = Arc::new(DatagramStats::default());
    let peers: Arc<Mutex<HashMap<SessionKey, Arc<Peer>>>> = Arc::new(Mutex::new(HashMap::new()));
    let router: Arc<dyn DatagramRouter> = Arc::new(cooperative_router());

    let service = DatagramService {
        ingress: Arc::clone(&ingress_dyn),
        router: Arc::clone(&router),
        options,
        stats: Arc::clone(&stats),
    };

    // Insert two live sessions directly: this test is about the table's ceiling,
    // not about whether a dial to 1.1.1.1 succeeds in a sandbox.
    for port in [1000u16, 2000] {
        let key = SessionKey {
            client: SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
            destination,
        };
        let peer = peer_for(&peers, key, daer_observe::FlowId::new(1), &[], &service)
            .await
            .expect("a direct session opens");
        assert!(Arc::ptr_eq(&peer, &peers.lock().await[&key]));
    }
    assert_eq!(peers.lock().await.len(), 2);
    assert_eq!(stats.snapshot().sessions_opened, 2);

    let third = SessionKey {
        client: SocketAddr::from((Ipv4Addr::LOCALHOST, 3000)),
        destination,
    };
    assert!(
        peer_for(&peers, third, daer_observe::FlowId::new(1), &[], &service)
            .await
            .is_none(),
        "a full table must refuse, not evict"
    );
    assert_eq!(peers.lock().await.len(), 2);
}

#[tokio::test]
async fn an_ipv6_peer_is_tracked_separately_from_an_ipv4_one() {
    // The table is keyed by SocketAddr, so the two families cannot collide.
    let destination: SocketAddr = "1.1.1.1:53".parse().expect("addr");
    let ingress = LoopbackIngress::bind(destination).await;
    let ingress_dyn = as_ingress(&ingress);
    let options = RelayOptions::default().with_idle_timeout(Duration::from_secs(3600));
    let stats = Arc::new(DatagramStats::default());
    let peers: Arc<Mutex<HashMap<SessionKey, Arc<Peer>>>> = Arc::new(Mutex::new(HashMap::new()));
    let router: Arc<dyn DatagramRouter> = Arc::new(cooperative_router());

    let v4 = SocketAddr::from((Ipv4Addr::LOCALHOST, 1234));
    let v6 = SocketAddr::from((Ipv6Addr::LOCALHOST, 1234));
    let service = DatagramService {
        ingress: Arc::clone(&ingress_dyn),
        router: Arc::clone(&router),
        options,
        stats: Arc::clone(&stats),
    };
    for address in [v4, v6] {
        let key = SessionKey {
            client: address,
            destination,
        };
        peer_for(&peers, key, daer_observe::FlowId::new(1), &[], &service)
            .await
            .expect("direct session opens");
    }
    assert_eq!(peers.lock().await.len(), 2);
}

/// A router whose every flow is `direct`.
///
/// This crate owns no routing policy, so the double answers `direct` directly rather
/// than through a configuration. What the tests here assert is the session table, the
/// reply direction and the source address — a routing decision is an input to those.
fn cooperative_router() -> DirectRouter {
    DirectRouter
}

#[tokio::test]
async fn a_relay_forwards_both_directions_through_direct() {
    // The whole path: an ingress socket receives a datagram, routes it, opens a
    // direct session to the original destination, and the reply comes back to the
    // peer that sent it. This is the assertion that the reply direction is wired to
    // the right peer rather than to "whoever spoke last".
    let destination = TokioUdp::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("origin");
    let destination_address = destination.local_addr().expect("addr");
    tokio::spawn(async move {
        let mut buffer = [0u8; 128];
        while let Ok((received, from)) = destination.recv_from(&mut buffer).await {
            let mut reply = b"re:".to_vec();
            reply.extend_from_slice(&buffer[..received]);
            if destination.send_to(&reply, from).await.is_err() {
                return;
            }
        }
    });

    let ingress = LoopbackIngress::bind(destination_address).await;
    let ingress_address = ingress.address();
    let client = TokioUdp::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("client");
    client.connect(ingress_address).await.expect("connect");

    let stats = Arc::new(DatagramStats::default());
    let options = RelayOptions::default().with_idle_timeout(Duration::from_secs(3600));
    let relay = tokio::spawn(serve_datagrams(
        as_ingress(&ingress),
        Arc::new(cooperative_router()),
        options,
        Arc::clone(&stats),
        std::future::pending::<()>(),
    ));

    client.send(b"ping").await.expect("send");
    let mut buffer = [0u8; 128];
    let received = tokio::time::timeout(Duration::from_secs(5), client.recv(&mut buffer))
        .await
        .expect("reply must arrive")
        .expect("recv");
    assert_eq!(&buffer[..received], b"re:ping");

    // The reply must have been sent **from** the original destination. The old code
    // sent it from the listener socket, so the client saw a source address it never
    // wrote to; a `connect(2)`-ed socket like this one drops such a packet, which is
    // why the assertion is on the recorded source and not only on the payload.
    let replies = ingress.replies();
    assert_eq!(replies.len(), 1, "exactly one reply for one request");
    assert_eq!(
        replies[0].0, destination_address,
        "the reply must carry the original destination as its source address"
    );

    relay.abort();
    let snapshot = stats.snapshot();
    assert_eq!(snapshot.to_upstream, 4);
    assert_eq!(snapshot.to_client, 7);
    assert_eq!(snapshot.sessions_opened, 1);
}

#[tokio::test]
async fn one_client_port_talking_to_two_destinations_gets_two_sessions() {
    // Falsifier for keying the session table by the client address alone. An
    // unconnected UDP socket legitimately sends to several servers (a resolver
    // rotating upstreams, STUN plus a media flow). The old table looked the session up
    // by `client` only, so the second destination's datagram rode the first session
    // and was delivered to the wrong server.
    //
    // The topology: one client port, two loopback origins, and an ingress that reports
    // the next destination in a scripted sequence. Both origins must see their own
    // packet, and the relay must report two sessions.
    let first = echo_origin().await;
    let second = echo_origin().await;
    let ingress = ScriptedIngress::bind(vec![first.0, second.0]).await;
    let ingress_address = ingress.address();
    let client = TokioUdp::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("client");

    let stats = Arc::new(DatagramStats::default());
    let relay = tokio::spawn(serve_datagrams(
        Arc::clone(&ingress) as Arc<dyn DatagramIngress>,
        Arc::new(cooperative_router()),
        RelayOptions::default().with_idle_timeout(Duration::from_secs(3600)),
        Arc::clone(&stats),
        std::future::pending::<()>(),
    ));

    let mut buffer = [0u8; 128];
    for (index, payload) in [b"one".as_slice(), b"two".as_slice()]
        .into_iter()
        .enumerate()
    {
        client
            .send_to(payload, ingress_address)
            .await
            .expect("send");
        let received = tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut buffer))
            .await
            .unwrap_or_else(|_| panic!("reply {index} must arrive"))
            .expect("recv");
        let mut expected = b"re:".to_vec();
        expected.extend_from_slice(payload);
        assert_eq!(&buffer[..received.0], expected, "reply {index}");
    }

    relay.abort();
    assert_eq!(
        first.1.load(Ordering::Relaxed),
        1,
        "the first origin saw exactly the first datagram"
    );
    assert_eq!(
        second.1.load(Ordering::Relaxed),
        1,
        "the second origin saw exactly the second datagram; a client-address-keyed \
             table would have sent it to the first origin instead"
    );
    assert_eq!(
        stats.snapshot().sessions_opened,
        2,
        "one session per (client, destination) pair"
    );
}

/// Spawns a UDP origin that echoes `re:<payload>`, returning its address and a shared
/// counter of how many datagrams it received.
async fn echo_origin() -> (SocketAddr, Arc<AtomicUsize>) {
    let socket = TokioUdp::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("origin");
    let address = socket.local_addr().expect("addr");
    let seen = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&seen);
    tokio::spawn(async move {
        let mut buffer = [0u8; 128];
        while let Ok((received, from)) = socket.recv_from(&mut buffer).await {
            counter.fetch_add(1, Ordering::Relaxed);
            let mut reply = b"re:".to_vec();
            reply.extend_from_slice(&buffer[..received]);
            if socket.send_to(&reply, from).await.is_err() {
                return;
            }
        }
    });
    (address, seen)
}
