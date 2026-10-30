// SPDX-License-Identifier: AGPL-3.0-only

//! The datagram half of the data path: one relay socket, one session per peer.
//!
//! # Why this is not `splice`
//!
//! TCP's [`crate::relay::splice`] hands two streams to `copy_bidirectional` and is
//! done. Datagrams have no connection to splice: a transparent UDP ingress receives
//! datagrams from unrelated peers on **one** socket, and each peer needs its own
//! outbound session. So this module owns a table instead: the first datagram from a
//! peer creates a session (after the routing decision), later datagrams from that peer
//! ride it, and every reply is written back to the ingress socket addressed to that
//! peer.
//!
//! # The direction that is easy to get wrong
//!
//! A UDP proxy must remember **where a reply goes**. The outbound session knows only
//! "send" and "receive", and the ingress socket is shared by every peer. That is why a
//! [`Peer`] carries its address and why the reply pump writes through the ingress
//! socket to that address instead of answering "the source of the last datagram" —
//! the latter is correct only until two peers are active at once, at which point it
//! silently crosses streams.
//!
//! # Bounded by design
//!
//! An open relay socket is reachable by anyone who can send it a packet, so every
//! table has a ceiling:
//!
//! * [`RelayOptions::max_sessions`] caps concurrent peers.
//! * [`RelayOptions::max_datagram_size`] caps the read buffer.
//! * [`RelayOptions::idle_timeout`] reaps a peer that stops sending, which keeps a
//!   long-lived relay socket from accumulating the whole internet.
//!
//! A datagram that arrives when the table is full is dropped. That is the correct
//! answer for UDP: there is no back-pressure to apply, and blocking the socket would
//! penalise the peers already being served.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use daer_outbound::DatagramTransport;
use tokio::sync::Mutex;

use crate::ingress_udp::DatagramIngress;

use crate::decide::Router;
use crate::error::IngressError;
use crate::inbound::FlowFacts;

/// Limits for one datagram relay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayOptions {
    /// Concurrent peers allowed on one ingress socket.
    pub max_sessions: usize,
    /// Upper bound on a single datagram's payload.
    pub max_datagram_size: usize,
    /// How long a peer may stay silent before its session is reaped.
    pub idle_timeout: Duration,
}

impl Default for RelayOptions {
    fn default() -> Self {
        Self {
            max_sessions: 1024,
            // The IPv4 maximum (65 507 = 65 535 − 20 − 8). A smaller value is a
            // deliberate trade of large-datagram support for a smaller read buffer.
            max_datagram_size: 65_507,
            idle_timeout: Duration::from_secs(120),
        }
    }
}

impl RelayOptions {
    /// Options with a different session ceiling.
    #[must_use]
    pub const fn with_max_sessions(mut self, max_sessions: usize) -> Self {
        self.max_sessions = max_sessions;
        self
    }

    /// Options with a different idle timeout.
    #[must_use]
    pub const fn with_idle_timeout(mut self, idle_timeout: Duration) -> Self {
        self.idle_timeout = idle_timeout;
        self
    }
}

/// What a datagram relay did.
///
/// Shared with the caller rather than returned, because the relay runs until its
/// ingress is closed and its counters must be readable while it is still live.
#[derive(Debug, Default)]
pub struct DatagramStats {
    to_upstream: AtomicU64,
    to_client: AtomicU64,
    dropped_full: AtomicU64,
    dropped_failed: AtomicU64,
    sessions_opened: AtomicU64,
}

impl DatagramStats {
    /// Payload bytes read from clients.
    #[must_use]
    pub fn to_upstream(&self) -> u64 {
        self.to_upstream.load(Ordering::Relaxed)
    }

    /// Payload bytes written back to clients.
    #[must_use]
    pub fn to_client(&self) -> u64 {
        self.to_client.load(Ordering::Relaxed)
    }

    /// Sessions successfully opened.
    #[must_use]
    pub fn sessions_opened(&self) -> u64 {
        self.sessions_opened.load(Ordering::Relaxed)
    }

    /// A consistent-enough point-in-time snapshot.
    #[must_use]
    pub fn snapshot(&self) -> DatagramSnapshot {
        DatagramSnapshot {
            to_upstream: self.to_upstream.load(Ordering::Relaxed),
            to_client: self.to_client.load(Ordering::Relaxed),
            dropped_full: self.dropped_full.load(Ordering::Relaxed),
            dropped_failed: self.dropped_failed.load(Ordering::Relaxed),
            sessions_opened: self.sessions_opened.load(Ordering::Relaxed),
        }
    }
}

/// A point-in-time view of a relay's counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DatagramSnapshot {
    /// Payload bytes read from clients.
    pub to_upstream: u64,
    /// Payload bytes written back to clients.
    pub to_client: u64,
    /// Datagrams dropped because the session table was full.
    pub dropped_full: u64,
    /// Datagrams dropped because opening their session failed.
    pub dropped_failed: u64,
    /// Sessions successfully opened.
    pub sessions_opened: u64,
}

/// Everything the datagram half of the service needs, bundled.
///
/// Named rather than passed as a tuple: the four pieces are a unit (a socket with a
/// router and its limits, sharing one counter set), and a signature that spells them out
/// inline makes every call site look like it is passing unrelated arguments.
#[derive(Debug, Clone)]
pub struct DatagramService {
    /// The transparent ingress socket.
    pub ingress: Arc<dyn DatagramIngress>,
    /// The routing generation this relay serves.
    pub router: Arc<Router>,
    /// Its limits.
    pub options: RelayOptions,
    /// Its counters, shared with whoever reports them.
    pub stats: Arc<DatagramStats>,
}

/// One peer's established outbound session.
struct Peer {
    /// The outbound leg, shared with the reply pump that was spawned for it.
    datagrams: Arc<dyn DatagramTransport>,
    /// Last time this peer was heard from, for idle reaping. The address itself is
    /// the table key, so storing it again would give two sources of truth for where a
    /// reply goes.
    last_seen_ms: AtomicU64,
    /// When the session opened, so `last_seen_ms` can be a plain millisecond delta
    /// instead of an `Instant` that cannot live in an atomic.
    opened_at: Instant,
}

impl Peer {
    /// Records that this peer sent something just now.
    fn touch(&self) {
        self.last_seen_ms.store(
            self.opened_at.elapsed().as_millis() as u64,
            Ordering::Relaxed,
        );
    }
}

/// Serves one transparent UDP ingress socket until `shutdown` resolves.
///
/// `original_destination` is the destination the kernel redirected this socket from;
/// it is the same for every peer on the socket, which is why it is a parameter rather
/// than something read per datagram.
///
/// Live sessions are **not** dropped on shutdown: the reply pumps are independent
/// tasks, so a reload can replace the ingress socket without silencing replies already
/// in flight. Their handles are returned in the stats and the caller owns reaping.
///
/// # Errors
///
/// Returns [`IngressError::Socket`] only for an ingress failure that is not a
/// per-datagram condition. One refused peer is counted in
/// [`DatagramStats::snapshot`]'s `dropped_failed`, because a refused flow must not stop
/// the socket serving the others.
pub async fn serve_datagrams(
    ingress: Arc<dyn DatagramIngress>,
    router: Arc<Router>,
    options: RelayOptions,
    stats: Arc<DatagramStats>,
    shutdown: impl std::future::Future<Output = ()>,
) -> Result<(), IngressError> {
    let peers: Arc<Mutex<HashMap<SocketAddr, Arc<Peer>>>> = Arc::new(Mutex::new(HashMap::new()));
    let mut buffer = vec![0u8; options.max_datagram_size];
    // A reap tick that does not depend on traffic: a silent relay would otherwise
    // never shrink its table, which is exactly the case where it grows.
    let reap_every = reap_interval(options.idle_timeout);
    let mut reaper = tokio::time::interval(reap_every);
    reaper.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tokio::pin!(shutdown);

    let service = DatagramService {
        ingress: Arc::clone(&ingress),
        router: Arc::clone(&router),
        options,
        stats: Arc::clone(&stats),
    };

    loop {
        let received = tokio::select! {
            () = &mut shutdown => {
                // Counted before the event, not inside it: a tracing field borrow held
                // across an await makes the whole relay future non-`Send`.
                let live = peers.lock().await.len();
                tracing::info!(
                    sessions = live,
                    "datagram ingress stopped; live sessions keep replying"
                );
                return Ok(());
            }
            _ = reaper.tick() => {
                let reaped = reap_idle(&peers, &options).await;
                if reaped > 0 {
                    tracing::debug!(reaped, "reaped idle datagram sessions");
                }
                continue;
            }
            received = ingress.recv(&mut buffer) => received,
        };

        let datagram = match received {
            Ok(datagram) => datagram,
            // A refused datagram is not a socket failure: a previous send may have
            // provoked an ICMP error that surfaces on the next receive, and killing
            // the relay for that would take down every peer on the socket.
            Err(error) if is_per_datagram_error(&error) => {
                tracing::trace!(%error, "ingress datagram failed; continuing");
                continue;
            }
            Err(IngressError::Rejected(reject)) => {
                stats.dropped_failed.fetch_add(1, Ordering::Relaxed);
                tracing::debug!(%reject, "dropped a datagram that was not redirected");
                continue;
            }
            Err(error) => return Err(error),
        };
        let peer_address = datagram.source;
        let original_destination = datagram.destination;
        let received = datagram.len;

        let peer = match peer_for(
            &peers,
            peer_address,
            original_destination,
            &buffer[..received],
            &service,
        )
        .await
        {
            Some(peer) => peer,
            None => {
                // Opening failed or the table was full: distinguish the two, because
                // one is a capacity signal and the other a policy or transport one.
                if peers.lock().await.len() >= service.options.max_sessions {
                    service.stats.dropped_full.fetch_add(1, Ordering::Relaxed);
                } else {
                    service.stats.dropped_failed.fetch_add(1, Ordering::Relaxed);
                }
                continue;
            }
        };

        // Liveness is "sent recently", so it is refreshed on every datagram, not only
        // when the session opened.
        peer.touch();

        let payload = buffer[..received].to_vec();
        service
            .stats
            .to_upstream
            .fetch_add(payload.len() as u64, Ordering::Relaxed);

        // Send on a task, not inline: a tunnel's `send` can await (a record write),
        // and blocking the receive loop on it would stall every other peer.
        let datagrams = Arc::clone(&peer.datagrams);
        tokio::spawn(async move {
            if let Err(error) = datagrams.send(&payload).await {
                tracing::debug!(%error, "datagram forward failed");
            }
        });
    }
}

/// Returns this peer's session, creating it if this is the first datagram from it.
///
/// The insert happens under the table lock so two concurrent first datagrams from the
/// same peer cannot race into two sessions — which would deliver every reply twice and
/// duplicate the routing decision's side effects.
async fn peer_for(
    peers: &Arc<Mutex<HashMap<SocketAddr, Arc<Peer>>>>,
    address: SocketAddr,
    original_destination: SocketAddr,
    initial_payload: &[u8],
    service: &DatagramService,
) -> Option<Arc<Peer>> {
    // The lookup is a short critical section; the *opening* is not.
    //
    // The original version held this lock across `open_datagram(...).await` and
    // `connect(...).await`, so the first datagram from any peer blocked every other
    // operation on the table — including the reply pump of a session that was already
    // running. A DNS-tunnel workload (many peers, one table) turned that into observed
    // starvation: the session was recorded as opened and its `send` was never scheduled.
    // The lock now covers only what has to be atomic: the two lookups, and the insert that
    // makes a second concurrent first datagram join the session instead of racing it.
    {
        let table = peers.lock().await;
        if let Some(peer) = table.get(&address) {
            return Some(Arc::clone(peer));
        }
        if table.len() >= service.options.max_sessions {
            return None;
        }
    }

    let sniffed_domain = if !initial_payload.is_empty() {
        match daer_sniff::sniff(initial_payload) {
            daer_sniff::Sniffed::Domain { name, .. } => Some(name),
            _ => None,
        }
    } else {
        None
    };

    let facts = FlowFacts {
        source: address,
        destination: original_destination,
    };
    let verdict = service
        .router
        .verdict_for_datagram(facts, sniffed_domain.as_deref());
    let connector = match service.router.open_datagram(facts, &verdict).await {
        Ok(connector) => connector,
        Err(error) => {
            tracing::debug!(%error, %address, "datagram flow refused");
            return None;
        }
    };

    let recorder = Arc::new(std::sync::Mutex::new(daer_outbound::Recorder::start(16)));
    let established = match connector
        .connect(&original_destination.to_string(), &recorder)
        .await
    {
        Ok(established) => established,
        Err(error) => {
            tracing::debug!(%error, %address, "datagram session failed");
            return None;
        }
    };

    let datagrams: Arc<dyn DatagramTransport> = Arc::from(established.datagrams);
    let peer = Arc::new(Peer {
        datagrams: Arc::clone(&datagrams),
        last_seen_ms: AtomicU64::new(0),
        opened_at: Instant::now(),
    });

    // Re-check under the lock: two concurrent first datagrams from the same peer must end
    // with **one** session, or every reply is delivered twice. The loser drops the session it
    // opened, which costs one extra dial and keeps the invariant.
    {
        let mut table = peers.lock().await;
        if let Some(existing) = table.get(&address) {
            return Some(Arc::clone(existing));
        }
        if table.len() >= service.options.max_sessions {
            return None;
        }
        table.insert(address, Arc::clone(&peer));
    }
    service
        .stats
        .sessions_opened
        .fetch_add(1, Ordering::Relaxed);

    // Replies are pumped by their own task so a silent tunnel cannot stall the
    // ingress loop. It ends when the session's receive side does.
    let ingress = Arc::clone(&service.ingress);
    let stats = Arc::clone(&service.stats);
    let buffer_size = service.options.max_datagram_size;
    tokio::spawn(async move {
        let mut buffer = vec![0u8; buffer_size];
        loop {
            let received = match datagrams.recv(&mut buffer).await {
                Ok(received) => received,
                Err(error) => {
                    tracing::debug!(%error, %address, "datagram session closed");
                    return;
                }
            };
            stats
                .to_client
                .fetch_add(received as u64, Ordering::Relaxed);
            if let Err(error) = ingress.send_to(&buffer[..received], address).await {
                tracing::debug!(%error, %address, "datagram reply failed");
                return;
            }
        }
    });

    Some(peer)
}

/// Removes sessions that have been silent longer than `idle_timeout`.
///
/// Runs on its own task rather than on every datagram: a reap per packet would pay a
/// table walk for the busiest socket on the box, and a relay with no traffic still
/// needs the table to shrink.
async fn reap_idle(peers: &Mutex<HashMap<SocketAddr, Arc<Peer>>>, options: &RelayOptions) -> usize {
    let idle_ms = options.idle_timeout.as_millis() as u64;
    let mut table = peers.lock().await;
    let before = table.len();
    table.retain(|_, peer| {
        let silence = (peer.opened_at.elapsed().as_millis() as u64)
            .saturating_sub(peer.last_seen_ms.load(Ordering::Relaxed));
        silence < idle_ms
    });
    before - table.len()
}

/// How often to reap: often enough to reclaim within a session's lifetime, slow enough
/// to be free on a busy socket.
fn reap_interval(idle_timeout: Duration) -> Duration {
    (idle_timeout / 4).max(Duration::from_secs(1))
}

/// True for ingress errors that concern one datagram rather than the socket.
fn is_per_datagram_error(error: &IngressError) -> bool {
    match error {
        IngressError::Socket(error) => matches!(
            error.kind(),
            io::ErrorKind::ConnectionRefused
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::WouldBlock
                | io::ErrorKind::UnexpectedEof
        ),
        IngressError::Rejected(_) => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
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
        assert!(is_per_datagram_error(&IngressError::Socket(
            io::Error::from(io::ErrorKind::ConnectionRefused)
        )));
        assert!(is_per_datagram_error(&IngressError::Socket(
            io::Error::from(io::ErrorKind::WouldBlock)
        )));
        assert!(!is_per_datagram_error(&IngressError::Socket(
            io::Error::from(io::ErrorKind::BrokenPipe)
        )));
        assert!(!is_per_datagram_error(&IngressError::Socket(
            io::Error::from(io::ErrorKind::PermissionDenied)
        )));
    }

    #[test]
    fn a_touch_makes_a_peer_young_again() {
        let peer = Peer {
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
        let peers: Mutex<HashMap<SocketAddr, Arc<Peer>>> = Mutex::new(HashMap::new());
        let old: SocketAddr = "127.0.0.1:1000".parse().expect("addr");
        let fresh: SocketAddr = "127.0.0.1:2000".parse().expect("addr");
        peers.lock().await.insert(
            old,
            Arc::new(Peer {
                datagrams: Arc::new(StubDatagrams),
                last_seen_ms: AtomicU64::new(0),
                opened_at: Instant::now() - Duration::from_secs(600),
            }),
        );
        peers.lock().await.insert(
            fresh,
            Arc::new(Peer {
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
            })
        }

        /// The address a client should send to.
        fn address(&self) -> SocketAddr {
            self.socket.local_addr().expect("addr")
        }
    }

    /// Erases a concrete ingress to the trait the relay takes.
    fn as_ingress(ingress: &Arc<LoopbackIngress>) -> Arc<dyn crate::ingress_udp::DatagramIngress> {
        Arc::clone(ingress) as Arc<dyn crate::ingress_udp::DatagramIngress>
    }

    impl crate::ingress_udp::DatagramIngress for LoopbackIngress {
        fn recv<'a>(
            &'a self,
            buffer: &'a mut [u8],
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<crate::ingress_udp::Datagram, IngressError>>
                    + Send
                    + 'a,
            >,
        > {
            Box::pin(async move {
                let (len, source) = self
                    .socket
                    .recv_from(buffer)
                    .await
                    .map_err(IngressError::Socket)?;
                Ok(crate::ingress_udp::Datagram {
                    source,
                    destination: self.destination,
                    len,
                })
            })
        }

        fn send_to<'a>(
            &'a self,
            payload: &'a [u8],
            peer: SocketAddr,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = io::Result<usize>> + Send + 'a>>
        {
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
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<usize, io::Error>> + Send + 'a>,
        > {
            Box::pin(async move { Ok(payload.len()) })
        }

        fn recv<'a>(
            &'a self,
            _buffer: &'a mut [u8],
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<usize, io::Error>> + Send + 'a>,
        > {
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
        let peers: Arc<Mutex<HashMap<SocketAddr, Arc<Peer>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let router = Arc::new(cooperative_router());

        let service = DatagramService {
            ingress: Arc::clone(&ingress_dyn),
            router: Arc::clone(&router),
            options,
            stats: Arc::clone(&stats),
        };

        // Insert two live sessions directly: this test is about the table's ceiling,
        // not about whether a dial to 1.1.1.1 succeeds in a sandbox.
        for port in [1000u16, 2000] {
            let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
            let peer = peer_for(&peers, address, destination, &[], &service)
                .await
                .expect("a direct session opens");
            assert!(Arc::ptr_eq(&peer, &peers.lock().await[&address]));
        }
        assert_eq!(peers.lock().await.len(), 2);
        assert_eq!(stats.snapshot().sessions_opened, 2);

        let third = SocketAddr::from((Ipv4Addr::LOCALHOST, 3000));
        assert!(
            peer_for(&peers, third, destination, &[], &service,)
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
        let peers: Arc<Mutex<HashMap<SocketAddr, Arc<Peer>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let router = Arc::new(cooperative_router());

        let v4 = SocketAddr::from((Ipv4Addr::LOCALHOST, 1234));
        let v6 = SocketAddr::from((Ipv6Addr::LOCALHOST, 1234));
        let service = DatagramService {
            ingress: Arc::clone(&ingress_dyn),
            router: Arc::clone(&router),
            options,
            stats: Arc::clone(&stats),
        };
        for address in [v4, v6] {
            peer_for(&peers, address, destination, &[], &service)
                .await
                .expect("direct session opens");
        }
        assert_eq!(peers.lock().await.len(), 2);
    }

    /// A router whose fallback is `direct` and whose program has no rules.
    ///
    /// Built from a real configuration rather than by constructing `Router` by hand, so
    /// the test exercises the same path a daemon takes.
    fn cooperative_router() -> Router {
        let config = daer_config::toml_config::load_str(
            "schema = 1\n\n[routing]\nrules = []\nfallback = \"direct\"\n",
        )
        .expect("config loads");
        Router::new(
            &config,
            crate::GenerationId::new(7),
            &crate::RouterOptions::default(),
        )
        .expect("router builds")
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

        relay.abort();
        let snapshot = stats.snapshot();
        assert_eq!(snapshot.to_upstream, 4);
        assert_eq!(snapshot.to_client, 7);
        assert_eq!(snapshot.sessions_opened, 1);
    }
}
