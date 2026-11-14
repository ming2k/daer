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

use netune::{DatagramConnector, DatagramTransport};
use netune_trace::TraceCollector;
use tokio::sync::Mutex;

use crate::error::{DialFailure, RelayError};
use crate::inbound::FlowFacts;
use crate::inbound::udp::DatagramIngress;

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
#[derive(Clone)]
pub struct DatagramService {
    /// The transparent ingress socket.
    pub ingress: Arc<dyn DatagramIngress>,
    /// The routing generations this relay serves, re-read per session.
    pub router: Arc<dyn DatagramRouter>,
    /// Its limits.
    pub options: RelayOptions,
    /// Its counters, shared with whoever reports them.
    pub stats: Arc<DatagramStats>,
}

impl std::fmt::Debug for DatagramService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DatagramService")
            .field("ingress", &self.ingress)
            .field("options", &self.options)
            .finish_non_exhaustive()
    }
}

/// The boxed future a [`DatagramRouter`] returns when opening an outbound leg.
///
/// A named alias rather than the spelled-out `Pin<Box<dyn Future...>>`: the same type
/// appears in the trait, in two implementations, and in the relay, and clippy is right that
/// repeating it makes the signatures unreadable.
pub type OpenDatagram<'a> = std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<DatagramLeg, DialFailure>> + Send + 'a>,
>;

/// Everything the relay needs to carry one datagram flow: where to dial, and through what.
///
/// The two come back together because they are answers to **one** routing decision. Asking
/// the decider twice (`dial_target(...)` and then `open_datagram(...)`) let the two answers
/// disagree — with a reload in between they can be evaluated against different generations,
/// and the flow is then dialed to a target the rule that opened the leg never chose.
#[derive(Clone)]
pub struct DatagramLeg {
    /// The authority to dial, which is the domain when one is known and the literal
    /// address otherwise.
    pub target: String,
    /// The outbound session the leg opens.
    pub connector: Arc<dyn DatagramConnector>,
}

impl std::fmt::Debug for DatagramLeg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DatagramLeg")
            .field("target", &self.target)
            .finish_non_exhaustive()
    }
}

/// The routing decision a datagram relay needs, one session at a time.
///
/// # Why this is a trait and not a concrete router
///
/// TCP re-reads the generation per flow (`RouterForGeneration` in `daemon.rs`), and the
/// datagram half used to capture one router at startup. A reload then changed nothing for
/// UDP: new datagram flows kept being routed by the rules the process booted with, silently
/// and indefinitely. A trait is what lets the relay ask for the *current* generation per
/// session while a test can still hand it a fixed one.
///
/// # Why nothing here names a verdict or a router type
///
/// This crate owns the accept, the relay and the session table; it does not own routing
/// policy. A `Verdict` parameter would drag the control plane's rule vocabulary into the
/// stable data path, and every new selection concept would then be a change here. The only
/// things the relay genuinely needs are the flow facts, the first payload, and a connector.
///
/// Name acquisition is deliberately not here. Fake-IP, DNS snooping and payload sniffing
/// are one policy, and that policy is evaluated once in `daer-control` for both TCP and
/// UDP. Handing the relay a `domain: Option<&str>` made the transport participate in the
/// decision and duplicated the TCP path.
pub trait DatagramRouter: Send + Sync + std::fmt::Debug {
    /// Resolves the flow and opens its outbound leg from the first datagram payload.
    fn open_datagram<'a>(&'a self, facts: FlowFacts, initial_payload: &'a [u8])
    -> OpenDatagram<'a>;
}

/// One peer's established outbound session, identified by both endpoints.
///
/// # Why the key is a pair and not just the client address
///
/// A UDP socket is not a connection. One client socket (one `ip:port`) legitimately sends to
/// many destinations at once — an unconnected resolver rotating upstreams, STUN plus the
/// media flow of the same game, a QUIC client racing two servers. Keying a session by the
/// client address alone makes the *first* destination win: every later datagram from that
/// port is written into the session opened for the first one, so the client's traffic goes
/// to a server it never addressed. The five-tuple is what identifies a UDP flow, and the
/// pair `(client, original destination)` is the part the relay can observe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct SessionKey {
    /// The client that sent the datagram.
    client: SocketAddr,
    /// The destination the kernel redirected it from.
    destination: SocketAddr,
}

/// One peer's established outbound session.
struct Peer {
    /// The session correlation ID, taken from the first datagram that opened it.
    flow_id: daer_observe::FlowId,
    /// The outbound leg, shared with the reply pump that was spawned for it.
    datagrams: Arc<dyn DatagramTransport>,
    /// Last time this peer was heard from, for idle reaping.
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
/// Returns [`RelayError::Socket`] only for an ingress failure that is not a
/// per-datagram condition. One refused peer is counted in
/// [`DatagramStats::snapshot`]'s `dropped_failed`, because a refused flow must not stop
/// the socket serving the others.
pub async fn serve_datagrams(
    ingress: Arc<dyn DatagramIngress>,
    router: Arc<dyn DatagramRouter>,
    options: RelayOptions,
    stats: Arc<DatagramStats>,
    shutdown: impl std::future::Future<Output = ()>,
) -> Result<(), RelayError> {
    let peers: Arc<Mutex<HashMap<SessionKey, Arc<Peer>>>> = Arc::new(Mutex::new(HashMap::new()));
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
                daer_observe::info!(daer_observe::EventCode::DatagramIngressStopped,
                    sessions = live,
                    "datagram ingress stopped; live sessions keep replying"
                );
                return Ok(());
            }
            _ = reaper.tick() => {
                let reaped = reap_idle(&peers, &options).await;
                if reaped > 0 {
                    daer_observe::debug!(daer_observe::EventCode::DatagramReaped,reaped, "reaped idle datagram sessions");
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
                daer_observe::trace!(daer_observe::EventCode::DatagramIngressFailed,%error, "ingress datagram failed; continuing");
                continue;
            }
            Err(RelayError::Rejected(reject)) => {
                stats.dropped_failed.fetch_add(1, Ordering::Relaxed);
                daer_observe::debug!(daer_observe::EventCode::DatagramRejected,%reject, "dropped a datagram that was not redirected");
                continue;
            }
            Err(error) => return Err(error),
        };
        let peer_address = datagram.source;
        let original_destination = datagram.destination;
        let received = datagram.len;
        let key = SessionKey {
            client: peer_address,
            destination: original_destination,
        };

        let peer =
            match peer_for(&peers, key, datagram.flow_id, &buffer[..received], &service).await {
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
        let flow_id = peer.flow_id;
        tokio::spawn(async move {
            if let Err(error) = datagrams.send(&payload).await {
                daer_observe::warn!(
                    daer_observe::EventCode::DatagramForwardFailed,
                    flow_id = %flow_id,
                    %error,
                    "datagram forward failed"
                );
            }
        });
    }
}

/// Returns this flow's session, creating it if this is the first datagram of it.
///
/// The insert happens under the table lock so two concurrent first datagrams of the same
/// flow cannot race into two sessions — which would deliver every reply twice and
/// duplicate the routing decision's side effects.
async fn peer_for(
    peers: &Arc<Mutex<HashMap<SessionKey, Arc<Peer>>>>,
    key: SessionKey,
    flow_id: daer_observe::FlowId,
    initial_payload: &[u8],
    service: &DatagramService,
) -> Option<Arc<Peer>> {
    let address = key.client;
    let original_destination = key.destination;
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
        if let Some(peer) = table.get(&key) {
            return Some(Arc::clone(peer));
        }
        if table.len() >= service.options.max_sessions {
            return None;
        }
    }

    let facts = FlowFacts {
        flow_id,
        source: address,
        destination: original_destination,
    };
    // One call, one answer: name acquisition, the routing decision, the target and the
    // connector all come from the same generation and the same call. The relay never
    // learns whether the name came from Fake-IP, the DNS snooper or payload inspection.
    let leg = match service.router.open_datagram(facts, initial_payload).await {
        Ok(leg) => leg,
        Err(error) => {
            daer_observe::warn!(
                daer_observe::EventCode::DatagramFlowRefused,
                flow_id = %flow_id,
                %error,
                %address,
                "datagram flow refused"
            );
            return None;
        }
    };

    let recorder = TraceCollector::disabled();
    let established = match leg.connector.connect(&leg.target, &recorder).await {
        Ok(established) => established,
        Err(error) => {
            daer_observe::warn!(
                daer_observe::EventCode::DatagramSessionFailed,
                flow_id = %flow_id,
                %error,
                %address,
                "datagram session failed"
            );
            return None;
        }
    };

    let datagrams: Arc<dyn DatagramTransport> = Arc::from(established.datagrams);
    let peer = Arc::new(Peer {
        flow_id,
        datagrams: Arc::clone(&datagrams),
        last_seen_ms: AtomicU64::new(0),
        opened_at: Instant::now(),
    });

    // Re-check under the lock: two concurrent first datagrams of the same flow must end
    // with **one** session, or every reply is delivered twice. The loser drops the session it
    // opened, which costs one extra dial and keeps the invariant.
    {
        let mut table = peers.lock().await;
        if let Some(existing) = table.get(&key) {
            return Some(Arc::clone(existing));
        }
        if table.len() >= service.options.max_sessions {
            return None;
        }
        table.insert(key, Arc::clone(&peer));
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
                    daer_observe::debug!(
                        daer_observe::EventCode::DatagramSessionClosed,
                        flow_id = %flow_id,
                        %error,
                        %address,
                        "datagram session closed"
                    );
                    return;
                }
            };
            stats
                .to_client
                .fetch_add(received as u64, Ordering::Relaxed);
            // The reply leaves **from the original destination**, not from the listener:
            // see `DatagramIngress::send_from`. Sending from the wildcard socket makes
            // every client discard the answer.
            if let Err(error) = ingress
                .send_from(&buffer[..received], original_destination, address)
                .await
            {
                daer_observe::warn!(
                    daer_observe::EventCode::DatagramReplyFailed,
                    flow_id = %flow_id,
                    %error,
                    %address,
                    "datagram reply failed"
                );
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
async fn reap_idle(peers: &Mutex<HashMap<SessionKey, Arc<Peer>>>, options: &RelayOptions) -> usize {
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
fn is_per_datagram_error(error: &RelayError) -> bool {
    match error {
        RelayError::Socket(error) => matches!(
            error.kind(),
            io::ErrorKind::ConnectionRefused
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::WouldBlock
                | io::ErrorKind::UnexpectedEof
        ),
        RelayError::Rejected(_) => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests;
