// SPDX-License-Identifier: AGPL-3.0-only

//! Port hopping: rotating the *local* port under a live QUIC connection (ADR-0029).
//!
//! # Why hop the local port, and why rotate the socket rather than re-dial
//!
//! A censor that throttles a QUIC flow has to key on something, and a five-tuple is the
//! cheapest key it has. The server's side of that tuple cannot change; the client's source
//! port can, and the reference rotates it every 30 seconds by default. A new source port means
//! a new five-tuple and a new throttle decision.
//!
//! Re-dialling would lose the connection. netune's endpoint polls the stack once, so the
//! `HopSocket` wrapper keeps a small set of bound sockets and switches which one sends; the
//! endpoint's connection ids are untouched. The reference replaces its `net.PacketConn` and
//! keeps a receive loop on the old one; this wrapper does the same below the QUIC engine.
//!
//! # The grace period
//!
//! The server acknowledges the switch on the *old* path, so the previous socket is kept for
//! one interval before it is dropped. Without it the first packets of the new path are lost,
//! and a Hysteria handshake that loses its first flight is a timeout with no cause.
//!
//! # Why `SO_MARK` is on every socket
//!
//! The mark is what keeps daer's own egress out of the transparent-proxy redirect. A hopped
//! socket without it would be redirected back into daer, and the loop would look like an
//! authentication failure.

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use netune_quic::{QuicSocketConfig, QuicUdpSocket, QuicUdpSocketFactory};

use crate::error::ProxyProtocolError;
use crate::hysteria2::obfs::{Obfs, ObfsSocket};
use daer_config::PortHopping;

/// The reference's floor for a hop interval (`udphop`): a shorter schedule exhausts the
/// server's port table faster than it releases entries.
pub const MIN_HOP_INTERVAL: Duration = Duration::from_secs(5);

/// The hop schedule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HopSchedule {
    pub min: Duration,
    pub max: Duration,
}

impl HopSchedule {
    /// Builds a schedule from a node's port-hopping table.
    ///
    /// # Errors
    ///
    /// Returns a message when the bounds are reversed or below [`MIN_HOP_INTERVAL`]. Both are
    /// load-time facts, and a 1-second schedule looks like a working node whose connections
    /// the server drops.
    pub fn from_hopping(hopping: &PortHopping) -> Result<Option<Self>, String> {
        if !hopping.is_enabled() {
            return Ok(None);
        }
        let millis =
            |value: daer_config::TimeSpan| u64::try_from(value.as_nanos() / 1_000_000).unwrap_or(0);
        let single = Duration::from_millis(millis(hopping.interval).max(1));
        let min = if hopping.min_interval.as_nanos() > 0 {
            Duration::from_millis(millis(hopping.min_interval))
        } else {
            single
        };
        let max = if hopping.max_interval.as_nanos() > 0 {
            Duration::from_millis(millis(hopping.max_interval))
        } else {
            single
        };
        if min > max {
            return Err(format!(
                "hop-min-interval ({}ms) must not exceed hop-max-interval ({}ms)",
                min.as_millis(),
                max.as_millis()
            ));
        }
        if min < MIN_HOP_INTERVAL {
            return Err(format!(
                "the hop interval must be at least {}s, got {}ms",
                MIN_HOP_INTERVAL.as_secs(),
                min.as_millis()
            ));
        }
        Ok(Some(Self { min, max }))
    }

    /// The next interval, drawn uniformly from `[min, max]`.
    ///
    /// Randomised because a fixed period is itself a signature: a censor that sees a new source
    /// port every exactly 30 s can simply follow it.
    #[must_use]
    pub fn next(self) -> Duration {
        if self.min == self.max {
            return self.min;
        }
        let low = self.min.as_millis();
        let high = self.max.as_millis();
        let span = high - low;
        let pick = u128::from(fastrand::u64(..)) % (span + 1);
        Duration::from_millis(u64::try_from(low + pick).unwrap_or(u64::MAX))
    }
}

/// The socket stack handed to the QUIC connector.
///
/// The `hop` handle is kept separately so a rotation task can add sockets while the
/// obfuscation wrapper (when configured) sits above the same stack.
pub struct SocketStack {
    socket: Arc<dyn QuicUdpSocket>,
    hop: Arc<HopSocket>,
    target: SocketAddr,
    config: QuicSocketConfig,
}

impl std::fmt::Debug for SocketStack {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SocketStack")
            .field("local_addr", &self.hop.local)
            .finish_non_exhaustive()
    }
}

impl SocketStack {
    /// The abstract socket the QUIC endpoint should use.
    #[must_use]
    pub fn socket(&self) -> Arc<dyn QuicUdpSocket> {
        Arc::clone(&self.socket)
    }

    /// Starts source-port hopping on this stack, if the node configured it.
    #[must_use]
    pub fn start_hopper(&self, schedule: HopSchedule) -> PortHopper {
        PortHopper::start(
            Arc::clone(&self.hop),
            schedule,
            self.target,
            self.config.clone(),
        )
    }
}

/// Builds one socket stack for each QUIC connection netune opens.
///
/// netune calls [`QuicUdpSocketFactory::create`] after egress confinement and before the first
/// Initial packet, and passes the connector's [`QuicSocketConfig`]. Retaining the stack here is
/// what lets [`Hysteria2Connector`](super::connector::Hysteria2Connector) start port hopping only
/// after the handshake succeeds: a failed dial drops the stack and spawns no rotation task.
pub struct SocketStackFactory {
    obfs: Option<Obfs>,
    stack: Mutex<Option<SocketStack>>,
}

impl std::fmt::Debug for SocketStackFactory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SocketStackFactory")
            .field("obfs", &self.obfs.as_ref().map(Obfs::kind))
            .finish_non_exhaustive()
    }
}

impl SocketStackFactory {
    /// Creates a factory for one Hysteria 2 dial.
    #[must_use]
    pub fn new(obfs: Option<Obfs>) -> Self {
        Self {
            obfs,
            stack: Mutex::new(None),
        }
    }

    /// Takes the stack the factory built for the connection that just completed.
    ///
    /// `None` means netune completed a handshake without asking for a socket, which would be a
    /// connector bug rather than a recoverable dial failure.
    #[must_use]
    pub fn take(&self) -> Option<SocketStack> {
        self.stack
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take()
    }
}

impl QuicUdpSocketFactory for SocketStackFactory {
    fn create(
        &self,
        target: SocketAddr,
        config: &QuicSocketConfig,
    ) -> io::Result<Arc<dyn QuicUdpSocket>> {
        let stack = build_stack(target, config, self.obfs.as_ref())
            .map_err(|error| io::Error::other(error.to_string()))?;
        let socket = stack.socket();
        *self.stack.lock().unwrap_or_else(|error| error.into_inner()) = Some(stack);
        Ok(socket)
    }
}

/// The rotating base layer: one datagram socket at a time, with the previous one
/// retained for the acknowledgement that may still arrive on it.
#[derive(Debug)]
pub struct HopSocket {
    sockets: Mutex<Vec<Arc<tokio::net::UdpSocket>>>,
    current: AtomicUsize,
    local: SocketAddr,
}

impl HopSocket {
    fn new(socket: tokio::net::UdpSocket) -> io::Result<Self> {
        let local = socket.local_addr()?;
        Ok(Self {
            sockets: Mutex::new(vec![Arc::new(socket)]),
            current: AtomicUsize::new(0),
            local,
        })
    }

    fn add(&self, socket: tokio::net::UdpSocket) {
        let mut sockets = self.sockets.lock().unwrap_or_else(|e| e.into_inner());
        sockets.push(Arc::new(socket));
        // The peer acknowledges the switch on the old path. Keeping one previous socket
        // covers that race without accumulating one socket per hop forever.
        while sockets.len() > 2 {
            sockets.remove(0);
        }
        self.current.store(sockets.len() - 1, Ordering::Release);
    }
}

impl QuicUdpSocket for HopSocket {
    fn poll_recv_from(
        &self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>> {
        let sockets = self.sockets.lock().unwrap_or_else(|e| e.into_inner());
        if sockets.is_empty() {
            return Poll::Pending;
        }
        let start = self.current.load(Ordering::Acquire).min(sockets.len() - 1);
        for offset in 0..sockets.len() {
            let index = (start + offset) % sockets.len();
            match QuicUdpSocket::poll_recv_from(sockets[index].as_ref(), cx, buf) {
                Poll::Pending => continue,
                ready => return ready,
            }
        }
        Poll::Pending
    }

    fn poll_send_to(
        &self,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: SocketAddr,
    ) -> Poll<io::Result<usize>> {
        let socket = {
            let sockets = self.sockets.lock().unwrap_or_else(|e| e.into_inner());
            let index = self.current.load(Ordering::Acquire).min(sockets.len() - 1);
            Arc::clone(&sockets[index])
        };
        QuicUdpSocket::poll_send_to(socket.as_ref(), cx, buf, target)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }
}

/// Binds the bottom socket of the stack.
///
/// netune's [`QuicSocketConfig`] is applied here, including `SO_MARK` before `bind`/`connect`, so
/// the kernel's route decision for the socket's own traffic sees the mark.
///
/// # Errors
///
/// Returns a message naming the target when any configured socket option or the bind fails.
pub fn base_socket(
    target: SocketAddr,
    config: &QuicSocketConfig,
) -> Result<tokio::net::UdpSocket, ProxyProtocolError> {
    config.create_tokio_socket(target).map_err(|error| {
        ProxyProtocolError::Connect(format!("create udp socket for {target}: {error}"))
    })
}

/// Builds the whole socket stack for one connection: the marked base socket, the hop layer, and
/// the obfuscation layer if the node configured one.
///
/// # Errors
///
/// Returns a message when a socket cannot be created or registered.
pub fn build_stack(
    target: SocketAddr,
    config: &QuicSocketConfig,
    obfs: Option<&Obfs>,
) -> Result<SocketStack, ProxyProtocolError> {
    let base = base_socket(target, config)?;
    let hop =
        Arc::new(HopSocket::new(base).map_err(|error| {
            ProxyProtocolError::Connect(format!("inspect udp socket: {error}"))
        })?);
    // Obfuscation sits directly above the socket: one salt per datagram, so it must be the
    // last thing that touches the bytes before `sendmsg`.
    let socket: Arc<dyn QuicUdpSocket> = match obfs {
        Some(obfs) => Arc::new(ObfsSocket::new(hop.clone(), obfs.clone())),
        None => hop.clone(),
    };
    Ok(SocketStack {
        socket,
        hop,
        target,
        config: config.clone(),
    })
}

/// Drives the hop schedule for one endpoint.
///
/// Returns a handle that stops the task when dropped, so a node whose connection ends stops
/// rotating sockets immediately rather than at the next interval.
pub struct PortHopper {
    stop: Arc<std::sync::atomic::AtomicBool>,
    handle: tokio::task::JoinHandle<()>,
}

impl std::fmt::Debug for PortHopper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PortHopper").finish_non_exhaustive()
    }
}

impl Drop for PortHopper {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Release);
        self.handle.abort();
    }
}

impl PortHopper {
    /// Starts hopping the local source port on `schedule`.
    ///
    /// Only the *source* port rotates. Hysteria 2's `udpHopPacketConn` rotates the destination
    /// too, but it owns the dial; in netune the destination is fixed by the connection, so a
    /// node that publishes several destination ports is still reached because the *initial*
    /// dial samples from the `ports` set (`Hysteria2Connector::resolve`). ADR-0029 records the
    /// gap.
    #[must_use]
    pub fn start(
        hop: Arc<HopSocket>,
        schedule: HopSchedule,
        target: SocketAddr,
        config: QuicSocketConfig,
    ) -> Self {
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let handle = tokio::spawn(async move {
            loop {
                let interval = schedule.next();
                tokio::time::sleep(interval).await;
                if flag.load(std::sync::atomic::Ordering::Acquire) {
                    return;
                }
                let fresh = match base_socket(target, &config) {
                    Ok(fresh) => fresh,
                    // A transient bind failure is not fatal: the reference skips the hop
                    // ("Could be temporary, just skip this hop") rather than dropping the
                    // connection.
                    Err(_) => continue,
                };
                hop.add(fresh);
            }
        });
        Self { stop, handle }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_schedule_shorter_than_the_reference_floor_is_refused() {
        let hopping = PortHopping {
            interval: daer_config::TimeSpan::from_secs(1),
            ..PortHopping::default()
        };
        let error = HopSchedule::from_hopping(&hopping).expect_err("1s is under the floor");
        assert!(error.contains("5s"), "{error}");

        let hopping = PortHopping {
            interval: daer_config::TimeSpan::from_secs(30),
            ..PortHopping::default()
        };
        let schedule = HopSchedule::from_hopping(&hopping)
            .expect("30s is fine")
            .expect("hopping is configured");
        assert_eq!(schedule.min, Duration::from_secs(30));
        assert_eq!(schedule.max, Duration::from_secs(30));
    }

    #[test]
    fn no_hop_key_means_no_hopping() {
        assert_eq!(HopSchedule::from_hopping(&PortHopping::default()), Ok(None));
    }

    #[test]
    fn reversed_bounds_are_refused_by_name() {
        let hopping = PortHopping {
            min_interval: daer_config::TimeSpan::from_secs(60),
            max_interval: daer_config::TimeSpan::from_secs(30),
            ..PortHopping::default()
        };
        let error = HopSchedule::from_hopping(&hopping).expect_err("min > max");
        assert!(error.contains("hop-min-interval"), "{error}");
    }

    #[test]
    fn a_randomised_interval_stays_inside_its_bounds() {
        let schedule = HopSchedule {
            min: Duration::from_secs(10),
            max: Duration::from_secs(20),
        };
        for _ in 0..64 {
            let next = schedule.next();
            assert!(next >= schedule.min && next <= schedule.max, "{next:?}");
        }
        // A single-valued schedule is exact, so an operator who wrote one interval gets it.
        let exact = HopSchedule {
            min: Duration::from_secs(30),
            max: Duration::from_secs(30),
        };
        assert_eq!(exact.next(), Duration::from_secs(30));
    }

    #[tokio::test]
    async fn the_base_socket_is_bound_to_an_ephemeral_port_of_the_target_family() {
        // A hopped socket without the connector's mark would be redirected back into daer by
        // its own eBPF rule; `QuicSocketConfig::create_tokio_socket` is where that mark is
        // applied, before the bind.
        let target: SocketAddr = "127.0.0.1:443".parse().expect("literal");
        let socket = base_socket(target, &QuicSocketConfig::default()).expect("binds");
        let address = socket.local_addr().expect("has an address");
        assert_ne!(
            address.port(),
            0,
            "an ephemeral port is assigned by the kernel"
        );
        assert!(address.ip().is_unspecified());
        assert!(address.is_ipv4());

        // The control: the family follows the target rather than a node-wide switch.
        let target: SocketAddr = "[::1]:443".parse().expect("literal");
        let socket = base_socket(target, &QuicSocketConfig::default()).expect("binds");
        assert!(socket.local_addr().expect("has an address").is_ipv6());
    }

    #[tokio::test]
    async fn the_factory_hands_out_one_stack_and_retains_it_for_the_hopper() {
        let factory = SocketStackFactory::new(None);
        let target: SocketAddr = "127.0.0.1:443".parse().expect("literal");
        let socket = factory
            .create(target, &QuicSocketConfig::default())
            .expect("creates a stack");
        assert_ne!(socket.local_addr().expect("bound").port(), 0);
        assert!(factory.take().is_some(), "the hopper needs the hop handle");
        assert!(
            factory.take().is_none(),
            "one connection owns exactly one stack"
        );
    }
}
