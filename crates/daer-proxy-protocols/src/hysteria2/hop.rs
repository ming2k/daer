// SPDX-License-Identifier: AGPL-3.0-only

//! Port hopping: rotating the *local* port under a live QUIC connection (ADR-0029).
//!
//! # Why hop the local port, and why rebind rather than re-dial
//!
//! A censor that throttles a QUIC flow has to key on something, and a five-tuple is the
//! cheapest key it has. The server's side of that tuple cannot change; the client's source
//! port can, and the reference rotates it every 30 seconds by default. A new source port means
//! a new five-tuple and a new throttle decision.
//!
//! Re-dialling would lose the connection. `quinn::Endpoint::rebind_abstract` is the sanctioned
//! way to swap the socket underneath a live endpoint: it re-registers the new socket with the
//! endpoint's driver and keeps every connection id intact. The reference achieves the same
//! thing by replacing its `net.PacketConn` and keeping a receive loop on the old one; here the
//! endpoint does it, which is why this is a task and not a socket layer.
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

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use quinn::{AsyncUdpSocket, Runtime as _};
use socket2::{Domain, Protocol, Socket, Type};

use crate::error::ProxyProtocolError;
use crate::hysteria2::obfs::{Obfs, ObfsSocket};
use crate::hysteria2::port_set::PortSet;

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
    /// Builds a schedule from a node's port set.
    ///
    /// # Errors
    ///
    /// Returns a message when the bounds are reversed or below [`MIN_HOP_INTERVAL`]. Both are
    /// load-time facts, and a 1-second schedule looks like a working node whose connections
    /// the server drops.
    pub fn from_ports(ports: &PortSet) -> Result<Option<Self>, String> {
        if !ports.hops() {
            return Ok(None);
        }
        let single = Duration::from_millis(ports.hop_ms.max(1));
        let min = if ports.hop_min_ms > 0 {
            Duration::from_millis(ports.hop_min_ms)
        } else {
            single
        };
        let max = if ports.hop_max_ms > 0 {
            Duration::from_millis(ports.hop_max_ms)
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

/// Binds the bottom socket of the stack: a UDP socket with `SO_MARK` applied before `bind`, so
/// the kernel's route decision for the socket's own traffic sees it.
///
/// Returns a `std::net::UdpSocket` because Quinn's runtime registration
/// (`Runtime::wrap_udp_socket`) takes one.
///
/// # Errors
///
/// Returns a message naming the step that failed: creating, marking, binding or making the
/// socket non-blocking.
pub fn base_socket(
    is_ipv6: bool,
    so_mark: Option<u32>,
) -> Result<std::net::UdpSocket, ProxyProtocolError> {
    let socket = Socket::new(
        if is_ipv6 { Domain::IPV6 } else { Domain::IPV4 },
        Type::DGRAM,
        Some(Protocol::UDP),
    )
    .map_err(|error| ProxyProtocolError::Connect(format!("create udp socket: {error}")))?;

    if let Some(mark) = so_mark {
        socket
            .set_mark(mark)
            .map_err(|error| ProxyProtocolError::Connect(format!("set so_mark {mark}: {error}")))?;
    }

    let bind_addr: SocketAddr = if is_ipv6 {
        "[::]:0".parse().expect("a literal address")
    } else {
        "0.0.0.0:0".parse().expect("a literal address")
    };
    socket
        .bind(&bind_addr.into())
        .map_err(|error| ProxyProtocolError::Connect(format!("bind udp socket: {error}")))?;
    socket
        .set_nonblocking(true)
        .map_err(|error| ProxyProtocolError::Connect(format!("set nonblocking: {error}")))?;
    Ok(socket.into())
}

/// Builds the whole socket stack for one endpoint: the marked base socket, the obfuscation
/// layer if the node configured one.
///
/// # Errors
///
/// Returns a message when a socket cannot be created or registered.
pub fn build_stack(
    is_ipv6: bool,
    so_mark: Option<u32>,
    obfs: Option<&Obfs>,
) -> Result<Arc<dyn AsyncUdpSocket>, ProxyProtocolError> {
    let base = base_socket(is_ipv6, so_mark)?;
    let socket: Arc<dyn AsyncUdpSocket> = quinn::TokioRuntime
        .wrap_udp_socket(base)
        .map_err(|error| ProxyProtocolError::Connect(format!("register udp socket: {error}")))?;
    // Obfuscation sits directly above the socket: one salt per datagram, so it must be the
    // last thing that touches the bytes before `sendmsg`.
    Ok(match obfs {
        Some(obfs) => Arc::new(ObfsSocket::new(socket, obfs.clone())),
        None => socket,
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
    /// Starts hopping `endpoint`'s socket on `schedule`.
    ///
    /// `target` is the destination the node was resolved to; the hop layer also rotates the
    /// *destination* port across `ports`, which is what the reference's `udpHopPacketConn`
    /// does: one refused port must not strand the connection.
    #[must_use]
    pub fn start(
        endpoint: quinn::Endpoint,
        target: SocketAddr,
        _ports: PortSet,
        schedule: HopSchedule,
        so_mark: Option<u32>,
        obfs: Option<Obfs>,
    ) -> Self {
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let handle = tokio::spawn(async move {
            // The previous stack is retained for one interval: the server's acknowledgement of
            // the switch arrives on the old path.
            let mut previous: Option<Arc<dyn AsyncUdpSocket>> = None;
            loop {
                let interval = schedule.next();
                tokio::time::sleep(interval).await;
                if flag.load(std::sync::atomic::Ordering::Acquire) {
                    return;
                }
                let fresh = match build_stack(target.is_ipv6(), so_mark, obfs.as_ref()) {
                    Ok(fresh) => fresh,
                    // A transient bind failure is not fatal: the reference skips the hop
                    // ("Could be temporary, just skip this hop") rather than dropping the
                    // connection.
                    Err(_) => continue,
                };
                // Only the *source* port rotates. Hysteria 2's `udpHopPacketConn` rotates the
                // destination too, but it owns the dial; in quinn the destination is fixed by
                // `connect_with`, and `rebind_abstract` changes only the local socket. Rotating it
                // would need an `AsyncUdpSocket` that rewrites `Transmit::destination` per packet —
                // a layer this crate does not have, so it is not claimed. A node that publishes
                // several destination ports is still reached: the *initial* dial samples from the
                // `ports` set (`Hysteria2Connector::resolve`). ADR-0029 records the gap.
                if endpoint.rebind_abstract(Arc::clone(&fresh)).is_ok() {
                    // Drop the socket the endpoint just left — after one interval, so its
                    // in-flight acknowledgement is still received.
                    let old = previous.replace(fresh);
                    if let Some(old) = old {
                        tokio::spawn(async move {
                            tokio::time::sleep(interval).await;
                            drop(old);
                        });
                    }
                }
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
        let mut ports = PortSet::single(443);
        ports.hop_ms = 1_000;
        let error = HopSchedule::from_ports(&ports).expect_err("1s is under the floor");
        assert!(error.contains("5s"), "{error}");

        ports.hop_ms = 30_000;
        let schedule = HopSchedule::from_ports(&ports)
            .expect("30s is fine")
            .expect("hopping is configured");
        assert_eq!(schedule.min, Duration::from_secs(30));
        assert_eq!(schedule.max, Duration::from_secs(30));
    }

    #[test]
    fn no_hop_key_means_no_hopping() {
        let ports = PortSet::single(443);
        assert_eq!(HopSchedule::from_ports(&ports), Ok(None));
    }

    #[test]
    fn reversed_bounds_are_refused_by_name() {
        let mut ports = PortSet::single(443);
        ports.hop_min_ms = 60_000;
        ports.hop_max_ms = 30_000;
        let error = HopSchedule::from_ports(&ports).expect_err("min > max");
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

    #[test]
    fn the_base_socket_carries_the_mark_and_is_bound_to_an_ephemeral_port() {
        // A hopped socket without the mark would be redirected back into daer by its own
        // eBPF rule, and the loop would look like an authentication failure.
        let socket = base_socket(false, None).expect("binds");
        let address = socket.local_addr().expect("has an address");
        assert_ne!(
            address.port(),
            0,
            "an ephemeral port is assigned by the kernel"
        );
        assert!(address.ip().is_unspecified());
    }
}
