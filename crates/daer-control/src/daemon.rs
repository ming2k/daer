// SPDX-License-Identifier: AGPL-3.0-only

//! The daemon: load the datapath, attach it, and serve.
//!
//! # What this connects
//!
//! Every part below already existed and was tested on its own; this module is the wiring
//! that was missing, and it is the difference between "a library of parts" and "a
//! transparent proxy":
//!
//! ```text
//!   config ──▶ Generations ──▶ Router ──┐
//!                                        ├──▶ serve(ingress, router) ──▶ relay ──▶ node
//!   datapath.o ──▶ load ──▶ attach tc ──┘
//! ```
//!
//! # The order is not arbitrary
//!
//! The kernel program must be attached **before** the listener accepts anything: a flow
//! that reaches the transparent port without a datapath behind it was not redirected, and
//! `is_self_connect` would reject it. Attaching first also means the first flow of the
//! system's life is proxied rather than passed through.
//!
//! The listener is bound before the program is attached, though, and that is deliberate:
//! the `PARAM` global carries the listener's port, so the port has to exist before the
//! program is loaded. Binding a socket does not accept from it.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use daer_config::Config;

use crate::decide::{Router, RouterOptions};
use crate::generation::{Generations, ReloadError};
use crate::inbound::TransparentListener;
use crate::serve::{self, ServeStats};
use crate::supervise::Supervisor;

/// What the datapath needs to know about this run.
///
/// Mirrors [`daer_ebpf::RuntimeParam`] but in daer's own vocabulary, so the control plane
/// does not have to spell the object's field names.
#[derive(Debug, Clone)]
pub struct DatapathSettings {
    /// The transparent port the kernel redirects to.
    pub tproxy_port: u16,
    /// Interfaces to attach the LAN-side programs to.
    pub lan_interfaces: Vec<String>,
    /// Interfaces to attach the WAN-side programs to.
    pub wan_interfaces: Vec<String>,
    /// Functionality that needs privileges the process does not have.
    pub allow_partial: bool,
}

/// What could not be wired, when running with reduced capability.
///
/// Returned rather than logged so a caller can decide: `daer run` refuses to start when
/// this is non-empty, while `daer run --no-datapath` reports it and serves anyway (which is
/// what makes the accept/relay path usable in a container without `CAP_NET_ADMIN`).
#[derive(Debug, Default, Clone)]
pub struct DatapathStatus {
    /// True when the kernel program is loaded and attached.
    pub attached: bool,
    /// Reasons the datapath is not attached.
    pub skipped: Vec<String>,
}

impl DatapathStatus {
    /// True when nothing was skipped, i.e. the kernel side is live.
    #[must_use]
    pub fn is_attached(&self) -> bool {
        self.attached
    }
}

/// A running daemon.
pub struct Daemon {
    /// The listener the kernel redirects into.
    pub listener: TransparentListener,
    /// The port it bound.
    pub port: u16,
    /// The configuration generations, swapped on reload.
    pub generations: Arc<Generations>,
    /// Live flows, owned apart from the accept loop.
    pub supervisor: Supervisor,
    /// What the datapath could or could not do.
    pub datapath: DatapathStatus,
    /// The relay's counters, when the datagram half is running.
    ///
    /// Readable so a deployment can tell working UDP from silently dropped UDP: without a
    /// counter, "the client says UDP is broken" has no answer that is not a packet capture.
    pub datagram_stats: Option<Arc<crate::datagram::DatagramStats>>,
    /// The transparent UDP socket, when the datagram relay could be bound.
    ///
    /// `None` means the relay is not running, and that is a decision the daemon reports at
    /// `WARN`: a client that believes its UDP is tunnelled and gets silence instead has been
    /// lied to, which is worse than a refusal it can see (ADR-0006).
    pub datagrams: Option<Arc<dyn crate::ingress_udp::DatagramIngress>>,
}

impl std::fmt::Debug for Daemon {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Daemon")
            .field("port", &self.port)
            .field("datapath", &self.datapath)
            .finish_non_exhaustive()
    }
}

impl Daemon {
    /// Binds the transparent port and compiles the first generation.
    ///
    /// # Errors
    ///
    /// Returns the listener error when the port cannot be bound (it needs
    /// `IP_TRANSPARENT`, so this is where a missing capability shows up first), and a
    /// [`ReloadError`] when the configuration does not compile.
    pub fn bind(config: &Config, options: &RouterOptions) -> Result<Self, BindError> {
        let port = config.global.tproxy_port;
        // Bound before the object is loaded: the port is part of `PARAM`, so it has to be
        // known first. Binding does not accept, so no flow is served before the datapath
        // exists.
        let listener = TransparentListener::bind_with_protection(
            Ipv4Addr::UNSPECIFIED,
            port,
            config.global.tproxy_port_protect,
        )
        .map_err(BindError::Ingress)?;
        let port = listener.port();
        let generations = Generations::new(config, options).map_err(BindError::Config)?;
        // The datagram half. A failure here is not fatal: the box can still proxy TCP, and a
        // daemon that refuses to start because UDP could not bind would take a working proxy
        // down over a secondary transport.
        let datagrams = match crate::ingress_udp::TransparentDatagramListener::bind(
            Ipv4Addr::UNSPECIFIED,
            port,
        ) {
            Ok(listener) => {
                Some(Arc::new(listener) as Arc<dyn crate::ingress_udp::DatagramIngress>)
            }
            Err(error) => {
                tracing::warn!(
                    %error,
                    port,
                    "the UDP relay is not running: datagrams will not be proxied \
                     (TCP is unaffected)"
                );
                None
            }
        };
        Ok(Self {
            listener,
            port,
            generations: Arc::new(generations),
            supervisor: Supervisor::new(),
            datapath: DatapathStatus::default(),
            datagrams: datagrams.clone(),
            datagram_stats: datagrams.map(|_| Arc::new(crate::datagram::DatagramStats::default())),
        })
    }

    /// The current generation, pinned into an `Arc`.
    ///
    /// Returns the generation rather than its router because the borrow has to outlive the
    /// call: a flow is pinned to the rules it arrived under, and an `Arc` is what keeps
    /// those rules alive while the flow runs.
    #[must_use]
    pub fn generation(&self) -> Arc<crate::generation::Generation> {
        self.generations.current()
    }

    /// How often to probe nodes, from the configuration the daemon was built with.
    ///
    /// Read from the *current* generation so a reload can change it: the scheduler is restarted
    /// on reload, and a value captured at startup would silently ignore the new file.
    #[must_use]
    pub fn health_interval(&self) -> daer_config::TimeSpan {
        self.generations.current().health_interval()
    }

    /// The datagram relay's counters, if the relay is running.
    #[must_use]
    pub fn datagram_stats(&self) -> Option<Arc<crate::datagram::DatagramStats>> {
        self.datagram_stats.as_ref().map(Arc::clone)
    }

    /// The health-check settings of the current generation.
    ///
    /// The whole table rather than just the interval: a probe's URL, HTTP method and UDP DNS
    /// endpoints are configuration, and passing only the interval is how they came to be ignored.
    #[must_use]
    pub fn health_check(&self) -> daer_config::HealthCheck {
        self.generations.current().health_check()
    }

    /// Runs the accept loop until `shutdown` resolves.
    ///
    /// Reload is *not* driven from here: it needs a file watch and a signal, and both are
    /// the caller's policy rather than the data path's.
    ///
    /// # Errors
    ///
    /// Returns an accept failure that is not resource exhaustion. Per-flow failures are
    /// counted in [`Self::stats`], not returned.
    pub async fn serve(
        &self,
        shutdown: impl std::future::Future<Output = ()>,
    ) -> Result<(), crate::error::IngressError> {
        // The generation is re-read per flow, so a reload is visible to the next flow
        // without restarting the loop.
        let supervisor = self.supervisor.clone();
        let loop_router = RouterForGeneration {
            generations: Arc::clone(&self.generations),
        };
        let Some(ingress) = self.datagrams.as_ref() else {
            // No datagram socket: TCP only, which is what `Daemon::bind` reported at `WARN`.
            serve::serve(&self.listener, &loop_router, &supervisor, shutdown).await?;
            return Ok(());
        };

        // Both halves need to observe the same shutdown, and a `Future` is not `Clone`, so it is
        // driven once inside a broadcast: the TCP loop and the datagram relay each hold a
        // receiver and stop when the sender fires.
        let service = crate::datagram::DatagramService {
            ingress: Arc::clone(ingress),
            router: self.generations.current().router_arc(),
            options: crate::datagram::RelayOptions::default(),
            stats: self.datagram_stats.as_ref().map_or_else(
                || Arc::new(crate::datagram::DatagramStats::default()),
                Arc::clone,
            ),
        };
        let signal = Arc::new(tokio::sync::Notify::new());
        let notify = Arc::clone(&signal);
        let trigger = async move {
            shutdown.await;
            notify.notify_waiters();
        };
        let tcp = {
            let signal = Arc::clone(&signal);
            async move { signal.notified().await }
        };
        let udp = {
            let signal = Arc::clone(&signal);
            async move { signal.notified().await }
        };
        let (stopped, datagrams, ()) = tokio::join!(
            crate::serve::serve(&self.listener, &loop_router, &supervisor, tcp),
            crate::datagram::serve_datagrams(
                Arc::clone(&service.ingress),
                Arc::clone(&service.router),
                service.options,
                Arc::clone(&service.stats),
                udp,
            ),
            trigger,
        );
        // `serve_datagrams` returns `Err` only for a fatal ingress failure; the TCP result is the
        // one the caller acts on, and a datagram failure is reported rather than returned so a
        // misbehaving UDP socket cannot silence HTTP.
        if let Err(error) = datagrams {
            tracing::warn!(%error, "the datagram relay stopped");
        }
        stopped?;
        Ok(())
    }

    /// A point-in-time snapshot of the loop's counters.
    #[must_use]
    pub fn stats(&self) -> ServeStats {
        self.supervisor.metrics().snapshot()
    }

    /// Rebuilds the configuration and publishes it atomically.
    ///
    /// A generation that fails to build publishes nothing, so a bad reload leaves the
    /// running policy untouched — see [`Generations::reload`].
    ///
    /// # Errors
    ///
    /// Returns [`ReloadError`], which names the generation that is still serving.
    pub fn reload(&self, config: &Config, options: &RouterOptions) -> Result<(), ReloadError> {
        self.generations.reload(config, options).map(|_| ())
    }
}

/// Why a daemon could not be created.
#[derive(Debug)]
pub enum BindError {
    /// The transparent port could not be bound.
    Ingress(crate::error::IngressError),
    /// The configuration does not compile.
    Config(ReloadError),
}

impl std::fmt::Display for BindError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ingress(error) => write!(f, "cannot bind the transparent port: {error}"),
            Self::Config(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for BindError {}

/// A [`Decide`](crate::serve::Decide) that reads the *current* generation per flow.
///
/// Without this the loop would hold the router of the generation it started with, and a
/// reload would change nothing until the loop restarted — which is exactly the connection
/// drop a reload is supposed to avoid.
struct RouterForGeneration {
    generations: Arc<Generations>,
}

impl crate::serve::Decide for RouterForGeneration {
    type Upstream = <Router as crate::serve::Decide>::Upstream;
    type Future<'a>
        = <Router as crate::serve::Decide>::Future<'a>
    where
        Self: 'a;

    fn decide<'a>(&'a self, flow: &'a crate::inbound::Accepted) -> Self::Future<'a> {
        // `current()` is an atomic read of an `Arc`, so this is cheap on the hot path. The
        // `Arc` is moved into the future: it is what pins this flow to the rules it arrived
        // under, even if a reload swaps the generation while the flow is being opened.
        let generation = self.generations.current();
        Box::pin(async move {
            let router = generation.router();
            crate::serve::Decide::decide(router, flow).await
        })
    }
}

/// Resolves `wan-interface = ["auto"]` to the interface carrying the default route.
///
/// # Errors
///
/// Returns a message when no default route exists, which is not a configuration error but
/// an environment one: a box with no route cannot proxy anything.
pub fn detect_wan_interface() -> Result<String, String> {
    // `/proc/net/route` is the dependency-free way to read the main table: the default
    // route is the one with destination 00000000 and the lowest metric.
    let table = std::fs::read_to_string("/proc/net/route")
        .map_err(|error| format!("cannot read /proc/net/route: {error}"))?;
    let mut best: Option<(u32, String)> = None;
    for line in table.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 8 {
            continue;
        }
        let (name, destination, flags, metric) = (fields[0], fields[1], fields[3], fields[6]);
        if destination != "00000000" {
            continue;
        }
        // RTF_UP is 0x0001: a route that is not up is not a default.
        let Ok(flags) = u32::from_str_radix(flags, 16) else {
            continue;
        };
        if flags & 0x0001 == 0 {
            continue;
        }
        let metric = metric.parse::<u32>().unwrap_or(u32::MAX);
        if best.as_ref().is_none_or(|(current, _)| metric < *current) {
            best = Some((metric, name.to_owned()));
        }
    }
    best.map(|(_, name)| name)
        .ok_or_else(|| "no default route: cannot detect the WAN interface".to_owned())
}

/// Expands `auto` in the configured interface lists.
///
/// # Errors
///
/// As [`detect_wan_interface`], when `auto` is asked for and no default route exists.
pub fn resolve_interfaces(
    lan: &[String],
    wan: &[String],
) -> Result<(Vec<String>, Vec<String>), String> {
    let mut resolved_wan = Vec::with_capacity(wan.len());
    for entry in wan {
        if entry == "auto" {
            let detected = detect_wan_interface()?;
            tracing::info!(interface = %detected, "detected the WAN interface");
            if !resolved_wan.contains(&detected) {
                resolved_wan.push(detected);
            }
        } else {
            resolved_wan.push(entry.clone());
        }
    }
    Ok((lan.to_vec(), resolved_wan))
}

/// The listener's local address, for logging and for the kernel parameter.
#[must_use]
pub fn listen_address(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::UNSPECIFIED, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_resolves_to_one_interface() {
        // Only asserts the shape, not the name: the test box's default route is not the
        // developer's. A box with no route is skipped rather than failed.
        let (lan, wan) = match resolve_interfaces(&[], &["auto".to_owned()]) {
            Ok(resolved) => resolved,
            Err(reason) => {
                eprintln!("skipped: {reason}");
                return;
            }
        };
        assert!(lan.is_empty());
        assert_eq!(wan.len(), 1, "auto must resolve to exactly one name");
        assert_ne!(wan[0], "auto", "the literal must not survive resolution");
    }

    #[test]
    fn a_named_interface_is_passed_through() {
        let (_, wan) = resolve_interfaces(&[], &["eth0".to_owned()]).expect("resolves");
        assert_eq!(wan, ["eth0"]);
    }

    #[test]
    fn a_duplicate_auto_is_collapsed() {
        // Two `auto` entries would attach the same program to the same interface twice,
        // which the kernel rejects as a duplicate filter.
        let Ok((_, wan)) = resolve_interfaces(&[], &["auto".to_owned(), "auto".to_owned()]) else {
            return;
        };
        assert_eq!(wan.len(), 1, "{wan:?}");
    }
}
