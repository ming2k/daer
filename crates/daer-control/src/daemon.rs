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

use daer_relay::relay::datagram::{
    DatagramService, DatagramStats as DatagramCounters, RelayOptions,
};
use daer_relay::{
    DatagramIngress, Decide, FlowFacts, RelayError, ServeStats, Supervisor,
    TransparentDatagramListener, TransparentListener, serve_parallel,
};

use crate::decide::{Router, RouterOptions};
use crate::generation::{Generations, ReloadError};

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

/// Aborts a spawned task when its owner is dropped or cancelled.
///
/// `JoinHandle` detaches on drop, so cancelling `Daemon::serve` (an aborted test, a reload
/// path that gives up, or a future dropped by its caller) used to leave the datagram relay
/// running on a listener nobody owned any more. That task kept polling the close-on-drop
/// socket path until the runtime shut down, which is a leak and, under an edge-triggered
/// readiness loop, a CPU spin. The guard makes cancellation reach the task.
struct AbortOnDrop<T> {
    task: tokio::task::JoinHandle<T>,
}

impl<T> AbortOnDrop<T> {
    fn new(task: tokio::task::JoinHandle<T>) -> Self {
        Self { task }
    }

    async fn stop(mut self) {
        self.task.abort();
        let _ = (&mut self.task).await;
    }
}

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.task.abort();
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
    /// The process-wide correlation ID allocator.
    ///
    /// The listeners are the ingress boundary and allocate `FlowId`s from this allocator;
    /// keeping it on the daemon means the run ID and every flow/query ID share one namespace.
    pub ids: Arc<daer_observe::Ids>,
    /// Live flows, owned apart from the accept loop.
    pub supervisor: Supervisor,
    /// What the datapath could or could not do.
    pub datapath: DatapathStatus,
    /// The relay's counters, when the datagram half is running.
    ///
    /// Readable so a deployment can tell working UDP from silently dropped UDP: without a
    /// counter, "the client says UDP is broken" has no answer that is not a packet capture.
    pub datagram_stats: Option<Arc<DatagramCounters>>,
    /// The transparent UDP socket, when the datagram relay could be bound.
    ///
    /// `None` means the relay is not running, and that is a decision the daemon reports at
    /// `WARN`: a client that believes its UDP is tunnelled and gets silence instead has been
    /// lied to, which is worse than a refusal it can see (ADR-0006).
    pub datagrams: Option<Arc<dyn DatagramIngress>>,
    /// The private ingress and its host-side facts, when the listeners were bound inside it.
    ///
    /// This field owns the guard and is declared **after every socket**: Rust drops fields in
    /// declaration order, so the namespace is removed only after the listening sockets are
    /// closed. Keeping the whole [`crate::netns::PreparedIngress`] here, rather than only the
    /// namespace, means the attach step cannot use a different topology from the one the
    /// listeners were bound in.
    ingress: Option<crate::netns::PreparedIngress>,
}

impl std::fmt::Debug for Daemon {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Daemon")
            .field("port", &self.port)
            .field("datapath", &self.datapath)
            .finish_non_exhaustive()
    }
}

/// Creates UDP reply sockets on the ingress side of the namespace boundary.
///
/// The UDP outbound leg lives in the host, but the reply must be born where the original
/// destination is owned and must leave through `daer0peer`, exactly like a TCP listener
/// reply. `ReplySocketFactory` is the relay's seam for that; this type is the control
/// plane's implementation.
#[derive(Debug)]
struct IngressReplySockets {
    namespace: Arc<crate::netns::IngressNamespace>,
    socket_mark: Option<u32>,
}

impl daer_relay::inbound::ReplySocketFactory for IngressReplySockets {
    fn bind(&self, source: SocketAddr) -> std::io::Result<std::net::UdpSocket> {
        let namespace = Arc::clone(&self.namespace);
        let name = namespace.name().to_owned();
        let socket_mark = self.socket_mark;
        namespace
            .with(move || daer_relay::inbound::bind_reply_socket(source, socket_mark))
            .map_err(|error| {
                std::io::Error::other(format!(
                    "cannot enter {name} to bind a reply socket: {error}"
                ))
            })?
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
        Self::bind_in(config, options, None)
    }

    /// Binds the transparent port inside `ingress`, if one is supplied.
    ///
    /// The ingress is the private namespace from [`crate::netns::PreparedIngress`]. The
    /// listener must be created there: a socket belongs to the network namespace that was
    /// current when it was created, and `bpf_sk_assign` can only hand a packet to a socket
    /// in the namespace the packet is delivered in. The daemon takes ownership of the
    /// ingress so the topology used for binding and the topology used for attachment are
    /// the same value.
    ///
    /// # Errors
    ///
    /// Same as [`Self::bind`]. A failure to enter the namespace is reported as a listener
    /// bind error, because from the caller's point of view the port could not be bound
    /// where it needs to live.
    pub fn bind_in(
        config: &Config,
        options: &RouterOptions,
        ingress: Option<crate::netns::PreparedIngress>,
    ) -> Result<Self, BindError> {
        let namespace = ingress
            .as_ref()
            .map(|ingress| Arc::clone(&ingress.namespace));
        let port = config.global.tproxy_port;
        let protect = config.global.tproxy_port_protect;
        let socket_mark = match options.so_mark {
            Some(mark) => mark,
            None => config.global.so_mark,
        };
        let ids = Arc::new(daer_observe::Ids::new());
        // Bound before the object is loaded: the port is part of `PARAM`, so it has to be
        // known first. Binding does not accept, so no flow is served before the datapath
        // exists.
        let listener = match &namespace {
            Some(namespace) => {
                let handle = tokio::runtime::Handle::current();
                namespace
                    .with(move || {
                        let _entered = handle.enter();
                        TransparentListener::bind_with_options(
                            Ipv4Addr::UNSPECIFIED,
                            port,
                            protect,
                            socket_mark,
                        )
                    })
                    .map_err(|error| BindError::Ingress(RelayError::Socket(error)))?
                    .map_err(BindError::Ingress)?
            }
            None => TransparentListener::bind_with_options(
                Ipv4Addr::UNSPECIFIED,
                port,
                protect,
                socket_mark,
            )
            .map_err(BindError::Ingress)?,
        };
        let listener = listener.with_ids(Arc::clone(&ids));
        let port = listener.port();
        let generations = Generations::new(config, options).map_err(BindError::Config)?;
        // The datagram half. A failure here is not fatal: the box can still proxy TCP, and a
        // daemon that refuses to start because UDP could not bind would take a working proxy
        // down over a secondary transport.
        let datagrams = match &namespace {
            Some(namespace) => {
                let handle = tokio::runtime::Handle::current();
                namespace
                    .with(move || {
                        let _entered = handle.enter();
                        TransparentDatagramListener::bind_with_options(
                            Ipv4Addr::UNSPECIFIED,
                            port,
                            socket_mark,
                        )
                    })
                    .map_err(|error| BindError::Ingress(RelayError::Socket(error)))?
                    .map_err(BindError::Ingress)
            }
            None => TransparentDatagramListener::bind_with_options(
                Ipv4Addr::UNSPECIFIED,
                port,
                socket_mark,
            )
            .map_err(BindError::Ingress),
        };
        let datagrams = match datagrams {
            Ok(listener) => {
                let listener = match &namespace {
                    Some(namespace) => listener.with_reply_factory(Arc::new(IngressReplySockets {
                        namespace: Arc::clone(namespace),
                        socket_mark,
                    })),
                    None => listener,
                }
                .with_ids(Arc::clone(&ids));
                Some(Arc::new(listener) as Arc<dyn DatagramIngress>)
            }
            Err(error) => {
                daer_observe::warn!(daer_observe::EventCode::DaemonUdpUnavailable,
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
            ids,
            supervisor: Supervisor::new(),
            datapath: DatapathStatus::default(),
            datagrams: datagrams.clone(),
            datagram_stats: datagrams.map(|_| Arc::new(DatagramCounters::default())),
            ingress,
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
    pub fn datagram_stats(&self) -> Option<Arc<DatagramCounters>> {
        self.datagram_stats.as_ref().map(Arc::clone)
    }

    /// The private ingress this daemon's listeners were bound in, if any.
    ///
    /// The attach step reads the peer MAC, ifindex and namespace from this value. It is the
    /// same value the bind used, so a caller cannot accidentally attach a different pair.
    #[must_use]
    pub fn ingress(&self) -> Option<&crate::netns::PreparedIngress> {
        self.ingress.as_ref()
    }

    /// The four fds the datapath may assign a redirected flow to.
    ///
    /// # Errors
    ///
    /// Returns a message naming the missing half when a UDP relay could not bind. The
    /// datapath must not be attached in that state: a redirected datagram with no listener
    /// in its `listen_socket_map` slot is shot after the datapath has already taken it off
    /// the direct path, which looks exactly like a network outage.
    pub fn listeners(&self) -> Result<daer_ebpf::Listeners, String> {
        let Some(datagrams) = self.datagrams.as_ref() else {
            return Err(
                "the UDP relay is not bound, so the datapath has no datagram listener to \
                 assign a redirected datagram to; refusing to attach rather than dropping \
                 every UDP flow (see the WARN about the datagram socket)"
                    .to_owned(),
            );
        };
        let Some(udp4) = datagrams.raw_fd() else {
            return Err(
                "the datagram ingress cannot expose an IPv4 socket fd, so the datapath \
                 cannot assign redirected IPv4 datagrams to it"
                    .to_owned(),
            );
        };
        let Some(udp6) = datagrams.raw_fd_v6() else {
            return Err(
                "the datagram ingress cannot expose an IPv6 socket fd, so the datapath \
                 cannot assign redirected IPv6 datagrams to it"
                    .to_owned(),
            );
        };
        Ok(daer_ebpf::Listeners {
            tcp4: self.listener.raw_fd_v4(),
            udp4,
            tcp6: self.listener.raw_fd_v6(),
            udp6,
        })
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
    ) -> Result<(), RelayError> {
        // The generation is re-read per flow, so a reload is visible to the next flow
        // without restarting the loop.
        let supervisor = self.supervisor.clone();
        let loop_router = Arc::new(RouterForGeneration {
            generations: Arc::clone(&self.generations),
        });
        let Some(ingress) = self.datagrams.as_ref() else {
            // No datagram socket: TCP only, which is what `Daemon::bind` reported at `WARN`.
            serve_parallel(&self.listener, loop_router, &supervisor, shutdown).await?;
            return Ok(());
        };

        // Both halves need to observe the same shutdown, and a `Future` is not `Clone`, so it is
        // driven once inside a broadcast: the TCP loop and the datagram relay each hold a
        // receiver and stop when the sender fires.
        let service = DatagramService {
            ingress: Arc::clone(ingress),
            router: Arc::new(DatagramRouterForGeneration {
                generations: Arc::clone(&self.generations),
            }),
            options: RelayOptions::default(),
            stats: self
                .datagram_stats
                .as_ref()
                .map_or_else(|| Arc::new(DatagramCounters::default()), Arc::clone),
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
        // The datagram relay runs in its own task, not inside the `join!` that drives the TCP
        // accept loop. The two services share a runtime but must not share a task: a slow or
        // blocking UDP operation must never stop the accept loop from polling `accept(2)`.
        // TCP is the service that must remain responsive; UDP has its own lifecycle.
        let udp = {
            let signal = Arc::clone(&signal);
            signal.notified_owned()
        };
        let udp_task = AbortOnDrop::new(tokio::spawn(async move {
            let result = daer_relay::relay::serve_datagrams(
                service.ingress,
                service.router,
                service.options,
                service.stats,
                udp,
            )
            .await;
            if let Err(error) = result {
                daer_observe::warn!(daer_observe::EventCode::DaemonUdpUnavailable,%error, "the datagram relay stopped");
            }
        }));
        let (stopped, ()) = tokio::join!(
            serve_parallel(&self.listener, Arc::clone(&loop_router), &supervisor, tcp),
            trigger,
        );
        // The UDP task observes the same notification. Stop it explicitly so an in-flight
        // datagram operation cannot outlive the daemon's ingress.
        udp_task.stop().await;
        stopped?;
        let stats = self.stats();
        daer_observe::info!(
            daer_observe::EventCode::FlowAcceptStopped,
            accepted = stats.accepted,
            rejected = stats.rejected,
            failed = stats.failed,
            "relay accept loop stopped"
        );
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
    Ingress(RelayError),
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

/// A [`Decide`](Decide) that reads the *current* generation per flow.
///
/// Without this the loop would hold the router of the generation it started with, and a
/// reload would change nothing until the loop restarted — which is exactly the connection
/// drop a reload is supposed to avoid.
struct RouterForGeneration {
    generations: Arc<Generations>,
}

impl Decide for RouterForGeneration {
    type Upstream = <Router as Decide>::Upstream;
    type Future<'a>
        = <Router as Decide>::Future<'a>
    where
        Self: 'a;

    fn decide<'a>(&'a self, flow: &'a daer_relay::Accepted) -> Self::Future<'a> {
        // `current()` is an atomic read of an `Arc`, so this is cheap on the hot path. The
        // `Arc` is moved into the future: it is what pins this flow to the rules it arrived
        // under, even if a reload swaps the generation while the flow is being opened.
        let generation = self.generations.current();
        Box::pin(async move {
            let router = generation.router();
            Decide::decide(router, flow).await
        })
    }
}

/// A [`DatagramRouter`](daer_relay::DatagramRouter) that reads the *current* generation
/// per session.
///
/// The datagram half had no equivalent of [`RouterForGeneration`]: it captured one
/// `Arc<Router>` when the relay started, so a `SIGHUP` reload changed nothing for UDP. New
/// datagram flows kept being routed by the rules the process booted with, silently and
/// indefinitely, while TCP followed the new file.
struct DatagramRouterForGeneration {
    generations: Arc<Generations>,
}

impl std::fmt::Debug for DatagramRouterForGeneration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DatagramRouterForGeneration(..)")
    }
}

impl daer_relay::DatagramRouter for DatagramRouterForGeneration {
    fn known_domain(&self, destination: SocketAddr) -> Option<String> {
        self.generations
            .current()
            .router()
            .known_domain(destination)
    }

    fn open_datagram<'a>(
        &'a self,
        facts: FlowFacts,
        domain: Option<&'a str>,
    ) -> daer_relay::OpenDatagram<'a> {
        // The generation is pinned into an `Arc` *before* the future is created: it is what
        // keeps this session's rules alive, and what stops a reload landing between the
        // verdict and the dial from changing where the flow goes.
        let generation = self.generations.current();
        Box::pin(async move {
            let router = generation.router();
            let verdict = router.verdict_for_datagram(facts, domain);
            router
                .open_datagram(facts, &verdict, domain)
                .await
                .map_err(|error| match error {
                    RelayError::Dial { failure, .. } => failure,
                    other => daer_observe::DialFailure::new(
                        daer_observe::DialStage::Policy,
                        daer_observe::diagnostic::codes::INTERNAL,
                        other.to_string(),
                    ),
                })
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
            daer_observe::info!(daer_observe::EventCode::DaemonWanDetected,interface = %detected, "detected the WAN interface");
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
