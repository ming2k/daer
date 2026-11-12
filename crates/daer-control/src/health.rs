// SPDX-License-Identifier: AGPL-3.0-only

//! The health-check scheduler: what turns measured latency into a selection.
//!
//! Before this module existed, `HttpChecker`, `TcpChecker` and `UdpDnsChecker` were all
//! implemented and none was ever called — the `udp-dns` configuration row was a field with
//! no reader. A group's `policy` (`min-moving-avg`, `min-latency`, …) selects from
//! *measured* state, so without a scheduler every group was permanently empty and
//! `select()` returned `None`: the daemon could route but never choose.
//!
//! # What is probed, and with which instrument
//!
//! A probe's job is to answer "can this node carry my traffic, and how fast". The
//! instrument follows from what the node claims:
//!
//! * a node that reports **UDP** support is probed with [`UdpDnsChecker`], because a
//!   TCP-only probe would report a node healthy while every datagram it carries is
//!   dropped;
//! * otherwise the **TCP** probe is used, which every TCP-capable node answers.
//!
//! The HTTP probe is deliberately not the default: it measures a request/response, which
//! mixes in the node's own HTTP path and the check URL's origin. A bare handshake (or a
//! single DNS answer) is the smallest thing that still proves reachability, and it is what
//! the node's latency means for the routing decision.
//!
//! # Why the results go to the generation, not to a copy
//!
//! [`Scheduler::record`] writes into the [`Router`] that flows are currently selecting
//! from. Recording into a detached copy would measure one thing and select from another —
//! the classic "healthy in the dashboard, dead in the datapath" failure.
//!
//! # Interval and tolerance
//!
//! `check-interval` is the tick; `check-tolerance` shifts the switching threshold between
//! the best node and the current one, so a node does not flip on a 1 ms difference. Both
//! come from the configuration, and a zero interval disables probing entirely (which is
//! the right shape for a test or a single-node configuration).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use daer_config::{ProbeMode, ProbeSettings, TimeSpan};
use daer_outbound::{
    CheckError, CheckUrl, DialerId, HttpChecker, Protocol, TcpChecker, UdpDnsChecker,
};
use tokio::sync::Mutex;

use crate::decide::Router;

/// One node to probe, resolved from its link.
#[derive(Debug, Clone)]
pub struct ProbeTarget {
    /// The election this candidate belongs to.
    pub election: String,
    /// The node's identity within the election.
    pub dialer: DialerId,
    /// Its name, for diagnostics.
    pub name: String,
    /// The literal address to probe, when the node has one.
    ///
    /// `None` for a domain-named node. A detoured node is still probeable: the name is passed
    /// to the chain's own resolver, which is the same resolution the data path uses.
    pub address: Option<SocketAddr>,
    /// Whether the node claims to carry datagrams.
    pub udp: bool,
    /// The live node dialer, so a detoured probe can open the chain to the node's server.
    pub node: Arc<daer_outbound::NodeDialer>,
    /// The election's effective probe settings.
    pub probe: ProbeSettings,
}

/// Why a probe attempt did not produce a latency.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeFailure {
    /// The node's link has no resolvable `host:port` to probe.
    MissingAddress(String),
    /// The node speaks a protocol this build cannot probe without opening a session.
    Unsupported(Protocol),
    /// The probe ran and failed.
    Check(CheckError),
    /// The probe could not open the detour chain to the node's server.
    Chain(String),
}

impl std::fmt::Display for ProbeFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingAddress(name) => {
                write!(f, "node {name:?} has no address to probe")
            }
            Self::Unsupported(protocol) => write!(
                f,
                "node protocol {:?} cannot be probed without opening a session",
                protocol.as_str()
            ),
            Self::Check(error) => write!(f, "{error}"),
            Self::Chain(message) => write!(f, "detour chain: {message}"),
        }
    }
}

/// The result of one node's probe.
#[derive(Debug, Clone)]
pub struct ProbeResult {
    /// Which node.
    pub target: ProbeTarget,
    /// The measured latency, when the node answered.
    pub latency: Option<TimeSpan>,
    /// Why it did not, when it did not.
    pub failure: Option<ProbeFailure>,
}

impl ProbeResult {
    /// Whether the node answered.
    #[must_use]
    pub const fn is_alive(&self) -> bool {
        self.latency.is_some()
    }
}

impl From<daer_outbound::OutboundError> for ProbeFailure {
    fn from(error: daer_outbound::OutboundError) -> Self {
        Self::Chain(error.to_string())
    }
}

/// What a server-mode probe uses.
///
/// A URL-mode probe does not use this value: it establishes a session through the
/// node and asks the URL through netune's HTTP client. The distinction is explicit in
/// [`ProbeMode`], not inferred from a list's first entry.
#[derive(Debug)]
pub struct ProbeInstruments {
    pub tcp: TcpChecker,
    /// The UDP DNS endpoints a datagram-carrying node is probed against.
    pub udp_dns: Vec<SocketAddr>,
    pub udp: UdpDnsChecker,
    /// `udp-dns` entries that are names rather than addresses, reported rather than dropped.
    pub unresolved_udp: Vec<String>,
}

/// Splits `host:port` or `[v6]:port` without resolving anything.
fn split_host_port(entry: &str) -> Option<(&str, u16)> {
    let entry = entry.trim();
    if let Some(rest) = entry.strip_prefix('[') {
        let (host, rest) = rest.split_once(']')?;
        let port = rest.strip_prefix(':')?.parse().ok()?;
        return Some((host, port));
    }
    let (host, port) = entry.rsplit_once(':')?;
    if host.contains(':') {
        return None;
    }
    Some((host, port.parse().ok()?))
}

impl ProbeInstruments {
    /// Instruments that probe each node on its own address and nothing else.
    #[must_use]
    pub fn default_for(interval: Duration) -> Self {
        let timeout = probe_timeout(interval);
        Self {
            tcp: TcpChecker::new(timeout),
            udp_dns: Vec::new(),
            udp: UdpDnsChecker::new(timeout),
            unresolved_udp: Vec::new(),
        }
    }

    /// Builds the server-mode instruments an election asks for.
    #[must_use]
    pub fn from_settings(
        settings: &ProbeSettings,
        socket_config: daer_outbound::SocketConfig,
    ) -> Self {
        let timeout = settings
            .timeout
            .as_std()
            .unwrap_or_else(|| Duration::from_secs(5));
        let mut udp_dns = Vec::new();
        let mut unresolved_udp = Vec::new();
        for entry in &settings.udp_dns {
            if let Ok(ip) = entry.parse::<std::net::IpAddr>() {
                udp_dns.push(SocketAddr::new(ip, 53));
                continue;
            }
            match split_host_port(entry) {
                Some((host, port)) => match host.parse::<std::net::IpAddr>() {
                    Ok(ip) => udp_dns.push(SocketAddr::new(ip, port)),
                    Err(_) => unresolved_udp.push(entry.clone()),
                },
                None => unresolved_udp.push(entry.clone()),
            }
        }
        Self {
            tcp: TcpChecker::new(timeout).with_socket_config(socket_config.clone()),
            udp_dns,
            udp: UdpDnsChecker::new(timeout).with_socket_config(socket_config),
            unresolved_udp,
        }
    }
}

/// Runs probes and records their results into a routing generation.
pub struct Scheduler {
    router: Arc<Router>,
    interval: Duration,
    socket_config: daer_outbound::SocketConfig,
    /// Test-only override for server-mode instruments.
    forced: Option<ProbeInstruments>,
    write: Mutex<()>,
    /// Last time each candidate was probed, so a slower election is not hammered at the
    /// shortest tick.
    last: Mutex<std::collections::HashMap<(String, DialerId), std::time::Instant>>,
}

impl std::fmt::Debug for Scheduler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Scheduler")
            .field("interval", &self.interval)
            .finish_non_exhaustive()
    }
}

impl Scheduler {
    /// Builds a scheduler for one routing generation.
    #[must_use]
    pub fn new(router: Arc<Router>, interval: Duration) -> Self {
        let socket_config = daer_outbound::SocketConfig {
            mark: router.socket_mark(),
            ..daer_outbound::SocketConfig::default()
        };
        Self {
            router,
            interval,
            socket_config,
            forced: None,
            write: Mutex::new(()),
            last: Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Builds a scheduler whose server-mode probes use `instruments`.
    #[must_use]
    pub fn with_instruments(
        router: Arc<Router>,
        interval: Duration,
        instruments: ProbeInstruments,
    ) -> Self {
        let mut scheduler = Self::new(router, interval);
        scheduler.forced = Some(instruments);
        scheduler
    }

    /// The generation this scheduler reports into.
    #[must_use]
    pub fn router(&self) -> &Arc<Router> {
        &self.router
    }

    /// Every node that can be probed, across every election.
    #[must_use]
    pub fn targets(&self) -> Vec<ProbeTarget> {
        let mut targets = Vec::new();
        for (election, rows) in self.router.elections_for_probes() {
            for row in rows {
                if row.address.is_none() && row.node.detour().is_none() {
                    daer_observe::debug!(daer_observe::EventCode::HealthNodeUnprobeable,%election, %row.name, "node has no literal address; not probed");
                    continue;
                }
                targets.push(ProbeTarget {
                    election: election.clone(),
                    dialer: row.dialer,
                    name: row.name,
                    address: row.address,
                    udp: row.udp,
                    node: row.node,
                    probe: row.probe,
                });
            }
        }
        targets
    }

    /// Probes one node with the instrument its claims require.
    ///
    /// A node that claims UDP support is probed over UDP: a TCP probe would report it
    /// healthy while its datagrams are dropped, which is exactly the failure a health
    /// check exists to catch.
    pub async fn probe(&self, target: &ProbeTarget) -> ProbeResult {
        let timeout = target
            .probe
            .timeout
            .as_std()
            .unwrap_or_else(|| Duration::from_secs(5));

        // A URL-mode probe goes *through* the node. This is the Clash `url-test`
        // semantic: establishing the proxy session and asking the URL through it is
        // the only measurement that proves the node can carry traffic, not merely
        // that its server port accepts a connection.
        if target.probe.mode == ProbeMode::Url {
            let Some(raw) = &target.probe.url else {
                return ProbeResult {
                    target: clone_target(target),
                    latency: None,
                    failure: Some(ProbeFailure::Check(CheckError::InvalidUrl(
                        "mode = \"url\" without a URL".to_owned(),
                    ))),
                };
            };
            let url = match CheckUrl::parse(raw) {
                Ok(url) => url,
                Err(error) => {
                    return ProbeResult {
                        target: clone_target(target),
                        latency: None,
                        failure: Some(ProbeFailure::Check(error)),
                    };
                }
            };
            let method =
                daer_outbound::HttpMethod::parse(&target.probe.method).unwrap_or_else(|error| {
                    daer_observe::warn!(
                        daer_observe::EventCode::ElectionProbeMethodInvalid,
                        %error,
                        method = %target.probe.method,
                        "health check: unusable method; falling back to HEAD"
                    );
                    daer_outbound::HttpMethod::Head
                });
            let checker =
                HttpChecker::new(method, timeout).with_socket_config(self.socket_config.clone());
            let outcome = tokio::time::timeout(timeout, async {
                let established = target.node.connect(&url.authority()).await?;
                checker
                    .check_through(established, &url)
                    .await
                    .map_err(ProbeFailure::Check)
            })
            .await;
            return match outcome {
                Ok(Ok(latency)) => ProbeResult {
                    target: clone_target(target),
                    latency: Some(latency),
                    failure: None,
                },
                Ok(Err(failure)) => ProbeResult {
                    target: clone_target(target),
                    latency: None,
                    failure: Some(failure),
                },
                Err(_) => ProbeResult {
                    target: clone_target(target),
                    latency: None,
                    failure: Some(ProbeFailure::Check(CheckError::Timeout)),
                },
            };
        }

        // A detoured node's liveness is the chain's liveness. Measuring its server directly
        // would report a node dead precisely when the detour is doing its job, and a
        // stream-carried UDP protocol shares the same chain anyway (ADR-0044).
        if target.node.detour().is_some() {
            let started = std::time::Instant::now();
            let outcome = tokio::time::timeout(
                timeout,
                target
                    .node
                    .probe_server(&daer_outbound::TraceCollector::disabled()),
            )
            .await;
            return match outcome {
                Ok(Ok(established)) => {
                    let elapsed = started.elapsed();
                    drop(established);
                    ProbeResult {
                        target: clone_target(target),
                        latency: Some(TimeSpan::from_nanos(elapsed.as_nanos() as i64)),
                        failure: None,
                    }
                }
                Ok(Err(error)) => ProbeResult {
                    target: clone_target(target),
                    latency: None,
                    failure: Some(ProbeFailure::Chain(error.to_string())),
                },
                Err(_) => ProbeResult {
                    target: clone_target(target),
                    latency: None,
                    failure: Some(ProbeFailure::Check(CheckError::Timeout)),
                },
            };
        }

        let address = target
            .address
            .expect("probe target has an address or a detour");
        let latency = if let Some(instruments) = &self.forced {
            server_probe(instruments, target, address).await
        } else {
            let instruments =
                ProbeInstruments::from_settings(&target.probe, self.socket_config.clone());
            if !instruments.unresolved_udp.is_empty() {
                daer_observe::debug!(daer_observe::EventCode::ElectionProbeUdpName,
                    entries = ?instruments.unresolved_udp,
                    "health check: udp-dns entries that are names are not probed"
                );
            }
            server_probe(&instruments, target, address).await
        };
        match latency {
            Ok(latency) => ProbeResult {
                target: clone_target(target),
                latency: Some(latency),
                failure: None,
            },
            Err(error) => ProbeResult {
                target: clone_target(target),
                latency: None,
                failure: Some(ProbeFailure::Check(error)),
            },
        }
    }

    /// Records one result into the generation.
    ///
    /// # Errors
    ///
    /// Returns the router's error when the election or dialer has gone away (a reload
    /// replaced this generation), which the caller treats as "this scheduler is stale".
    pub async fn record(&self, result: &ProbeResult) -> Result<(), daer_outbound::OutboundError> {
        let _guard = self.write.lock().await;
        self.router.record(
            &result.target.election,
            result.target.dialer,
            result.is_alive(),
            result.latency,
        )?;
        Ok(())
    }

    /// Probes every target that is due and records the results.
    pub async fn sweep(&self) -> Vec<ProbeResult> {
        let now = std::time::Instant::now();
        let targets: Vec<ProbeTarget> = {
            let last = self.last.lock().await;
            self.targets()
                .into_iter()
                .filter(|target| {
                    let interval = target.probe.interval.as_std().unwrap_or(Duration::ZERO);
                    if interval.is_zero() {
                        return false;
                    }
                    last.get(&(target.election.clone(), target.dialer))
                        .is_none_or(|previous| now.duration_since(*previous) >= interval)
                })
                .collect()
        };
        if targets.is_empty() {
            return Vec::new();
        }
        // Concurrent, because a sweep of N nodes must take one probe timeout, not N.
        let results = probe_all(self, &targets).await;
        for result in &results {
            self.last
                .lock()
                .await
                .insert((result.target.election.clone(), result.target.dialer), now);
            if let Err(error) = self.record(result).await {
                daer_observe::warn!(daer_observe::EventCode::HealthProbeRecordFailed,
                    %error,
                    election = %result.target.election,
                    node = %result.target.name,
                    "probe result could not be recorded; this generation is stale"
                );
                break;
            }
            match (&result.latency, &result.failure) {
                (Some(latency), _) => {
                    daer_observe::trace!(daer_observe::EventCode::HealthNodeAlive,
                        election = %result.target.election,
                        node = %result.target.name,
                        latency_ns = latency.as_nanos(),
                        "node alive"
                    )
                }
                (None, Some(failure)) => {
                    daer_observe::warn!(daer_observe::EventCode::HealthProbeFailed,
                        election = %result.target.election,
                        node = %result.target.name,
                        %failure,
                        "node probe failed"
                    )
                }
                (None, None) => {}
            }
        }
        results
    }

    /// Runs sweeps until `shutdown` resolves.
    ///
    /// The first sweep happens immediately: a daemon that waits one full interval before
    /// probing has no selectable node for that interval, which is exactly when it most
    /// needs one.
    pub async fn run(self, shutdown: impl std::future::Future<Output = ()>) {
        if self.interval.is_zero() {
            daer_observe::debug!(
                daer_observe::EventCode::HealthProbingDisabled,
                "health probing disabled (check-interval is zero)"
            );
            return;
        }
        let mut ticker = tokio::time::interval(self.interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                () = &mut shutdown => {
                    daer_observe::info!(daer_observe::EventCode::HealthSchedulerStopped,"health scheduler stopped");
                    return;
                }
                _ = ticker.tick() => {
                    self.sweep().await;
                }
            }
        }
    }
}

/// Runs the server-mode liveness probe.
///
/// A datagram-carrying node is measured over UDP: a TCP probe would report it healthy
/// while its datagrams are dropped. The endpoints come from the election's `udp-dns`;
/// otherwise the node's own address is used.
async fn server_probe(
    instruments: &ProbeInstruments,
    target: &ProbeTarget,
    address: SocketAddr,
) -> Result<TimeSpan, CheckError> {
    if target.udp {
        let endpoints: Vec<SocketAddr> = if instruments.udp_dns.is_empty() {
            vec![address]
        } else {
            instruments.udp_dns.clone()
        };
        let mut last = None;
        for endpoint in &endpoints {
            match instruments.udp.check(*endpoint).await {
                Ok(latency) => return Ok(latency),
                Err(error) => last = Some(error),
            }
        }
        Err(last.unwrap_or(CheckError::Timeout))
    } else {
        instruments.tcp.check(address).await
    }
}

/// The probe deadline for one tick.
///
/// A quarter of the interval, floored at 200 ms: long enough for a slow node to answer, and
/// short enough that a dead node has failed long before the next tick starts.
fn probe_timeout(interval: Duration) -> Duration {
    (interval / 4).max(Duration::from_millis(200))
}

/// Runs every probe concurrently and collects the results that finished.
///
/// `probe` borrows the scheduler, so the futures cannot be spawned. They are collected into
/// a `Vec` and driven together, which gives a sweep of N nodes one probe timeout rather
/// than N — the property that matters when a group has twenty nodes and the interval is
/// thirty seconds.
async fn probe_all(scheduler: &Scheduler, targets: &[ProbeTarget]) -> Vec<ProbeResult> {
    use std::future::Future;
    use std::pin::Pin;
    use std::task::Poll;

    let mut futures: Vec<Pin<Box<dyn Future<Output = ProbeResult> + Send + '_>>> = targets
        .iter()
        .map(|target| {
            let future: Pin<Box<dyn Future<Output = ProbeResult> + Send + '_>> =
                Box::pin(scheduler.probe(target));
            future
        })
        .collect();
    let mut results = Vec::with_capacity(futures.len());
    let mut pending = futures.len();
    let mut done = vec![false; futures.len()];

    std::future::poll_fn(|context| {
        for (index, future) in futures.iter_mut().enumerate() {
            if done[index] {
                continue;
            }
            if let Poll::Ready(result) = future.as_mut().poll(context) {
                results.push(result);
                done[index] = true;
                pending -= 1;
            }
        }
        if pending == 0 {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    })
    .await;
    results
}

fn clone_target(target: &ProbeTarget) -> ProbeTarget {
    ProbeTarget {
        election: target.election.clone(),
        dialer: target.dialer,
        name: target.name.clone(),
        address: target.address,
        udp: target.udp,
        node: Arc::clone(&target.node),
        probe: target.probe.clone(),
    }
}

/// Spawns a scheduler for `router` unless probing is disabled or there is nothing probe.
///
/// Returns `None` when every election disables probing or when no node has a literal
/// address to probe.
#[must_use]
pub fn spawn(
    router: Arc<Router>,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> Option<tokio::task::JoinHandle<()>> {
    let interval = shortest_interval(&router).unwrap_or(Duration::ZERO);
    if interval.is_zero() || !has_measurable_nodes(&router) {
        daer_observe::debug!(
            daer_observe::EventCode::DaemonHealthDisabled,
            probes = with_interval(interval),
            "health probing not started; see election probe intervals and node addresses"
        );
        return None;
    }
    let scheduler = Scheduler::new(router, interval);
    let mut shutdown = shutdown;
    Some(tokio::spawn(async move {
        let stopped = async move {
            while shutdown.changed().await.is_ok() {
                if *shutdown.borrow() {
                    return;
                }
            }
        };
        scheduler.run(stopped).await;
    }))
}

fn shortest_interval(router: &Router) -> Option<Duration> {
    router
        .elections_for_probes()
        .into_iter()
        .flat_map(|(_, rows)| rows)
        .filter_map(|row| row.probe.interval.as_std())
        .filter(|interval| !interval.is_zero())
        .min()
}

fn with_interval(interval: Duration) -> String {
    if interval.is_zero() {
        "disabled by every election probe interval".to_owned()
    } else {
        format!("{interval:?}")
    }
}

/// Builds the probe table for a router without exposing the election internals.
impl Router {
    /// Every probe target, grouped by election name.
    #[must_use]
    pub fn probe_table(&self) -> Vec<(String, Vec<crate::decide::ProbeRow>)> {
        self.elections_for_probes()
    }
}

/// Whether a checker's policy needs measurement at all.
///
/// A manual election does not rank candidates; `daer probe` is the on-demand path for a
/// pinned node. Random needs liveness even though it does not rank latency.
#[must_use]
pub fn policy_needs_measurement(policy: daer_common::SelectionPolicy) -> bool {
    !matches!(policy, daer_common::SelectionPolicy::Manual)
}

/// A node that a group cannot measure is still selectable by `fixed(0)`; this reports
/// whether `Scheduler` would have anything to do.
#[must_use]
pub fn has_measurable_nodes(router: &Router) -> bool {
    router
        .probe_table()
        .iter()
        .any(|(_, rows)| !rows.is_empty())
}

/// A dialer that could not be resolved to a probe address.
#[must_use]
pub fn unresolvable(target: &ProbeTarget) -> ProbeFailure {
    ProbeFailure::MissingAddress(target.name.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UdpSocket;

    fn router(src: &str) -> Arc<Router> {
        let config = daer_config::toml_config::load_str(src).expect("config loads");
        Arc::new(
            Router::new(
                &config,
                crate::GenerationId::new(1),
                &crate::RouterOptions::default(),
            )
            .expect("router builds"),
        )
    }

    #[test]
    fn a_probe_timeout_is_a_fraction_of_the_interval_but_never_below_200ms() {
        assert_eq!(
            probe_timeout(Duration::from_secs(30)),
            Duration::from_millis(7500)
        );
        assert_eq!(
            probe_timeout(Duration::from_millis(100)),
            Duration::from_millis(200)
        );
    }

    #[test]
    fn a_manual_policy_is_not_measured() {
        // `fixed(n)` is explicit intent; a probe must not rewrite it.
        assert!(!policy_needs_measurement(
            daer_common::SelectionPolicy::Manual
        ));
        assert!(policy_needs_measurement(
            daer_common::SelectionPolicy::MinMovingAverage
        ));
    }

    #[test]
    fn a_node_without_a_literal_address_is_skipped_rather_than_guessed() {
        // A domain-named node would need its own resolution; a probe that resolved
        // differently from the data path would measure the wrong destination.
        let router = router(
            "schema = 2\n\n[[node]]\nname = \"n\"\ntype = \"socks5\"\nserver = \"example.com\"\nport = 1080\n\n\
             [[group]]\nname = \"gg\"\n\n[[election]]\nname = \"g\"\ngroup = \"gg\"\ntype = \"min-moving-avg\"\n\n\
             [routing]\nrules = []\nfallback = \"g\"\n",
        );
        let scheduler = Scheduler::new(router, Duration::from_secs(30));
        assert!(
            scheduler.targets().is_empty(),
            "a domain-named node must not be probed by guessing an address"
        );
    }

    #[tokio::test]
    async fn a_node_is_probed_with_the_instrument_its_claims_require() {
        // A `socks5` node carries datagrams, so the probe is a DNS exchange, not a TCP
        // handshake: a TCP probe would report it healthy while its datagrams are dropped.
        let socket = UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("binds");
        let address = socket.local_addr().expect("addr");
        tokio::spawn(async move {
            let mut buffer = [0u8; 512];
            while let Ok((received, from)) = socket.recv_from(&mut buffer).await {
                let mut reply = buffer[..received].to_vec();
                if reply.len() > 2 {
                    reply[2] |= 0x80;
                }
                if socket.send_to(&reply, from).await.is_err() {
                    return;
                }
            }
        });

        let ip = address.ip();
        let port = address.port();
        let router = router(&format!(
            "schema = 2\n\n[[node]]\nname = \"n\"\ntype = \"socks5\"\nserver = \"{ip}\"\nport = {port}\n\n\
             [[group]]\nname = \"gg\"\n\n[[election]]\nname = \"g\"\ngroup = \"gg\"\ntype = \"min-moving-avg\"\n\n\
             [routing]\nrules = []\nfallback = \"g\"\n"
        ));
        let scheduler = Scheduler::with_instruments(
            Arc::clone(&router),
            Duration::from_secs(30),
            ProbeInstruments::default_for(Duration::from_secs(30)),
        );
        let targets = scheduler.targets();
        assert_eq!(targets.len(), 1, "the literal address is probeable");
        assert!(targets[0].udp, "a socks5 node claims UDP support");

        let result = scheduler.probe(&targets[0]).await;
        assert!(
            result.is_alive(),
            "a listening node must answer: {result:?}"
        );
        assert!(result.latency.expect("latency").as_nanos() > 0);

        scheduler.record(&result).await.expect("records");
        // The selection now has measured state, which is the whole point.
        assert!(
            router.has_selection("g"),
            "a measured node must be selectable"
        );
    }

    #[test]
    fn a_manual_election_has_nothing_to_probe() {
        // A manual election does not rank candidates; probing it would only rewrite a
        // choice the operator made.
        let router = router(
            "schema = 2\n\n[[node]]\nname = \"n\"\ntype = \"socks5\"\nserver = \"127.0.0.1\"\nport = 9\n\n\
             [[election]]\nname = \"g\"\nnode = \"n\"\ntype = \"manual\"\n\n\
             [routing]\nrules = []\nfallback = \"g\"\n",
        );
        assert!(
            router.probe_table().is_empty(),
            "a manual election must not contribute probe rows"
        );
        let scheduler = Scheduler::new(router, Duration::from_secs(30));
        assert!(scheduler.targets().is_empty());
    }

    #[test]
    fn a_bare_udp_dns_address_uses_the_conventional_port() {
        let check = daer_config::ProbeSettings {
            udp_dns: vec!["dns.google:53".to_owned(), "8.8.8.8".to_owned()],
            ..daer_config::ProbeSettings::default()
        };
        let instruments =
            ProbeInstruments::from_settings(&check, daer_outbound::SocketConfig::default());
        assert!(
            instruments
                .udp_dns
                .contains(&"8.8.8.8:53".parse().expect("addr")),
            "{:?}",
            instruments.udp_dns
        );
        assert!(
            !instruments.udp_dns.is_empty(),
            "the literal default must be usable: {:?}",
            instruments.udp_dns
        );
        assert!(
            instruments
                .unresolved_udp
                .iter()
                .any(|entry| entry.starts_with("dns.google")),
            "a name is reported, never silently resolved: {:?}",
            instruments.unresolved_udp
        );
    }

    #[tokio::test]
    async fn a_node_that_claims_udp_is_probed_over_udp() {
        // The failure this prevents: a TCP probe passes while every datagram is dropped.
        let socket = UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("binds");
        let address = socket.local_addr().expect("addr");
        tokio::spawn(async move {
            let mut buffer = [0u8; 512];
            while let Ok((received, from)) = socket.recv_from(&mut buffer).await {
                let mut reply = buffer[..received].to_vec();
                if reply.len() > 2 {
                    reply[2] |= 0x80; // QR: a DNS response
                }
                if socket.send_to(&reply, from).await.is_err() {
                    return;
                }
            }
        });

        let ip = address.ip();
        let port = address.port();
        let router = router(&format!(
            "schema = 2\n\n[[node]]\nname = \"n\"\ntype = \"socks5\"\nserver = \"{ip}\"\nport = {port}\n\n\
             [[group]]\nname = \"gg\"\n\n[[election]]\nname = \"g\"\ngroup = \"gg\"\ntype = \"min-moving-avg\"\n\n\
             [routing]\nrules = []\nfallback = \"g\"\n"
        ));
        let scheduler = Scheduler::with_instruments(
            Arc::clone(&router),
            Duration::from_secs(30),
            ProbeInstruments::default_for(Duration::from_secs(30)),
        );
        let mut targets = scheduler.targets();
        assert_eq!(targets.len(), 1);
        // SOCKS5 carries datagrams, so the probe must use the UDP instrument.
        assert!(targets[0].udp, "a socks5 node claims UDP support");
        targets[0].udp = true;

        let result = scheduler.probe(&targets[0]).await;
        assert!(result.is_alive(), "the DNS stand-in answers: {result:?}");
    }

    #[tokio::test]
    async fn a_dead_node_is_recorded_as_not_alive_rather_than_omitted() {
        // Recording a failure is what removes a node from selection; skipping it would
        // leave a dead node alive forever.
        let router = router(
            "schema = 2\n\n[[node]]\nname = \"n\"\ntype = \"socks5\"\nserver = \"127.0.0.1\"\nport = 9\n\n\
             [[group]]\nname = \"gg\"\n\n[[election]]\nname = \"g\"\ngroup = \"gg\"\ntype = \"min-moving-avg\"\n\n\
             [routing]\nrules = []\nfallback = \"g\"\n",
        );
        let scheduler = Scheduler::with_instruments(
            Arc::clone(&router),
            Duration::from_secs(30),
            ProbeInstruments::default_for(Duration::from_secs(30)),
        );
        let targets = scheduler.targets();
        assert_eq!(targets.len(), 1);

        let result = scheduler.probe(&targets[0]).await;
        assert!(!result.is_alive());
        assert!(result.failure.is_some());
        scheduler.record(&result).await.expect("records");
        assert!(
            !router.has_selection("g"),
            "a dead node must not be selectable"
        );
    }

    #[tokio::test]
    async fn a_zero_interval_disables_probing_entirely() {
        let router = router(
            "schema = 2\n\n[[node]]\nname = \"n\"\ntype = \"socks5\"\nserver = \"127.0.0.1\"\nport = 9\n\n\
             [[election]]\nname = \"g\"\nnode = \"n\"\ntype = \"manual\"\n\n\
             [routing]\nrules = []\nfallback = \"g\"\n",
        );
        let scheduler = Scheduler::new(router, Duration::ZERO);
        // Returns rather than ticking: a test or a single-node configuration must not
        // spawn a prober.
        scheduler.run(std::future::pending::<()>()).await;
    }

    #[tokio::test]
    async fn a_sweep_probes_every_target_and_records_all_results() {
        async fn answering_dns() -> std::net::SocketAddr {
            let socket = UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("binds");
            let address = socket.local_addr().expect("addr");
            tokio::spawn(async move {
                let mut buffer = [0u8; 512];
                while let Ok((received, from)) = socket.recv_from(&mut buffer).await {
                    let mut reply = buffer[..received].to_vec();
                    if reply.len() > 2 {
                        reply[2] |= 0x80;
                    }
                    if socket.send_to(&reply, from).await.is_err() {
                        return;
                    }
                }
            });
            address
        }
        let a = answering_dns().await;
        let b = answering_dns().await;

        let router = router(&format!(
            "schema = 2\n\n\
             [[node]]\nname = \"a\"\ntype = \"socks5\"\nserver = \"{}\"\nport = {}\n\
             [[node]]\nname = \"b\"\ntype = \"socks5\"\nserver = \"{}\"\nport = {}\n\n\
             [[group]]\nname = \"gg\"\n\n[[election]]\nname = \"g\"\ngroup = \"gg\"\ntype = \"min-moving-avg\"\n\n\
             [routing]\nrules = []\nfallback = \"g\"\n",
            a.ip(),
            a.port(),
            b.ip(),
            b.port()
        ));
        let scheduler = Scheduler::new(Arc::clone(&router), Duration::from_secs(30));
        let results = scheduler.sweep().await;
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(ProbeResult::is_alive), "{results:?}");
        assert!(router.has_selection("g"));
    }

    #[test]
    fn a_detoured_node_is_probeable_even_when_its_server_is_a_name() {
        // The detour chain resolves the outer server's name, so a local pre-resolution would
        // measure a different destination. The target must reach the scheduler; the chain probe
        // is what resolves it, exactly like the data path.
        let router = router(
            "schema = 2\n\n\
             [[node]]\nname = \"inner\"\ntype = \"socks5\"\nserver = \"127.0.0.1\"\nport = 9\n\n\
             [[node]]\nname = \"outer\"\ntype = \"socks5\"\nserver = \"outer.example\"\nport = 443\ndetour = \"inner\"\n\n\
             [[group]]\nname = \"gg\"\nfilters = [\"name(outer)\"]\n\n[[election]]\nname = \"g\"\ngroup = \"gg\"\ntype = \"min-moving-avg\"\n\n\
             [routing]\nrules = []\nfallback = \"g\"\n",
        );
        let scheduler = Scheduler::new(router, Duration::from_secs(30));
        let targets = scheduler.targets();
        assert_eq!(targets.len(), 1, "the detoured node must be probeable");
        assert_eq!(targets[0].name, "outer");
        assert!(
            targets[0].address.is_none(),
            "the outer server is intentionally a name"
        );
        assert!(targets[0].node.detour().is_some());
    }
}
