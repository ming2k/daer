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

use daer_config::TimeSpan;
use daer_outbound::{
    CheckError, CheckUrl, DialerId, HttpChecker, Protocol, TcpChecker, UdpDnsChecker,
};
use tokio::sync::Mutex;

use crate::decide::Router;

/// One node to probe, resolved from its link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeTarget {
    /// The group this node belongs to.
    pub group: String,
    /// The node's identity within the group.
    pub dialer: DialerId,
    /// Its name, for diagnostics.
    pub name: String,
    /// The address the probe connects to.
    pub address: SocketAddr,
    /// Whether the node claims to carry datagrams.
    pub udp: bool,
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
        }
    }
}

/// The result of one node's probe.
#[derive(Debug, Clone, PartialEq, Eq)]
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

/// What to probe with, from `[global.health-check]` and its per-group overrides.
///
/// # Why this is a value rather than three arguments
///
/// These were configuration keys that nothing read: `tcp-cpu-url`, `tcp-method` and `udp-dns`
/// were parsed, validated and ignored, so an operator who pointed the probe at their own
/// endpoint got a bare TCP handshake to the node instead and never knew (ADR-0006). Grouping
/// them makes "the probe uses what the file says" a single fact to inspect and to test.
#[derive(Debug)]
pub struct ProbeInstruments {
    /// The HTTP(S) request an `http`-scheme `tcp-url` performs, if one is configured.
    pub http: Option<(HttpChecker, CheckUrl)>,
    /// The address a bare `ip` entry in `tcp-url` is dialled on, if one is configured.
    ///
    /// The port comes from the node, so only the probe's *kind* is fixed here: `None` means the
    /// node's own address is dialled, which is the only thing a health check can do without a
    /// configured endpoint.
    pub tcp: TcpChecker,
    /// The UDP DNS endpoints a datagram-carrying node is probed against.
    pub udp_dns: Vec<SocketAddr>,
    /// The checker for those endpoints.
    pub udp: UdpDnsChecker,
    /// The `udp-dns` entries that are names rather than addresses, reported rather than dropped.
    ///
    /// An entry that is not an `ip:port` cannot be probed without resolving it, and resolving it
    /// inside the probe would be a second, silent DNS decision — the same rule the node's own
    /// address follows.
    pub unresolved_udp: Vec<String>,
}

/// Splits `host:port` or `[v6]:port` without resolving anything.
///
/// Local because the only caller is the probe table, and because a shared parser would tempt a
/// future caller into resolving: the point is that a *name* stays a name here.
fn split_host_port(entry: &str) -> Option<(&str, u16)> {
    let entry = entry.trim();
    if let Some(rest) = entry.strip_prefix('[') {
        let (host, rest) = rest.split_once(']')?;
        let port = rest.strip_prefix(':')?.parse().ok()?;
        return Some((host, port));
    }
    // A bare IPv6 address has multiple colons and no port; anything with one colon is host:port.
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
            http: None,
            tcp: TcpChecker::new(timeout),
            udp_dns: Vec::new(),
            udp: UdpDnsChecker::new(timeout),
            unresolved_udp: Vec::new(),
        }
    }

    /// Builds the instruments a configuration asks for.
    ///
    /// # What an unusable entry does
    ///
    /// An entry that does not parse is **reported and skipped**, never silently dropped and never
    /// fatal: `daer config validate` rejects a malformed `tcp-url` already, so a value that
    /// reaches here unparsed is a name (a URL with no literal address), and refusing to probe
    /// *anything* because one endpoint needs DNS would be worse than probing the node directly.
    #[must_use]
    pub fn from_config(
        check: &daer_config::HealthCheck,
        interval: Duration,
        method: daer_outbound::HttpMethod,
    ) -> Self {
        let timeout = probe_timeout(interval);

        // The first `tcp-url` entry decides the probe's shape: a URL makes it an HTTP request, a
        // bare address makes it a handshake. Both are accepted by the schema, and the upstream
        // semantics are "URL first, then addresses", so the first entry is the authority.
        let mut http = None;
        let mut tcp_url_seen = false;
        for entry in &check.tcp_url {
            if entry.contains("://") {
                match CheckUrl::parse(entry) {
                    Ok(url) => {
                        http = Some((HttpChecker::new(method, timeout), url));
                        tcp_url_seen = true;
                        break;
                    }
                    Err(error) => {
                        tracing::warn!(%entry, %error, "health check: unusable tcp-url entry");
                    }
                }
            } else if entry.parse::<std::net::IpAddr>().is_ok() {
                // A bare address means "dial the node", which is the default instrument.
                tcp_url_seen = true;
                break;
            } else {
                tracing::debug!(
                    %entry,
                    "health check: tcp-url entry is a name, not an address; the node's own \
                     address is dialled instead"
                );
            }
        }
        let _ = tcp_url_seen;

        let mut udp_dns = Vec::new();
        let mut unresolved_udp = Vec::new();
        for entry in &check.udp_dns {
            // `host:port` or `ip:port`. An IP is used directly; a name is reported, because
            // resolving it here would be a second, silent DNS decision.
            match split_host_port(entry) {
                Some((host, port)) => match host.parse::<std::net::IpAddr>() {
                    Ok(ip) => udp_dns.push(SocketAddr::new(ip, port)),
                    Err(_) => unresolved_udp.push(entry.clone()),
                },
                None => unresolved_udp.push(entry.clone()),
            }
        }

        Self {
            http,
            tcp: TcpChecker::new(timeout),
            udp_dns,
            udp: UdpDnsChecker::new(timeout),
            unresolved_udp,
        }
    }
}

/// Runs probes and records their results into a routing generation.
pub struct Scheduler {
    router: Arc<Router>,
    interval: Duration,
    instruments: ProbeInstruments,
    /// Serialises records: the router's group table is behind a lock, and a probe result
    /// arriving during a selection must not interleave half-way through it.
    write: Mutex<()>,
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
    ///
    /// `interval` is `check-interval`; a zero value means "never probe", and
    /// [`Scheduler::run`] returns immediately in that case.
    #[must_use]
    pub fn new(router: Arc<Router>, interval: Duration) -> Self {
        // A scheduler built without a configuration probes each node on its own address, which is
        // what a test wants and what a configuration that names no endpoint gets.
        let instruments = ProbeInstruments::default_for(interval);
        Self::with_instruments(router, interval, instruments)
    }

    /// Builds a scheduler whose probes use `instruments`.
    #[must_use]
    pub fn with_instruments(
        router: Arc<Router>,
        interval: Duration,
        instruments: ProbeInstruments,
    ) -> Self {
        Self {
            router,
            interval,
            instruments,
            write: Mutex::new(()),
        }
    }

    /// The instruments this scheduler probes with, for diagnostics and tests.
    #[must_use]
    pub fn instruments(&self) -> &ProbeInstruments {
        &self.instruments
    }

    /// The generation this scheduler reports into.
    #[must_use]
    pub fn router(&self) -> &Arc<Router> {
        &self.router
    }

    /// Every node that can be probed, across every group.
    ///
    /// A node without a literal address is skipped: probing would need the node's own
    /// resolution, and a probe that resolves differently from the data path measures the
    /// wrong destination.
    #[must_use]
    pub fn targets(&self) -> Vec<ProbeTarget> {
        let mut targets = Vec::new();
        for (group, ids) in self.router.probe_table() {
            for (dialer, name, protocol, address, udp) in ids {
                let Some(address) = address else {
                    tracing::debug!(%group, %name, "node has no literal address; not probed");
                    continue;
                };
                let _ = (&protocol, ProbeFailure::Unsupported(protocol.clone()));
                targets.push(ProbeTarget {
                    group: group.clone(),
                    dialer,
                    name,
                    address,
                    udp,
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
        // A datagram-carrying node is measured against the configured DNS endpoints when there
        // are any: those are reachable over UDP by definition, whereas the node's own port is a
        // proxy port that speaks no DNS. Otherwise the node's own address is measured, which is
        // the only thing left that says anything true about it.
        let latency = if target.udp {
            // A datagram-carrying node is measured over UDP. The endpoints come from `udp-dns`
            // when the configuration names any; otherwise the node's own address is used, which
            // is what `Scheduler::new` (a test, or a configuration that overrides nothing) gives.
            // A *TCP* probe here would report the node healthy while every datagram is dropped,
            // which is the failure the instrument choice exists to catch.
            let endpoints: Vec<SocketAddr> = if self.instruments.udp_dns.is_empty() {
                vec![target.address]
            } else {
                self.instruments.udp_dns.clone()
            };
            let mut last = None;
            let mut answered = None;
            for endpoint in &endpoints {
                match self.instruments.udp.check(*endpoint).await {
                    Ok(latency) => {
                        answered = Some(latency);
                        break;
                    }
                    Err(error) => last = Some(error),
                }
            }
            match answered {
                Some(latency) => Ok(latency),
                None => Err(last.unwrap_or(CheckError::Timeout)),
            }
        } else if let Some((checker, url)) = &self.instruments.http {
            checker.check(url, target.address.ip()).await
        } else {
            self.instruments.tcp.check(target.address).await
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
    /// Returns the router's error when the group or dialer has gone away (a reload
    /// replaced this generation), which the caller treats as "this scheduler is stale".
    pub async fn record(&self, result: &ProbeResult) -> Result<(), daer_outbound::OutboundError> {
        let _guard = self.write.lock().await;
        self.router.record(
            &result.target.group,
            result.target.dialer,
            result.is_alive(),
            result.latency,
        )?;
        Ok(())
    }

    /// Probes every target once and records the results.
    ///
    /// Returns the results so a caller can log or surface them; the recording is the
    /// side effect that matters for selection.
    pub async fn sweep(&self) -> Vec<ProbeResult> {
        let targets = self.targets();
        // Concurrent, because a sweep of N nodes must take one probe timeout, not N.
        let results = probe_all(self, &targets).await;
        for result in &results {
            if let Err(error) = self.record(result).await {
                tracing::debug!(
                    %error,
                    group = %result.target.group,
                    node = %result.target.name,
                    "probe result could not be recorded; this generation is stale"
                );
                break;
            }
            match (&result.latency, &result.failure) {
                (Some(latency), _) => tracing::trace!(
                    group = %result.target.group,
                    node = %result.target.name,
                    latency_ns = latency.as_nanos(),
                    "node alive"
                ),
                (None, Some(failure)) => tracing::debug!(
                    group = %result.target.group,
                    node = %result.target.name,
                    %failure,
                    "node probe failed"
                ),
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
            tracing::debug!("health probing disabled (check-interval is zero)");
            return;
        }
        let mut ticker = tokio::time::interval(self.interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                () = &mut shutdown => {
                    tracing::info!("health scheduler stopped");
                    return;
                }
                _ = ticker.tick() => {
                    self.sweep().await;
                }
            }
        }
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
        group: target.group.clone(),
        dialer: target.dialer,
        name: target.name.clone(),
        address: target.address,
        udp: target.udp,
    }
}

/// Spawns a scheduler for `router` unless probing is disabled or there is nothing probe.
///
/// This is the one call a daemon makes. It exists so the wiring lives here, next to the
/// reasoning about intervals and policies, instead of being re-derived at every entry
/// point — and so "probing never ran" is a visible decision (`None`) rather than a task
/// that silently did nothing.
///
/// Returns `None` when `interval` is zero (probing disabled by configuration) or when no
/// node has a literal address to probe.
#[must_use]
pub fn spawn(
    router: Arc<Router>,
    check: &daer_config::HealthCheck,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> Option<tokio::task::JoinHandle<()>> {
    // A negative interval is a configuration error the loader already rejects; treating it
    // as zero here keeps a bad value from spawning a busy loop.
    let interval = check.interval.as_std().unwrap_or(Duration::ZERO);
    if interval.is_zero() || !has_measurable_nodes(&router) {
        tracing::debug!(
            probes = with_interval(interval),
            "health probing not started; see check-interval and node addresses"
        );
        return None;
    }
    // The method comes from `tcp-method`, which used to be validated and ignored: a probe that
    // pointed at an endpoint rejecting `HEAD` reported the node dead for a configuration reason.
    let method = daer_outbound::HttpMethod::parse(&check.tcp_method).unwrap_or_else(|error| {
        tracing::warn!(
            %error,
            method = %check.tcp_method,
            "health check: unusable tcp-method; falling back to HEAD"
        );
        daer_outbound::HttpMethod::Head
    });
    let instruments = ProbeInstruments::from_config(check, interval, method);
    if !instruments.unresolved_udp.is_empty() {
        tracing::debug!(
            entries = ?instruments.unresolved_udp,
            "health check: udp-dns entries that are names are not probed;              a probe must not resolve a name the data path resolves elsewhere"
        );
    }
    let scheduler = Scheduler::with_instruments(router, interval, instruments);
    let mut shutdown = shutdown;
    Some(tokio::spawn(async move {
        let stopped = async move {
            // A watch channel that starts at `false` and is set to `true` on stop.
            while shutdown.changed().await.is_ok() {
                if *shutdown.borrow() {
                    return;
                }
            }
        };
        scheduler.run(stopped).await;
    }))
}

fn with_interval(interval: Duration) -> String {
    if interval.is_zero() {
        "disabled by check-interval = 0".to_owned()
    } else {
        format!("{interval:?}")
    }
}

/// Builds the probe table for a router without exposing the group internals.
///
/// The tuple shape keeps this crate's public surface small: a caller gets what a probe
/// needs, not the dialers themselves.
type ProbeRow = (DialerId, String, Protocol, Option<SocketAddr>, bool);

impl Router {
    /// Every probe target, grouped by group name.
    #[must_use]
    pub fn probe_table(&self) -> Vec<(String, Vec<ProbeRow>)> {
        self.groups_for_probes()
    }
}

/// Whether a checker's policy needs measured latency at all.
///
/// `fixed(n)` is explicit user intent and must not be overridden by a probe: recording
/// into an unmeasured group would rewrite an operator's choice.
#[must_use]
pub fn policy_needs_measurement(policy: daer_common::SelectionPolicy) -> bool {
    !matches!(policy, daer_common::SelectionPolicy::Fixed)
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
    fn a_fixed_policy_is_not_measured() {
        // `fixed(n)` is explicit intent; a probe must not rewrite it.
        assert!(!policy_needs_measurement(
            daer_common::SelectionPolicy::Fixed
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
            "schema = 1\n\n[[node]]\ntag = \"n\"\nurl = \"socks5://example.com:1080\"\n\n\
             [[group]]\nname = \"g\"\npolicy = \"fixed(0)\"\n\n\
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

        let router = router(&format!(
            "schema = 1\n\n[[node]]\ntag = \"n\"\nurl = \"socks5://{address}\"\n\n\
             [[group]]\nname = \"g\"\npolicy = \"min-moving-avg\"\n\n\
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

        let router = router(&format!(
            "schema = 1\n\n[[node]]\ntag = \"n\"\nurl = \"socks5://{address}\"\n\n\
             [[group]]\nname = \"g\"\npolicy = \"min-moving-avg\"\n\n\
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
            "schema = 1\n\n[[node]]\ntag = \"n\"\nurl = \"socks5://127.0.0.1:9\"\n\n\
             [[group]]\nname = \"g\"\npolicy = \"min-moving-avg\"\n\n\
             [routing]\nrules = []\nfallback = \"g\"\n",
        );
        let scheduler = Scheduler::new(Arc::clone(&router), Duration::from_secs(30));
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
            "schema = 1\n\n[[node]]\ntag = \"n\"\nurl = \"socks5://127.0.0.1:9\"\n\n\
             [[group]]\nname = \"g\"\npolicy = \"fixed(0)\"\n\n\
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
            "schema = 1\n\n\
             [[node]]\ntag = \"a\"\nurl = \"socks5://{a}\"\n\
             [[node]]\ntag = \"b\"\nurl = \"socks5://{b}\"\n\n\
             [[group]]\nname = \"g\"\npolicy = \"min-moving-avg\"\n\n\
             [routing]\nrules = []\nfallback = \"g\"\n"
        ));
        let scheduler = Scheduler::new(Arc::clone(&router), Duration::from_secs(30));
        let results = scheduler.sweep().await;
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(ProbeResult::is_alive), "{results:?}");
        assert!(router.has_selection("g"));
    }
}
