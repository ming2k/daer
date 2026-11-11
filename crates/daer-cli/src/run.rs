// SPDX-License-Identifier: AGPL-3.0-only

//! The `run` subcommand: the daemon entry point.
//!
//! # What it does, in order
//!
//! 1. loads and validates the configuration (a bad file must fail before any kernel state
//!    is touched);
//! 2. creates the private ingress namespace, moves the peer into it, and binds the
//!    transparent port inside it (`IP_TRANSPARENT`; `CAP_SYS_ADMIN` + `CAP_NET_ADMIN`);
//! 3. attaches the datapath, including the peer hook inside the namespace;
//! 4. serves until `SIGINT`/`SIGTERM` or a reload.
//!
//! # Why `--no-datapath`
//!
//! Attaching needs `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_PERFMON` (the verifier's
//! `allow_ptr_leaks` gate for variable-offset packet parsing) and `CAP_SYS_ADMIN` (the
//! private ingress namespace). Without them the accept/relay path is
//! still exercisable — a flow that reaches the transparent port is routed and relayed
//! exactly as it would be — but **nothing is redirected into it**, so it is a
//! development and container probe, not a proxy. The listener itself still binds with
//! `IP_TRANSPARENT`, so `--no-datapath` removes the `CAP_BPF`/`CAP_PERFMON`/`CAP_SYS_ADMIN`
//! requirements, not `CAP_NET_ADMIN`. Starting without saying so would be the
//! worst outcome: a running daemon that silently forwards nothing.
//!
//! # Reload
//!
//! `SIGHUP` re-reads the configuration and publishes a new generation. A generation that
//! fails to build publishes nothing, so a typo cannot stop a working proxy.

use crate::preflight;
use crate::sd_notify::Notifier;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::Context;
use daer_control::daemon::{Daemon, resolve_interfaces};
use daer_control::datapath;
use daer_control::datapath::{DEVICE, PEER};
use daer_control::decide::RouterOptions;
use daer_control::rule_provider::{
    DEFAULT_TIMEOUT as DEFAULT_REFRESH_TIMEOUT, ProviderSchedule, RefreshOutcome,
    refresh_rule_provider,
};
use daer_routing::RuleProviderPool;

/// How the daemon was asked to run.
#[derive(Debug, Clone)]
pub struct RunOptions {
    /// Configuration path.
    pub config: PathBuf,
    /// Path to the compiled datapath object.
    pub object: PathBuf,
    /// Serve without attaching the kernel program.
    pub no_datapath: bool,
    /// Report what would happen and change nothing.
    ///
    /// A dry run builds the generation, validates the object and reads the capabilities, then
    /// exits — before the port is bound, before the device pair or ingress namespace is
    /// created, before any sysctl or policy route is written, and before `bpf()`. It needs no
    /// capability (ADR-0029).
    pub dry_run: bool,
    /// How long a stop may wait for live flows before the process exits.
    ///
    /// The listener stops accepting immediately. This is the upper bound for traffic that was
    /// already relayed, and the value the service unit shortens to keep restarts responsive.
    pub shutdown_timeout: Duration,
}

/// Runs the daemon until a signal stops it.
///
/// # Errors
///
/// Returns a message instead of a panic for every expected failure: a missing object, a
/// port that cannot be bound, a configuration that does not compile, or a datapath that
/// cannot be attached.
pub async fn run(options: RunOptions) -> anyhow::Result<()> {
    let run_started = Instant::now();
    // The unit is `Type=notify`: every status below is visible as the unit's state, and the
    // final `READY=1` is what tells systemd the proxy can actually serve. Outside systemd
    // this is a no-op, so a foreground `daer run` behaves exactly as before.
    let notifier = Notifier::from_env();
    notifier.status("loading configuration");
    // ADR-0006: one loader for the data path and the diagnostics. Startup and `SIGHUP` both go
    // through it, so a subscription node cannot exist in `daer route nodes` and not in the
    // running daemon.
    let resolved = daer_control::load_resolved(&options.config).await?;
    crate::incident::set_config_path(&options.config);
    let loaded = resolved.config;
    // The bootstrap subscriber was installed before `load_resolved`, so subscription and
    // provider warnings are visible. This applies the configuration's level; a malformed
    // directive is a startup error, not a silent fallback to `info`.
    super::set_log_filter(&loaded.global.log_level).map_err(anyhow::Error::msg)?;
    for warning in &resolved.warnings {
        daer_observe::warn!(daer_observe::EventCode::DaemonConfigWarning,%warning, "configuration warning");
    }

    // The host forwarding policy is the operator's, not daer's. A dry run reports a missing
    // prerequisite without failing; a real run checks again in `PreparedIngress::prepare`
    // and refuses before it creates a device or changes a route.
    if options.dry_run
        && !options.no_datapath
        && let Err(error) = datapath::check_host_sysctls()
    {
        daer_observe::warn!(
            daer_observe::EventCode::DryRunHostSysctlMissing,
            %error,
            "host sysctl prerequisite is not met; a real run would refuse to start"
        );
    }

    // A previous run may have been killed before its guards ran. Its journal detaches TC
    // filters and removes the qdiscs; an older journal may also restore a host sysctl. The
    // namespace, pair and host policy routing are removed even without a journal. This
    // happens before the daemon waits for a route, so stale filters cannot keep redirecting
    // traffic during that wait.
    // A dry run changes nothing, so it deliberately skips this.
    if !options.dry_run
        && let Err(error) = datapath::cleanup_system_state()
    {
        daer_observe::warn!(daer_observe::EventCode::DaemonRecoveryWarning,%error, "could not fully recover state from a previous run");
    }

    notifier.status("waiting for network interfaces");
    // Interfaces first: `auto` is resolved once, so a reload cannot silently move the
    // attachment to a different interface.
    //
    // `disable-waiting-network` decides what "no default route" means: with it off (the default)
    // daer waits, because a daemon started by systemd before DHCP has finished would otherwise
    // exit and stay down; with it on, a missing route is fatal immediately, which is what a
    // container with a static route wants.
    let (lan, wan) = wait_for_interfaces(
        &loaded.global.lan_interface,
        &loaded.global.wan_interface,
        !loaded.global.disable_waiting_network,
    )
    .await?;
    daer_observe::info!(
        daer_observe::EventCode::DaemonInterfacesResolved,
        ?lan,
        ?wan,
        "interfaces resolved"
    );

    // ADR-0029: the dry run ends here. Everything above this line reads the box; everything
    // below it mutates the box (namespace, bind, veth pair, sysctls, policy route) or the
    // kernel (BPF load, tc attach). Returning before the first mutation is what makes
    // "--dry-run" mean "changed nothing" rather than "did everything, then exited".
    if options.dry_run {
        return report_plan(&loaded, &options, &lan, &wan).await;
    }

    notifier.status("preparing the private ingress");

    // The socket mark, decided once for the whole run.
    //
    // Every socket consumer has to agree or the proxy captures its own traffic and loops:
    // the generation's dialers, the transparent listeners (including their replies), and
    // the datapath's `PARAM.socket_mark`. `--no-datapath` deliberately gets `None`: nothing
    // is redirected, so there is no capture loop to evade; the listener still needs
    // `CAP_NET_ADMIN` for `IP_TRANSPARENT`.
    let so_mark = if options.no_datapath {
        None
    } else {
        Some(loaded.global.so_mark.unwrap_or(DEFAULT_SOCKET_MARK))
    };

    // The DNS half is built first, and its Fake-IP pool and snooper are handed to every
    // generation. Without this the pool existed and nothing wrote to it: the resolver's
    // synthetic addresses were unknown to the router, so Fake-IP could never work through
    // the daemon. One pool for the process also survives a reload, which is what a client's
    // open connections to a synthetic address require.
    let (dns, fake_ip, snooper) = start_dns(&loaded, &options).await?;
    let base_options = RouterOptions::for_config(&options.config)
        .with_socket_mark(so_mark)
        .with_fake_ip(fake_ip)
        .with_dns_snooper(Some(snooper))
        // A dial's span reaches the journal. Without this the transport's recorder is filled
        // by netune and dropped, so "why is this node slow" has no answer in any log — which is
        // exactly the state the daemon was in before the observer existed.
        .with_dial_observer(Some(std::sync::Arc::new(daer_outbound::LogObserver)))
        .with_rule_providers(Some(resolved.rule_providers.pool.clone()));
    // The ingress namespace is created before the listeners: a socket belongs to the
    // network namespace that was current when it was created, and `bpf_sk_assign` can only
    // hand a redirected packet to a listener in the packet's namespace. `--no-datapath`
    // has no redirect and therefore no namespace.
    let ingress = if options.no_datapath {
        None
    } else {
        Some(
            daer_control::PreparedIngress::prepare()
                .map_err(|error| anyhow::anyhow!("cannot prepare the private ingress: {error}"))?,
        )
    };
    let mut daemon = match ingress {
        Some(ingress) => Daemon::bind_in(&loaded, &base_options, Some(ingress)),
        None => Daemon::bind(&loaded, &base_options),
    }
    .map_err(|error| anyhow::anyhow!("{error}"))?;
    daer_observe::info!(daer_observe::EventCode::DaemonListening,
        port = daemon.port,
        so_mark = ?so_mark,
        namespace = daemon
            .ingress()
            .map(|ingress| ingress.namespace.name()),
        generation = %daemon.generation().describe(),
        "listening for redirected flows"
    );

    let mut telemetry = None;
    let ebpf: Option<daer_control::datapath::Attached> = if options.no_datapath {
        daemon.datapath = daer_control::daemon::DatapathStatus {
            attached: false,
            skipped: vec!["--no-datapath".to_owned()],
        };
        daer_observe::warn!(
            daer_observe::EventCode::DaemonNoDatapath,
            "serving without the kernel datapath (--no-datapath): nothing is redirected \
             into the transparent port, so no traffic is actually proxied"
        );
        None
    } else {
        notifier.status("attaching the kernel datapath");
        let mut attached = attach(&daemon, &options, &lan, &wan, so_mark).await?;
        daemon.datapath = daer_control::daemon::DatapathStatus {
            attached: true,
            skipped: Vec::new(),
        };
        telemetry = Some(attached.take_telemetry().map_err(anyhow::Error::msg)?);
        Some(attached)
    };

    // The observer only exists once the datapath is attached, so the generation that will
    // serve has to be rebuilt with it. This is not cosmetic: without the observer the router
    // matches on addresses and the sniffed name only, so every `mac(...)`, `dscp(...)`, and
    // `pname(...)` rule is compiled, accepted, and inert.
    let options_router = match ebpf.as_ref() {
        Some(attached) => {
            let with_observer = base_options
                .clone()
                .with_kernel_observer(Some(attached.observer()));
            // A rebuild, not a mutation: a generation is immutable once published, and the
            // reload path is the only thing that replaces one. A failure here leaves the
            // address-only generation serving, which is correct but degraded, so it is a
            // warning rather than a refusal.
            match daemon.reload(&loaded, &with_observer) {
                Ok(()) => {
                    daer_observe::info!(daer_observe::EventCode::DaemonDatapathRebuilt,
                        generation = %daemon.generation().describe(),
                        "generation rebuilt with the datapath's flow facts (mac/dscp/pname)"
                    );
                    with_observer
                }
                Err(error) => {
                    daer_observe::warn!(
                        daer_observe::EventCode::DaemonDatapathRebuildFailed,
                        %error,
                        "could not rebuild the generation with the datapath's flow facts; \
                         mac/dscp/pname rules will not match"
                    );
                    base_options
                }
            }
        }
        None => base_options,
    };

    // ADR-0006: health scheduling is part of the daemon, not an optional extra. Without it a
    // latency policy's alive set stays empty and every flow to such a group is refused.
    let mut health = start_health(&daemon);

    // The datapath's counters and ring were dead before ADR-0040. The reader starts with the
    // service and is aborted with it; a dropped event is counted by the kernel and therefore
    // visible in the next `DatapathEvent`/`DatapathStats` pair.
    let bpf_snapshot = std::sync::Arc::new(std::sync::Mutex::new(None));
    let telemetry_task = telemetry
        .map(|telemetry| spawn_datapath_telemetry(telemetry, std::sync::Arc::clone(&bpf_snapshot)));
    let status_task = crate::status::spawn_socket();

    let result = serve_until_signal(ServeInputs {
        daemon: &daemon,
        config: &loaded,
        options: &options,
        router_options: &options_router,
        ebpf: ebpf.as_ref(),
        health: &mut health,
        resolved_pool: &resolved.rule_providers.pool,
        notifier: &notifier,
        dns: dns.as_ref(),
        bpf: &bpf_snapshot,
        started: run_started,
    })
    .await;
    if let Some(task) = telemetry_task {
        task.abort();
        let _ = task.await;
    }
    if let Some(task) = status_task {
        task.abort();
        let _ = task.await;
    }
    crate::status::remove_socket();
    health.stop();
    if let Some(dns) = dns {
        dns.stop().await;
    }
    // `Attached`'s drop detaches the peer link on a thread inside `daer0ns` before dropping
    // the object. Normal field drop order does the rest: the datapath guards remove their
    // routes and sysctls, `Daemon` closes the listeners, and `IngressNamespace` deletes the
    // namespace. There is no explicit teardown path for a caller to forget.
    result
}

/// Writes the versioned status snapshot atomically.
///
/// The snapshot is the same data `daer status --json` returns. A failed write is a debug
/// event, not a service failure: the live socket remains the authoritative path and the file
/// is the crash fallback.
fn write_state(
    daemon: &Daemon,
    dns: Option<&DnsHandle>,
    bpf: &std::sync::Arc<std::sync::Mutex<Option<daer_ebpf::telemetry::BpfCounters>>>,
    started: Instant,
) {
    let generation = daemon.generation();
    let stats = daemon.stats();
    let datagram = daemon.datagram_stats().map(|stats| stats.snapshot());
    let dns = dns.map(|dns| dns.resolver.stats().snapshot());
    let bpf = bpf
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .clone();
    let policy_hash = generation
        .policy_hash()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();

    let value = serde_json::json!({
        "schema": 1,
        "run_id": daemon.ids.run_id().to_string(),
        "pid": std::process::id(),
        "uptime_secs": started.elapsed().as_secs(),
        "generation": {
            "id": generation.id().to_string(),
            "policy_hash": format!("sha256:{policy_hash}"),
            "rules": generation.rules(),
            "groups": generation.groups(),
            "nodes": generation.nodes(),
            "warnings": generation.warnings(),
        },
        "datapath": {
            "attached": daemon.datapath.is_attached(),
            "skipped": daemon.datapath.skipped,
            "port": daemon.port,
            "namespace": daemon.ingress().map(|ingress| ingress.namespace.name()),
        },
        "flows": {
            "in_flight": daemon.supervisor.in_flight(),
            "accepted": stats.accepted,
            "rejected": stats.rejected,
            "failed": stats.failed,
            "exhausted": stats.exhausted,
            "panicked": stats.panicked,
        },
        "datagram": datagram.map(|stats| serde_json::json!({
            "to_upstream": stats.to_upstream,
            "to_client": stats.to_client,
            "sessions_opened": stats.sessions_opened,
            "dropped_full": stats.dropped_full,
            "dropped_failed": stats.dropped_failed,
        })),
        "dns": dns.map(|stats| serde_json::json!({
            "hits": stats.hits,
            "stale_hits": stats.stale_hits,
            "misses": stats.misses,
            "upstream_calls": stats.upstream_calls,
            "upstream_errors": stats.upstream_errors,
            "rejects": stats.rejects,
            "as_is": stats.as_is,
            "failovers": stats.failovers,
        })),
        "event_counters": daer_observe::counters::snapshot(),
        "bpf": bpf.map(|counters| {
            let mut values = serde_json::Map::new();
            for (key, value) in counters.nonzero() {
                values.insert(key.to_string(), serde_json::Value::from(value));
            }
            serde_json::Value::Object(values)
        }),
    });

    let result = (|| -> std::io::Result<()> {
        std::fs::create_dir_all("/run/daer")?;
        let path = std::path::Path::new(crate::status::STATE_PATH);
        let temporary = path.with_extension("json.tmp");
        std::fs::write(&temporary, serde_json::to_vec_pretty(&value)?)?;
        std::fs::rename(&temporary, path)
    })();
    if let Err(error) = result {
        daer_observe::debug!(
            daer_observe::EventCode::DaemonStateWriteFailed,
            path = crate::status::STATE_PATH,
            %error,
            "could not write the runtime state snapshot"
        );
    }
}

/// How often the datapath ring is drained and how often counters are snapshotted.
const DATAPATH_TELEMETRY_TICK: Duration = Duration::from_secs(1);
const DATAPATH_COUNTER_TICKS: u64 = 10;
const DATAPATH_EVENTS_PER_TICK: usize = 256;

/// Drains the kernel's structured events and publishes counter deltas.
///
/// The ring is rate-limited per key by the datapath; it is the explanation, not the
/// measurement. The counter delta is the measurement, emitted only when it is non-zero so an
/// idle daemon does not write a line every ten seconds.
fn spawn_datapath_telemetry(
    mut telemetry: daer_ebpf::telemetry::DatapathTelemetry,
    snapshot: std::sync::Arc<std::sync::Mutex<Option<daer_ebpf::telemetry::BpfCounters>>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(DATAPATH_TELEMETRY_TICK);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut previous = telemetry.read_counters().ok();
        if let Some(current) = previous.as_ref() {
            *snapshot.lock().unwrap_or_else(|e| e.into_inner()) = Some(current.clone());
        }
        let mut ticks = 0u64;
        loop {
            ticker.tick().await;
            for event in telemetry.drain_events(DATAPATH_EVENTS_PER_TICK) {
                let pname = String::from_utf8_lossy(&event.pname)
                    .trim_end_matches('\0')
                    .to_owned();
                daer_observe::warn!(
                    daer_observe::EventCode::DatapathEvent,
                    event_type = %daer_ebpf::telemetry::event_type_name(event.kind),
                    pid = event.pid,
                    pname = %pname,
                    outbound = event.outbound,
                    l4proto = event.l4proto,
                    sip = %daer_ebpf::telemetry::event_address(event.sip),
                    dip = %daer_ebpf::telemetry::event_address(event.dip),
                    sport = event.sport,
                    dport = event.dport,
                    monotonic_ns = event.timestamp,
                    "datapath event"
                );
            }
            ticks = ticks.wrapping_add(1);
            if !ticks.is_multiple_of(DATAPATH_COUNTER_TICKS) {
                continue;
            }
            match telemetry.read_counters() {
                Ok(now) => {
                    if let Some(before) = previous.as_ref() {
                        let delta = now.delta(before);
                        if !delta.is_zero() {
                            daer_observe::info!(
                                daer_observe::EventCode::DatapathStats,
                                interval_ms = DATAPATH_TELEMETRY_TICK.as_millis()
                                    * u128::from(DATAPATH_COUNTER_TICKS),
                                counters = ?delta.nonzero().collect::<Vec<_>>(),
                                "datapath counters"
                            );
                        }
                    }
                    *snapshot.lock().unwrap_or_else(|e| e.into_inner()) = Some(now.clone());
                    previous = Some(now);
                }
                Err(error) => {
                    daer_observe::warn!(
                        daer_observe::EventCode::DatapathTelemetryFailed,
                        %error,
                        "datapath telemetry read failed"
                    );
                }
            }
        }
    })
}

/// Prepares the DNS half and starts a server **only when the configuration asks for one**.
///
/// # Why the daemon has a DNS half at all
///
/// A transparent proxy that does not answer DNS cannot route by name for a client that
/// resolves through it, and — more concretely — Fake-IP has nowhere to allocate an address.
/// The resolver already existed as its own subcommand, but `daer run` never started it, so
/// the daemon's `FakeIpPool` and `DnsSnooper` were empty structs nothing wrote to: every
/// synthetic destination was unknown, and `domain(...)` rules could only fire from a
/// sniffed SNI.
///
/// # Why the server is conditional
///
/// Binding `0.0.0.0:53` unconditionally is not a convenience, it is a regression: a box
/// already running `systemd-resolved` (or any resolver on port 53) would see `daer run` fail
/// with `EADDRINUSE`, and a box that does not want daer to be its resolver would have one
/// installed anyway. The listener is started when the operator said so — `dns.bind` is set,
/// or Fake-IP is enabled, which has no meaning without a resolver to hand out the synthetic
/// addresses. Otherwise the daemon still builds the pool and the snooper (so a later reload
/// that turns Fake-IP on needs no second path) and says at `INFO` that it is not serving.
///
/// # Why the state is returned rather than owned here
///
/// The pool and the snooper are the *contract* between the two halves: DNS writes a
/// name-to-address mapping, the data path reads it back. They are owned by the process (this
/// function hands them to `RouterOptions`, which every generation clones) so a `SIGHUP`
/// reload keeps the mappings a client's open connections depend on.
///
/// # Errors
///
/// Returns the resolver build error or, when the server was asked for, the bind error. Both
/// are load-time failures: a daemon that cannot answer the queries it was configured to serve
/// is a configuration the operator has to fix, not one to serve around.
async fn start_dns(
    config: &daer_config::Config,
    options: &RunOptions,
) -> anyhow::Result<(
    Option<DnsHandle>,
    Option<std::sync::Arc<daer_dns::FakeIpPool>>,
    std::sync::Arc<daer_dns::DnsSnooper>,
)> {
    // The pool is built from the configuration even when Fake-IP is disabled: the type
    // reports `is_enabled()`, and building it unconditionally means a reload that turns
    // Fake-IP on does not need a second constructor path.
    let fake_ip = std::sync::Arc::new(
        daer_dns::FakeIpPool::from_config(&config.dns.fake_ip)
            .map_err(|error| anyhow::anyhow!("dns.fake-ip: {error}"))?,
    );
    let snooper = std::sync::Arc::new(daer_dns::DnsSnooper::default());

    // Fake-IP without a resolver is inert: nothing allocates a synthetic address, so the pool
    // would never be consulted. Treating it as a request for the server is what makes the
    // feature usable without a second configuration key.
    let wants_server = config.dns.bind.is_some() || config.dns.fake_ip.enabled;
    let transports = crate::dns::transports(config)?;
    let resolver = std::sync::Arc::new(
        daer_dns::Resolver::with_state(
            config,
            transports,
            std::sync::Arc::clone(&fake_ip),
            std::sync::Arc::clone(&snooper),
        )
        .map_err(|error| anyhow::anyhow!("cannot build the dns resolver: {error}"))?,
    );

    if !wants_server {
        daer_observe::info!(
            daer_observe::EventCode::DaemonDnsNotStarted,
            "dns server not started: `dns.bind` is unset and fake-ip is disabled, so this \
             daemon is not the box's resolver (set `dns.bind` to serve, or enable `[dns.fake-ip]`)"
        );
        return Ok((None, Some(fake_ip), snooper));
    }

    let plan = crate::dns::Plan::resolve(config).map_err(anyhow::Error::msg)?;
    let (shutdown, _) = tokio::sync::broadcast::channel::<()>(1);
    let mut udp_shutdown = shutdown.subscribe();
    let mut tcp_shutdown = shutdown.subscribe();
    let address = plan.address;
    let udp = {
        let resolver = std::sync::Arc::clone(&resolver);
        tokio::spawn(async move {
            daer_dns::serve_udp(resolver, address, async move {
                let _ = udp_shutdown.recv().await;
            })
            .await
        })
    };
    let tcp = {
        let resolver = std::sync::Arc::clone(&resolver);
        tokio::spawn(async move {
            daer_dns::serve_tcp(resolver, address, async move {
                let _ = tcp_shutdown.recv().await;
            })
            .await
        })
    };
    daer_observe::info!(daer_observe::EventCode::DaemonDnsStarted,
        plan = %plan.describe(),
        fake_ip = fake_ip.is_enabled(),
        "dns server started: name-based routing and fake-ip are live"
    );
    let _ = options;
    Ok((
        Some(DnsHandle {
            shutdown,
            udp,
            tcp,
            resolver,
        }),
        Some(fake_ip),
        snooper,
    ))
}

/// The running DNS server, stopped on shutdown.
///
/// Holds the broadcast sender rather than the tasks' join handles: dropping the sender makes
/// every receiver's `recv` return, which is how the two servers stop together.
struct DnsHandle {
    shutdown: tokio::sync::broadcast::Sender<()>,
    udp: tokio::task::JoinHandle<Result<(), daer_dns::ServerError>>,
    tcp: tokio::task::JoinHandle<Result<(), daer_dns::ServerError>>,
    /// The resolver behind both servers, for the live snapshot.
    resolver: std::sync::Arc<daer_dns::Resolver>,
}

impl DnsHandle {
    /// Signals both servers and waits for them.
    async fn stop(self) {
        let _ = self.shutdown.send(());
        for handle in [self.udp, self.tcp] {
            match handle.await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    daer_observe::warn!(daer_observe::EventCode::DaemonDnsStoppedWithError,%error, "dns server stopped with an error")
                }
                Err(error) => {
                    daer_observe::warn!(daer_observe::EventCode::DaemonDnsTaskFailed,%error, "dns server task did not finish")
                }
            }
        }
    }
}

/// Prints the preflight report and returns, changing nothing.
///
/// This is the unprivileged gate (ADR-0029). It builds the generation the daemon would
/// serve, validates the compiled object against the ABI, computes the runtime parameter and
/// reads the capabilities — none of which binds a port, creates a device, writes a sysctl,
/// installs a route or calls `bpf()`.
///
/// # Errors
///
/// Returns when the configuration does not compile, or when an object was requested and is
/// invalid. Both are things a preflight is supposed to catch, so they are errors rather than
/// warnings: a dry run that reports a broken object and exits zero is the failure mode this
/// exists to prevent.
async fn report_plan(
    loaded: &daer_config::Config,
    options: &RunOptions,
    lan: &[String],
    wan: &[String],
) -> anyhow::Result<()> {
    let router_options = RouterOptions::for_config(&options.config);
    let object = resolve_object_path(&options.object);
    let object_arg = (!options.no_datapath).then_some(object.as_path());

    let plan = preflight::plan(loaded, &router_options, lan, wan, object_arg)
        .map_err(|error| anyhow::anyhow!("{}", error.source))?;

    daer_observe::info!(
        daer_observe::EventCode::DryRunReport,
        "--dry-run: nothing is bound, created or attached; this is a report only"
    );

    daer_observe::info!(daer_observe::EventCode::DryRunConfigCompiles,
        generation = %plan.generation.describe(),
        rules = plan.generation.rules(),
        "configuration compiles"
    );

    // The tier is a performance property with a large blast radius (ADR-0005/ADR-0011), and
    // before this line it was only discoverable from a running daemon's log.
    match preflight::deferral_reason(&plan) {
        None => daer_observe::info!(
            daer_observe::EventCode::DryRunKernelEquivalent,
            "kernel policy: equivalent — the datapath reproduces userspace's verdict for every flow"
        ),
        Some(reason) => daer_observe::warn!(
            daer_observe::EventCode::DryRunKernelDeferral,
            %reason,
            "kernel policy: defer — every flow is handed to the control plane, so the kernel \
             fast path is not used"
        ),
    }

    let param = preflight::planned_param(plan.port, plan.socket_mark);
    daer_observe::info!(daer_observe::EventCode::DryRunListen,
        port = plan.port,
        so_mark = ?plan.socket_mark,
        control_plane_pid = param.control_plane_pid,
        "would listen for redirected flows"
    );
    daer_observe::info!(daer_observe::EventCode::DryRunInterfaces,?plan.lan, ?plan.wan, "would attach to these interfaces");

    if options.no_datapath {
        daer_observe::warn!(
            daer_observe::EventCode::DryRunNoDatapath,
            "--no-datapath: the kernel object would not be loaded or attached"
        );
    } else if let Some(report) = &plan.object {
        daer_observe::info!(daer_observe::EventCode::DryRunObjectValid,
            object = %report.path.display(),
            maps = report.detail.maps,
            programs = report.detail.programs,
            "datapath object is valid: names, sections and BTF func_info match the ABI"
        );
    } else if let Some(error) = &plan.object_error {
        anyhow::bail!("datapath object is not usable: {error}");
    }

    let (device, peer) = preflight::device_pair_present();
    let pair_state = if device || peer {
        "an existing device pair would be removed and a fresh pair created"
    } else {
        "the device pair would be created"
    };
    daer_observe::info!(
        daer_observe::EventCode::DryRunPairState,
        device_present = device,
        peer_present = peer,
        "{pair_state}"
    );

    match preflight::privileged_blocker(plan.capabilities) {
        None => daer_observe::info!(
            daer_observe::EventCode::DryRunCapabilitiesPresent,
            "capabilities present: `daer run` would bind, create the pair and attach here"
        ),
        Some(reason) => {
            daer_observe::warn!(daer_observe::EventCode::DryRunPrivilegedSkipped,%reason, "the privileged phase would not run here")
        }
    }

    daer_observe::info!(
        daer_observe::EventCode::DryRunComplete,
        "--dry-run: report complete, nothing was changed"
    );
    Ok(())
}

/// A generation value that is fresh for every daemon start.
///
/// The datapath stores it in every `conn_state` entry and compares it before inheriting a
/// cached routing decision. The map is pinned by name, so a constant value would let an
/// entry from a previous process survive a restart and reject the next connection on the
/// same five-tuple as a mid-stream SYN.
fn fresh_datapath_generation() -> u16 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.subsec_nanos())
        .unwrap_or(0);
    datapath_generation_from(std::process::id(), nanos)
}

/// The pure half of [`fresh_datapath_generation`], so the zero sentinel is testable.
fn datapath_generation_from(pid: u32, nanos: u32) -> u16 {
    (((pid ^ nanos) & 0xffff) as u16).max(1)
}

/// Attaches the datapath to the ingress prepared before the listeners were bound.
async fn attach(
    daemon: &Daemon,
    options: &RunOptions,
    lan: &[String],
    wan: &[String],
    so_mark: Option<u32>,
) -> anyhow::Result<daer_control::datapath::Attached> {
    let ingress = daemon
        .ingress()
        .ok_or_else(|| anyhow::anyhow!("the datapath has no private ingress to attach to"))?;
    let object_path = resolve_object_path(&options.object);
    if !object_path.exists() {
        return Err(anyhow::anyhow!(
            "datapath object {} does not exist; build it with `cargo xtask ebpf`, or run with \
             --no-datapath to serve without it",
            options.object.display()
        ));
    }

    let param = daer_ebpf::RuntimeParam {
        tproxy_port: u32::from(daemon.port),
        // The datapath checks this pid to tell its own traffic from a client's; a wrong
        // value makes daer proxy itself. `std::process::id` is the running pid.
        control_plane_pid: std::process::id(),
        device_ifindex: ingress.device_ifindex,
        netns_id: 0,
        peer_mac: ingress.peer_mac,
        padding_after_mac: [0, 0],
        // `redirect_peer` needs a kernel new enough to have `bpf_redirect_peer`; the object
        // carries a probe for it, and leaving it off is the safe default that still works.
        use_redirect_peer: false,
        has_bpf_get_current_task: true,
        // `conn_state_map` is pinned across daemon restarts. A constant generation made
        // every previous run's ACTIVE entries look like they belonged to this run, so a
        // reused five-tuple was refused as a mid-stream SYN rebind (and then passed
        // through without routing) forever. A fresh value per start invalidates them.
        datapath_generation: fresh_datapath_generation(),
        // The same value the generation's dialers carry: the datapath compares this against
        // `skb->mark` to recognise daer's own traffic, so a mismatch makes daer proxy itself.
        socket_mark: so_mark.unwrap_or(0),
    };

    // The listeners come from the daemon rather than being assembled here: the UDP fd is
    // part of the same contract, and a datapath attached without it drops every datagram
    // it redirects.
    let listeners = daemon
        .listeners()
        .map_err(|reason| anyhow::anyhow!("cannot attach the datapath: {reason}"))?;
    let ebpf = datapath::attach(
        &object_path,
        &param,
        lan,
        wan,
        listeners,
        &daemon.generation().router().kernel_policy(),
        ingress,
    )
    .map_err(|error| anyhow::anyhow!("cannot attach the datapath: {error}"))?;
    daer_observe::info!(daer_observe::EventCode::DaemonDatapathAttached,
        port = daemon.port,
        namespace = ingress.namespace.name(),
        device = DEVICE,
        peer = PEER,
        ?lan,
        ?wan,
        object = %object_path.display(),
        "datapath attached: redirected flows will be proxied"
    );
    Ok(ebpf)
}

pub fn resolve_object_path(path: &Path) -> PathBuf {
    resolve_object_path_in(path, INSTALLED_OBJECT_PATHS)
}

/// Where a packaged installation puts the datapath object.
const INSTALLED_OBJECT_PATHS: [&str; 3] = [
    "/usr/lib/daer/datapath.o",
    "/usr/local/lib/daer/datapath.o",
    "/usr/share/daer/datapath.o",
];

/// [`resolve_object_path`] with the search path injected.
///
/// Split out because the public form reads the host's `/usr/lib`, which makes a test of
/// "no candidate exists" pass or fail depending on what the machine has installed. That is
/// the definition of a test that cannot be trusted: it was green on a clean checkout and red
/// on any box with a packaged daer.
fn resolve_object_path_in(
    path: &Path,
    candidates: impl IntoIterator<Item = impl AsRef<Path>>,
) -> PathBuf {
    if path.exists() {
        return path.to_path_buf();
    }
    // If the path was the default relative path and does not exist in the working directory,
    // look in standard system-wide installation locations before failing.
    for candidate in candidates {
        let candidate = candidate.as_ref();
        if candidate.exists() {
            return candidate.to_path_buf();
        }
    }
    path.to_path_buf()
}

/// The mark used when `global.so-mark` is absent.
///
/// Non-zero and unlikely to collide with a routing rule's mark: `0` means "no mark" to the
/// kernel, which is exactly the case that causes self-capture.
pub const DEFAULT_SOCKET_MARK: u32 = 0x0dae;

/// The daemon state the signal/reload loop needs.
///
/// Grouped rather than passed one by one because the loop hands the same objects to the
/// serving future, `reload` and the provider-refresh path. A separate argument list is how one
/// of those paths would eventually be given a stale generation or a second notifier.
struct ServeInputs<'a> {
    daemon: &'a Daemon,
    config: &'a daer_config::Config,
    options: &'a RunOptions,
    router_options: &'a RouterOptions,
    ebpf: Option<&'a daer_control::datapath::Attached>,
    health: &'a mut HealthScheduler,
    resolved_pool: &'a RuleProviderPool,
    notifier: &'a Notifier,
    dns: Option<&'a DnsHandle>,
    bpf: &'a std::sync::Arc<std::sync::Mutex<Option<daer_ebpf::telemetry::BpfCounters>>>,
    started: Instant,
}

/// Serves until a signal, reloading on `SIGHUP` or provider refresh interval.
async fn serve_until_signal(inputs: ServeInputs<'_>) -> anyhow::Result<()> {
    let ServeInputs {
        daemon,
        config,
        options,
        router_options,
        ebpf,
        health,
        resolved_pool,
        notifier,
        dns,
        bpf,
        started,
    } = inputs;
    #[cfg(unix)]
    let mut hangup = {
        use tokio::signal::unix::{SignalKind, signal};
        signal(SignalKind::hangup()).context("cannot install a SIGHUP handler")?
    };
    #[cfg(unix)]
    let mut terminate = {
        use tokio::signal::unix::{SignalKind, signal};
        signal(SignalKind::terminate()).context("cannot install a SIGTERM handler")?
    };
    #[cfg(unix)]
    let mut sigusr1 = {
        use tokio::signal::unix::{SignalKind, signal};
        signal(SignalKind::user_defined1()).context("cannot install a SIGUSR1 handler")?
    };

    let serve = daemon.serve(async move {
        #[cfg(unix)]
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = terminate.recv() => {}
        }
        #[cfg(not(unix))]
        let _ = tokio::signal::ctrl_c().await;
    });
    tokio::pin!(serve);

    // Signal handlers exist and the serving future is constructed before the unit is declared
    // ready: a SIGTERM arriving immediately after `READY=1` must stop the daemon normally, not
    // hit the default disposition.
    if options.no_datapath {
        notifier.ready("serving without the kernel datapath (nothing is proxied)");
    } else {
        notifier.ready("serving; the kernel datapath is attached");
    }
    // systemd arms the watchdog when `READY=1` arrives, so the pings start after that.
    let _watchdog = notifier.watchdog_handle();

    // The pool the refresh path mutates. It starts as the pool the loader produced, so a
    // provider refreshed before any change is compared against the rules actually in use.
    let mut provider_pool = resolved_pool.clone();

    // The wake-up cadence is the *shortest* declared interval, because waking less often would
    // make a provider miss its own deadline (ADR-0037). Which providers a wake-up actually
    // serves is decided per provider by `ProviderSchedule::due`, not by this timer.
    let mut schedule = ProviderSchedule::from_config(config);
    let mut last_refresh: HashMap<String, Instant> = HashMap::new();
    let mut provider_ticker = schedule.min_interval().map(tokio::time::interval);
    if let Some(ticker) = &mut provider_ticker {
        ticker.reset();
    }
    // `/run/daer/state.json` is the crash fallback for `daer status`. It is written on a
    // timer rather than on every flow: the live socket is the exact answer, the file is the
    // last known state when the process is gone.
    let mut state_ticker = tokio::time::interval(Duration::from_secs(5));
    state_ticker.reset();
    write_state(daemon, dns, bpf, started);

    loop {
        #[cfg(unix)]
        tokio::select! {
            result = &mut serve => {
                result.map_err(|error| anyhow::anyhow!("the accept loop stopped: {error}"))?;
                // Live flows are owned by the supervisor, not by the loop, so stopping the
                // loop leaves them relaying. Draining is what keeps a shutdown from
                // truncating a response: a truncated body is indistinguishable from a wrong
                // one at the client. The bound is a flag so a reload/restart is not held
                // hostage by an idle keep-alive connection.
                notifier.stopping("stopping the listener; draining live flows");
                notifier.extend_timeout(
                    options
                        .shutdown_timeout
                        .saturating_add(std::time::Duration::from_secs(5)),
                );
                let drained = drain(daemon, options.shutdown_timeout).await;
                daer_observe::info!(daer_observe::EventCode::DaemonShutdown,
                    drained,
                    in_flight = daemon.supervisor.in_flight(),
                    "shutdown complete"
                );
                return Ok(());
            }
            _ = sigusr1.recv() => {
                match crate::incident::capture(
                    "sigusr1",
                    serde_json::json!({"run_id": daemon.ids.run_id().to_string()}),
                ) {
                    Ok(path) => {
                        let incident_id = path
                            .file_name()
                            .and_then(|name| name.to_str())
                            .unwrap_or("unknown")
                            .to_owned();
                        daer_observe::warn!(
                            daer_observe::EventCode::IncidentCapture,
                            incident_id = %incident_id,
                            trigger = "sigusr1",
                            path = %path.display(),
                            events = crate::incident::EVENT_LOG_PATH,
                            redaction = "incident-v1",
                            "incident bundle captured"
                        );
                    }
                    Err(error) => {
                        daer_observe::warn!(
                            daer_observe::EventCode::IncidentCaptureFailed,
                            trigger = "sigusr1",
                            %error,
                            "incident bundle could not be written"
                        );
                    }
                }
            }
            _ = hangup.recv() => {
                notifier.reloading();
                let reloaded =
                    reload(daemon, options, router_options, ebpf, health).await;
                // `RELOADING=1` is only cleared by `READY=1`. It must be sent even when the
                // new configuration was rejected, because the old generation is still serving.
                if reloaded.is_some() {
                    notifier.ready("reloaded; serving the new generation");
                } else {
                    notifier.ready("reload rejected; the previous generation is still serving");
                }
                if let Some(reloaded_pool) = reloaded {
                    provider_pool = reloaded_pool;
                    // SIGHUP may have changed `[[rule-provider]]`, so the cadence is rebuilt
                    // from the configuration that was just reloaded. Keeping the startup
                    // ticker would leave a changed `interval` silently ignored for the
                    // daemon's lifetime.
                    match daer_config::load(&options.config) {
                        Ok(reloaded) => {
                            schedule = ProviderSchedule::from_config(&reloaded.config);
                            provider_ticker = schedule.min_interval().map(tokio::time::interval);
                            if let Some(ticker) = &mut provider_ticker {
                                ticker.reset();
                            }
                            last_refresh.clear();
                        }
                        Err(error) => {
                            // The full reload succeeded, so this is a file change racing the
                            // second read. Keep the previous cadence rather than stopping the
                            // daemon over a value it already knows how to run with.
                            daer_observe::warn!(daer_observe::EventCode::ProviderCadenceRereadFailed,%error, "could not re-read the provider cadence; keeping the previous schedule");
                        }
                    }
                }
                // A rejected reload leaves both the running generation and the cadence
                // untouched: a typo must not stop a working proxy.
            }
            _ = state_ticker.tick() => {
                write_state(daemon, dns, bpf, started);
            }
            _ = async {
                match &mut provider_ticker {
                    Some(ticker) => ticker.tick().await,
                    None => std::future::pending().await,
                }
            } => {
                refresh_due_providers(
                    &schedule,
                    &mut last_refresh,
                    &mut provider_pool,
                    ProviderRefreshContext {
                        options,
                        router_options,
                        daemon,
                        ebpf,
                        health,
                    },
                )
                .await;
            }
        }
        #[cfg(not(unix))]
        {
            let result = (&mut serve).await;
            result.map_err(|error| anyhow::anyhow!("the accept loop stopped: {error}"))?;
            return Ok(());
        }
    }
}

/// Refreshes only the providers whose own interval has elapsed, and rebuilds the routing
/// generation only when their rule content actually changed (ADR-0037).
///
/// # Why this is not just `reload()`
///
/// `reload()` re-resolves everything, including node subscriptions, and unconditionally swaps
/// the routing generation. Doing that on a timer re-fetched node subscriptions that declare no
/// cadence of their own, and discarded every measured node latency — plus restarted health
/// probes — for providers that answered `304 Not Modified`. This path keeps the running
/// generation when the content is identical and never touches subscriptions.
/// The daemon state a provider refresh publishes into.
///
/// Grouped rather than passed one by one: the refresh path and `reload` must hand the same
/// objects to `publish_generation`/`health.restart`, and a separate argument list is where a
/// future call site would silently pass a stale generation.
struct ProviderRefreshContext<'a> {
    options: &'a RunOptions,
    router_options: &'a RouterOptions,
    daemon: &'a Daemon,
    ebpf: Option<&'a daer_control::datapath::Attached>,
    health: &'a mut HealthScheduler,
}

async fn refresh_due_providers(
    schedule: &ProviderSchedule,
    last_refresh: &mut HashMap<String, Instant>,
    pool: &mut RuleProviderPool,
    context: ProviderRefreshContext<'_>,
) {
    let ProviderRefreshContext {
        options,
        router_options,
        daemon,
        ebpf,
        health,
    } = context;
    let due: Vec<String> = schedule
        .due(|tag| last_refresh.get(tag).map(Instant::elapsed))
        .iter()
        .map(|entry| entry.tag.clone())
        .collect();
    if due.is_empty() {
        return;
    }

    // Read the declarations from disk without the network: a provider refresh must not turn
    // into a subscription fetch just because it needed to know a URL.
    let config = match daer_config::load(&options.config) {
        Ok(loaded) => loaded.config,
        Err(error) => {
            daer_observe::error!(daer_observe::EventCode::ProviderRefreshSkipped,%error, "rule provider refresh skipped: the configuration does not load");
            return;
        }
    };
    let directory = options
        .config
        .parent()
        .map_or_else(|| Path::new(".").to_path_buf(), Path::to_path_buf);

    let mut changed = false;
    // Refresh into a copy. The running generation must keep routing with the pool it was
    // built from until `daemon.reload` accepts the new one; mutating `pool` first would make
    // a rejected refresh look "unchanged" on the next tick and strand the new rules forever.
    let mut staged = pool.clone();
    for tag in due {
        last_refresh.insert(tag.clone(), Instant::now());
        let Some(provider) = config
            .rule_provider
            .iter()
            .find(|provider| provider.tag == tag)
        else {
            // The tag vanished from the configuration; SIGHUP owns that transition.
            daer_observe::debug!(daer_observe::EventCode::ProviderRemoved,%tag, "rule provider no longer declared; nothing to refresh");
            continue;
        };

        let current = staged.get(&tag).map(std::sync::Arc::as_ref);
        let refreshed =
            refresh_rule_provider(provider, &directory, current, DEFAULT_REFRESH_TIMEOUT).await;
        match refreshed.outcome {
            RefreshOutcome::Changed => {
                if let Some(set) = refreshed.set {
                    staged.insert(tag.clone(), set);
                    changed = true;
                }
                daer_observe::info!(daer_observe::EventCode::ProviderUpdated,%tag, "rule provider updated");
            }
            RefreshOutcome::Unchanged => {
                // The provider answered 304: its rules are what is already loaded. Touching the
                // generation here is what used to reset measured latency for no reason.
                daer_observe::debug!(daer_observe::EventCode::ProviderUnchanged,%tag, "rule provider unchanged");
            }
            RefreshOutcome::Failed => {
                daer_observe::warn!(daer_observe::EventCode::ProviderRefreshFailed,
                    %tag,
                    error = refreshed.error.as_deref().unwrap_or("unknown"),
                    "rule provider refresh failed; keeping the running rule set"
                );
            }
        }
    }

    if !changed {
        return;
    }

    // Only a real content change reaches the data path, and it goes through the same
    // load-then-swap shape as a reload so a failure cannot leave a half-published policy.
    let republished_options = router_options
        .clone()
        .with_rule_providers(Some(std::sync::Arc::new(staged.clone())));
    match daemon.reload(&config, &republished_options) {
        Ok(()) => {
            *pool = staged;
            publish_generation(daemon, ebpf);
            health.restart(daemon);
            daer_observe::info!(
                daer_observe::EventCode::ProviderRefreshPublished,
                providers = pool.len(),
                "rule provider refresh published a new generation"
            );
        }
        Err(error) => {
            daer_observe::error!(daer_observe::EventCode::ProviderRefreshRejected,%error, "refresh rejected; the running generation is unchanged");
        }
    }
}

/// Publishes the current generation to the kernel datapath, when one is attached.
///
/// Shared by `reload` and the provider refresh so the two paths cannot disagree about what
/// "publishing a policy" means.
fn publish_generation(daemon: &Daemon, ebpf: Option<&daer_control::datapath::Attached>) {
    let Some(attached) = ebpf else {
        return;
    };
    let generation = daemon.generation();
    let router = generation.router();
    let gen_id = u16::try_from(generation.id().get()).unwrap_or(u16::MAX);
    // The publish runs inside the observer's own lock: `AyaWriter` needs `&mut Ebpf`, which
    // only the owner of the object can hand out.
    let published = attached
        .with_ebpf(|object| datapath::republish_policy(object, gen_id, &router.kernel_policy()));
    match published {
        Ok(Ok(())) => {}
        Ok(Err(error)) => daer_observe::error!(daer_observe::EventCode::DatapathRepublishFailed,
            %error,
            "republishing kernel policy failed; kernel will use previous slot"
        ),
        Err(reason) => {
            daer_observe::error!(daer_observe::EventCode::DatapathObjectMissing,%reason, "cannot reach the datapath object")
        }
    }
}

/// Resolves the interfaces, waiting for a default route when the configuration allows it.
///
/// # Why waiting is the default
///
/// A daemon started by systemd (`After=network-online.target`) can still reach `main` before
/// DHCP has installed a default route, and exiting at that point leaves the service down until
/// someone notices — which is the failure `disable-waiting-network = false` exists to prevent.
/// The wait is bounded: two minutes, with a line every five seconds so an operator watching the
/// journal sees progress rather than a hang.
///
/// `disable-waiting-network = true` skips all of it: a box with a static route wants to learn
/// about a configuration mistake immediately, not after two minutes.
///
/// # Errors
///
/// Returns the resolution failure when waiting is disabled or the budget is exhausted, and always
/// when `wan-interface` is empty — an empty list is a configuration error, not an environment
/// one, so waiting cannot fix it.
async fn wait_for_interfaces(
    lan: &[String],
    wan: &[String],
    wait: bool,
) -> anyhow::Result<(Vec<String>, Vec<String>)> {
    if wan.is_empty() {
        return Err(anyhow::anyhow!(
            "global.wan-interface is empty: daer cannot know which interface carries \
             proxied traffic. Set it to a name or \"auto\""
        ));
    }

    const BUDGET: Duration = Duration::from_secs(120);
    const TICK: Duration = Duration::from_secs(5);

    let started = std::time::Instant::now();
    loop {
        match resolve_interfaces(lan, wan) {
            Ok((lan, wan)) if !wan.is_empty() => return Ok((lan, wan)),
            Ok((_, wan)) => {
                // `auto` resolved to nothing: there is no default route yet.
                if !wait || started.elapsed() >= BUDGET {
                    return Err(anyhow::anyhow!(
                        "no interface carries a default route (wan resolved to {wan:?}); set \
                         global.wan-interface to a name, or wait for the network"
                    ));
                }
                daer_observe::info!(
                    daer_observe::EventCode::DaemonWaitingRoute,
                    waited_ms = started.elapsed().as_millis(),
                    "waiting for a default route (disable-waiting-network = false)"
                );
            }
            Err(reason) => {
                if !wait || started.elapsed() >= BUDGET {
                    return Err(anyhow::anyhow!("interfaces: {reason}"));
                }
                daer_observe::info!(daer_observe::EventCode::DaemonWaitingInterfaces,%reason, "waiting for the interfaces to come up");
            }
        }
        tokio::time::sleep(TICK).await;
    }
}

/// Starts health scheduling against the generation that is serving right now.
///
/// Returns a [`HealthScheduler`] whose [`HealthScheduler::restart`] re-spawns the probes
/// against a new generation. That is the ADR-0006 invariant: the scheduler holds the router
/// it probes, so a reload must hand it the new one rather than leave it measuring a
/// generation nothing routes to. The old code started the scheduler once at startup and
/// never restarted it, so after the first `SIGHUP` the new generation's groups received no
/// probes at all and a latency policy silently stopped selecting.
fn start_health(daemon: &Daemon) -> HealthScheduler {
    let mut scheduler = HealthScheduler::default();
    scheduler.restart(daemon);
    scheduler
}

/// The live health-probe task, replaceable on reload.
///
/// # Why the handle is held
///
/// Dropping a `JoinHandle` detaches the task rather than aborting it, so the old code leaked
/// a scheduler per reload. Stopping it explicitly is what keeps exactly one scheduler
/// running, and it is why this type owns the shutdown sender.
#[derive(Debug, Default)]
struct HealthScheduler {
    current: Option<(
        tokio::sync::watch::Sender<bool>,
        tokio::task::JoinHandle<()>,
    )>,
}

impl HealthScheduler {
    /// Stops whatever is running and starts probes for `daemon`'s current generation.
    fn restart(&mut self, daemon: &Daemon) {
        self.stop();
        let generation = daemon.generation();
        let interval = daemon.health_interval();
        let (stop, watch) = tokio::sync::watch::channel(false);
        // The whole `[global.health-check]` table, so the probe's URL, method and DNS
        // endpoints are the configured ones rather than a built-in default (ADR-0006).
        let handle = daer_control::spawn_health_scheduler(
            generation.router_arc(),
            &daemon.health_check(),
            watch,
        );
        match handle {
            Some(handle) => {
                daer_observe::info!(daer_observe::EventCode::DaemonHealthStarted,
                    interval_ms = interval.as_std().map(|i| i.as_millis()).unwrap_or(0),
                    generation = %generation.describe(),
                    "health scheduling started: node selection can measure latency"
                );
                self.current = Some((stop, handle));
            }
            None => {
                daer_observe::debug!(
                    daer_observe::EventCode::DaemonHealthDisabled,
                    "health scheduling not started (the interval is zero or no node has a \
                     literal address to probe)"
                );
            }
        }
    }

    /// Stops the running scheduler, waiting for its task to finish.
    ///
    /// Waiting matters: a probe in flight holds sockets to nodes, and leaving it running
    /// while a new scheduler starts would double the probe load for a moment. The wait is
    /// bounded by the task observing its watch channel.
    fn stop(&mut self) {
        let Some((stop, handle)) = self.current.take() else {
            return;
        };
        let _ = stop.send(true);
        // `abort` rather than awaiting the handle: this runs inside a synchronous reload
        // path, and the scheduler's own loop exits on the watch channel. Aborting only
        // matters for a probe already in flight, which is exactly what should be cut short.
        handle.abort();
    }
}

/// Re-reads the configuration and publishes it, reporting what happened.
/// Reloads on `SIGHUP`, keeping the running generation when anything fails.
///
/// # Why this is `async` and must stay that way
///
/// It used to be a synchronous function that called `super::block_on(...)` to re-run the shared
/// loader. `block_on` builds a runtime and calls `Runtime::block_on`, and this function is
/// called from inside `daemon.serve`'s `select!` — i.e. from inside the multi-threaded runtime.
/// Tokio refuses that outright ("Cannot start a runtime from within a runtime"), so the *first*
/// `SIGHUP` panicked the daemon in its main task: the accept loop stopped, the process printed a
/// panic and exited, and every in-flight flow died with it. Reload is the one operation an
/// operator reaches for to avoid a restart, so it failing by aborting the process is the worst
/// possible shape for this bug.
///
/// Awaiting the loader directly is the fix and the compile-time guarantee: `load_resolved` is
/// `async`, so nothing here can block a worker again without the compiler objecting.
///
/// # What a reload does *not* do
///
/// It runs inside the signal loop, so the accept loop is not polled while it awaits. A
/// subscription fetch with a slow endpoint (the loader's budget is 20 s) therefore delays new
/// accepts for up to that long: the kernel keeps the connections in the listener's backlog and
/// nothing is dropped, but they are not served until the reload finishes. Moving it to a spawned
/// task would fix the latency and is the right shape once reload also republishes kernel state
/// under a lock — that is tracked in `docs/dev/roadmap.md` §2.5, together with the 1000-reload
/// soak that would measure it.
async fn reload(
    daemon: &Daemon,
    options: &RunOptions,
    router_options: &RouterOptions,
    ebpf: Option<&daer_control::datapath::Attached>,
    health: &mut HealthScheduler,
) -> Option<RuleProviderPool> {
    let started = std::time::Instant::now();
    let loaded = match daer_control::load_resolved(&options.config).await {
        Ok(loaded) => loaded,
        Err(error) => {
            // A file that no longer parses is the common reload failure; the running policy
            // is untouched, which is the whole point of building before swapping.
            daer_observe::error!(daer_observe::EventCode::GenerationReloadRejected,%error, "reload rejected; the running generation is unchanged");
            return None;
        }
    };
    let reloaded_pool = loaded.rule_providers.pool.clone();
    let reloaded_options = router_options
        .clone()
        .with_rule_providers(Some(loaded.rule_providers.pool.clone()));
    match daemon.reload(&loaded.config, &reloaded_options) {
        Ok(()) => {
            publish_generation(daemon, ebpf);
            // The scheduler holds the router it probes, so it has to be handed the new
            // generation; leaving it running would measure a policy nothing routes to.
            health.restart(daemon);
            let generation = daemon.generation();
            daer_observe::info!(daer_observe::EventCode::GenerationReloaded,
                generation = %generation.describe(),
                elapsed_ms = started.elapsed().as_millis(),
                "reloaded"
            );
            // The caller's refresh pool must be the one the new generation routes with,
            // otherwise the next timer tick would re-fetch against rules that are no longer
            // in use and report every provider as changed.
            Some(
                std::sync::Arc::try_unwrap(reloaded_pool)
                    .unwrap_or_else(|shared| (*shared).clone()),
            )
        }
        Err(error) => {
            daer_observe::error!(daer_observe::EventCode::GenerationReloadRejected,%error, "reload rejected; the running generation is unchanged");
            None
        }
    }
}

/// Default grace period for live flows on a manual `SIGTERM`/`SIGINT`.
///
/// The shipped systemd unit passes a shorter value: a restart should not wait ten seconds on
/// an idle keep-alive connection, while a manual stop keeps the more conservative default.
pub const DEFAULT_SHUTDOWN_TIMEOUT_SECS: u64 = 10;

/// Closes live flows politely on shutdown.
///
/// Exposed so the caller can wait: dropping the process while flows are mid-relay truncates
/// them, and a truncated HTTP response is indistinguishable from a wrong one at the client.
pub async fn drain(daemon: &Daemon, timeout: Duration) -> bool {
    tokio::time::timeout(timeout, daemon.supervisor.drain())
        .await
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_datapath_generation_is_never_the_zero_sentinel() {
        // Zero is the map's uninitialized default and must not be a valid generation.
        assert_eq!(datapath_generation_from(0x1_0000, 0), 1);
        assert_ne!(datapath_generation_from(0x1234, 0x5678), 0);
        assert_ne!(datapath_generation_from(0x1234, 0x5678), 1);
    }

    #[test]
    fn resolve_object_path_returns_existing_path() {
        let cargo_toml = Path::new("Cargo.toml");
        assert_eq!(resolve_object_path(cargo_toml), cargo_toml);
    }

    #[test]
    fn resolve_object_path_preserves_non_existing_when_no_candidates() {
        // An empty candidate list, not the host's `/usr/lib`: the assertion is about the
        // fallback, and a machine with a packaged daer must not change the answer.
        let non_existing = Path::new("/non/existing/datapath.o");
        assert_eq!(
            resolve_object_path_in(non_existing, std::iter::empty::<&Path>()),
            non_existing
        );
    }

    #[test]
    fn resolve_object_path_finds_the_first_existing_candidate() {
        let directory = std::env::temp_dir().join(format!("daer-object-{}", std::process::id()));
        std::fs::create_dir_all(&directory).expect("creates the directory");
        let present = directory.join("datapath.o");
        std::fs::write(&present, b"x").expect("writes");
        let absent = directory.join("missing.o");
        assert_eq!(
            resolve_object_path_in(Path::new("/non/existing/datapath.o"), [&absent, &present]),
            present
        );
        let _ = std::fs::remove_dir_all(&directory);
    }
}
