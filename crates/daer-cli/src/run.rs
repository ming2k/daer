// SPDX-License-Identifier: AGPL-3.0-only

//! The `run` subcommand: the daemon entry point.
//!
//! # What it does, in order
//!
//! 1. loads and validates the configuration (a bad file must fail before any kernel state
//!    is touched);
//! 2. binds the transparent port (`IP_TRANSPARENT`, so this is the first capability check);
//! 3. prepares the device pair and attaches the datapath;
//! 4. serves until `SIGINT`/`SIGTERM` or a reload.
//!
//! # Why `--no-datapath`
//!
//! Attaching needs `CAP_BPF` and `CAP_NET_ADMIN`. Without them the accept/relay path is
//! still exercisable — a flow that reaches the transparent port is routed and relayed
//! exactly as it would be — but **nothing is redirected into it**, so it is a
//! development and container probe, not a proxy. Starting without saying so would be the
//! worst outcome: a running daemon that silently forwards nothing.
//!
//! # Reload
//!
//! `SIGHUP` re-reads the configuration and publishes a new generation. A generation that
//! fails to build publishes nothing, so a typo cannot stop a working proxy.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context;
use daer_control::daemon::{Daemon, resolve_interfaces};
use daer_control::datapath;
use daer_control::datapath::{DEVICE, PEER};
use daer_control::decide::RouterOptions;

/// How the daemon was asked to run.
#[derive(Debug, Clone)]
pub struct RunOptions {
    /// Configuration path.
    pub config: PathBuf,
    /// Path to the compiled datapath object.
    pub object: PathBuf,
    /// Serve without attaching the kernel program.
    pub no_datapath: bool,
    /// Exit once the datapath is attached instead of serving.
    pub dry_run: bool,
}

/// Runs the daemon until a signal stops it.
///
/// # Errors
///
/// Returns a message instead of a panic for every expected failure: a missing object, a
/// port that cannot be bound, a configuration that does not compile, or a datapath that
/// cannot be attached.
pub async fn run(options: RunOptions) -> anyhow::Result<()> {
    // ADR-0006: one loader for the data path and the diagnostics. Startup and `SIGHUP` both go
    // through it, so a subscription node cannot exist in `daer route nodes` and not in the
    // running daemon.
    let resolved = daer_control::load_resolved(&options.config).await?;
    let loaded = resolved.config;
    // Installed from the configuration, before anything can log: every later line
    // (`interfaces resolved`, `datapath attached`, per-flow decisions) depends on it.
    super::init_logging(&loaded.global.log_level);
    for warning in &resolved.warnings {
        tracing::warn!(%warning, "configuration warning");
    }

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
    tracing::info!(?lan, ?wan, "interfaces resolved");

    // The socket mark, decided once for the whole run.
    //
    // Three consumers have to agree or the proxy captures its own traffic and loops: the
    // generation's dialers (`ROUTER_OPTIONS`), the datapath's `PARAM.dae_socket_mark`, and the
    // operator's nftables exclusion. `--no-datapath` deliberately gets `None`: without
    // `CAP_NET_ADMIN` a marked dial fails outright, and nothing is redirected anyway.
    let so_mark = if options.no_datapath {
        None
    } else {
        Some(loaded.global.so_mark.unwrap_or(DEFAULT_SOCKET_MARK))
    };
    let options_router =
        RouterOptions::with_assets_beside(&options.config).with_socket_mark(so_mark);
    let daemon =
        Daemon::bind(&loaded, &options_router).map_err(|error| anyhow::anyhow!("{error}"))?;
    tracing::info!(
        port = daemon.port,
        so_mark = ?so_mark,
        generation = %daemon.generation().describe(),
        "listening for redirected flows"
    );

    let mut ebpf = if options.no_datapath {
        tracing::warn!(
            "serving without the kernel datapath (--no-datapath): nothing is redirected \
             into the transparent port, so no traffic is actually proxied"
        );
        None
    } else {
        Some(attach(&daemon, &options, &lan, &wan, so_mark).await?)
    };

    if options.dry_run {
        tracing::info!("--dry-run: datapath attached, exiting without serving");
        return Ok(());
    }

    // ADR-0006: health scheduling is part of the daemon, not an optional extra. Without it a
    // latency policy's alive set stays empty and every flow to such a group is refused.
    let (health_stop, _health) = start_health(&daemon);

    let result = serve_until_signal(&daemon, &options, &options_router, ebpf.as_mut()).await;
    let _ = health_stop.send(true);
    result
}

/// Prepares the device pair and attaches the datapath.
async fn attach(
    daemon: &Daemon,
    options: &RunOptions,
    lan: &[String],
    wan: &[String],
    so_mark: Option<u32>,
) -> anyhow::Result<aya::Ebpf> {
    if !options.object.exists() {
        return Err(anyhow::anyhow!(
            "datapath object {} does not exist; build it with `make ebpf`, or run with \
             --no-datapath to serve without it",
            options.object.display()
        ));
    }

    datapath::ensure_device_pair()
        .map_err(|error| anyhow::anyhow!("cannot prepare {DEVICE}/{PEER}: {error}"))?;
    let peer_mac = datapath::peer_mac()
        .map_err(|error| anyhow::anyhow!("cannot read the peer MAC: {error}"))?;
    let device_ifindex = datapath::ifindex(DEVICE)
        .map_err(|error| anyhow::anyhow!("cannot read the {DEVICE} ifindex: {error}"))?;

    let param = daer_ebpf::RuntimeParam {
        tproxy_port: u32::from(daemon.port),
        // The datapath checks this pid to tell its own traffic from a client's; a wrong
        // value makes daer proxy itself. `std::process::id` is the running pid.
        control_plane_pid: std::process::id(),
        device_ifindex,
        netns_id: 0,
        peer_mac,
        padding_after_mac: [0, 0],
        // `redirect_peer` needs a kernel new enough to have `bpf_redirect_peer`; the object
        // carries a probe for it, and leaving it off is the safe default that still works.
        use_redirect_peer: false,
        has_bpf_get_current_task: true,
        datapath_generation: 1,
        // The same value the generation's dialers carry: the datapath compares this against
        // `skb->mark` to recognise daer's own traffic, so a mismatch makes daer proxy itself.
        socket_mark: so_mark.unwrap_or(0),
    };

    let ebpf = datapath::attach(
        &options.object,
        &param,
        lan,
        wan,
        daer_control::datapath::Listeners {
            tcp4: daemon.listener.raw_fd_v4(),
            tcp6: daemon.listener.raw_fd_v6(),
        },
        &daemon.generation().router().kernel_policy(),
    )
    .map_err(|error| anyhow::anyhow!("cannot attach the datapath: {error}"))?;
    tracing::info!(
        port = daemon.port,
        device = DEVICE,
        peer = PEER,
        ?lan,
        ?wan,
        "datapath attached: redirected flows will be proxied"
    );
    Ok(ebpf)
}

/// The mark used when `global.so-mark` is absent.
///
/// Non-zero and unlikely to collide with a routing rule's mark: `0` means "no mark" to the
/// kernel, which is exactly the case that causes self-capture.
pub const DEFAULT_SOCKET_MARK: u32 = 0x0dae;

/// Serves until a signal, reloading on `SIGHUP`.
async fn serve_until_signal(
    daemon: &Daemon,
    options: &RunOptions,
    router_options: &RouterOptions,
    mut ebpf: Option<&mut aya::Ebpf>,
) -> anyhow::Result<()> {
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

    loop {
        #[cfg(unix)]
        tokio::select! {
            result = &mut serve => {
                result.map_err(|error| anyhow::anyhow!("the accept loop stopped: {error}"))?;
                // Live flows are owned by the supervisor, not by the loop, so stopping the
                // loop leaves them relaying. Draining is what keeps a shutdown from
                // truncating a response: a truncated body is indistinguishable from a wrong
                // one at the client.
                let drained = drain(daemon, DRAIN_TIMEOUT).await;
                tracing::info!(
                    drained,
                    in_flight = daemon.supervisor.in_flight(),
                    "shutdown complete"
                );
                return Ok(());
            }
            _ = hangup.recv() => {
                reload(daemon, options, router_options, ebpf.as_deref_mut());
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
                tracing::info!(
                    waited_ms = started.elapsed().as_millis(),
                    "waiting for a default route (disable-waiting-network = false)"
                );
            }
            Err(reason) => {
                if !wait || started.elapsed() >= BUDGET {
                    return Err(anyhow::anyhow!("interfaces: {reason}"));
                }
                tracing::info!(%reason, "waiting for the interfaces to come up");
            }
        }
        tokio::time::sleep(TICK).await;
    }
}

/// Starts health scheduling against the generation that is serving right now.
///
/// Returns the shutdown sender and the handle. The handle is deliberately kept: dropping it
/// would abort the task, which is the failure mode this whole function exists to prevent
/// (ADR-0006 — the scheduler existed and was never spawned).
///
/// A group whose policy needs measurement but whose nodes have no literal address (a name, not
/// an `ip:port`) is reported: probing it would be a second, silent DNS decision, and the flow
/// path resolves the name again anyway.
fn start_health(
    daemon: &Daemon,
) -> (
    tokio::sync::watch::Sender<bool>,
    Option<tokio::task::JoinHandle<()>>,
) {
    let (stop, watch) = tokio::sync::watch::channel(false);
    let generation = daemon.generation();
    let interval = daemon.health_interval();
    // The whole `[global.health-check]` table, so the probe's URL, method and DNS endpoints are
    // the configured ones rather than a built-in default (ADR-0006).
    let handle = daer_control::spawn_health_scheduler(
        generation.router_arc(),
        &daemon.health_check(),
        watch,
    );
    match &handle {
        Some(_) => tracing::info!(
            interval_ms = interval.as_std().map(|i| i.as_millis()).unwrap_or(0),
            "health scheduling started: node selection can measure latency"
        ),
        None => tracing::debug!(
            "health scheduling not started (the interval is zero or no node has a literal \
             address to probe)"
        ),
    }
    (stop, handle)
}

/// Re-reads the configuration and publishes it, reporting what happened.
fn reload(
    daemon: &Daemon,
    options: &RunOptions,
    router_options: &RouterOptions,
    mut ebpf: Option<&mut aya::Ebpf>,
) {
    let started = std::time::Instant::now();
    let loaded = match super::block_on(daer_control::load_resolved(&options.config)) {
        Ok(loaded) => loaded,
        Err(error) => {
            // A file that no longer parses is the common reload failure; the running policy
            // is untouched, which is the whole point of building before swapping.
            tracing::error!(%error, "reload rejected; the running generation is unchanged");
            return;
        }
    };
    match daemon.reload(&loaded.config, router_options) {
        Ok(()) => {
            let generation = daemon.generation();
            let router = generation.router();
            if let Some(ebpf) = ebpf.as_mut() {
                let gen_id = u16::try_from(generation.id().get()).unwrap_or(u16::MAX);
                if let Err(error) =
                    datapath::republish_policy(ebpf, gen_id, &router.kernel_policy())
                {
                    tracing::error!(
                        %error,
                        "republishing kernel policy failed; kernel will use previous slot"
                    );
                }
            }
            tracing::info!(
                generation = %generation.describe(),
                elapsed_ms = started.elapsed().as_millis(),
                "reloaded"
            );
        }
        Err(error) => {
            tracing::error!(%error, "reload rejected; the running generation is unchanged");
        }
    }
}

/// How long a shutdown waits for live flows.
///
/// Long enough for a normal response to finish, short enough that an operator restarting the
/// service is not waiting on a stuck peer.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

/// Closes live flows politely on shutdown.
///
/// Exposed so the caller can wait: dropping the process while flows are mid-relay truncates
/// them, and a truncated HTTP response is indistinguishable from a wrong one at the client.
pub async fn drain(daemon: &Daemon, timeout: Duration) -> bool {
    tokio::time::timeout(timeout, daemon.supervisor.drain())
        .await
        .is_ok()
}
