// SPDX-License-Identifier: AGPL-3.0-only

//! The `daer` command line.
//!
//! Two kinds of subcommand live here and they have different shapes:
//!
//! * **inspection** — `config`, `route`: load, compile, answer, exit. No runtime, no
//!   signals, no side effects.
//! * **service** — `dns serve`: binds sockets, installs signal handlers and runs until told
//!   to stop. It is the only path that needs an async runtime, so only it constructs one.

mod dns;
mod run;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::Context;
use clap::{Parser, Subcommand};
use daer_config::{Config, DEFAULT_CONFIG_DIR, DEFAULT_CONFIG_NAMES, FunctionOrString};
use daer_outbound::{FilterSet, parse_group_policy};
use daer_routing::{
    AliasOptimizer, DatReaderOptimizer, DeduplicateParamsOptimizer, MergeAndSortOptimizer,
    NormalizedProgram, Outbound, RoutingError, RulesBuilder, ValidationSink, is_builtin_outbound,
    parse_outbound,
};

/// The reference configuration, also printed by `daer config example`.
const EXAMPLE_TOML: &str = include_str!("../../../daer.example.toml");

#[derive(Debug, Parser)]
#[command(
    name = "daer",
    version,
    about = "eBPF-based transparent proxy",
    disable_help_subcommand = true
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Work with a configuration file.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Convert or inspect outbound nodes.
    Node {
        #[command(subcommand)]
        command: NodeCommand,
    },
    /// Explain what daer would do with a flow, without running it.
    Route {
        #[command(subcommand)]
        command: RouteCommand,
    },
    /// Run or inspect the DNS resolver.
    Dns {
        #[command(subcommand)]
        command: dns::Command,
    },
    /// Run the transparent proxy.
    Run {
        #[arg(short, long, value_name = "PATH")]
        config: Option<PathBuf>,
        /// The compiled datapath object.
        #[arg(long, value_name = "PATH", default_value = "target/ebpf/datapath.o")]
        object: PathBuf,
        /// Serve without attaching the kernel program.
        ///
        /// Nothing is redirected into the transparent port in this mode, so no traffic is
        /// proxied: it exists to exercise the accept/relay path without `CAP_NET_ADMIN`.
        #[arg(long)]
        no_datapath: bool,
        /// Attach the datapath and exit without serving.
        #[arg(long)]
        dry_run: bool,
    },
    /// Print build information.
    Version,
}

#[derive(Debug, Subcommand)]
enum RouteCommand {
    /// Print the routing decision for a source/destination pair.
    ///
    /// The same decision the data path makes, from the same compiled generation:
    /// the answer here is the answer a running daer would act on.
    Explain {
        /// Client address (`ip:port`).
        source: SocketAddr,
        /// Destination address (`ip:port`).
        destination: SocketAddr,
        #[arg(short, long, value_name = "PATH")]
        config: Option<PathBuf>,
        /// Show every rule and every predicate, not just the winner.
        #[arg(long)]
        why: bool,
        /// The sniffed domain, as a `domain(...)` rule would see it.
        ///
        /// Without this a `domain(...)` rule is unverifiable from the command line,
        /// which makes the most common kind of rule the one kind a diagnostic cannot
        /// check. A name here is what sniffing would have supplied.
        #[arg(long, value_name = "NAME")]
        domain: Option<String>,
    },
    /// List every node in every group, with its protocol and security identity.
    ///
    /// Answers "which nodes exist, and how is each session protected" without opening a
    /// connection or printing a secret.
    Nodes {
        #[arg(short, long, value_name = "PATH")]
        config: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum NodeCommand {
    /// Convert an outbound URI link (vless://, ss://, trojan://, socks5://, http://, direct://)
    /// into a structured [[node]] TOML table.
    Convert {
        /// Outbound URI link to convert. If omitted, reads lines from standard input.
        link: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    /// Load the configuration and dry-run routing, groups and outbounds.
    Validate {
        /// Entry configuration file.
        #[arg(short, long, value_name = "PATH")]
        config: Option<PathBuf>,
    },
    /// Print the configuration in canonical TOML.
    Fmt {
        #[arg(short, long, value_name = "PATH")]
        config: Option<PathBuf>,
    },
    /// Print a commented reference configuration.
    Example,
    /// Print the JSON Schema of a configuration file.
    ///
    /// Point an editor at it (`#:schema ./daer.schema.json`) or validate a file in
    /// CI without building daer.
    Schema,
}

/// Runs `future` on a runtime built for the duration of the call.
///
/// Only the subcommands that do I/O (`dns serve`, `config validate`, `route
/// nodes`) pay for a runtime. The purely computational ones (`fmt`, `schema`,
/// `example`, `route explain` on an inline configuration) stay synchronous, which
/// keeps them fast enough to run in a loop and impossible to leave a thread behind.
fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a current-thread runtime")
        .block_on(future)
}

/// Runs the daemon on a multi-threaded runtime.
///
/// # Why the daemon cannot use [`block_on`]
///
/// `daer run` supervises work it does not drive itself: every relayed flow, every datagram, and
/// the reply pump of every datagram session are `tokio::spawn`ed tasks. On a current-thread
/// runtime those tasks only run while the *main* future is suspended at an `.await` that yields
/// to the scheduler, and the daemon's main future is a `select!` over signal and accept futures
/// — so a spawned task can starve indefinitely behind it.
///
/// That is not theoretical: a datagram was received, its session was opened, and the
/// `tokio::spawn`ed `send` to the origin never ran, so the client timed out with the daemon
/// reporting a healthy session. Two worker threads are enough to break the dependency (the
/// accept loop and the relay are separate tasks, and neither blocks), and the count comes from
/// the machine so a busy box is not limited to two.
fn block_on_daemon<F: std::future::Future>(future: F) -> F::Output {
    let workers = std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(2)
        .max(2);
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_all()
        .build()
        .expect("a multi-threaded runtime")
        .block_on(future)
}

/// Installs the log subscriber once, from `RUST_LOG` or the configuration's `log-level`.
///
/// # Why this is not in a library
///
/// A binary owns its process-wide state, and a library that installs a subscriber takes that
/// decision away from the program that links it. Every `tracing::info!` in `daer-control` and
/// `daer-dns` was written expecting *someone* to install one; before this existed they were
/// all silently dropped, including the reload and per-flow fields `docs/how-to/diagnostics.md`
/// documents as the way to answer "why did this flow go there".
fn init_logging(level: &str) {
    use tracing_subscriber::EnvFilter;
    // `RUST_LOG` wins: it is what an operator reaches for when a service misbehaves, and it
    // has to work without editing the configuration file.
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(level))
        .unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_writer(std::io::stderr)
        .try_init();
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Config { command } => match command {
            ConfigCommand::Validate { config } => resolve_config(config).and_then(|path| {
                // Only subcommands that fetch (validate, route) need a runtime; the
                // rest stay synchronous and side-effect free.
                block_on(async move { validate(&path).await })
            }),
            ConfigCommand::Fmt { config } => resolve_config(config).and_then(|path| fmt(&path)),
            ConfigCommand::Example => {
                print!("{EXAMPLE_TOML}");
                Ok(())
            }
            ConfigCommand::Schema => {
                println!("{}", daer_config::schema::json_schema());
                Ok(())
            }
        },
        Command::Node { command } => match command {
            NodeCommand::Convert { link } => convert_node(link.as_deref()),
        },
        Command::Route { command } => match command {
            RouteCommand::Explain {
                source,
                destination,
                config,
                why,
                domain,
            } => resolve_config(config).and_then(|path| {
                block_on(async move {
                    explain_route(&path, source, destination, why, domain.as_deref()).await
                })
            }),
            RouteCommand::Nodes { config } => resolve_config(config)
                .and_then(|path| block_on(async move { list_nodes(&path).await })),
        },
        Command::Run {
            config,
            object,
            no_datapath,
            dry_run,
        } => resolve_config(config).and_then(|path| {
            // The daemon supervises spawned tasks (relays, datagrams, probes); see
            // `block_on_daemon` for why a current-thread runtime starves them.
            block_on_daemon(async move {
                run::run(run::RunOptions {
                    config: path,
                    object,
                    no_datapath,
                    dry_run,
                })
                .await
            })
        }),
        Command::Dns { command } => match command {
            dns::Command::Serve {
                config,
                listen,
                udp_only,
                tcp_only,
            } => resolve_config(config).and_then(|path| {
                // The only subcommand that runs a service, so the only one that builds a
                // runtime. Inspection commands stay synchronous and side-effect free.
                let runtime = tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()
                    .context("cannot start the async runtime")?;
                runtime.block_on(serve_dns(&path, listen, udp_only, tcp_only))
            }),
            dns::Command::Check { config } => {
                resolve_config(config).and_then(|path| check_dns(&path))
            }
        },
        Command::Version => {
            println!(
                "{} {} ({}, {})",
                daer_common::consts::APP_NAME,
                env!("CARGO_PKG_VERSION"),
                std::env::consts::OS,
                std::env::consts::ARCH
            );
            Ok(())
        }
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{err:#}");
            ExitCode::FAILURE
        }
    }
}

/// Runs the DNS server until a signal arrives.
async fn serve_dns(
    path: &Path,
    listen: Option<SocketAddr>,
    udp_only: bool,
    tcp_only: bool,
) -> anyhow::Result<()> {
    let config = dns::load(path)?;
    let plan =
        dns::Plan::resolve(&config, listen, udp_only, tcp_only).map_err(anyhow::Error::msg)?;
    let resolver = dns::build_resolver(&config)?;

    println!("daer dns: serving {}", plan.describe());

    {
        // One shutdown signal for both sockets, so they stop together. `watch` rather than a
        // oneshot because both servers need it and neither should own it.
        let (shutdown, _) = tokio::sync::broadcast::channel::<()>(1);
        let mut udp_shutdown = shutdown.subscribe();
        let mut tcp_shutdown = shutdown.subscribe();

        let udp = plan.udp.then(|| {
            let resolver = std::sync::Arc::clone(&resolver);
            let address = plan.address;
            tokio::spawn(async move {
                daer_dns::serve_udp(resolver, address, async move {
                    let _ = udp_shutdown.recv().await;
                })
                .await
            })
        });
        let tcp = plan.tcp.then(|| {
            let resolver = std::sync::Arc::clone(&resolver);
            let address = plan.address;
            tokio::spawn(async move {
                daer_dns::serve_tcp(resolver, address, async move {
                    let _ = tcp_shutdown.recv().await;
                })
                .await
            })
        });

        wait_for_signal().await;
        eprintln!("daer dns: shutting down");
        let _ = shutdown.send(());

        for handle in [udp, tcp].into_iter().flatten() {
            match handle.await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => eprintln!("daer dns: {error}"),
                Err(error) => eprintln!("daer dns: server task failed: {error}"),
            }
        }
        Ok(())
    }
}

/// Resolves when the process is asked to stop.
async fn wait_for_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut terminate = match signal(SignalKind::terminate()) {
            Ok(signal) => signal,
            Err(error) => {
                eprintln!("daer dns: cannot install SIGTERM handler: {error}");
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// Reports which upstreams this build can use.
fn check_dns(path: &Path) -> anyhow::Result<()> {
    let config = dns::load(path)?;
    // Compile the resolver as well: `check` must fail for anything `serve` would refuse, or
    // it is a check that cannot be trusted.
    let _ = dns::build_resolver(&config)?;

    let reports = dns::check_upstreams(&config).map_err(anyhow::Error::msg)?;
    if reports.is_empty() {
        println!("{}: no dns.upstream entries declared", path.display());
        return Ok(());
    }
    let unusable = reports
        .iter()
        .filter(|report| report.unavailable.is_some())
        .count();
    for report in &reports {
        println!("{}", report.line());
    }
    if unusable > 0 {
        anyhow::bail!(
            "{unusable} of {} upstream(s) cannot be used by this build",
            reports.len()
        );
    }
    println!(
        "{}: {} upstream(s), all usable",
        path.display(),
        reports.len()
    );
    Ok(())
}

/// Resolves `--config`, falling back to the first conventional path that exists.
fn resolve_config(explicit: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    if let Some(path) = explicit {
        return Ok(path);
    }
    let dir = Path::new(DEFAULT_CONFIG_DIR);
    for name in DEFAULT_CONFIG_NAMES {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    anyhow::bail!(
        "no configuration found in {DEFAULT_CONFIG_DIR} (tried {}); pass --config",
        DEFAULT_CONFIG_NAMES.join(", ")
    )
}

/// A loaded configuration and where it came from.
#[derive(Debug)]
struct LoadedConfig {
    config: Config,
    files: Vec<PathBuf>,
    warnings: Vec<String>,
}

fn load_config(path: &Path) -> anyhow::Result<LoadedConfig> {
    if path.extension().and_then(|ext| ext.to_str()) != Some("toml") {
        anyhow::bail!("{}: expected a `.toml` configuration", path.display());
    }
    let loaded = daer_config::toml_config::load(path)
        .with_context(|| format!("failed to load {}", path.display()))?;
    Ok(LoadedConfig {
        config: loaded.config,
        files: loaded.files,
        warnings: loaded.warnings,
    })
}

async fn validate(path: &Path) -> anyhow::Result<()> {
    let report = validate_config(path).await?;
    for warning in &report.warnings {
        eprintln!("warning: {warning}");
    }
    println!(
        "{}: ok, {} routing rule(s), {} file(s)",
        path.display(),
        report.rules,
        report.files
    );
    Ok(())
}

fn fmt(path: &Path) -> anyhow::Result<()> {
    let loaded = load_config(path)?;
    print!("{}", daer_config::toml_config::to_string(&loaded.config));
    Ok(())
}

fn convert_node(link: Option<&str>) -> anyhow::Result<()> {
    if let Some(link) = link {
        let structured =
            daer_config::StructuredNode::from_link(link).map_err(|e| anyhow::anyhow!("{e}"))?;
        println!(
            "{}",
            structured
                .to_toml_node()
                .map_err(|e| anyhow::anyhow!("{e}"))?
        );
    } else {
        use std::io::BufRead;
        let stdin = std::io::stdin();
        let mut count = 0;
        for line in stdin.lock().lines() {
            let line = line?;
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
                continue;
            }
            let structured = daer_config::StructuredNode::from_link(line)
                .map_err(|e| anyhow::anyhow!("{line:?}: {e}"))?;
            println!(
                "{}",
                structured
                    .to_toml_node()
                    .map_err(|e| anyhow::anyhow!("{e}"))?
            );
            count += 1;
        }
        if count == 0 {
            anyhow::bail!("no links provided via stdin");
        }
    }
    Ok(())
}

/// Prints the routing decision for one flow and whether it is actionable.
///
/// Exit status is part of the contract: `0` when the flow has a usable outbound,
/// `1` when it would be dropped (`block`, a missing group, or an empty group). A
/// diagnostic that always exits 0 cannot be used in a check.
async fn explain_route(
    path: &Path,
    source: SocketAddr,
    destination: SocketAddr,
    why: bool,
    domain: Option<&str>,
) -> anyhow::Result<()> {
    let explanation = explain(path, &source.to_string(), &destination.to_string(), domain).await?;
    println!("{explanation}");
    if why {
        // The trace is what turns "it went to proxy" into "rule 3's domain predicate
        // is the one that did not match".
        println!();
        print!("{}", explanation.trace);
        let shadowed = explanation.trace.shadowed();
        if !shadowed.is_empty() {
            println!();
            for rule in shadowed {
                println!(
                    "rule {} would also have matched; it is reachable only if rule {} stops matching",
                    rule.rule,
                    explanation.rule.unwrap_or_default()
                );
            }
        }
    }
    if &*explanation.outbound.name == "block" {
        println!("  verdict    : dropped by a rule");
        anyhow::bail!("the flow would be blocked");
    }
    // An empty group is a decision that cannot be carried out: the flow has a
    // destination, and there is no node to send it to. Reporting that as success
    // would make the exit status useless as a check — the whole reason it exists.
    if !explanation.outbound_is_actionable() {
        println!(
            "  verdict    : undeliverable, group {:?} has no selectable node",
            explanation.outbound.name
        );
        anyhow::bail!(
            "the flow would be dropped: outbound {:?} has no selectable node",
            explanation.outbound.name
        );
    }
    Ok(())
}

/// Loads a configuration with every `[[subscription]]` resolved.
///
/// Every inspection command goes through this, because a diagnostic that reads a
/// different configuration than the daemon serves is worse than no diagnostic: it
/// answers confidently about a node pool that does not exist.
async fn load_resolved(path: &Path) -> anyhow::Result<LoadedConfig> {
    // One loader for every entry point (ADR-0006). This used to be a second implementation that
    // resolved subscriptions differently from `daer run` and never warned about an empty group,
    // which is how `route nodes` and the daemon came to disagree about the node pool.
    let resolved = daer_control::load_resolved(path).await?;
    Ok(LoadedConfig {
        config: resolved.config,
        files: resolved.files,
        warnings: resolved.warnings,
    })
}

/// Lists every node with its protocol and security identity.
async fn list_nodes(path: &Path) -> anyhow::Result<()> {
    let loaded = load_resolved(path).await?;
    let options = daer_control::RouterOptions::with_assets_beside(path);
    let generations = daer_control::Generations::new(&loaded.config, &options)
        .with_context(|| path.display().to_string())?;
    let router = generations.current();
    let nodes = router.router().nodes();
    if nodes.is_empty() {
        println!("{}: no nodes declared", path.display());
        return Ok(());
    }

    let mut group = String::new();
    for node in &nodes {
        if node.group != group {
            println!("[{}]", node.group);
            group.clone_from(&node.group);
        }
        println!("  {node}", node = node_describe(node));
    }
    println!();
    // The fallback decides in the output whether a whole subscription is unprotected, which is
    // something an operator should see without reading every line.
    let plaintext = nodes
        .iter()
        .filter(|node| !node.security.is_confidential())
        .count();
    if plaintext > 0 {
        println!(
            "{plaintext} of {} node(s) carry no confidentiality: socks5/http send credentials in \
             plain text, and `direct` is by definition unencrypted",
            nodes.len()
        );
    }
    Ok(())
}

/// One node line, without the group it was already printed under.
fn node_describe(node: &daer_control::NodeIdentity) -> String {
    format!(
        "{} [{} | {}]",
        node.node,
        node.protocol.as_str(),
        node.security.describe()
    )
}

/// The decision for one flow, from the same compiled generation a running daer
/// would use.
async fn explain(
    path: &Path,
    source: &str,
    destination: &str,
    domain: Option<&str>,
) -> anyhow::Result<daer_control::Explanation> {
    let source: SocketAddr = source.parse().context("invalid source address")?;
    let destination: SocketAddr = destination.parse().context("invalid destination address")?;
    let loaded = load_resolved(path).await?;
    let options = daer_control::RouterOptions::with_assets_beside(path);
    let generations = daer_control::Generations::new(&loaded.config, &options)
        .with_context(|| path.display().to_string())?;
    Ok(generations
        .current()
        .router()
        .explain_with_domain(source, destination, domain))
}

#[derive(Debug)]
struct ValidationReport {
    rules: usize,
    files: usize,
    warnings: Vec<String>,
}

/// Dry-runs the same optimizer and lowering chain the data path uses, and
/// resolves every outbound name.
///
/// Asynchronous because a subscription is fetched here: `validate` must exercise
/// the same resolution a run would, or it is verifying a different configuration
/// than the one that will serve.
async fn validate_config(path: &Path) -> anyhow::Result<ValidationReport> {
    let mut loaded = load_config(path)?;
    let mut warnings = loaded.warnings.clone();

    let config_dir = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    let dat_reader = DatReaderOptimizer::new(vec![config_dir.clone()]);

    let program = NormalizedProgram::new(
        &loaded.config.routing.rules,
        loaded.config.routing.fallback.clone(),
        &[
            &AliasOptimizer,
            &dat_reader,
            &MergeAndSortOptimizer,
            &DeduplicateParamsOptimizer,
        ],
    )
    .context("invalid routing rules")?;

    let mut sink = ValidationSink::default();
    {
        let mut builder = RulesBuilder::new(&mut sink);
        program
            .lower(&mut builder, |fallback| {
                let outbound = fallback_outbound(fallback)?;
                resolve_outbound(&loaded.config, &outbound.name)
            })
            .context("invalid routing rules")?;
    }
    warnings.extend(sink.warnings);

    for rule in &program.rules {
        let outbound = parse_outbound(&rule.outbound).context("invalid routing rules")?;
        resolve_outbound(&loaded.config, &outbound.name).context("invalid routing rules")?;
    }

    validate_groups(&loaded.config)?;

    // Resolve subscriptions before checking the node pool, so a node that only a
    // subscription provides is checked like any other.
    let resolution = daer_control::resolve_subscriptions(&mut loaded.config, &config_dir).await;
    if !resolution.subscriptions.is_empty() {
        if resolution.all_usable() {
            warnings.push(format!(
                "subscriptions: {} ({} node(s) added)",
                resolution.describe(),
                resolution.from_subscription
            ));
        } else {
            anyhow::bail!(
                "{} of {} subscription(s) produced no node and no cache could supply one: {}",
                resolution.failed().len(),
                resolution.subscriptions.len(),
                resolution.describe()
            );
        }
    }

    validate_runtime(&loaded.config, &mut warnings)?;

    Ok(ValidationReport {
        rules: loaded.config.routing.rules.len(),
        files: loaded.files.len(),
        warnings,
    })
}

/// Validates `group` policies and filters the way the run path builds them.
fn validate_groups(config: &Config) -> anyhow::Result<()> {
    for group in &config.group {
        parse_group_policy(&group.policy)
            .map_err(|message| anyhow::anyhow!("group {:?}: {message}", group.name))?;
        let filters: Vec<Vec<daer_config::Function>> = group
            .filters
            .iter()
            .map(|filter| filter.functions.clone())
            .collect();
        let annotations: Vec<Vec<daer_config::Param>> = group
            .filters
            .iter()
            .map(|filter| filter.annotate.clone())
            .collect();
        FilterSet::compile(&filters, &annotations)
            .map_err(|error| anyhow::anyhow!("group {:?}: {error}", group.name))?;
    }
    Ok(())
}

fn fallback_outbound(fallback: &FunctionOrString) -> Result<Outbound, RoutingError> {
    let function = fallback.as_function().map_err(RoutingError::new)?;
    parse_outbound(&function)
}

/// Fails on anything the run path would refuse, so `validate` is a real gate.
///
/// Checks that were missing, each of which produced a green light for a
/// configuration that cannot run:
///
/// * `dns.bind` was never parsed here, so `bind = "0.0.0.0:53"` passed `validate`
///   and then failed every `dns serve`;
/// * a node whose protocol this build cannot speak was skipped silently at
///   generation build time, so a configuration made only of `vmess://` nodes
///   validated clean and then had no selectable node at all.
///
/// Subscriptions are *resolved*, not assumed: `validate` fetches them, so a
/// subscription that is unreachable and uncached is an error here rather than an
/// empty group at run time.
///
/// A validator that passes a configuration the daemon cannot serve is worse than no
/// validator: it is trusted.
fn validate_runtime(config: &Config, warnings: &mut Vec<String>) -> anyhow::Result<()> {
    // The DNS plan is what `dns serve` binds; validating it here is the only way
    // `validate` and `serve` cannot disagree.
    crate::dns::Plan::resolve(config, None, false, false)
        .map_err(|message| anyhow::anyhow!("{message}"))?;

    // Every node must be either usable or named as unusable: a node that is
    // silently unselectable makes a group look populated while every flow to it
    // fails.
    let mut unusable = Vec::new();
    for node in &config.node {
        let label = node.label();
        match daer_outbound::NodeDialer::from_node(
            node,
            daer_outbound::DialerOptions::new(None, std::time::Duration::from_secs(1)),
        ) {
            Ok(_) => {}
            Err(error) => {
                if node.subscription.is_some() {
                    warnings.push(format!(
                        "subscription node {label:?} is not selectable by this build (skipped): {error}"
                    ));
                } else {
                    unusable.push(format!("{label}: {error}"));
                }
            }
        }
    }
    if !unusable.is_empty() {
        anyhow::bail!(
            "{} node(s) cannot be selected by this build:\n  {}",
            unusable.len(),
            unusable.join("\n  ")
        );
    }

    for group in &config.group {
        let matched = config
            .node
            .iter()
            .filter(|node| daer_control::group_mentions_node(group, node))
            .count();
        if matched == 0 {
            warnings.push(format!(
                "group {:?} selects no node from the {} declared node(s); every flow routed to \
                 it will fail",
                group.name,
                config.node.len()
            ));
        }
    }

    Ok(())
}

/// Whether a group's filters could select `node`.
///
/// Filters are expressions, so this is a conservative *lower* bound: it returns
/// true when the group names no filters at all, and otherwise defers to the real
/// filter engine. A false negative here would be a spurious warning, which is why
/// the check is only used to warn.
fn resolve_outbound(config: &Config, name: &str) -> Result<(), RoutingError> {
    if is_builtin_outbound(name) || config.group.iter().any(|group| group.name == name) {
        return Ok(());
    }
    Err(RoutingError::new(format!(
        "outbound (group) {name:?} not found; please define it in a [[group]] table"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let mut path = std::env::temp_dir();
            path.push(format!(
                "daer-cli-{name}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).expect("creates dir");
            Self(path)
        }

        fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
            let path = self.0.join(name);
            std::fs::File::create(&path)
                .expect("creates file")
                .write_all(bytes)
                .expect("writes");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                    .expect("chmod");
            }
            path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn varint(mut value: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let byte = (value & 0x7f) as u8;
            value >>= 7;
            if value == 0 {
                out.push(byte);
                return out;
            }
            out.push(byte | 0x80);
        }
    }

    fn length_delimited(number: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = varint(u64::from((number << 3) | 2));
        out.extend_from_slice(&varint(payload.len() as u64));
        out.extend_from_slice(payload);
        out
    }

    fn geoip_dat(code: &str, prefix: u8, ip: &[u8]) -> Vec<u8> {
        let mut cidr = length_delimited(1, ip);
        cidr.extend_from_slice(&varint(0x10));
        cidr.extend_from_slice(&varint(u64::from(prefix)));
        let mut entry = length_delimited(1, code.as_bytes());
        entry.extend_from_slice(&length_delimited(2, &cidr));
        length_delimited(1, &entry)
    }

    fn geosite_dat(code: &str, value: &str) -> Vec<u8> {
        let mut domain = vec![0x08, 0x03];
        domain.extend_from_slice(&length_delimited(2, value.as_bytes()));
        let mut entry = length_delimited(1, code.as_bytes());
        entry.extend_from_slice(&length_delimited(2, &domain));
        length_delimited(1, &entry)
    }

    #[test]
    fn the_reference_example_validates() {
        let dir = TempDir::new("example");
        let mut geoip = geoip_dat("cn", 24, &[1, 2, 3, 0]);
        geoip.extend(geoip_dat("private", 8, &[10, 0, 0, 0]));
        dir.write("geoip.dat", &geoip);
        dir.write("geosite.dat", &geosite_dat("cn", "example.cn"));
        let config = dir.write("config.toml", EXAMPLE_TOML.as_bytes());

        let report = block_on(validate_config(&config)).expect("the shipped example validates");
        assert!(report.rules > 0);
        assert_eq!(report.files, 1);

        // ADR-0006/ADR-0007: a configuration whose group can select no node must *say so*, and
        // the shipped example is exactly that shape — its nodes are commented out on purpose, so
        // `route explain` reports an empty group instead of pretending. What this asserts is the
        // diagnostic, not a silent success: the failure mode being guarded against is a default
        // policy that selects nothing **without** anyone noticing.
        let resolution = block_on(load_resolved(&config)).expect("resolves");
        assert!(
            resolution
                .warnings
                .iter()
                .any(|warning| warning.contains("selects no node")),
            "the example has no active nodes, so loading it must warn that its group is empty; \
             got {:?}",
            resolution.warnings
        );

        // And a node added to the pool must make the group selectable under the default policy,
        // which is the part that regressed (`min-moving-avg` selected nothing until a probe ran).
        let text = format!(
            "{}\n[[node]]\ntag = \"example\"\ntype = \"socks5\"\nserver = \"127.0.0.1\"\nport = 1080\n",
            EXAMPLE_TOML
        );
        let config_with_node = dir.write("with-node.toml", text.as_bytes());
        let resolved = block_on(load_resolved(&config_with_node)).expect("resolves");
        let options = daer_control::RouterOptions::with_assets_beside(&config_with_node);
        let generations =
            daer_control::Generations::new(&resolved.config, &options).expect("builds");
        let node = generations
            .current()
            .router()
            .node_identity("proxy")
            .expect("the example's default policy must select a node once one exists");
        assert_eq!(node.group, "proxy");
    }

    #[test]
    fn validates_a_toml_config_with_geodata() {
        let dir = TempDir::new("ok");
        let mut geoip = geoip_dat("cn", 24, &[1, 2, 3, 0]);
        geoip.extend(geoip_dat("private", 8, &[10, 0, 0, 0]));
        dir.write("geoip.dat", &geoip);
        dir.write("geosite.dat", &geosite_dat("cn", "example.cn"));
        let config = dir.write(
            "config.toml",
            br#"[[group]]
name = "proxy"
policy = "min-moving-avg"

[routing]
rules = ["dip(geoip:cn) -> direct", "domain(geosite:cn) -> proxy"]
fallback = "proxy"
"#,
        );

        let report = block_on(validate_config(&config)).expect("validates");
        assert_eq!(report.rules, 2);
        assert_eq!(report.files, 1);
    }

    #[test]
    fn rejects_unknown_formats() {
        let dir = TempDir::new("ext");
        let config = dir.write("config.yaml", b"[global]\n");
        let error = block_on(validate_config(&config)).expect_err("must fail");
        assert!(
            format!("{error:#}").contains("expected a `.toml`"),
            "{error:#}"
        );
    }

    #[test]
    fn rejects_unknown_groups() {
        let dir = TempDir::new("unknown");
        let config = dir.write(
            "config.toml",
            b"[routing]\nrules = [\"dport(443) -> nope\"]\nfallback = \"nope\"\n",
        );
        let error = block_on(validate_config(&config)).expect_err("must fail");
        assert!(format!("{error:#}").contains("not found"), "{error:#}");
    }

    #[test]
    fn rejects_missing_geodata() {
        let dir = TempDir::new("missing");
        let config = dir.write(
            "config.toml",
            b"[routing]\nrules = [\"dip(geoip:cn) -> direct\"]\nfallback = \"direct\"\n",
        );
        let error = block_on(validate_config(&config)).expect_err("must fail");
        assert!(format!("{error:#}").contains("geoip.dat"), "{error:#}");
    }

    #[test]
    fn rejects_a_dns_bind_that_is_an_address_not_an_ip() {
        // The example configuration shipped `0.0.0.0:53` for a while, and `validate`
        // passed it while `dns serve` refused it. The gate is now the same code.
        let dir = TempDir::new("badbind");
        let config = dir.write("config.toml", b"[dns]\nbind = \"0.0.0.0:53\"\n");
        let error = block_on(validate_config(&config)).expect_err("must fail");
        let message = format!("{error:#}");
        assert!(message.contains("dns.bind"), "{message}");
        assert!(message.contains("not an IP"), "{message}");
    }

    #[test]
    fn rejects_a_node_whose_protocol_this_build_cannot_speak() {
        let dir = TempDir::new("badproto");
        let config = dir.write(
            "config.toml",
            br#"[[node]]
tag = "v"
type = "vmess"

[[group]]
name = "g"
policy = "min"

[routing]
fallback = "g"
"#,
        );
        let error = block_on(validate_config(&config)).expect_err("must fail");
        let message = format!("{error:#}");
        assert!(message.contains("vmess"), "{message}");
    }

    #[test]
    fn rejects_a_chained_link_rather_than_truncating_it() {
        let err = convert_node(Some("socks5://127.0.0.1:1080 -> socks5://127.0.0.1:1081"))
            .expect_err("chained link must fail");
        assert!(format!("{err:#}").contains("chained links"), "{err:#}");
    }

    #[test]
    fn warns_when_a_group_selects_no_node() {
        let dir = TempDir::new("emptynode");
        let config = dir.write(
            "config.toml",
            b"[[group]]\nname = \"g\"\npolicy = \"min\"\n",
        );
        let report = block_on(validate_config(&config)).expect("validates");
        assert!(
            report
                .warnings
                .iter()
                .any(|warning| warning.contains("selects no node")),
            "{:?}",
            report.warnings
        );
    }

    #[test]
    fn rejects_bad_group_policies() {
        let dir = TempDir::new("badgroup");
        let config = dir.write(
            "config.toml",
            b"[[group]]\nname = \"g\"\npolicy = \"fastest\"\n",
        );
        let error = block_on(validate_config(&config)).expect_err("must fail");
        assert!(
            format!("{error:#}").contains("unexpected policy"),
            "{error:#}"
        );
    }

    #[test]
    fn rejects_bad_group_filter_regexes() {
        let dir = TempDir::new("badfilter");
        let config = dir.write(
            "config.toml",
            b"[[group]]\nname = \"g\"\npolicy = \"min-avg10\"\nfilters = [\"name(regex: '[')\"]\n",
        );
        let error = block_on(validate_config(&config)).expect_err("must fail");
        assert!(format!("{error:#}").contains("bad regexp"), "{error:#}");
    }

    #[test]
    fn accepts_groups_with_filters_and_annotations() {
        let dir = TempDir::new("goodgroup");
        let config = dir.write(
            "config.toml",
            br#"[[group]]
name = "g"
policy = "fixed(0)"
filters = [
    "name(keyword: HK) && !name(keyword: 'ExpireAt:')",
    { match = "subtag(my_sub)", annotate = { add_latency = "-500ms" } },
]
"#,
        );
        block_on(validate_config(&config)).expect("validates");
    }

    #[test]
    fn route_explain_names_the_rule_that_fires() {
        let dir = TempDir::new("explain");
        let config = dir.write(
            "config.toml",
            br#"[[node]]
tag = "n1"
type = "socks5"
server = "127.0.0.1"
port = 1080

[[group]]
name = "proxy"
policy = "fixed(0)"

[routing]
rules = ["port(443) -> proxy"]
fallback = "direct"
"#,
        );

        let explanation = block_on(explain(
            &config,
            "10.0.0.2:40000",
            "93.184.216.34:443",
            None,
        ))
        .expect("explains");
        assert_eq!(explanation.rule, Some(0));
        assert_eq!(explanation.rule_text, "port(443) -> proxy");
        assert_eq!(&*explanation.outbound.name, "proxy");

        let explanation = block_on(explain(&config, "10.0.0.2:40000", "93.184.216.34:80", None))
            .expect("explains");
        assert_eq!(explanation.rule, None, "the fallback decided");
        assert_eq!(&*explanation.outbound.name, "direct");
    }

    #[test]
    fn route_explain_reports_an_empty_group_as_a_failure() {
        // The documented contract: exit 1 when the flow would be dropped. A group
        // with no selectable node cannot carry the flow, so it is a drop — the
        // earlier behaviour printed a verdict and exited 0, which made the exit
        // status useless for the check it exists for.
        let dir = TempDir::new("explain-empty-group");
        let config = dir.write(
            "config.toml",
            b"[[group]]\nname = \"empty\"\npolicy = \"min\"\n[routing]\nfallback = \"empty\"\n",
        );
        let error = block_on(explain_route(
            &config,
            "10.0.0.2:40000".parse().expect("source"),
            "93.184.216.34:443".parse().expect("destination"),
            false,
            None,
        ))
        .expect_err("an empty group must not exit 0");
        let message = error.to_string();
        assert!(message.contains("no selectable node"), "{message}");
    }

    #[test]
    fn route_explain_reports_a_blocked_flow_as_a_failure() {
        let dir = TempDir::new("explain-block");
        let config = dir.write(
            "config.toml",
            b"[routing]\nrules = [\"port(443) -> block\"]\nfallback = \"direct\"\n",
        );

        let error = block_on(explain_route(
            &config,
            "10.0.0.2:40000".parse().expect("source"),
            "93.184.216.34:443".parse().expect("destination"),
            false,
            None,
        ))
        .expect_err("a blocked flow must not exit 0");
        assert!(error.to_string().contains("blocked"), "{error}");
    }

    #[test]
    fn route_explain_why_reports_every_rule_and_predicate() {
        let dir = TempDir::new("explain-why");
        let config = dir.write(
            "config.toml",
            b"[routing]\nrules = [\"port(443) -> block\", \"l4proto(tcp) -> direct\"]\nfallback = \"direct\"\n",
        );

        let explanation = block_on(explain(&config, "10.0.0.2:40000", "93.184.216.34:80", None))
            .expect("explains");
        let rendered = explanation.trace.to_string();
        assert!(rendered.contains("rule 0 [skipped]"), "{rendered}");
        assert!(rendered.contains("port(443)"), "{rendered}");
        assert!(rendered.contains("rule 1 [fired]"), "{rendered}");
        // TCP matches, so the second rule fires; nothing else needs to be explained.
        assert!(explanation.trace.shadowed().is_empty(), "{rendered}");
    }

    #[test]
    fn route_nodes_lists_the_security_identity_of_every_node() {
        let dir = TempDir::new("nodes");
        let config = dir.write(
            "config.toml",
            br#"
[[node]]
tag = "ss"
type = "shadowsocks"
server = "1.2.3.4"
port = 8388
method = "aes-256-gcm"
password = "secret"

[[node]]
tag = "tj"
type = "trojan"
server = "node.example.com"
port = 443
password = "pw"

[[node]]
tag = "plain"
type = "socks5"
server = "127.0.0.1"
port = 1080

[[group]]
name = "proxy"
policy = "fixed(0)"
"#,
        );

        let loaded = load_config(&config).expect("loads");
        let options = daer_control::RouterOptions::with_assets_beside(&config);
        let generations = daer_control::Generations::new(&loaded.config, &options).expect("builds");
        let nodes = generations.current().router().nodes();
        assert_eq!(nodes.len(), 3, "{nodes:#?}");

        let ss = nodes.iter().find(|node| node.node == "ss").expect("ss");
        assert_eq!(ss.protocol, daer_outbound::Protocol::ShadowSocks);
        assert!(ss.security.is_confidential());
        assert!(ss.security.describe().contains("aes-256-gcm"), "{ss:?}");

        let trojan = nodes.iter().find(|node| node.node == "tj").expect("trojan");
        assert!(trojan.security.is_confidential());
        assert!(
            trojan
                .security
                .describe()
                .contains("tls sni=node.example.com"),
            "{trojan:?}"
        );

        let plain = nodes
            .iter()
            .find(|node| node.node == "plain")
            .expect("plain");
        assert!(!plain.security.is_confidential(), "socks5 is plaintext");

        // The one property that must never regress: no secret is printed.
        for node in &nodes {
            assert!(!node.describe().contains("secret"), "{}", node.describe());
            assert!(!node.describe().contains("pw@"), "{}", node.describe());
        }
    }

    #[test]
    fn route_explain_names_the_selected_node() {
        let dir = TempDir::new("explain-node");
        let config = dir.write(
            "config.toml",
            br#"[[node]]
tag = "tj"
type = "trojan"
server = "node.example.com"
port = 443
password = "pw"

[[group]]
name = "proxy"
policy = "fixed(0)"

[routing]
rules = ["port(443) -> proxy"]
fallback = "direct"
"#,
        );

        let explanation = block_on(explain(
            &config,
            "10.0.0.2:40000",
            "93.184.216.34:443",
            None,
        ))
        .expect("explains");
        let selected = explanation.selected.clone().expect("a node is selected");
        assert_eq!(selected.group, "proxy");
        assert_eq!(selected.node, "tj");
        assert!(selected.security.is_confidential());
        let rendered = explanation.to_string();
        assert!(rendered.contains("node       : proxy: tj"), "{rendered}");
        assert!(rendered.contains("tls sni=node.example.com"), "{rendered}");
        assert!(!rendered.contains("pw@"), "no credential in the output");
    }

    #[test]
    fn structured_nodes_integrate_with_routing_and_diagnostics() {
        let dir = TempDir::new("structured-nodes");
        let config = dir.write(
            "config.toml",
            br#"
schema = 1

[[node]]
tag = "hk-vless"
type = "vless"
server = "198.51.100.1"
port = 443
uuid = "b831381d-6324-4d53-ad4f-8cda48b30811"
flow = "xtls-rprx-vision"
[node.reality]
sni = "impersonate.example.com"
public-key = "f26c_e2kFv8-39rQz10M_xU8vI3f9Qk2lW0mNoPqRsT"
short-id = "ab01cd02"
fingerprint = "chrome"

[[node]]
tag = "us-ss"
type = "shadowsocks"
server = "198.51.100.2"
port = 8388
method = "chacha20-ietf-poly1305"
password = "super-secret-password"

[[group]]
name = "proxy"
policy = "fixed(0)"

[routing]
rules = []
fallback = "proxy"
"#,
        );

        let report = block_on(validate_config(&config)).expect("validates structured node config");
        assert_eq!(report.files, 1);

        let loaded = load_config(&config).expect("loads");
        assert_eq!(loaded.config.node.len(), 2);
        let options = daer_control::RouterOptions::with_assets_beside(&config);
        let generations = daer_control::Generations::new(&loaded.config, &options).expect("builds");
        let nodes = generations.current().router().nodes();
        assert_eq!(nodes.len(), 2);

        let vless = nodes
            .iter()
            .find(|n| n.node == "hk-vless")
            .expect("vless node");
        assert_eq!(vless.protocol, daer_outbound::Protocol::Reality);
        assert!(vless.security.is_confidential());
        assert!(vless.describe().contains("reality"));

        let ss = nodes.iter().find(|n| n.node == "us-ss").expect("ss node");
        assert_eq!(ss.protocol, daer_outbound::Protocol::ShadowSocks);
        assert!(ss.security.is_confidential());
        assert!(!ss.describe().contains("super-secret-password"));

        // Explain route verification
        let explanation = block_on(explain(
            &config,
            "10.0.0.2:40000",
            "93.184.216.34:443",
            None,
        ))
        .expect("explains");
        let selected = explanation.selected.expect("node selected");
        assert_eq!(selected.node, "hk-vless");
    }

    #[test]
    fn convert_node_command_converts_uri_to_structured_toml() {
        let vless_link = "vless://df4af3d0-030e-4062-baa6-eb9dd45298ef@fkus1keria.itknowledgeblog.com:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=portal.citygrainla.com&pbk=9IKqS8KEelO5cwsRvHXcz2-15-npnsx6k38qcf-GS0E&sid=672f#US%20VIP%2001";
        assert!(convert_node(Some(vless_link)).is_ok());

        let ss_link =
            "ss://YWVzLTEyOC1ncm06bm9uZQ==@127.0.0.1:1080?udp=0#Website%3A%20user.totorofree.com";
        assert!(convert_node(Some(ss_link)).is_ok());
    }

    #[test]
    fn subscription_node_filtering_and_selection() {
        let dir = TempDir::new("sub-filter");
        // Persist cache fixture with links from a real subscription
        let persist_dir = dir.0.join("persist.d");
        let cache = daer_outbound::subscription::Cache::new(persist_dir, "mysub");
        let _ = cache.write(&[
            "vless://df4af3d0-030e-4062-baa6-eb9dd45298ef@fkus1keria.itknowledgeblog.com:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=portal.citygrainla.com&pbk=9IKqS8KEelO5cwsRvHXcz2-15-npnsx6k38qcf-GS0E&sid=672f#US%20VIP%2001".to_owned(),
            "vless://df4af3d0-030e-4062-baa6-eb9dd45298ef@fkjp1keria.itknowledgeblog.com:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.titech.ac.jp&pbk=VAqawSsDR9SnBoN8ucLfUXIZO3Ugkd27HN7TOqh1AXo&sid=f0#Japan%20VIP%2001".to_owned(),
            "hysteria2://df4af3d0-030e-4062-baa6-eb9dd45298ef@151.242.183.252:20443?sni=apple.com#HK%2001".to_owned(),
        ]);

        let sub_url = "https://example.com/api/subscribe?token=test";
        let config_toml = format!(
            r#"
schema = 1

[[subscription]]
tag = "mysub"
url = "{sub_url}"
persist = true

[[group]]
name = "fastest-jp"
policy = "min-moving-avg"
filters = [
    "subtag(mysub) && name(keyword: 'Japan')"
]

[routing]
rules = ["dport(443) -> fastest-jp"]
fallback = "direct"
"#
        );
        let config = dir.write("config.toml", config_toml.as_bytes());

        let resolved = block_on(load_resolved(&config)).expect("resolves subscription");
        assert_eq!(resolved.config.node.len(), 3);

        // Verify group mentions node
        let jp_node = resolved
            .config
            .node
            .iter()
            .find(|n| n.label().contains("Japan"))
            .expect("jp node");
        let us_node = resolved
            .config
            .node
            .iter()
            .find(|n| n.label().contains("US"))
            .expect("us node");
        let jp_group = &resolved.config.group[0];

        assert!(daer_control::group_mentions_node(jp_group, jp_node));
        assert!(!daer_control::group_mentions_node(jp_group, us_node));

        // Validate config should succeed (unsupported hysteria2 from subscription produces a warning, not failure)
        let report = block_on(validate_config(&config)).expect("validates");
        assert!(
            report
                .warnings
                .iter()
                .any(|w| w.contains("cannot be selected") || w.contains("is not selectable"))
        );

        // Generates router and selects Japan node
        let options = daer_control::RouterOptions::with_assets_beside(&config);
        let generations =
            daer_control::Generations::new(&resolved.config, &options).expect("builds router");
        let selected_node = generations
            .current()
            .router()
            .node_identity("fastest-jp")
            .expect("node selected");
        assert_eq!(selected_node.group, "fastest-jp");
        assert!(selected_node.node.contains("Japan"));
    }

    #[test]
    fn a_direct_verdict_selects_no_node() {
        let dir = TempDir::new("explain-direct");
        let config = dir.write(
            "config.toml",
            br#"[routing]
rules = []
fallback = "direct"
"#,
        );
        let explanation = block_on(explain(
            &config,
            "10.0.0.2:40000",
            "93.184.216.34:443",
            None,
        ))
        .expect("explains");
        assert!(explanation.selected.is_none(), "direct picks no node");
        assert!(!explanation.to_string().contains("node       :"));
    }

    #[test]
    fn route_explain_refuses_a_configuration_that_cannot_run() {
        let dir = TempDir::new("explain-bad");
        let config = dir.write(
            "config.toml",
            b"[routing]\nrules = []\nfallback = \"nope\"\n",
        );
        let error = block_on(explain_route(
            &config,
            "10.0.0.2:40000".parse().expect("source"),
            "93.184.216.34:443".parse().expect("destination"),
            false,
            None,
        ))
        .expect_err("must not explain a configuration it cannot run");
        assert!(format!("{error:#}").contains("not found"), "{error:#}");
    }

    #[test]
    fn accepts_builtin_outbounds() {
        let dir = TempDir::new("builtin");
        let config = dir.write(
            "config.toml",
            b"[routing]\nrules = [\"dport(443) -> block\"]\nfallback = \"direct\"\n",
        );
        block_on(validate_config(&config)).expect("validates");
    }
}
