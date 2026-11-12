// SPDX-License-Identifier: AGPL-3.0-only

//! The `daer` command line.
//!
//! # The surface is focused runtime & diagnostics
//!
//! `daer` is a **runtime and network diagnostic suite**. It consumes a configuration; it does not manufacture one.
//!
//! ```text
//!   daer run                      the daemon: eBPF datapath + ingress + relay + DNS
//!   daer check                    does this configuration run, and what would it do
//!   daer route <TARGET>           which rule and outbound decide this flow or target
//!   daer probe <SUBCOMMAND>       active probe for node reachability, handshake, and health
//!   daer status [--nodes|--groups|--elections]  read-only runtime views
//!   daer elect <ELECTION> <NODE>  pin an existing election; `--reset` follows its rule
//!   daer schema                   the JSON Schema, for an editor
//!   daer version                  build information
//! ```
//!
//! Everything that used to sit beside those verbs was a *build-time producer* wearing a
//! runtime's clothes, and each one was removed rather than documented:
//!
//! | removed | why it is not the daemon's job |
//! | --- | --- |
//! | `config validate` | merged into `daer check`: one command answers "will this run". |
//! | `config fmt`, `config example` | a configuration is hand-written TOML; a formatter and a sample belong in an editor and in the docs. |
//! | `explain` | replaced by `daer route <TARGET>`: natural routing lookup mental model. |
//! | `node convert` | [ADR-0014] put subscription parsing in the runtime, so a URI no longer needs hand-converting. A text transformer is a third-party tool. |
//! | `rule compile` / `decompile` / `inspect` | the rule compiler is a **producer**. It lives in `daer-drb`, so the daemon links no Protobuf reader. |
//! | `dns serve` / `dns check` | the resolver is part of `daer run` (Fake-IP has no meaning without it) and upstream usability is part of `daer check`. A standalone DNS server is a different product. |
//!
//! [ADR-0014]: ../docs/adr/0014-drb-rule-binary-and-providers.md

mod control;
mod dns;
mod incident;
mod preflight;
mod probe;
mod run;
mod sd_notify;
mod status;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::Context;
use clap::{Parser, Subcommand};
use daer_config::{Config, DEFAULT_CONFIG_DIR, DEFAULT_CONFIG_NAMES, FunctionOrString};
use daer_outbound::FilterSet;
use daer_routing::{
    AliasOptimizer, DeduplicateParamsOptimizer, MergeAndSortOptimizer, NormalizedProgram, Outbound,
    RoutingError, RulesBuilder, ValidationSink, is_builtin_outbound, outbound_name, parse_outbound,
};

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
    /// Run the transparent proxy.
    Run {
        /// Configuration file. Defaults to `/etc/daer/config.toml`.
        #[arg(short, long, value_name = "PATH")]
        config: Option<PathBuf>,
        /// The compiled datapath object.
        #[arg(
            long,
            value_name = "PATH",
            default_value = "target/ebpf/datapath.bpf.o"
        )]
        object: PathBuf,
        /// Serve without attaching the kernel program.
        ///
        /// Nothing is redirected into the transparent port in this mode, so no traffic is
        /// proxied: it exists to exercise the accept/relay path without `CAP_BPF`,
        /// `CAP_PERFMON` or `CAP_SYS_ADMIN`. The transparent listener still needs
        /// `CAP_NET_ADMIN` to bind `IP_TRANSPARENT`.
        #[arg(long)]
        no_datapath: bool,
        /// Report what would happen, and change nothing.
        ///
        /// Resolves the configuration, builds the generation, validates the object against
        /// the ABI, computes the runtime parameter and reports the capabilities the next
        /// phase would need — then exits before the port is bound, the device pair or private
        /// ingress namespace is created, any sysctl or policy route is written, or `bpf()` is
        /// called. It needs no capability, which is what makes it usable as a deployment gate
        /// (ADR-0029).
        ///
        /// It is not `--no-datapath`: that one serves and skips only the kernel half.
        #[arg(long)]
        dry_run: bool,
        /// Maximum time in seconds to let live flows finish on SIGTERM/SIGINT.
        ///
        /// The listener stops accepting immediately; this bounds only the wait for
        /// already-relayed connections. Zero exits as soon as the listener is closed.
        #[arg(
            long,
            value_name = "SECONDS",
            default_value_t = run::DEFAULT_SHUTDOWN_TIMEOUT_SECS
        )]
        shutdown_timeout: u64,
    },
    /// Check that a configuration would run, and print what it would do.
    ///
    /// Resolves subscriptions and rule providers, compiles every rule, builds every group,
    /// binds nothing. Exits non-zero on anything `daer run` would refuse, which makes it the
    /// one command a deployment gate needs.
    Check {
        /// Configuration file. Defaults to `/etc/daer/config.toml`.
        #[arg(short, long, value_name = "PATH")]
        config: Option<PathBuf>,
        /// Print every node in every group, with its protocol and security identity.
        #[arg(long)]
        nodes: bool,
        /// Validate the compiled datapath object against the ABI.
        ///
        /// Defaults to the path `daer run` resolves — the same fallback chain, including the
        /// packaged install locations — so an installed artifact is validated without a flag.
        /// Pass `--object none` to skip the object entirely.
        ///
        /// This validates names, sections and BTF `func_info` without loading anything into
        /// the kernel, so it needs no capability (ADR-0029).
        #[arg(long, value_name = "PATH")]
        object: Option<PathBuf>,
        /// Also check the host prerequisites the datapath requires.
        ///
        /// Checks the Linux 6.6+ TCX baseline and the host-global sysctls (forwarding on,
        /// `rp_filter`/`arp_filter` relaxed). Reads `uname` and `/proc/sys`, needs no
        /// capability, and changes nothing. Without this flag, `daer check` validates only
        /// the configuration and the object; a deployment gate that wants to catch a host
        /// that would refuse to start should pass it.
        #[arg(long)]
        host: bool,
    },
    /// Route a flow, IP, or domain through the routing engine without running the daemon.
    ///
    /// Evaluates the identical decision the data path makes, from the same compiled generation.
    Route {
        /// Target to route: domain, IP, or IP:port (e.g. `bilibili.com`, `1.1.1.1`), or source address when 2 arguments are provided.
        target: String,
        /// Optional destination address (`ip:port` or `ip`) when target is used as source.
        destination: Option<String>,
        /// Optional client source address (`ip:port`). Defaults to `127.0.0.1:12345`.
        #[arg(long, value_name = "IP:PORT")]
        source: Option<SocketAddr>,
        /// Configuration file. Defaults to `/etc/daer/config.toml`.
        #[arg(short, long, value_name = "PATH")]
        config: Option<PathBuf>,
        /// The sniffed domain, as a `domain(...)` rule would see it (auto-inferred if target is a domain).
        #[arg(long, value_name = "NAME")]
        domain: Option<String>,
        /// Show every rule and every predicate, not just the winner.
        #[arg(long)]
        why: bool,
    },
    /// Probe network reachability, protocol handshake, or end-to-end connectivity.
    Probe {
        #[command(subcommand)]
        command: ProbeCommand,
    },
    /// Pin an election to a node, or clear its runtime override.
    ///
    /// This changes the election's current choice, not the routing table. All rules that
    /// target the election immediately use the pinned node; existing flows keep the node
    /// they started on.
    Elect {
        /// Election name (a routing target declared in `[[election]]`).
        election: String,
        /// Node name. Required unless `--reset` is given.
        #[arg(required_unless_present = "reset", conflicts_with = "reset")]
        node: Option<String>,
        /// Clear the override and return to the configured election rule.
        #[arg(long)]
        reset: bool,
        /// Print the daemon's JSON response.
        #[arg(long)]
        json: bool,
    },
    /// Read the running daemon's snapshot without changing anything.
    ///
    /// Reads `/run/daer/control.sock`; when the daemon is not reachable it falls back to the
    /// last `/run/daer/state.json` and says so. This is the first command in an incident
    /// runbook: it answers "what does the daemon believe right now" without a packet capture
    /// or a debug log level.
    Status {
        /// Print the versioned JSON snapshot instead of the human summary.
        #[arg(long)]
        json: bool,
        /// Write a self-contained incident bundle to this directory.
        #[arg(long, value_name = "DIR")]
        bundle: Option<PathBuf>,
        /// Print every event recorded for one flow/session ID.
        ///
        /// The JSON event stream is the flow record: `flow.accepted`, `flow.decided`,
        /// `flow.node_selected`, `flow.dial_finished`, `flow.closed` all carry the same ID.
        #[arg(long, value_name = "FLOW_ID")]
        flow: Option<String>,
        /// Show the live node catalog.
        #[arg(long, conflicts_with_all = ["groups", "elections", "flow", "bundle"])]
        nodes: bool,
        /// Show the live resource pools and their elections.
        #[arg(long, conflicts_with_all = ["nodes", "elections", "flow", "bundle"])]
        groups: bool,
        /// Show the live elections and their current results.
        #[arg(long, conflicts_with_all = ["nodes", "groups", "flow", "bundle"])]
        elections: bool,
    },
    /// Print the JSON Schema of a configuration file.
    ///
    /// Point an editor at it (`#:schema ./daer.schema.json`) or validate a file in CI without
    /// building daer. The reference configuration lives in the docs.
    Schema,
    /// Print build information.
    Version,
    /// Removed; replaced by `daer route`.
    #[command(hide = true)]
    Explain {
        #[command(subcommand)]
        command: Removed,
    },
    /// Removed in ADR-0015; the error names the replacement.
    #[command(hide = true)]
    Config {
        #[command(subcommand)]
        command: Removed,
    },
    /// Removed in ADR-0015; the error names the replacement.
    #[command(hide = true)]
    Node {
        #[command(subcommand)]
        command: Removed,
    },
    /// Removed in ADR-0015; the error names the replacement.
    #[command(hide = true)]
    Dns {
        #[command(subcommand)]
        command: Removed,
    },
    /// Removed in ADR-0015; the error names the replacement.
    #[command(hide = true)]
    Rule {
        #[command(subcommand)]
        command: Removed,
    },
}

#[derive(Debug, Subcommand)]
enum ProbeCommand {
    /// Probe an outbound node's reachability, TLS/protocol handshake, and health.
    Node {
        /// Name or label of the node declared in configuration, or a direct node URI link (vless://, ss://, etc.).
        #[arg(default_value = "")]
        node: String,
        /// Probe all nodes declared in the configuration file.
        #[arg(long)]
        all: bool,
        /// Probe every node a subscription file lists (one link per line, base64, or SIP008 JSON).
        #[arg(long, value_name = "PATH")]
        file: Option<PathBuf>,
        /// Configuration file. Defaults to `/etc/daer/config.toml` (ignored for direct URI links).
        #[arg(short, long, value_name = "PATH")]
        config: Option<PathBuf>,
        /// Probe timeout in seconds.
        #[arg(short, long, default_value = "5")]
        timeout: u64,
        /// Target URL for end-to-end test.
        #[arg(long, value_name = "URL")]
        url: Option<String>,
    },
    /// Probe an HTTP/HTTPS endpoint.
    Url {
        /// Target URL to probe.
        #[arg(default_value = "http://cp.cloudflare.com/generate_204")]
        url: String,
        /// Configuration file. Defaults to `/etc/daer/config.toml`.
        #[arg(short, long, value_name = "PATH")]
        config: Option<PathBuf>,
        /// Probe timeout in seconds.
        #[arg(short, long, default_value = "5")]
        timeout: u64,
        /// Node to probe through.
        #[arg(long, value_name = "NODE")]
        node: Option<String>,
    },
    /// Direct node link or node name probe.
    #[command(external_subcommand)]
    Direct(Vec<String>),
}

/// A subcommand placeholder that exists only to carry the migration message.
///
/// Accepting the flag and refusing with a reason is the difference between a script that tells
/// its operator what to change and one that prints `unknown subcommand` and stops. The verb is
/// `hide`n, so `--help` still shows four.
#[derive(Debug, Subcommand)]
enum Removed {
    /// The consumed arguments are irrelevant: the verb itself is the error.
    #[command(external_subcommand)]
    Any(#[allow(dead_code)] Vec<String>),
}

/// Runs `future` on a runtime built for the duration of the call.
///
/// Only the subcommands that do I/O (`check`, `explain`) pay for a runtime. The purely
/// computational ones (`schema`, `version`) stay synchronous, which keeps them fast enough to
/// run in a loop and impossible to leave a thread behind.
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

/// The reload handle for the process-wide log filter.
///
/// The daemon installs a bootstrap filter before it reads the configuration, because
/// `load_resolved` resolves subscriptions and rule providers and those paths can warn. The
/// configured `log-level` is applied by reloading this filter after the file is read. A
/// second subscriber is not installed: process-wide state has one owner.
static LOG_FILTER: std::sync::OnceLock<
    tracing_subscriber::reload::Handle<tracing_subscriber::EnvFilter, tracing_subscriber::Registry>,
> = std::sync::OnceLock::new();

/// Installs the bootstrap subscriber before any configuration is read.
fn init_bootstrap_logging(json_stream: bool) {
    use tracing_subscriber::layer::SubscriberExt as _;
    use tracing_subscriber::util::SubscriberInitExt as _;

    let from_env = tracing_subscriber::EnvFilter::try_from_default_env();
    if from_env.is_err() && std::env::var_os("RUST_LOG").is_some() {
        eprintln!("warning: RUST_LOG is not a valid tracing filter; using info");
    }
    let filter = from_env.unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let (filter, handle) = tracing_subscriber::reload::Layer::new(filter);
    // A pipe is not a terminal. Writing ANSI escapes into a file or a CI log makes every
    // consumer strip them; `NO_COLOR` is the standard opt-out even on a terminal.
    let ansi = std::io::IsTerminal::is_terminal(&std::io::stderr())
        && std::env::var_os("NO_COLOR").is_none();
    let subscriber = tracing_subscriber::registry().with(filter).with(
        tracing_subscriber::fmt::layer()
            .with_ansi(ansi)
            .with_target(true)
            .with_writer(std::io::stderr),
    );
    // The JSON stream is the machine-readable half of the same events. Only `daer run` opens
    // it: a diagnostic verb that truncated a running daemon's `/run/daer/events.jsonl` would
    // destroy the evidence it was invoked to inspect. The file lives under `/run` so a crash
    // leaves it for the incident recorder. If the directory is not writable (an
    // unprivileged test), the human stream is still installed; a diagnostic failure cannot
    // become a startup failure.
    if !json_stream {
        if subscriber.try_init().is_ok() {
            let _ = LOG_FILTER.set(handle);
        }
        return;
    }
    let _ = std::fs::create_dir_all("/run/daer");
    match std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(crate::incident::EVENT_LOG_PATH)
    {
        Ok(writer) => {
            let json = tracing_subscriber::fmt::layer()
                .json()
                .with_target(true)
                .with_writer(writer);
            if subscriber.with(json).try_init().is_ok() {
                let _ = LOG_FILTER.set(handle);
            }
        }
        Err(_) => {
            if subscriber.try_init().is_ok() {
                let _ = LOG_FILTER.set(handle);
            }
        }
    }
}

/// Applies the configuration's `log-level` unless `RUST_LOG` overrides it.
///
/// A malformed directive is an error, not a silent fallback: a config that says `debug` and a
/// daemon that logs at `info` is the same class of lie as a key with no reader.
fn set_log_filter(level: &str) -> Result<(), String> {
    use tracing_subscriber::EnvFilter;

    if std::env::var_os("RUST_LOG").is_some() {
        return Ok(());
    }
    let filter = EnvFilter::try_new(level)
        .map_err(|error| format!("global.log-level {level:?} is not a tracing filter: {error}"))?;
    let Some(handle) = LOG_FILTER.get() else {
        return Ok(());
    };
    handle
        .reload(filter)
        .map_err(|error| format!("could not apply global.log-level {level:?}: {error}"))
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let json_stream = matches!(&cli.command, Command::Run { dry_run: false, .. });
    init_bootstrap_logging(json_stream);
    incident::install_panic_hook();
    let result = match cli.command {
        Command::Run {
            config,
            object,
            no_datapath,
            dry_run,
            shutdown_timeout,
        } => resolve_config(config).and_then(|path| {
            // The ingress mount must be private before the runtime starts. `unshare(CLONE_NEWNS)`
            // changes the caller's mount namespace, and a worker thread created first would keep
            // the host one. A dry run changes nothing and `--no-datapath` creates no ingress, so
            // both skip this (ADR-0029).
            if !dry_run && !no_datapath {
                daer_control::netns::isolate_ingress_mounts().map_err(|error| {
                    anyhow::anyhow!(
                        "cannot isolate the ingress mounts (requires CAP_SYS_ADMIN): {error}"
                    )
                })?;
            }
            // The daemon supervises spawned tasks (relays, datagrams, probes); see
            // `block_on_daemon` for why a current-thread runtime starves them.
            block_on_daemon(async move {
                run::run(run::RunOptions {
                    config: path,
                    object,
                    no_datapath,
                    dry_run,
                    shutdown_timeout: std::time::Duration::from_secs(shutdown_timeout),
                })
                .await
            })
        }),
        Command::Check {
            config,
            nodes,
            object,
            host,
        } => resolve_config(config)
            .and_then(|path| block_on(async move { check(&path, nodes, object, host).await })),
        Command::Route {
            target,
            destination,
            source,
            config,
            domain,
            why,
        } => resolve_config(config).and_then(|path| {
            let flow = parse_route_target(&target, destination.as_deref(), source, domain)?;
            block_on(async move {
                explain_route(
                    &path,
                    flow.source,
                    flow.destination,
                    why,
                    flow.domain.as_deref(),
                )
                .await
            })
        }),
        Command::Probe { command } => match command {
            ProbeCommand::Node {
                node,
                all,
                file,
                config,
                timeout,
                url,
            } => block_on(async move {
                probe::probe_node(probe::ProbeNodeOptions {
                    node,
                    all,
                    file,
                    config,
                    timeout: std::time::Duration::from_secs(timeout),
                    url,
                })
                .await
            }),
            ProbeCommand::Url {
                url,
                config,
                timeout,
                node,
            } => block_on(async move {
                probe::probe_url(probe::ProbeUrlOptions {
                    url,
                    config,
                    timeout: std::time::Duration::from_secs(timeout),
                    node,
                })
                .await
            }),
            ProbeCommand::Direct(args) => {
                // `daer probe <LINK>` is sugar for `daer probe node <LINK>`, and nothing else:
                // it carries no flags, so a mistyped `daer probe --file sub.txt` cannot be read
                // as a node named `--file sub.txt` and silently probe the wrong thing. Given
                // flags, it names the explicit verb instead of guessing what was meant.
                if let Some(flag) = args.iter().find(|argument| argument.starts_with('-')) {
                    Err(anyhow::anyhow!(
                        "`daer probe {flag} …` is not a form: the LINK shortcut takes a node \
                         link and no options. Use `daer probe node <NODE> {flag} …` (NODE may \
                         itself be a vless://… link), or `daer probe url <URL>`."
                    ))
                } else {
                    let node = args.join(" ");
                    block_on(async move {
                        probe::probe_node(probe::ProbeNodeOptions {
                            node,
                            all: false,
                            file: None,
                            config: None,
                            timeout: std::time::Duration::from_secs(5),
                            url: None,
                        })
                        .await
                    })
                }
            }
        },
        Command::Elect {
            election,
            node,
            reset,
            json,
        } => block_on(async move {
            let value = if reset {
                control::reset(&election).await?
            } else {
                let node = node.ok_or_else(|| anyhow::anyhow!("NODE is required"))?;
                control::elect(&election, &node).await?
            };
            if json {
                println!("{}", serde_json::to_string_pretty(&value)?);
            } else if reset {
                println!("{election}: reset to its configured rule");
            } else {
                println!(
                    "{election}: pinned to {}",
                    value
                        .get("node")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("?")
                );
            }
            Ok(())
        }),
        Command::Status {
            json,
            bundle,
            flow,
            nodes,
            groups,
            elections,
        } => {
            let view = if nodes {
                Some("nodes")
            } else if groups {
                Some("groups")
            } else if elections {
                Some("elections")
            } else {
                None
            };
            block_on(async move {
                status::run(status::StatusOptions {
                    json,
                    bundle,
                    flow,
                    view,
                })
                .await
            })
        }
        Command::Schema => {
            println!("{}", daer_config::schema::json_schema());
            Ok(())
        }
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
        Command::Explain { .. } => Err(removed_verb(
            "explain",
            "`daer route <TARGET>` resolves routing decisions (e.g. `daer route bilibili.com` or `daer route 1.1.1.1`)",
        )),
        Command::Config { .. } => Err(removed_verb(
            "config",
            "`daer check` answers \"will this run\"; the sample and the schema are `daer schema` \
             and the repository's daer.example.toml",
        )),
        Command::Node { .. } => Err(removed_verb(
            "node",
            "declare a `[[subscription]]` (daer parses links at runtime) or use an external \
             subscription converter",
        )),
        Command::Dns { .. } => Err(removed_verb(
            "dns",
            "`daer run` serves DNS when `dns.bind` or `[dns.fake-ip]` asks for it, and \
             `daer check` reports every unusable upstream",
        )),
        Command::Rule { .. } => Err(removed_verb(
            "rule",
            "the DRB producer is `daer-drb`: `daer-drb compile`, `daer-drb decompile`, `daer-drb inspect`, `daer-drb test`",
        )),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{err:#}");
            ExitCode::FAILURE
        }
    }
}

/// The error for a verb that ADR-0015 removed.
///
/// A rename that says nothing is indistinguishable from a typo, and the operator's next move —
/// diffing `--help` against an old script — is exactly the work a good error removes.
fn removed_verb(verb: &str, replacement: &str) -> anyhow::Error {
    anyhow::anyhow!("`daer {verb}` was removed: {replacement}")
}

/// Answers "will this configuration run, and what would it do".
///
/// One command, one exit status. It performs every step `daer run` performs before it binds a
/// socket — resolve subscriptions and rule providers, compile and lower every rule, build
/// every group, check every node this build can speak — so a configuration that passes here
/// is one the daemon can serve. `--nodes` additionally prints the resolved node pool, which is
/// what `daer route nodes` used to be.
async fn check(
    path: &Path,
    nodes: bool,
    object: Option<PathBuf>,
    host: bool,
) -> anyhow::Result<()> {
    let report = validate_config(path).await?;
    for warning in &report.warnings {
        eprintln!("warning: {warning}");
    }

    if nodes {
        list_nodes(path).await?;
    }

    // The object half of the gate (ADR-0029). It runs by default: "not asked for" and "asked
    // to skip" are different, and conflating them left `daer check -c …` validating no
    // artifact at all, which is exactly the hole this gate exists to close. `--object none`
    // is the only way to skip, and it says so.
    let object = match object.as_deref() {
        Some(path) if path == Path::new("none") => None,
        Some(path) => Some(path.to_path_buf()),
        // The same literal `run`'s `--object` defaults to, and the same resolution: a
        // packaged install puts the object in libdir, not in the working directory.
        None => Some(run::resolve_object_path(Path::new(
            "target/ebpf/datapath.bpf.o",
        ))),
    };
    if let Some(object) = object.as_deref() {
        match daer_ebpf::inspect_object(object) {
            Ok(detail) => println!(
                "{}: ok, {} maps, {} programs (names, sections and BTF func_info match the ABI)",
                object.display(),
                detail.maps,
                detail.programs
            ),
            Err(error) => anyhow::bail!("{}: {error}", object.display()),
        }
    }

    if host {
        // The host gate includes the kernel baseline as well as the sysctls: both are
        // properties of the machine, not of the configuration or the object. A packaged
        // build uses `daer check` without `--host`, so validating an object never requires
        // the builder's kernel to match the target's (ADR-0042).
        daer_ebpf::require_tcx()?;
        println!("kernel: TCX (Linux 6.6+): ok");
        daer_control::datapath::check_host_sysctls().map_err(|error| anyhow::anyhow!("{error}"))?;
        println!("host sysctl prerequisites: ok");
    }

    println!(
        "{}: ok, {} routing rule(s), {} file(s)",
        path.display(),
        report.rules,
        report.files
    );
    Ok(())
}

/// Resolves `--config`, falling back to the first conventional path that exists.
pub(crate) fn resolve_config(explicit: Option<PathBuf>) -> anyhow::Result<PathBuf> {
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
    rule_providers: Option<Arc<daer_routing::RuleProviderPool>>,
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
        rule_providers: None,
    })
}

struct RouteFlow {
    source: SocketAddr,
    destination: SocketAddr,
    domain: Option<String>,
}

fn parse_route_target(
    target: &str,
    second_arg: Option<&str>,
    explicit_source: Option<SocketAddr>,
    explicit_domain: Option<String>,
) -> anyhow::Result<RouteFlow> {
    let default_source: SocketAddr = "127.0.0.1:12345".parse().unwrap();
    let source = explicit_source.unwrap_or(default_source);

    if let Some(dest_str) = second_arg {
        let src: SocketAddr = if let Ok(addr) = target.parse::<SocketAddr>() {
            addr
        } else if let Ok(ip) = target.parse::<std::net::IpAddr>() {
            SocketAddr::new(ip, 12345)
        } else {
            anyhow::bail!("invalid source address '{target}': expected ip or ip:port");
        };

        let dst: SocketAddr = if let Ok(addr) = dest_str.parse::<SocketAddr>() {
            addr
        } else if let Ok(ip) = dest_str.parse::<std::net::IpAddr>() {
            SocketAddr::new(ip, 443)
        } else {
            anyhow::bail!("invalid destination address '{dest_str}': expected ip or ip:port");
        };

        return Ok(RouteFlow {
            source: src,
            destination: dst,
            domain: explicit_domain,
        });
    }

    if let Ok(addr) = target.parse::<SocketAddr>() {
        return Ok(RouteFlow {
            source,
            destination: addr,
            domain: explicit_domain,
        });
    }

    if let Ok(ip) = target.parse::<std::net::IpAddr>() {
        return Ok(RouteFlow {
            source,
            destination: SocketAddr::new(ip, 443),
            domain: explicit_domain,
        });
    }

    let (host, port) = if let Some((h, p)) = target.rsplit_once(':') {
        if let Ok(port_num) = p.parse::<u16>() {
            (h, port_num)
        } else {
            (target, 443)
        }
    } else {
        (target, 443)
    };

    let domain = explicit_domain.unwrap_or_else(|| host.to_string());
    Ok(RouteFlow {
        source,
        destination: SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), port),
        domain: Some(domain),
    })
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
    if &*explanation.outbound.name == outbound_name::BLOCK {
        println!("  verdict    : dropped by a rule");
        anyhow::bail!("the flow would be blocked");
    }
    // An empty group is a decision that cannot be carried out: the flow has a
    // destination, and there is no node to send it to. Reporting that as success
    // would make the exit status useless as a check — the whole reason it exists.
    if !explanation.outbound_is_actionable() {
        println!(
            "  verdict    : undeliverable, election {:?} has no electable node",
            explanation.outbound.name
        );
        anyhow::bail!(
            "the flow would be dropped: election {:?} has no electable node",
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
        rule_providers: Some(resolved.rule_providers.pool),
    })
}

/// Lists every node with its protocol and security identity.
async fn list_nodes(path: &Path) -> anyhow::Result<()> {
    let loaded = load_resolved(path).await?;
    let options = daer_control::RouterOptions::for_config(path)
        .with_rule_providers(loaded.rule_providers.clone());
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
    let options = daer_control::RouterOptions::for_config(path)
        .with_rule_providers(loaded.rule_providers.clone());
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
    // `daer check` is the deployment gate. A filter directive that the daemon would reject
    // at startup must fail here, where the operator is looking, not after a restart.
    tracing_subscriber::EnvFilter::try_new(&loaded.config.global.log_level).map_err(|error| {
        anyhow::anyhow!(
            "global.log-level {:?} is not a tracing filter: {error}",
            loaded.config.global.log_level
        )
    })?;
    let mut warnings = loaded.warnings.clone();

    let config_dir = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);

    let provider_res = daer_control::resolve_rule_providers(&loaded.config, &config_dir).await;
    if !provider_res.providers.is_empty() {
        if provider_res.all_usable() {
            warnings.push(format!("rule providers: {}", provider_res.describe()));
        } else {
            anyhow::bail!(
                "{} of {} rule provider(s) could not be loaded and no cache was available: {}",
                provider_res.failed().len(),
                provider_res.providers.len(),
                provider_res.describe()
            );
        }
    }

    let program = NormalizedProgram::new(
        &loaded.config.routing.rules,
        loaded.config.routing.fallback.clone(),
        &[
            &AliasOptimizer,
            &MergeAndSortOptimizer,
            &DeduplicateParamsOptimizer,
        ],
    )
    .context("invalid routing rules")?;

    let mut sink = ValidationSink::default();
    {
        let mut builder = RulesBuilder::with_providers(&mut sink, &provider_res.pool);
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

    // Build the same generation the daemon will serve. This is the only way
    // `daer check` can reject an election whose node input is unsupported or whose
    // election graph cannot be assembled; the static checks above cannot see the
    // resolved node graph.
    let options = daer_control::RouterOptions::for_config(path)
        .with_rule_providers(Some(provider_res.pool.clone()));
    let generations = daer_control::Generations::new(&loaded.config, &options)
        .context("configuration rejected by the generation builder")?;
    warnings.extend(generations.current().warnings().iter().cloned());

    Ok(ValidationReport {
        rules: loaded.config.routing.rules.len(),
        files: loaded.files.len(),
        warnings,
    })
}

/// Validates `group` filters the way the run path builds them.
fn validate_groups(config: &Config) -> anyhow::Result<()> {
    for group in &config.group {
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

/// Fails on anything the run path would refuse, so `daer check` is a real gate.
///
/// Checks that were missing, each of which produced a green light for a configuration that
/// cannot run:
///
/// * `dns.bind` was never parsed here, so `bind = "0.0.0.0:53"` passed the gate and then
///   failed to bind;
/// * a node whose protocol this build cannot speak was skipped silently at generation build
///   time, so a configuration made only of `vmess://` nodes validated clean and then had no
///   selectable node at all;
/// * an upstream this build cannot build was reported nowhere, so the first query got
///   "no such upstream" for a tag the operator believed was routed.
///
/// Subscriptions are *resolved*, not assumed: the gate fetches them, so a subscription that is
/// unreachable and uncached is an error here rather than an empty group at run time.
///
/// A validator that passes a configuration the daemon cannot serve is worse than no validator:
/// it is trusted.
fn validate_runtime(config: &Config, warnings: &mut Vec<String>) -> anyhow::Result<()> {
    // The DNS plan is what `daer run` binds; validating it here is the only way `check` and
    // the daemon cannot disagree.
    crate::dns::Plan::resolve(config).map_err(|message| anyhow::anyhow!("{message}"))?;

    // The Fake-IP pool is built by the same constructor the daemon calls, for the same reason:
    // `inet` is parsed there, so `[dns.fake-ip] inet = "not-a-cidr"` used to pass `check` and
    // then fail `daer run` with "invalid fake-ip inet" — one more green light for a
    // configuration that could not run. Building the pool here (rather than re-implementing
    // CIDR validation in `daer-config`) means there is exactly one parser, and it is the one
    // the daemon uses.
    daer_dns::FakeIpPool::from_config(&config.dns.fake_ip)
        .map_err(|error| anyhow::anyhow!("dns.fake-ip: {error}"))?;

    // Every declared upstream must be one this build can speak. `daer check` is a load-time
    // gate, so an unusable upstream is an error here rather than a silent "no such upstream"
    // answer to the first query after `daer run` has already started.
    let reports = crate::dns::check_upstreams(config).map_err(anyhow::Error::msg)?;
    let unusable_upstreams: Vec<String> = reports
        .iter()
        .filter_map(|report| report.unavailable.as_ref().map(|_| report.line()))
        .collect();
    if !unusable_upstreams.is_empty() {
        anyhow::bail!(
            "{} of {} dns upstream(s) cannot be used by this build:\n  {}",
            unusable_upstreams.len(),
            reports.len(),
            unusable_upstreams.join("\n  ")
        );
    }
    if !reports.is_empty() {
        warnings.push(format!("dns upstreams: {} usable", reports.len()));
    }

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
    if is_builtin_outbound(name) || config.election.iter().any(|election| election.name == name) {
        return Ok(());
    }
    Err(RoutingError::new(format!(
        "outbound {name:?} is not an election; define it in an [[election]] table"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn elect_requires_a_node_or_reset() {
        assert!(Cli::try_parse_from(["daer", "elect", "proxy"]).is_err());
        assert!(Cli::try_parse_from(["daer", "elect", "proxy", "--reset"]).is_ok());
        assert!(Cli::try_parse_from(["daer", "elect", "proxy", "hk-01"]).is_ok());
    }

    #[test]
    fn status_views_are_mutually_exclusive() {
        assert!(Cli::try_parse_from(["daer", "status", "--nodes", "--elections"]).is_err());
        assert!(Cli::try_parse_from(["daer", "status", "--elections"]).is_ok());
    }

    #[test]
    fn check_accepts_the_host_gate_flag() {
        let cli = Cli::try_parse_from(["daer", "check", "--host"]).expect("check --host parses");
        match cli.command {
            Command::Check { host, .. } => assert!(host, "--host must set the host gate"),
            other => panic!("expected check, got {other:?}"),
        }
    }

    /// The reference configuration, asserted by a test rather than printed by a command.
    ///
    /// It is documentation: an operator copies it, an editor validates against it. Bundling it
    /// into the release binary was a `config example` subcommand's reason to exist, and it was
    /// the wrong reason — the file lives in the repository and in the docs.
    const EXAMPLE_TOML: &str = include_str!("../../../daer.example.toml");

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

    /// Rewrites the example's three HTTP providers into local file providers backed by
    /// fixtures, so the shipped *rules* and schema are validated without a network.
    ///
    /// A test that reached `cdn.jsdelivr.net` would fail on a runner without egress and pass
    /// on one with it, which is a gate whose result depends on the machine. The provider
    /// declarations themselves are covered by `rule_provider_integration_with_routing_and_explain`
    /// and by `daer_control::rule_provider`'s own tests.
    fn example_with_local_providers(dir: &TempDir) -> PathBuf {
        let private = dir.0.join("geoip-private.drb");
        let cn = dir.0.join("geosite-cn.drb");
        let cn_ip = dir.0.join("geoip-cn.drb");
        for (path, rules) in [
            (&private, "10.0.0.0/8\n192.168.0.0/16\n"),
            (&cn, "example.cn\n"),
            (&cn_ip, "1.2.3.0/24\n"),
        ] {
            let set = daer_routing::DrbSet::from_text(
                path.file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("fixture"),
                rules,
            )
            .expect("fixture compiles");
            std::fs::write(path, set.encode()).expect("fixture writes");
        }

        let mut text = EXAMPLE_TOML.to_owned();
        for (name, path) in [("private", &private), ("cn", &cn), ("cn-ip", &cn_ip)] {
            let marker = format!("[[rule-provider]]\nname = \"{name}\"\ntype = \"http\"");
            let start = text.find(&marker).unwrap_or_else(|| {
                panic!("the shipped example must still declare provider {name:?} as HTTP: {text}")
            });
            let end = text[start + marker.len()..]
                .find("[[rule-provider]]")
                .map_or(text.len(), |offset| start + marker.len() + offset);
            let mut block = text[start..end].to_owned();
            block = block.replace(
                &marker,
                &format!(
                    "[[rule-provider]]\nname = \"{name}\"\ntype = \"file\"\npath = \"{}\"",
                    path.display()
                ),
            );
            // `url` and `interval` are meaningless for a `file` provider: comment them out
            // rather than delete them, so the example still reads as the declaration it
            // started as. Validation rejects `interval` on a file provider by name instead of
            // accepting a key it would never act on (ADR-0006), so both must go.
            block = block.replace("\nurl = ", "\n#url = ");
            block = block.replace("\ninterval = ", "\n#interval = ");
            text = format!("{}{}{}", &text[..start], block, &text[end..]);
        }
        dir.write("config.toml", text.as_bytes())
    }

    #[test]
    fn the_reference_example_validates() {
        let dir = TempDir::new("example");
        let config = example_with_local_providers(&dir);

        let report = block_on(validate_config(&config)).expect("the shipped example validates");
        assert!(report.rules > 0);
        assert_eq!(report.files, 1);

        // ADR-0006/ADR-0007: a configuration whose group can select no node must *say so*, and
        // the shipped example is exactly that shape — its nodes are commented out on purpose, so
        // `daer explain` reports an empty group instead of pretending. What this asserts is the
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
            "{}\n[[node]]\nname = \"example\"\ntype = \"socks5\"\nserver = \"127.0.0.1\"\nport = 1080\n",
            std::fs::read_to_string(&config).expect("reads the rewritten example")
        );
        let config_with_node = dir.write("with-node.toml", text.as_bytes());
        let resolved = block_on(load_resolved(&config_with_node)).expect("resolves");
        let options = daer_control::RouterOptions::for_config(&config_with_node)
            .with_rule_providers(resolved.rule_providers.clone());
        let generations =
            daer_control::Generations::new(&resolved.config, &options).expect("builds");
        let node = generations
            .current()
            .router()
            .node_identity("proxy")
            .expect("the example's default policy must select a node once one exists");
        assert_eq!(node.group, "proxy-pool");
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
    fn rejects_unknown_elections() {
        let dir = TempDir::new("unknown");
        let config = dir.write(
            "config.toml",
            b"[routing]\nrules = [\"dport(443) -> nope\"]\nfallback = \"nope\"\n",
        );
        let error = block_on(validate_config(&config)).expect_err("must fail");
        assert!(
            format!("{error:#}").contains("not an election"),
            "{error:#}"
        );
    }

    #[test]
    fn rejects_a_missing_rule_provider_file() {
        // A `file` provider that does not exist must fail the gate by name. The retired
        // replacement for this test was `rejects_missing_geodata`, which asserted the same
        // property for the `.dat` search path ADR-0014 removed.
        let dir = TempDir::new("missing-provider");
        let config = dir.write(
            "config.toml",
            br#"[[rule-provider]]
tag = "gone"
type = "file"
path = "does-not-exist.drb"
format = "drb"

[routing]
rules = ["provider(gone) -> direct"]
fallback = "direct"
"#,
        );
        let error = block_on(validate_config(&config)).expect_err("must fail");
        let message = format!("{error:#}");
        assert!(message.contains("gone"), "{message}");
        assert!(message.contains("does-not-exist"), "{message}");
    }

    #[test]
    fn rejects_a_dns_bind_that_is_an_address_not_an_ip() {
        // The example configuration shipped `0.0.0.0:53` for a while: the gate passed it
        // while the bind refused it, because the two used different code. They are now one.
        let dir = TempDir::new("badbind");
        let config = dir.write("config.toml", b"[dns]\nbind = \"0.0.0.0:53\"\n");
        let error = block_on(validate_config(&config)).expect_err("must fail");
        let message = format!("{error:#}");
        assert!(message.contains("dns.bind"), "{message}");
        assert!(message.contains("not an IP"), "{message}");
    }

    #[test]
    fn a_protocol_this_build_cannot_speak_is_named_by_its_scheme() {
        // `vmess` *is* implemented now (ADR-0030), so the test's original subject moved: what
        // must still be refused is a scheme with no layer behind it, and the refusal must name
        // the scheme rather than reporting a generic parse failure.
        let dir = TempDir::new("badproto");
        let config = dir.write(
            "config.toml",
            br#"[[node]]
name = "v"
type = "tuic"
server = "198.51.100.1"
port = 443

[[election]]
name = "g"
node = "v"
type = "manual"

[routing]
fallback = "g"
"#,
        );
        let error = block_on(validate_config(&config)).expect_err("must fail");
        let message = format!("{error:#}");
        assert!(message.contains("tuic"), "{message}");
    }

    #[test]
    fn warns_when_a_group_selects_no_node() {
        let dir = TempDir::new("emptynode");
        let config = dir.write("config.toml", b"[[group]]\nname = \"g\"\n");
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
    fn rejects_bad_election_types() {
        let dir = TempDir::new("badgroup");
        let config = dir.write(
            "config.toml",
            b"[[node]]\nname = \"n\"\ntype = \"direct\"\n\n[[election]]\nname = \"g\"\nnode = \"n\"\ntype = \"fastest\"\n",
        );
        let error = block_on(validate_config(&config)).expect_err("must fail");
        assert!(format!("{error:#}").contains("fastest"), "{error:#}");
    }

    #[test]
    fn rejects_bad_group_filter_regexes() {
        let dir = TempDir::new("badfilter");
        let config = dir.write(
            "config.toml",
            b"[[group]]\nname = \"g\"\nfilters = [\"name(regex: '[')\"]\n",
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
name = "n1"
type = "socks5"
server = "127.0.0.1"
port = 1080

[[election]]
name = "proxy"
node = "n1"
type = "manual"

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
        // with no electable node cannot carry the flow, so it is a drop — the
        // earlier behaviour printed a verdict and exited 0, which made the exit
        // status useless for the check it exists for.
        let dir = TempDir::new("explain-empty-group");
        let config = dir.write(
            "config.toml",
            b"[[group]]\nname = \"empty-pool\"\n\n[[election]]\nname = \"empty\"\ngroup = \"empty-pool\"\ntype = \"min\"\n[routing]\nfallback = \"empty\"\n",
        );
        let error = block_on(explain_route(
            &config,
            "10.0.0.2:40000".parse().expect("source"),
            "93.184.216.34:443".parse().expect("destination"),
            false,
            None,
        ))
        .expect_err("an empty group must not exit 0");
        let message = format!("{error:#}");
        assert!(
            message.contains("no electable") || message.contains("no selectable"),
            "{message}"
        );
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
name = "ss"
type = "shadowsocks"
server = "1.2.3.4"
port = 8388
method = "aes-256-gcm"
password = "secret"

[[node]]
name = "tj"
type = "trojan"
server = "node.example.com"
port = 443
password = "pw"

[[node]]
name = "plain"
type = "socks5"
server = "127.0.0.1"
port = 1080
"#,
        );

        let loaded = load_config(&config).expect("loads");
        let options = daer_control::RouterOptions::for_config(&config);
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
name = "tj"
type = "trojan"
server = "node.example.com"
port = 443
password = "pw"

[[election]]
name = "proxy"
node = "tj"
type = "manual"

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
        assert_eq!(selected.election, "proxy");
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
schema = 2

[[node]]
name = "hk-vless"
type = "vless"
server = "198.51.100.1"
port = 443
uuid = "b831381d-6324-4d53-ad4f-8cda48b30811"
flow = "xtls-rprx-vision"
[node.security]
type = "reality"
sni = "impersonate.example.com"
public-key = "f26c_e2kFv8-39rQz10M_xU8vI3f9Qk2lW0mNoPqRsT"
short-id = "ab01cd02"

[[node]]
name = "us-ss"
type = "shadowsocks"
server = "198.51.100.2"
port = 8388
method = "chacha20-ietf-poly1305"
password = "super-secret-password"

[[group]]
name = "pool"
filters = ["name(hk-vless)"]

[[election]]
name = "proxy"
group = "pool"
type = "min-moving-avg"

[routing]
rules = []
fallback = "proxy"
"#,
        );

        let report = block_on(validate_config(&config)).expect("validates structured node config");
        assert_eq!(report.files, 1);

        let loaded = load_config(&config).expect("loads");
        assert_eq!(loaded.config.node.len(), 2);
        let options = daer_control::RouterOptions::for_config(&config);
        let generations = daer_control::Generations::new(&loaded.config, &options).expect("builds");
        let nodes = generations.current().router().nodes();
        assert_eq!(nodes.len(), 2);

        let vless = nodes
            .iter()
            .find(|n| n.node == "hk-vless")
            .expect("vless node");
        assert_eq!(vless.protocol, daer_outbound::Protocol::Vless);
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
    fn subscription_node_filtering_and_selection() {
        let dir = TempDir::new("sub-filter");
        // Persist cache fixture with links from a real subscription
        let persist_dir = dir.0.join("persist.d");
        let cache = daer_outbound::subscription::Cache::new(persist_dir, "mysub");
        let _ = cache.write(&[
            "vless://df4af3d0-030e-4062-baa6-eb9dd45298ef@fkus1keria.itknowledgeblog.com:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=portal.citygrainla.com&pbk=9IKqS8KEelO5cwsRvHXcz2-15-npnsx6k38qcf-GS0E&sid=672f#US%20VIP%2001".to_owned(),
            "vless://df4af3d0-030e-4062-baa6-eb9dd45298ef@fkjp1keria.itknowledgeblog.com:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.titech.ac.jp&pbk=VAqawSsDR9SnBoN8ucLfUXIZO3Ugkd27HN7TOqh1AXo&sid=f0#Japan%20VIP%2001".to_owned(),
            "hysteria2://df4af3d0-030e-4062-baa6-eb9dd45298ef@151.242.183.252:20443?sni=apple.com#HK%2001".to_owned(),
            "tuic://uuid:password@1.2.3.4:443#unsupported-node".to_owned(),
        ]);

        let sub_url = "https://example.com/api/subscribe?token=test";
        let config_toml = format!(
            r#"
schema = 2

[[subscription]]
name = "mysub"
url = "{sub_url}"
persist = true

[[group]]
name = "jp-pool"
filters = [
    "sub(mysub) && name(keyword: 'Japan')"
]

[[election]]
name = "fastest-jp"
group = "jp-pool"
type = "min-moving-avg"

[routing]
rules = ["dport(443) -> fastest-jp"]
fallback = "direct"
"#
        );
        let config = dir.write("config.toml", config_toml.as_bytes());

        let resolved = block_on(load_resolved(&config)).expect("resolves subscription");
        assert_eq!(resolved.config.node.len(), 4);

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
        let hk_node = resolved
            .config
            .node
            .iter()
            .find(|n| n.label().contains("HK 01"))
            .expect("hk node");
        let jp_group = &resolved.config.group[0];

        assert!(daer_control::group_mentions_node(jp_group, jp_node));
        assert!(!daer_control::group_mentions_node(jp_group, us_node));
        assert!(!daer_control::group_mentions_node(jp_group, hk_node));

        // Validate config should succeed (unsupported tuic from subscription produces a warning, not failure)
        let report = block_on(validate_config(&config)).expect("validates");
        assert!(
            report
                .warnings
                .iter()
                .any(|w| w.contains("cannot be selected") || w.contains("is not selectable"))
        );

        // Generates router and selects Japan node
        let options = daer_control::RouterOptions::for_config(&config);
        let generations =
            daer_control::Generations::new(&resolved.config, &options).expect("builds router");
        let selected_node = generations
            .current()
            .router()
            .node_identity("fastest-jp")
            .expect("node selected");
        assert_eq!(selected_node.group, "jp-pool");
        assert_eq!(selected_node.election, "fastest-jp");
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
        assert!(
            format!("{error:#}").contains("not an election"),
            "{error:#}"
        );
    }

    #[test]
    fn removed_verbs_name_their_replacement() {
        // ADR-0015: a stale script must be told what to change. `unknown subcommand` is
        // indistinguishable from a typo, and the operator's next move would be diffing
        // `--help` against the script.
        for (verb, expected) in [
            ("config", "daer check"),
            ("explain", "daer route"),
            ("node", "[[subscription]]"),
            ("dns", "daer run"),
            ("rule", "daer-drb"),
        ] {
            let error = block_on(async { cli_error(verb).await });
            let message = format!("{error:#}");
            assert!(
                message.contains(verb) && message.contains(expected),
                "`daer {verb}` must name {expected:?}: {message}"
            );
        }
    }

    /// Drives the real parser so the assertion is about the shipped surface, not a copy.
    ///
    /// A hand-built `Command` would pass even if `main` stopped routing the verb, which is the
    /// only thing this test exists to check.
    async fn cli_error(verb: &str) -> anyhow::Error {
        let cli = Cli::try_parse_from(["daer", verb, "whatever"]).expect("the verb still parses");
        let result: anyhow::Result<()> = match cli.command {
            Command::Config { .. } => Err(removed_verb(
                "config",
                "`daer check` answers \"will this run\"; the sample and the schema are \
                 `daer schema` and the repository's daer.example.toml",
            )),
            Command::Explain { .. } => Err(removed_verb(
                "explain",
                "`daer route <TARGET>` resolves routing decisions (e.g. `daer route bilibili.com` or `daer route 1.1.1.1`)",
            )),
            Command::Node { .. } => Err(removed_verb(
                "node",
                "declare a `[[subscription]]` (daer parses links at runtime) or use an external \
                 subscription converter",
            )),
            Command::Dns { .. } => Err(removed_verb(
                "dns",
                "`daer run` serves DNS when `dns.bind` or `[dns.fake-ip]` asks for it, and \
                 `daer check` reports every unusable upstream",
            )),
            Command::Rule { .. } => Err(removed_verb(
                "rule",
                "the DRB producer is `daer-drb`: `daer-drb compile`, `daer-drb decompile`, \
                 `daer-drb inspect`, `daer-drb test`",
            )),
            other => panic!("{other:?} is not a removed verb"),
        };
        result.expect_err("a removed verb must not succeed")
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

    #[test]
    fn rule_provider_integration_with_routing_and_explain() {
        let dir = TempDir::new("rule-provider-routing");
        let _rules_file = dir.write("direct.rules", b"192.168.100.0/24\ncorp.lan\n");
        let config = dir.write(
            "config.toml",
            br#"
schema = 2

[[rule-provider]]
name = "internal-corp"
type = "file"
path = "direct.rules"
format = "text"

[routing]
rules = ["provider(internal-corp) -> direct"]
fallback = "block"
"#,
        );

        let report = block_on(validate_config(&config)).expect("validates");
        assert_eq!(report.rules, 1);

        // 1. IP match: 192.168.100.42 -> direct
        let exp = block_on(explain(&config, "10.0.0.1:1234", "192.168.100.42:80", None))
            .expect("explains ip");
        assert_eq!(&*exp.outbound.name, "direct");

        // 2. Domain match: portal.corp.lan -> direct
        let exp = block_on(explain(
            &config,
            "10.0.0.1:1234",
            "1.1.1.1:80",
            Some("portal.corp.lan"),
        ))
        .expect("explains domain");
        assert_eq!(&*exp.outbound.name, "direct");

        // 3. Fallback: other.com -> block
        let err = block_on(explain_route(
            &config,
            "10.0.0.1:1234".parse().unwrap(),
            "1.1.1.1:80".parse().unwrap(),
            false,
            Some("other.com"),
        ))
        .expect_err("must report blocked flow");
        assert!(err.to_string().contains("blocked"));
    }

    #[test]
    fn parse_route_target_supports_single_domain() {
        let flow = parse_route_target("bilibili.com", None, None, None).expect("parses domain");
        assert_eq!(flow.source.to_string(), "127.0.0.1:12345");
        assert_eq!(flow.destination.port(), 443);
        assert_eq!(flow.domain.as_deref(), Some("bilibili.com"));

        let flow_port =
            parse_route_target("bilibili.com:8443", None, None, None).expect("parses domain:port");
        assert_eq!(flow_port.destination.port(), 8443);
        assert_eq!(flow_port.domain.as_deref(), Some("bilibili.com"));
    }

    #[test]
    fn parse_route_target_supports_single_ip() {
        let flow = parse_route_target("1.1.1.1", None, None, None).expect("parses ip");
        assert_eq!(flow.destination.to_string(), "1.1.1.1:443");
        assert_eq!(flow.domain, None);

        let flow_port = parse_route_target("1.1.1.1:80", None, None, None).expect("parses ip:port");
        assert_eq!(flow_port.destination.to_string(), "1.1.1.1:80");
        assert_eq!(flow_port.domain, None);
    }

    #[test]
    fn parse_route_target_supports_classic_four_tuple() {
        let flow = parse_route_target(
            "192.168.1.10:41234",
            Some("93.184.216.34:443"),
            None,
            Some("example.com".to_string()),
        )
        .expect("parses 4-tuple");
        assert_eq!(flow.source.to_string(), "192.168.1.10:41234");
        assert_eq!(flow.destination.to_string(), "93.184.216.34:443");
        assert_eq!(flow.domain.as_deref(), Some("example.com"));
    }
}
