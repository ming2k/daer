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
mod private_fs;
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
use daer_config::{Config, DEFAULT_CONFIG_DIR, DEFAULT_CONFIG_NAMES, OutboundAction};
use daer_outbound::FilterSet;
use daer_routing::{
    DeduplicateParamsOptimizer, NormalizedProgram, RoutingError, RulesBuilder,
    SortFunctionsOptimizer, ValidationSink, outbound_name,
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
        /// Checks the Linux 6.6+ TCX baseline, the cgroup v2 hierarchy used by the `pname`
        /// hooks, and the host-global sysctls (forwarding on, `rp_filter`/`arp_filter`
        /// relaxed). Reads `uname` and `/proc/sys`, needs no capability, and changes
        /// nothing. Without this flag, `daer check` validates only the configuration and
        /// the object; a deployment gate that wants to catch a host that would refuse to
        /// start should pass it.
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
    let _ = crate::private_fs::ensure_dir(Path::new("/run/daer"));
    match crate::private_fs::open_private(Path::new(crate::incident::EVENT_LOG_PATH), true) {
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
        .map_err(|error| format!("log-level {level:?} is not a tracing filter: {error}"))?;
    let Some(handle) = LOG_FILTER.get() else {
        return Ok(());
    };
    handle
        .reload(filter)
        .map_err(|error| format!("could not apply log-level {level:?}: {error}"))
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
            "`daer run` serves DNS when `dns.bind` is set, and `daer check` reports every \
             unusable upstream",
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
        let cgroup = daer_ebpf::loader::cgroup_v2_path()?;
        println!("cgroup v2: {}: ok", cgroup.display());
        daer_control::datapath::check_host_sysctls().map_err(|error| anyhow::anyhow!("{error}"))?;
        println!("host sysctl prerequisites: ok");
    }

    println!("domain acquisition: {}", report.domain.describe());
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
    domain: daer_control::DomainPlan,
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
    tracing_subscriber::EnvFilter::try_new(&loaded.config.log_level).map_err(|error| {
        anyhow::anyhow!(
            "log-level {:?} is not a tracing filter: {error}",
            loaded.config.log_level
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
        &loaded.config.routing.rule,
        loaded.config.routing.fallback.clone(),
        &[&SortFunctionsOptimizer, &DeduplicateParamsOptimizer],
    )
    .context("invalid routing rules")?;

    let mut sink = ValidationSink::default();
    {
        let mut builder = RulesBuilder::with_providers(&mut sink, &provider_res.pool);
        program
            .lower(&mut builder, |fallback| {
                resolve_action(&loaded.config, fallback)
            })
            .context("invalid routing rules")?;
    }
    warnings.extend(sink.warnings);

    for rule in &program.rules {
        resolve_action(&loaded.config, &rule.action).context("invalid routing rules")?;
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
    let domain = generations.current().router().domain_plan().clone();

    Ok(ValidationReport {
        rules: loaded.config.routing.rule.len(),
        files: loaded.files.len(),
        domain,
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

fn resolve_action(config: &Config, action: &OutboundAction) -> Result<(), RoutingError> {
    daer_config::validate::check_action_target(config, action, "routing.action")
        .map_err(|error| RoutingError::new(error.to_string()))
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

#[cfg(test)]
mod tests;
