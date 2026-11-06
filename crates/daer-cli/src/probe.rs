// SPDX-License-Identifier: AGPL-3.0-only

//! The `probe` subcommand: online active network diagnostics.
//!
//! Unlike `daer route` (which is offline, static policy evaluation), `daer probe`
//! performs active network I/O to diagnose connectivity issues across layers:
//!
//! 1. DNS Resolution (L3): Can the node's hostname be resolved to an IP?
//! 2. TCP Reachability (L4): Can a TCP handshake succeed with the remote server:port?
//!    (Detects firewall blocks, GFW SYN drops, or dead server ports).
//! 3. Protocol Handshake (L7): Can the proxy protocol (VLESS/SS/Trojan/etc.) authenticate?
//!    (Detects bad credentials, UUID mismatch, REALITY public key errors, TLS handshake failures).
//! 4. End-to-End Internet Access: Can an HTTP request pass through the proxy tunnel?
//!    (Detects proxy relay blockage or upstream ISP drops).
//!
//! # Shape
//!
//! A probe **measures** ([`probe_one`]) and returns a [`NodeReport`]; printing is
//! [`NodeReport::render`]. Keeping the two apart is what lets a whole pool be probed
//! concurrently and still reported in configuration order: forty nodes that answered out of
//! order would otherwise print a report whose ordering depends on the network.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use anyhow::bail;
use daer_config::NodeEndpoint;
use daer_outbound::{DialerOptions, NodeDialer};
use daer_routing::outbound_name;
use tokio::net::TcpStream;

/// The URL an end-to-end probe asks for when `--url` is not given.
///
/// `generate_204` answers `204 No Content` with an empty body, so the probe's cost is one
/// round trip and the tunnel is proven without transferring a page.
const DEFAULT_PROBE_URL: &str = "http://cp.cloudflare.com/generate_204";

#[derive(Debug, Clone)]
pub struct ProbeNodeOptions {
    pub node: String,
    pub all: bool,
    /// A subscription file to probe: node links one per line, a base64 body, or SIP008 JSON.
    pub file: Option<std::path::PathBuf>,
    pub config: Option<std::path::PathBuf>,
    pub timeout: Duration,
    pub url: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ProbeUrlOptions {
    pub url: String,
    pub config: Option<std::path::PathBuf>,
    pub timeout: Duration,
    pub node: Option<String>,
}

/// Where a probe stopped.
///
/// One variant per phase, because "which phase failed" *is* the diagnosis: a TCP timeout is a
/// firewall, a handshake failure is a credential, and an end-to-end failure is a node that
/// authenticates but cannot reach the internet. Collapsing them into one message throws away
/// the only thing this command knows that the operator does not.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Failure {
    /// This build cannot speak the node's protocol at all.
    Unsupported(String),
    /// Phase 1: the node's hostname did not resolve.
    Dns(String),
    /// Phase 2: the node's address did not accept a TCP connection.
    Tcp(String),
    /// Phase 3: the protocol did not authenticate.
    Handshake(String),
    /// Phase 4: the tunnel carried nothing back.
    EndToEnd(String),
}

impl Failure {
    /// The operator-facing sentence explaining what to check.
    fn verdict(&self) -> &'static str {
        match self {
            Self::Unsupported(_) => {
                "this build has no client for that protocol; the node cannot be probed from here"
            }
            Self::Dns(_) => {
                "the node's hostname does not resolve; check the address or the local resolver"
            }
            Self::Tcp(_) => {
                "the server port is unreachable; the IP/port may be firewall-blocked, \
                 GFW-dropped, or the service may be offline"
            }
            Self::Handshake(_) => {
                "the protocol did not authenticate; check the UUID, password, TLS SNI, or \
                 REALITY key"
            }
            Self::EndToEnd(_) => {
                "the tunnel authenticated but carried no reply; the node cannot reach the \
                 probe URL"
            }
        }
    }

    /// The phase name, for the summary line.
    const fn phase(&self) -> &'static str {
        match self {
            Self::Unsupported(_) => "unsupported",
            Self::Dns(_) => "dns",
            Self::Tcp(_) => "tcp",
            Self::Handshake(_) => "handshake",
            Self::EndToEnd(_) => "end-to-end",
        }
    }
}

/// What one probe found, ready to print.
#[derive(Debug, Clone)]
struct NodeReport {
    label: String,
    protocol: String,
    /// `Some` once the endpoint was read; a `direct` node has none.
    endpoint: Option<String>,
    /// A direct node needs no remote probe, so it is reported as ok without one.
    direct: bool,
    /// The timings collected so far, in phase order.
    trace: Vec<String>,
    outcome: Result<(), Failure>,
}

impl NodeReport {
    /// Prints the report, and returns the failure when there was one.
    fn render(&self) -> Result<(), Failure> {
        println!("probing node: {} [{}]", self.label, self.protocol);
        if let Some(endpoint) = &self.endpoint {
            println!("  remote endpoint : {endpoint}");
        }
        for line in &self.trace {
            println!("{line}");
        }
        match &self.outcome {
            Ok(()) => Ok(()),
            Err(failure) => {
                println!("  verdict         : {}", failure.verdict());
                Err(failure.clone())
            }
        }
    }
}

/// Refuses a request that names more than one source of nodes.
///
/// `--file sub.txt lisa-us`, `--all --file sub.txt` and `lisa-us --all` all have a defensible
/// reading, and each of the three readings is *different*. Silently honouring one makes the
/// other argument a no-op the operator believed had taken effect — the failure mode this
/// command exists to remove. So the ambiguity is refused by name.
fn one_source_at_a_time(options: &ProbeNodeOptions) -> anyhow::Result<()> {
    let positional = !options.node.is_empty();
    let named = [positional, options.all, options.file.is_some()]
        .into_iter()
        .filter(|chosen| *chosen)
        .count();
    if named <= 1 {
        return Ok(());
    }
    let mut chosen = Vec::new();
    if positional {
        chosen.push(format!("NODE {:?}", options.node));
    }
    if options.all {
        chosen.push("--all".to_owned());
    }
    if options.file.is_some() {
        chosen.push("--file".to_owned());
    }
    anyhow::bail!(
        "{} of these name nodes at once: {}. Pick one: NODE for one node, --all for the \
         configuration's nodes, --file for a subscription body",
        chosen.len(),
        chosen.join(", ")
    )
}

pub async fn probe_node(options: ProbeNodeOptions) -> anyhow::Result<()> {
    one_source_at_a_time(&options)?;

    if let Some(file) = options.file.clone() {
        return probe_file(&file, &options).await;
    }

    if options.all {
        let config_path = crate::resolve_config(options.config.clone()).map_err(|e| {
            anyhow::anyhow!(
                "cannot find configuration file: {e}; specify -c/--config or pass a node URI link directly"
            )
        })?;
        let resolved = daer_control::load_resolved(&config_path).await?;
        if resolved.config.node.is_empty() {
            println!(
                "{}: no nodes declared in configuration",
                config_path.display()
            );
            return Ok(());
        }
        probe_pool(
            &resolved.config.node,
            &options,
            &format!("{} (--all)", config_path.display()),
        )
        .await
    } else if options.node.is_empty() {
        let config_path = crate::resolve_config(options.config.clone()).map_err(|e| {
            anyhow::anyhow!(
                "cannot find configuration file: {e}; specify -c/--config or pass a node URI link directly (e.g. vless://...)"
            )
        })?;
        let resolved = daer_control::load_resolved(&config_path).await?;
        let available: Vec<_> = resolved.config.node.iter().map(|n| n.label()).collect();
        if available.is_empty() {
            println!(
                "{}: no nodes declared in configuration",
                config_path.display()
            );
        } else {
            println!(
                "{}: available node(s): {}\nRun 'daer probe node <NAME> -c {}' or add '--all' to probe all nodes.",
                config_path.display(),
                available.join(", "),
                config_path.display()
            );
        }
        Ok(())
    } else if options.node == outbound_name::DIRECT {
        // `direct` is a built-in outbound name, not a node in the file, and it has no remote
        // server to probe. Reported as ok rather than as "node not found", which would be a
        // true statement about the file and a misleading one about the request.
        let report = NodeReport {
            label: outbound_name::DIRECT.to_owned(),
            protocol: "direct".to_owned(),
            endpoint: None,
            direct: true,
            trace: vec![
                "  endpoint        : local direct interface".to_owned(),
                "  verdict         : ok (direct outbound requires no remote server probe)"
                    .to_owned(),
            ],
            outcome: Ok(()),
        };
        report
            .render()
            .map_err(|failure| anyhow::anyhow!("{failure:?}"))
    } else {
        let node = resolve_node(&options).await?;
        let report = probe_one(node, options).await;
        report.render().map_err(|failure| {
            anyhow::anyhow!("{} probe failed: {}", failure.phase(), describe(&failure))
        })
    }
}

/// Finds the node `options.node` names: a link, or a name in the configuration.
async fn resolve_node(options: &ProbeNodeOptions) -> anyhow::Result<daer_config::Node> {
    if options.node.contains("://") {
        return daer_config::Node::from_link(&options.node)
            .map_err(|e| anyhow::anyhow!("invalid node link {:?}: {e}", options.node));
    }
    let config_path = crate::resolve_config(options.config.clone()).map_err(|e| {
        anyhow::anyhow!(
            "cannot find configuration file: {e}; specify -c/--config or pass a node URI link directly (e.g. vless://...)"
        )
    })?;
    let resolved = daer_control::load_resolved(&config_path).await?;
    let found = resolved
        .config
        .node
        .iter()
        .find(|n| {
            n.label() == options.node
                || n.tag.as_deref() == Some(&options.node)
                || n.default_name() == options.node
                || n.label().eq_ignore_ascii_case(&options.node)
                || n.tag
                    .as_deref()
                    .is_some_and(|t| t.eq_ignore_ascii_case(&options.node))
        })
        .or_else(|| {
            resolved.config.node.iter().find(|n| {
                n.label()
                    .to_ascii_lowercase()
                    .contains(&options.node.to_ascii_lowercase())
            })
        })
        .cloned();

    let Some(node) = found else {
        let available: Vec<_> = resolved.config.node.iter().map(|n| n.label()).collect();
        bail!(
            "node {:?} not found in {}; available nodes: {}",
            options.node,
            config_path.display(),
            if available.is_empty() {
                "<none>".to_string()
            } else {
                available.join(", ")
            }
        );
    };
    Ok(node)
}

fn describe(failure: &Failure) -> &str {
    match failure {
        Failure::Unsupported(detail)
        | Failure::Dns(detail)
        | Failure::Tcp(detail)
        | Failure::Handshake(detail)
        | Failure::EndToEnd(detail) => detail,
    }
}

/// The `[protocol]` label a report prints.
fn protocol_name(node: &daer_config::Node) -> &str {
    match &node.endpoint {
        NodeEndpoint::Direct(_) => "direct",
        NodeEndpoint::Socks5(_) => "socks5",
        NodeEndpoint::Http(_) => "http",
        NodeEndpoint::Shadowsocks(_) => "shadowsocks",
        NodeEndpoint::Trojan(_) => "trojan",
        NodeEndpoint::AnyTls(_) => "anytls",
        NodeEndpoint::Hysteria2(_) => "hysteria2",
        NodeEndpoint::Vless(_) => "vless",
        NodeEndpoint::Vmess(_) => "vmess",
        NodeEndpoint::Unsupported { scheme, .. } => scheme.as_str(),
    }
}

/// Probes one node. Measures only; [`NodeReport::render`] prints.
async fn probe_one(node: daer_config::Node, options: ProbeNodeOptions) -> NodeReport {
    let protocol = protocol_name(&node).to_owned();
    let mut report = NodeReport {
        label: node.label(),
        protocol,
        endpoint: None,
        direct: matches!(node.endpoint, NodeEndpoint::Direct(_)),
        trace: Vec::new(),
        outcome: Ok(()),
    };

    if report.direct {
        report
            .trace
            .push("  endpoint        : local direct interface".to_owned());
        report.trace.push(
            "  verdict         : ok (direct outbound requires no remote server probe)".to_owned(),
        );
        return report;
    }

    let (server, port) = match &node.endpoint {
        NodeEndpoint::Socks5(e) => (e.server.as_str(), e.port),
        NodeEndpoint::Http(e) => (e.server.as_str(), e.port),
        NodeEndpoint::Shadowsocks(e) => (e.server.as_str(), e.port),
        NodeEndpoint::Trojan(e) => (e.server.as_str(), e.port),
        NodeEndpoint::AnyTls(e) => (e.server.as_str(), e.port),
        NodeEndpoint::Hysteria2(e) => (e.server.as_str(), e.port()),
        NodeEndpoint::Vless(e) => (e.server.as_str(), e.port),
        NodeEndpoint::Vmess(e) => (e.server.as_str(), e.port),
        NodeEndpoint::Unsupported { scheme, .. } => {
            report.outcome = Err(Failure::Unsupported(format!(
                "unsupported protocol {scheme:?}"
            )));
            return report;
        }
        NodeEndpoint::Direct(_) => unreachable!("handled above"),
    };
    report.endpoint = Some(format!("{server}:{port}"));

    // Target authority for end-to-end probing
    let probe_url_str = options.url.as_deref().unwrap_or(DEFAULT_PROBE_URL);
    let check_url = match daer_outbound::CheckUrl::parse(probe_url_str) {
        Ok(url) => url,
        Err(error) => {
            report.outcome = Err(Failure::EndToEnd(format!(
                "invalid probe URL {probe_url_str:?}: {error}"
            )));
            return report;
        }
    };
    let probe_authority = format!("{}:{}", check_url.host(), check_url.port());

    // Phase 1: DNS Resolution
    let dns_start = Instant::now();
    let server_clean = server.trim_matches(|c| c == '[' || c == ']');
    let addrs: Vec<SocketAddr> = match tokio::net::lookup_host((server_clean, port)).await {
        Ok(iter) => iter.collect(),
        Err(error) => {
            report
                .trace
                .push(format!("  dns resolution  : failed ({error})"));
            report.outcome = Err(Failure::Dns(format!(
                "DNS resolution failed for server '{server}': {error}"
            )));
            return report;
        }
    };
    if addrs.is_empty() {
        report
            .trace
            .push("  dns resolution  : no IP addresses returned".to_owned());
        report.outcome = Err(Failure::Dns(format!(
            "DNS returned no address for '{server}'"
        )));
        return report;
    }
    let dns_ms = dns_start.elapsed().as_millis();
    let target_addr = addrs[0];
    report.trace.push(format!(
        "  dns resolution  : ok ({target_addr}) in {dns_ms}ms"
    ));

    // Phase 2: L3/L4 TCP Reachability
    let tcp_start = Instant::now();
    match tokio::time::timeout(options.timeout, TcpStream::connect(target_addr)).await {
        Ok(Ok(stream)) => {
            let tcp_ms = tcp_start.elapsed().as_millis();
            drop(stream);
            report.trace.push(format!(
                "  tcp connect     : ok in {tcp_ms}ms (L3/L4 reachable)"
            ));
        }
        Ok(Err(error)) => {
            report
                .trace
                .push(format!("  tcp connect     : failed ({error})"));
            report.outcome = Err(Failure::Tcp(format!(
                "TCP connect to {target_addr} failed: {error}"
            )));
            return report;
        }
        Err(_) => {
            report.trace.push(format!(
                "  tcp connect     : timed out after {}s",
                options.timeout.as_secs()
            ));
            report.outcome = Err(Failure::Tcp(format!(
                "TCP connect to {target_addr} timed out"
            )));
            return report;
        }
    }

    // Phase 3: L7 Protocol Handshake
    let dialer_opts = DialerOptions::new(None, options.timeout);
    let dialer = match NodeDialer::from_node(&node, dialer_opts) {
        Ok(dialer) => dialer,
        Err(error) => {
            report.outcome = Err(Failure::Unsupported(format!(
                "failed to construct node dialer: {error}"
            )));
            return report;
        }
    };

    let handshake_start = Instant::now();
    let stream = match tokio::time::timeout(options.timeout, dialer.connect(&probe_authority)).await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(first_error)) => {
            // A single attempt against a node that is far away and on a lossy path fails
            // perhaps half the time — measured identically through `xray` at the same moment —
            // so reporting the first reset as "the node is broken" is a lie about the node.
            // The retry does not blur a bad credential: a REALITY `pbk` mismatch forwards the
            // flow and fails with `the peer is not the REALITY node` on every attempt.
            tokio::time::sleep(Duration::from_millis(300)).await;
            match tokio::time::timeout(options.timeout, dialer.connect(&probe_authority)).await {
                Ok(Ok(stream)) => stream,
                Ok(Err(_)) => {
                    report
                        .trace
                        .push(format!("  handshake       : failed ({first_error})"));
                    report.outcome = Err(Failure::Handshake(format!(
                        "protocol handshake failed: {first_error}"
                    )));
                    return report;
                }
                Err(_) => {
                    report.trace.push(format!(
                        "  handshake       : timed out after {}s",
                        options.timeout.as_secs()
                    ));
                    report.outcome = Err(Failure::Handshake(
                        "protocol handshake timed out on the retry".to_owned(),
                    ));
                    return report;
                }
            }
        }
        Err(_) => {
            report.trace.push(format!(
                "  handshake       : timed out after {}s",
                options.timeout.as_secs()
            ));
            report.outcome = Err(Failure::Handshake(
                "protocol handshake timed out (the server accepted TCP but did not finish the \
                 handshake)"
                    .to_owned(),
            ));
            return report;
        }
    };
    let handshake_ms = handshake_start.elapsed().as_millis();
    report.trace.push(format!(
        "  handshake       : ok in {handshake_ms}ms (protocol authenticated)"
    ));

    // Phase 4: End-to-end HTTP(S) Probe
    //
    // Through netune's HTTP client, not a hand-written `GET` line. The hand-written version was
    // only ever correct for `http://`: an `https://` probe wrote cleartext into port 443, the peer
    // (correctly) reset, and the probe blamed the node. `check_through` hands the established
    // tunnel to the same client the health checker uses, so TLS for an `https://` URL is
    // negotiated *inside* the tunnel, which is what a TLS probe means.
    let checker = daer_outbound::HttpChecker::new(daer_outbound::HttpMethod::Get, options.timeout);
    let e2e_start = Instant::now();
    match checker.check_through(stream, &check_url).await {
        Ok(_) => {
            let e2e_ms = e2e_start.elapsed().as_millis();
            report.trace.push(format!(
                "  e2e probe       : ok in {e2e_ms}ms [{} {}]",
                match check_url.scheme() {
                    daer_outbound::Scheme::Http => "http",
                    daer_outbound::Scheme::Https => "https",
                },
                check_url.host_header()
            ));
            report
                .trace
                .push("  verdict         : node is fully operational".to_owned());
        }
        Err(error) => {
            match &error {
                daer_outbound::CheckError::Timeout => report.trace.push(format!(
                    "  e2e probe       : timed out after {}s",
                    options.timeout.as_secs()
                )),
                other => report
                    .trace
                    .push(format!("  e2e probe       : failed ({other})")),
            }
            report.outcome = Err(Failure::EndToEnd(format!("e2e HTTP probe failed: {error}")));
        }
    }
    report
}

/// Probes `nodes` concurrently and reports them in the order given.
///
/// Concurrency is not an optimisation here, it is the same model the daemon uses: the health
/// scheduler drives every node's probe as one set (`daer_control::health::probe_all`), so a
/// pool of forty costs one probe timeout rather than forty. A `--file` that took forty
/// timeouts would make the command unusable on exactly the pool size it exists for.
///
/// The *report* stays serial in configuration order: the point of the output is which node is
/// which, and ordering by who answered first destroys that.
async fn probe_pool(
    nodes: &[daer_config::Node],
    options: &ProbeNodeOptions,
    source: &str,
) -> anyhow::Result<()> {
    let mut tasks = tokio::task::JoinSet::new();
    for (index, node) in nodes.iter().enumerate() {
        let node = node.clone();
        let options = options.clone();
        tasks.spawn(async move { (index, probe_one(node, options).await) });
    }

    // `JoinSet` yields in completion order; each task carries its index so the report can be
    // printed in configuration order regardless of who answered first.
    let mut reports: Vec<Option<NodeReport>> = (0..nodes.len()).map(|_| None).collect();
    while let Some(joined) = tasks.join_next().await {
        match joined {
            Ok((index, report)) => reports[index] = Some(report),
            Err(error) => {
                return Err(anyhow::anyhow!(
                    "a probe task failed to run for {source}: {error}"
                ));
            }
        }
    }

    let mut failed = Vec::new();
    for report in reports.iter().flatten() {
        println!();
        if let Err(failure) = report.render() {
            failed.push(format!("{} ({})", report.label, failure.phase()));
        }
    }

    println!();
    println!(
        "{} of {} node(s) operational",
        nodes.len() - failed.len(),
        nodes.len()
    );
    if !failed.is_empty() {
        bail!(
            "{} node(s) in {source} failed probe: {}",
            failed.len(),
            failed.join(", ")
        );
    }
    Ok(())
}

/// Probes every node a subscription file describes.
///
/// The body is decoded by the same [`daer_outbound::subscription::decode`] the daemon uses when
/// it resolves a `[[subscription]]` (INV-LOADER-01), so a list that probes clean here is the
/// list the runtime would build. A link the parser rejects is reported and skipped, never
/// silently dropped: "no usable node" and "half the list was unreadable" lead an operator to
/// opposite conclusions.
async fn probe_file(file: &std::path::Path, options: &ProbeNodeOptions) -> anyhow::Result<()> {
    let body = std::fs::read(file)
        .map_err(|error| anyhow::anyhow!("cannot read {}: {error}", file.display()))?;
    let decoded = daer_outbound::subscription::decode(&body)
        .map_err(|error| anyhow::anyhow!("{}: {error}", file.display()))?;

    let mut nodes = Vec::new();
    for link in &decoded.links {
        match daer_config::Node::from_link(link) {
            Ok(node) => nodes.push(node),
            // The link itself is not echoed: a link carries a credential in its userinfo, and
            // this line goes to stderr, which is a log.
            Err(error) => eprintln!(
                "{}: skipping a link this build cannot parse: {error}",
                file.display()
            ),
        }
    }
    for rejected in &decoded.rejected {
        eprintln!(
            "{}: skipping a line the format did not accept: {rejected}",
            file.display()
        );
    }

    if nodes.is_empty() {
        bail!(
            "{}: {} bytes decoded as {:?} but yielded no usable node",
            file.display(),
            body.len(),
            decoded.format
        );
    }

    println!(
        "{}: {} node(s), format {:?}",
        file.display(),
        nodes.len(),
        decoded.format
    );

    probe_pool(&nodes, options, &file.display().to_string()).await
}

pub async fn probe_url(options: ProbeUrlOptions) -> anyhow::Result<()> {
    if let Some(node_name) = options.node {
        return probe_node(ProbeNodeOptions {
            node: node_name,
            all: false,
            file: None,
            config: options.config,
            timeout: options.timeout,
            url: Some(options.url),
        })
        .await;
    }

    let check_url = daer_outbound::CheckUrl::parse(&options.url)
        .map_err(|e| anyhow::anyhow!("invalid check URL {:?}: {e}", options.url))?;

    let host = check_url.host();
    let port = check_url.port();

    println!("probing url: {}", options.url);
    let dns_start = Instant::now();
    let addrs: Vec<SocketAddr> = match tokio::net::lookup_host((host, port)).await {
        Ok(iter) => iter.collect(),
        Err(err) => {
            println!("  dns resolution : failed ({err})");
            bail!("DNS resolution failed for '{host}': {err}");
        }
    };
    if addrs.is_empty() {
        bail!("no IP addresses resolved for '{host}'");
    }
    let dns_ms = dns_start.elapsed().as_millis();
    let target_addr = addrs[0];
    println!("  dns resolution : ok ({target_addr}) in {dns_ms}ms");

    let checker = daer_outbound::HttpChecker::new(daer_outbound::HttpMethod::Head, options.timeout);
    match checker.check(&check_url, target_addr.ip()).await {
        Ok(time_span) => {
            println!("  http probe     : ok (RTT {time_span})");
            println!("  verdict        : reachable");
            Ok(())
        }
        Err(err) => {
            println!("  http probe     : failed ({err})");
            println!("  verdict        : unreachable");
            bail!("HTTP probe failed: {err}");
        }
    }
}
