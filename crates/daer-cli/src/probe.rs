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

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use anyhow::bail;
use daer_config::NodeEndpoint;
use daer_outbound::{DialerOptions, NodeDialer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Debug, Clone)]
pub struct ProbeNodeOptions {
    pub node: String,
    pub config: std::path::PathBuf,
    pub timeout: Duration,
    pub url: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ProbeUrlOptions {
    pub url: String,
    pub config: std::path::PathBuf,
    pub timeout: Duration,
    pub node: Option<String>,
}

pub async fn probe_node(options: ProbeNodeOptions) -> anyhow::Result<()> {
    if options.node == "direct" {
        println!("probing node: direct [direct]");
        println!("  endpoint        : local direct interface");
        println!("  verdict         : ok (direct outbound requires no remote server probe)");
        return Ok(());
    }

    let resolved = daer_control::load_resolved(&options.config).await?;
    let target_node = resolved
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
        });

    let Some(node) = target_node else {
        let available: Vec<_> = resolved.config.node.iter().map(|n| n.label()).collect();
        bail!(
            "node {:?} not found in {}; available nodes: {}",
            options.node,
            options.config.display(),
            if available.is_empty() {
                "<none>".to_string()
            } else {
                available.join(", ")
            }
        );
    };

    let proto = match &node.endpoint {
        NodeEndpoint::Direct(_) => "direct",
        NodeEndpoint::Socks5(_) => "socks5",
        NodeEndpoint::Http(_) => "http",
        NodeEndpoint::Shadowsocks(_) => "shadowsocks",
        NodeEndpoint::Trojan(_) => "trojan",
        NodeEndpoint::AnyTls(_) => "anytls",
        NodeEndpoint::Hysteria2(_) => "hysteria2",
        NodeEndpoint::Vless(_) => "vless",
        NodeEndpoint::Unsupported { scheme, .. } => scheme.as_str(),
    };

    println!("probing node: {} [{proto}]", node.label());

    if let NodeEndpoint::Direct(_) = &node.endpoint {
        println!("  endpoint        : local direct interface");
        println!("  verdict         : ok (direct outbound requires no remote server probe)");
        return Ok(());
    }

    let (server, port) = match &node.endpoint {
        NodeEndpoint::Socks5(e) => (e.server.as_str(), e.port),
        NodeEndpoint::Http(e) => (e.server.as_str(), e.port),
        NodeEndpoint::Shadowsocks(e) => (e.server.as_str(), e.port),
        NodeEndpoint::Trojan(e) => (e.server.as_str(), e.port),
        NodeEndpoint::AnyTls(e) => (e.server.as_str(), e.port),
        NodeEndpoint::Hysteria2(e) => (e.server.as_str(), e.port),
        NodeEndpoint::Vless(e) => (e.server.as_str(), e.port),
        NodeEndpoint::Unsupported { scheme, .. } => {
            bail!("unsupported protocol {scheme:?}");
        }
        NodeEndpoint::Direct(_) => unreachable!(),
    };

    println!("  remote endpoint : {server}:{port}");

    // Target authority for end-to-end probing
    let probe_url_str = options
        .url
        .as_deref()
        .unwrap_or("http://cp.cloudflare.com/generate_204");
    let check_url = daer_outbound::CheckUrl::parse(probe_url_str)
        .map_err(|e| anyhow::anyhow!("invalid probe URL {probe_url_str:?}: {e}"))?;
    let probe_authority = format!("{}:{}", check_url.host(), check_url.port());

    // Phase 1: DNS Resolution
    let dns_start = Instant::now();
    let server_clean = server.trim_matches(|c| c == '[' || c == ']');
    let addrs: Vec<SocketAddr> = match tokio::net::lookup_host((server_clean, port)).await {
        Ok(iter) => iter.collect(),
        Err(err) => {
            println!("  dns resolution  : failed ({err})");
            println!("  verdict         : DNS resolution failed for server '{server}'");
            bail!("DNS resolution failed for server '{server}': {err}");
        }
    };
    if addrs.is_empty() {
        println!("  dns resolution  : no IP addresses returned");
        bail!("DNS returned no address for '{server}'");
    }
    let dns_ms = dns_start.elapsed().as_millis();
    let target_addr = addrs[0];
    println!("  dns resolution  : ok ({target_addr}) in {dns_ms}ms");

    // Phase 2: L3/L4 TCP Reachability
    let tcp_start = Instant::now();
    match tokio::time::timeout(options.timeout, TcpStream::connect(target_addr)).await {
        Ok(Ok(stream)) => {
            let tcp_ms = tcp_start.elapsed().as_millis();
            drop(stream);
            println!("  tcp connect     : ok in {tcp_ms}ms (L3/L4 reachable)");
        }
        Ok(Err(err)) => {
            println!("  tcp connect     : failed ({err})");
            println!(
                "  verdict         : server port unreachable (IP/port may be firewall-blocked, GFW-dropped, or service offline)"
            );
            bail!("TCP connect to {target_addr} failed: {err}");
        }
        Err(_) => {
            println!(
                "  tcp connect     : timed out after {}s",
                options.timeout.as_secs()
            );
            println!(
                "  verdict         : connection timed out (server IP/port is dropping packets or heavily congested)"
            );
            bail!("TCP connect to {target_addr} timed out");
        }
    }

    // Phase 3: L7 Protocol Handshake
    let dialer_opts = DialerOptions::new(None, options.timeout);
    let dialer = NodeDialer::from_node(node, dialer_opts)
        .map_err(|e| anyhow::anyhow!("failed to construct node dialer: {e}"))?;

    let handshake_start = Instant::now();
    let mut stream = match tokio::time::timeout(options.timeout, dialer.connect(&probe_authority))
        .await
    {
        Ok(Ok(stream)) => {
            let handshake_ms = handshake_start.elapsed().as_millis();
            println!("  handshake       : ok in {handshake_ms}ms (protocol authenticated)");
            stream
        }
        Ok(Err(err)) => {
            println!("  handshake       : failed ({err})");
            println!(
                "  verdict         : protocol handshake failed (check credentials, UUID, password, TLS SNI, or REALITY key)"
            );
            bail!("protocol handshake failed: {err}");
        }
        Err(_) => {
            println!(
                "  handshake       : timed out after {}s",
                options.timeout.as_secs()
            );
            println!(
                "  verdict         : handshake timed out (remote server accepted TCP but did not complete handshake)"
            );
            bail!("protocol handshake timed out");
        }
    };

    // Phase 4: End-to-end HTTP Probe
    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: daer-probe\r\nConnection: close\r\n\r\n",
        check_url.path(),
        check_url.host_header()
    );

    let e2e_start = Instant::now();
    if let Err(e) = stream.stream.write_all(req.as_bytes()).await {
        println!("  e2e probe       : send failed ({e})");
        bail!("e2e HTTP probe request write failed: {e}");
    }
    let mut buf = [0u8; 1024];
    match tokio::time::timeout(options.timeout, stream.stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => {
            let e2e_ms = e2e_start.elapsed().as_millis();
            let response = String::from_utf8_lossy(&buf[..n]);
            let status_line = response.lines().next().unwrap_or("HTTP/1.1 200 OK");
            println!("  e2e probe       : ok in {e2e_ms}ms [{status_line}]");
            println!("  verdict         : node is fully operational");
            Ok(())
        }
        Ok(Ok(_)) => {
            println!("  e2e probe       : remote server closed connection without response bytes");
            bail!("e2e HTTP probe closed without response");
        }
        Ok(Err(e)) => {
            println!("  e2e probe       : read failed ({e})");
            bail!("e2e HTTP probe read failed: {e}");
        }
        Err(_) => {
            println!(
                "  e2e probe       : timed out after {}s",
                options.timeout.as_secs()
            );
            bail!("e2e HTTP probe timed out");
        }
    }
}

pub async fn probe_url(options: ProbeUrlOptions) -> anyhow::Result<()> {
    if let Some(node_name) = options.node {
        return probe_node(ProbeNodeOptions {
            node: node_name,
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
