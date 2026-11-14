// SPDX-License-Identifier: AGPL-3.0-only

//! Enforces `[INV-NETUNE-01]` where the compiler cannot: a production path in this crate must
//! not open or name its own generic network transport.
//!
//! The crate legitimately owns proxy protocol framing, REALITY's TLS 1.3 client and the
//! product-specific Hysteria 2 socket stack. It does not own TCP/UDP establishment, DNS
//! resolution or an ordinary TLS handshake; those are netune's. Without this test the boundary
//! only exists in review, and a small direct `UdpSocket::bind` or `lookup_host` can silently
//! reintroduce a second resolver, a missing `SO_MARK` or an untraced handshake.
//!
//! The falsifier is literal: add one of the forbidden calls to non-test code and this test
//! names the file and line.

use std::fs;
use std::path::{Path, PathBuf};

/// Calls that create a generic network transport. Type references such as
/// `tokio::net::UdpSocket` in the Hysteria socket seam are allowed; *opening* one is not.
const FORBIDDEN_CALLS: &[(&str, &str)] = &[
    (
        "lookup_host",
        "DNS resolution belongs to netune's DnsResolver / UdpConnector",
    ),
    (
        "TcpStream::connect",
        "TCP establishment belongs to netune's TcpConnector",
    ),
    (
        "UdpSocket::bind",
        "UDP establishment belongs to netune's UdpConnector",
    ),
    (
        "TcpListener::bind",
        "TCP listeners belong to the transparent ingress, not a proxy protocol",
    ),
    (
        "tokio_rustls",
        "TLS handshakes belong to netune's TlsConnector",
    ),
];

/// The package name in a `Cargo.toml` dependency line.
///
/// Workspace entries are written `netune.workspace = true`; the package name is the part
/// before the first dot.
fn dependency_name(line: &str) -> Option<&str> {
    line.split_once('=')
        .map(|(name, _)| name.trim().split('.').next().unwrap_or_default())
}

/// Every Rust source under `src/`, recursively.
fn sources(directory: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(directory).expect("src is readable") {
        let path = entry.expect("directory entry is readable").path();
        if crate::common::is_test_source(&path) {
            continue;
        }
        if path.is_dir() {
            sources(&path, out);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn no_production_path_opens_its_own_network_transport() {
    let root = crate::common::crate_dir("daer-proxy-protocols");
    let mut files = Vec::new();
    sources(&root.join("src"), &mut files);

    let mut offenders = Vec::new();
    for file in files {
        let text = fs::read_to_string(&file).expect("source is UTF-8");
        // Test modules are allowed to stand up local doubles (a UDP echo server, a plain
        // listener, a rustls test server). They are not the shipped graph.
        let production = text
            .split_once("#[cfg(test)]")
            .map_or(text.as_str(), |(before, _)| before);

        for (line_number, line) in production.lines().enumerate() {
            for (needle, reason) in FORBIDDEN_CALLS {
                if line.contains(needle) {
                    offenders.push(format!(
                        "{}:{}: `{needle}` — {reason}",
                        file.strip_prefix(&root).unwrap_or(&file).display(),
                        line_number + 1
                    ));
                }
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "daer-proxy-protocols crossed the netune boundary ([INV-NETUNE-01], ADR-0002). \
         Generic network establishment must go through netune:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn the_normal_dependency_set_declares_no_second_transport_engine() {
    let manifest =
        fs::read_to_string(crate::common::crate_dir("daer-proxy-protocols").join("Cargo.toml"))
            .expect("Cargo.toml is readable");
    let normal = manifest
        .split_once("[dependencies]")
        .expect("the crate has a normal dependency section")
        .1
        .split_once("[dev-dependencies]")
        .map_or(
            manifest
                .split_once("[dependencies]")
                .expect("the crate has a normal dependency section")
                .1,
            |(before, _)| before,
        );

    for forbidden in ["tokio-rustls", "quinn", "quinn-proto", "h3", "h3-quinn"] {
        assert!(
            !normal
                .lines()
                .any(|line| dependency_name(line) == Some(forbidden)),
            "`{forbidden}` is a direct normal dependency of daer-proxy-protocols. \
             A second TLS/QUIC runtime belongs in netune; this crate keeps only product \
             protocol framing ([INV-NETUNE-01])."
        );
    }

    assert!(
        normal
            .lines()
            .any(|line| dependency_name(line) == Some("netune")),
        "daer-proxy-protocols must depend on netune for its generic network capability"
    );
}
