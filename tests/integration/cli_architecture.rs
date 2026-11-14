// SPDX-License-Identifier: AGPL-3.0-only

//! Enforces the netune boundary on the CLI's active diagnostics.
//!
//! `daer probe` is allowed to use an unmarked `SocketConfig`: it asks whether a node is
//! reachable outside the daemon's routing policy. It is not allowed to open a second
//! resolver or socket stack. Phase 1 uses netune's `SystemResolver`; phase 2 uses
//! `TcpConnector` with a resolver pinned to the address phase 1 reported. A raw
//! `lookup_host` or `TcpStream::connect` here would silently reintroduce the second stack
//! this audit removed.

use std::fs;
use std::path::{Path, PathBuf};

const FORBIDDEN: &[(&str, &str)] = &[
    (
        "lookup_host",
        "DNS resolution belongs to netune's DnsResolver",
    ),
    (
        "TcpStream::connect",
        "TCP establishment belongs to netune's TcpConnector",
    ),
    (
        "UdpSocket::bind",
        "UDP establishment belongs to netune's UdpConnector",
    ),
    ("TcpListener::bind", "the CLI does not own an IP listener"),
    (
        "tokio_rustls",
        "TLS handshakes belong to netune's TlsConnector",
    ),
];

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
fn the_cli_opens_no_generic_network_transport() {
    let root = crate::common::workspace_root();
    let mut files = Vec::new();
    sources(&root.join("crates/daer-cli/src"), &mut files);

    let mut offenders = Vec::new();
    for file in files {
        let relative = file.strip_prefix(&root).unwrap_or(&file);
        let text = fs::read_to_string(&file).expect("source is UTF-8");
        let production = text
            .split_once("#[cfg(test)]")
            .map_or(text.as_str(), |(before, _)| before);
        for (line_number, line) in production.lines().enumerate() {
            for (needle, reason) in FORBIDDEN {
                if line.contains(needle) {
                    offenders.push(format!(
                        "{}:{}: `{needle}` — {reason}",
                        relative.display(),
                        line_number + 1
                    ));
                }
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "daer-cli opened a generic network transport ([INV-NETUNE-01], ADR-0002):\n{}",
        offenders.join("\n")
    );
}
