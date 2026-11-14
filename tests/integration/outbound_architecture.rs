// SPDX-License-Identifier: AGPL-3.0-only

//! Enforces the transport boundary of outbound governance.
//!
//! `daer-outbound` decides *which* node and *which* socket policy; it does not open a
//! generic TCP/UDP socket or run a TLS handshake. Subscription fetches and health probes
//! must use the netune connector so the daemon's `SocketConfig` (notably `SO_MARK`) applies.

use std::fs;
use std::path::{Path, PathBuf};

const FORBIDDEN: &[(&str, &str)] = &[
    (
        "lookup_host",
        "DNS resolution belongs to netune's DnsResolver / connectors",
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
fn outbound_governance_opens_no_generic_transport() {
    let root = crate::common::crate_dir("daer-outbound");
    let mut files = Vec::new();
    sources(&root.join("src"), &mut files);

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
        "daer-outbound opened a generic network transport ([INV-NETUNE-01], ADR-0002):\n{}",
        offenders.join("\n")
    );
}
