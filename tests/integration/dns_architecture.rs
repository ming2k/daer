// SPDX-License-Identifier: AGPL-3.0-only

//! Enforces the transport boundary of the DNS crate.
//!
//! DNS upstreams are generic network clients and therefore belong to netune's
//! `UdpConnector`/`TcpConnector`/`TlsConnector`/`Client`; the DNS *server* listener is the
//! one deliberate exception because it is the transparent resolver's inbound role. A raw
//! `UdpSocket` or `TcpStream` in a transport module would mean the daemon's `SocketConfig`
//! and trace are no longer applied uniformly.

use std::fs;
use std::path::{Path, PathBuf};

const FORBIDDEN: &[(&str, &str)] = &[
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
        "the only listener in this crate is the DNS server role in `src/server.rs`",
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
fn only_the_dns_server_owns_a_raw_socket() {
    let root = crate::common::crate_dir("daer-dns");
    let mut files = Vec::new();
    sources(&root.join("src"), &mut files);

    let mut offenders = Vec::new();
    for file in files {
        let relative = file.strip_prefix(&root).unwrap_or(&file);
        // `server.rs` is the DNS *server* role: binding UDP/TCP here is the transparent
        // resolver's ingress, not a generic upstream client.
        if relative == Path::new("src/server.rs") {
            continue;
        }
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
        "daer-dns opened a generic network transport outside the DNS server role \
         ([INV-NETUNE-01]):\n{}",
        offenders.join("\n")
    );
}
