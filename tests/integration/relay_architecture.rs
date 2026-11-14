// SPDX-License-Identifier: AGPL-3.0-only

//! Enforces ADR-0017 and ADR-0018 as dependency graphs, not as prose.
//!
//! Two boundaries were introduced by splitting the workspace, and both are the kind that
//! erode silently: nobody adds `quinn` to a governance crate on purpose, and nobody writes a
//! `Verdict` into the accept loop deliberately. Each arrives as a small, reasonable-looking
//! import during an unrelated change. So each is asserted against the compiler's own answer
//! to "what does this crate link".
//!
//! The two assertions look different on purpose, because the two boundaries are different:
//!
//! * **`daer-relay` is checked over its whole closure.** It is supposed to be unable to
//!   decide anything, so the absence of every decider must hold transitively. Reaching
//!   `daer-config` indirectly is exactly as much of a breach as declaring it.
//! * **`daer-outbound` is checked over its direct dependencies.** It *must* depend on
//!   `daer-proxy-protocols` to open a dial, so `quinn` and `rustls` are in its closure by
//!   design — that is what ADR-0017 asks for, one crate in and no further. What must not
//!   happen is governance *declaring* a protocol engine, because that is how the crate grew
//!   a handshake of its own the first time.
//!
//! The falsifier for each is the same: add the edge and this test fails with the crate named.

use std::collections::BTreeSet;
use std::process::Command;

/// Crates `daer-relay` must not reach, even transitively: everything that decides.
const RELAY_FORBIDDEN: &[&str] = &[
    "daer-config",
    "daer-outbound",
    "daer-proxy-protocols",
    "daer-routing",
    "daer-ebpf",
    "daer-dns",
    "daer-sniff",
];

/// Crates `daer-outbound` must not declare: the protocol engines ADR-0017 moved out.
const OUTBOUND_FORBIDDEN: &[&str] = &[
    "quinn",
    "quinn-proto",
    "h3",
    "h3-quinn",
    "rustls",
    "rustls-platform-verifier",
    "tokio-rustls",
    "x25519-dalek",
    "ml-kem",
    "zeroize",
    "getrandom",
    "rand_core",
];

/// Crate-name prefixes that identify an AEAD, a hash or a key exchange.
const CRYPTO_PREFIXES: &[&str] = &[
    "aes", "chacha20", "poly1305", "hkdf", "hmac", "md-5", "sha1",
];

/// Runs `cargo metadata` once and hands back the parsed document.
fn metadata() -> serde_json::Value {
    let output = Command::new(env!("CARGO"))
        .args([
            "metadata",
            "--format-version",
            "1",
            "--locked",
            "--manifest-path",
        ])
        .arg(crate::common::workspace_path("Cargo.toml"))
        .output()
        .expect("runs cargo metadata");

    assert!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let json = String::from_utf8(output.stdout).expect("metadata is UTF-8");
    serde_json::from_str(&json).expect("metadata is JSON")
}

/// The resolve node of `package`.
fn node<'a>(value: &'a serde_json::Value, package: &str) -> &'a serde_json::Value {
    let packages = value["packages"].as_array().expect("packages array");
    let nodes = value["resolve"]["nodes"].as_array().expect("resolve nodes");

    let id = packages
        .iter()
        .find(|entry| entry["name"].as_str() == Some(package))
        .and_then(|entry| entry["id"].as_str())
        .unwrap_or_else(|| panic!("{package} is in the metadata"));

    nodes
        .iter()
        .find(|node| node["id"].as_str() == Some(id))
        .unwrap_or_else(|| panic!("{package} has a resolve node"))
}

/// The package names a resolve node depends on, filtered by edge kind.
///
/// `normal_only` selects the compiler-visible edges: `dep_kinds` carries `null` for a normal
/// dependency and `"dev"`/`"build"` for the others. A dev-dependency is deliberately
/// excluded, because the harness (`serde_json` here) is not part of what the crate ships.
fn dependency_names(
    value: &serde_json::Value,
    node: &serde_json::Value,
    normal_only: bool,
) -> BTreeSet<String> {
    let packages = value["packages"].as_array().expect("packages array");

    node["deps"]
        .as_array()
        .expect("deps array")
        .iter()
        .filter(|dep| {
            if !normal_only {
                return true;
            }
            dep["dep_kinds"].as_array().is_some_and(|kinds| {
                kinds
                    .iter()
                    .any(|kind| kind["kind"].is_null() || kind["kind"].as_str() == Some("normal"))
            })
        })
        .filter_map(|dep| dep["pkg"].as_str())
        .filter_map(|id| {
            packages
                .iter()
                .find(|package| package["id"].as_str() == Some(id))
                .and_then(|package| package["name"].as_str())
                .map(str::to_owned)
        })
        .collect()
}

/// Every package reachable from `package` over normal edges.
fn closure(value: &serde_json::Value, package: &str) -> BTreeSet<String> {
    let nodes = value["resolve"]["nodes"].as_array().expect("resolve nodes");
    let packages = value["packages"].as_array().expect("packages array");

    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut queue: Vec<String> = dependency_names(value, node(value, package), true)
        .into_iter()
        .collect();

    while let Some(current) = queue.pop() {
        if !seen.insert(current.clone()) {
            continue;
        }
        let Some(entry) = nodes
            .iter()
            .find(|node| node["id"].as_str() == Some(current.as_str()))
        else {
            continue;
        };
        queue.extend(dependency_names(value, entry, true));
    }

    let _ = packages;
    seen
}

#[test]
fn the_userspace_data_path_links_no_decider() {
    let value = metadata();
    let dependencies = closure(&value, "daer-relay");

    for forbidden in RELAY_FORBIDDEN {
        assert!(
            !dependencies.contains(*forbidden),
            "`daer-relay` reaches `{forbidden}` (ADR-0018, [INV-RELAY-01]). The data path \
             forwards bytes; it must not be able to compile a routing program, read a \
             configuration, select a node or speak a protocol — directly or through another \
             crate. A routing concept reachable from the accept loop also puts its failure \
             modes behind a config file instead of the doubles in \
             `daer-relay/src/testkit.rs`.\nFull closure: {dependencies:?}"
        );
    }
}

#[test]
fn outbound_governance_declares_no_protocol_engine() {
    let value = metadata();
    // Direct dependencies: `daer-proxy-protocols` is in the closure by design (ADR-0017
    // says governance names *which* tunnel, never *how*), but governance must not declare
    // an engine of its own — that is exactly how the crate grew a handshake the first time.
    let declared = dependency_names(&value, node(&value, "daer-outbound"), true);

    for forbidden in OUTBOUND_FORBIDDEN {
        assert!(
            !declared.contains(*forbidden),
            "`daer-outbound` declares `{forbidden}` (ADR-0017, [INV-PROTO-01]). Outbound \
             governance answers *which node*; a protocol engine declared here means every \
             consumer that only wants a health check also compiles a QUIC stack, a TLS \
             implementation or a key exchange.\nDeclared: {declared:?}"
        );
    }

    for prefix in CRYPTO_PREFIXES {
        let offenders: Vec<&String> = declared
            .iter()
            .filter(|name| name.starts_with(prefix))
            .collect();
        assert!(
            offenders.is_empty(),
            "`daer-outbound` declares a cryptographic construction ({offenders:?}) \
             (ADR-0017). Ciphers belong to `daer-proxy-protocols`; declaring one here is \
             the first half of a second handshake implementation.\nDeclared: {declared:?}"
        );
    }
}

/// The governance crate must not re-export a protocol type either.
///
/// A declared dependency proves the code *can* reach a protocol through the crate that owns
/// it; a re-export would make one reachable through the governance crate's own surface, and
/// the next selection feature would then reach a handshake without ever naming
/// `daer-proxy-protocols`.
#[test]
fn outbound_governance_re_exports_no_protocol_type() {
    let source = crate::common::workspace_path("crates/daer-outbound/src/lib.rs");
    let text = std::fs::read_to_string(source).expect("the crate root is readable");

    let offending: Vec<&str> = text
        .lines()
        .map(str::trim_start)
        .filter(|line| line.starts_with("pub use daer_proxy_protocols::"))
        .filter(|line| !line.contains("fragment"))
        .collect();

    assert!(
        offending.is_empty(),
        "`daer-outbound` re-exports a protocol type: {offending:?} (ADR-0017). The only \
         exception is `fragment`, because `DialerOptions` carries one as a value. A protocol \
         type reachable through the governance crate announces a boundary this crate does \
         not own."
    );
}

/// The data path's seam must name no routing vocabulary.
///
/// This is the readable half of [INV-RELAY-01]: the dependency closure already makes a
/// `Verdict` impossible to import, and this asserts the seam was not widened to a local
/// stand-in for one.
#[test]
fn the_relay_seam_names_no_routing_concept() {
    let mut hits = Vec::new();

    for entry in walk(&crate::common::crate_dir("daer-relay").join("src")) {
        let text = std::fs::read_to_string(&entry).expect("source is readable");
        for (index, line) in text.lines().enumerate() {
            // Only signatures: prose that explains *why* a verdict is absent is allowed.
            let is_signature =
                line.contains("fn ") || line.contains("type ") || line.contains("trait ");
            if !is_signature {
                continue;
            }
            for word in [
                "Verdict",
                "RouterOptions",
                "ElectionRuntime",
                "NodeDialer",
                "Property",
            ] {
                if line.contains(word) {
                    hits.push(format!("{}:{}: {line}", entry.display(), index + 1));
                }
            }
        }
    }

    assert!(
        hits.is_empty(),
        "the `daer-relay` seam names a routing concept (ADR-0018): {hits:?}. The relay needs \
         a name, a dial target and a connector; a verdict or a group in a signature makes \
         every new selection concept a change to the code that forwards bytes."
    );
}

fn walk(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(root) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if crate::common::is_test_source(&path) {
            continue;
        }
        if path.is_dir() {
            out.extend(walk(&path));
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            out.push(path);
        }
    }
    out
}
