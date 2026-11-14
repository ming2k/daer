//! Shared constants for the daer workspace.
//!
//! Every constant here has at least one reader in another crate; ADR-0023 makes that a
//! tested property rather than a convention. Values that describe a behaviour owned by a
//! single crate live in that crate: the `daer0`/`daer0peer` device names are
//! `daer_control::datapath::{DEVICE, PEER}`, because that is what creates the devices.

use std::fmt;
use std::str::FromStr;

/// The `SO_MARK` daer applies to its own sockets, and the value the datapath compares
/// against its `PARAM.socket_mark`.
///
/// `0x6461_6572` is the ASCII bytes `daer` in network (= big-endian) order. It is non-zero,
/// unlikely to collide with a routing mark, and self-describing in a packet capture or an
/// nftables rule. `0` means "no mark" to the kernel and is the value that causes self-capture,
/// so this is an internal constant rather than a configuration key.
pub const DEFAULT_SOCKET_MARK: u32 = 0x6461_6572;

/// Default bound for `MAX_MATCH_SET_LEN`, the number of 32-bit match words the
/// kernel routing program evaluates per packet. Overridable at build time with
/// `MAX_MATCH_SET_LEN=... cargo xtask ebpf`.
pub const MAX_MATCH_SET_LEN: usize = 1024;

/// The names of the outbounds the control plane always provides.
///
/// One definition for the whole workspace: `daer-routing` re-exports these for rule lowering,
/// `kernel.rs` maps two of them to the datapath's own ids, and `daer-config` uses
/// [`BUILTIN_OUTBOUNDS`] to reject a `[[group]]` that would shadow one of them. Spelling a name
/// twice is how a value gets changed in one place and compared in another.
pub mod outbound_name {
    /// Match, do not proxy.
    pub const DIRECT: &str = "direct";
    /// Match, drop the flow.
    pub const BLOCK: &str = "block";
    /// Reserved marker: the following rules are "must" (`<OutboundMustRules>` in the datapath).
    pub const MUST_RULES: &str = "must_rules";
    /// Reserved marker for the implicit sniff-punt projection.
    pub const CONTROL_PLANE_ROUTING: &str = "<Control Plane Routing>";
    /// Reserved marker: the match set continues as a disjunction.
    pub const LOGICAL_OR: &str = "<OR>";
    /// Reserved marker: the match set continues as a conjunction.
    pub const LOGICAL_AND: &str = "<AND>";
}

/// Names the control plane always provides, so a rule may name them without a `[[group]]`.
///
/// # Why shadowing is an error rather than a preference
///
/// `direct` and `block` are the datapath's own ids (`OUTBOUND_DIRECT = 0`,
/// `OUTBOUND_BLOCK = 1`), and the marker names are what the lowering uses to encode AND/OR
/// structure. A group called `direct` therefore does not override the builtin — the compiled
/// program treats the name as the builtin and the group's nodes are unreachable, while
/// `daer route` and `daer check --nodes` happily report the group's node as the selected
/// outbound. That divergence was observed directly: with `[[group]] name = "direct"` whose only
/// node pointed at a closed port, `daer route` printed `node: direct: dead-socks [socks5]` and the
/// daemon dialled the flow *directly*, returning the origin's bytes. A configuration that says one
/// thing while the daemon does another is the exact failure mode this workspace refuses.
pub const BUILTIN_OUTBOUNDS: [&str; 6] = [
    outbound_name::DIRECT,
    outbound_name::BLOCK,
    outbound_name::MUST_RULES,
    outbound_name::CONTROL_PLANE_ROUTING,
    outbound_name::LOGICAL_OR,
    outbound_name::LOGICAL_AND,
];

/// True for a name in [`BUILTIN_OUTBOUNDS`].
#[must_use]
pub fn is_builtin_outbound(name: &str) -> bool {
    BUILTIN_OUTBOUNDS.contains(&name)
}

/// How a group picks a node for a new connection.
///
/// Mirrors `consts.DialerSelectionPolicy` in the Go implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum SelectionPolicy {
    /// Pick a random alive node.
    #[default]
    Random,
    /// Return the input's only candidate. A manual election over a group is rejected
    /// at configuration load; runtime `elect` overrides use this variant.
    Manual,
    /// Pick the node with the lowest last measured latency.
    MinLastLatency,
    /// Pick the node with the lowest average of its last 10 latencies.
    MinAverage10,
    /// Pick the node with the lowest exponentially weighted moving average.
    MinMovingAverage,
}

impl SelectionPolicy {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Random => "random",
            Self::Manual => "manual",
            Self::MinLastLatency => "min",
            Self::MinAverage10 => "min-avg10",
            Self::MinMovingAverage => "min-moving-avg",
        }
    }

    /// True for the policies that rank nodes by a measured latency.
    pub const fn is_latency_based(self) -> bool {
        matches!(
            self,
            Self::MinLastLatency | Self::MinAverage10 | Self::MinMovingAverage
        )
    }
}

impl fmt::Display for SelectionPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for SelectionPolicy {
    type Err = UnsupportedSelectionPolicy;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "random" => Ok(Self::Random),
            "manual" => Ok(Self::Manual),
            "min" => Ok(Self::MinLastLatency),
            "min-avg10" => Ok(Self::MinAverage10),
            "min-moving-avg" => Ok(Self::MinMovingAverage),
            other => Err(UnsupportedSelectionPolicy {
                policy: other.to_owned(),
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsupportedSelectionPolicy {
    pub policy: String,
}

impl fmt::Display for UnsupportedSelectionPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unsupported selection policy: {}", self.policy)
    }
}

impl std::error::Error for UnsupportedSelectionPolicy {}

#[cfg(test)]
mod tests {
    /// Every exported constant has a reader outside this crate (ADR-0023).
    ///
    /// `rustc`'s dead-code lint does not fire on `pub` items, so a constant transcribed
    /// "for compatibility" can sit here unused for months — which is exactly how stale
    /// device constants contradicted the `daer0`/`daer0peer` devices the daemon actually
    /// creates. This test walks the crate sources of the workspace and fails
    /// when a constant in this file is not named anywhere else.
    ///
    /// The list is explicit rather than reflective because Rust has no runtime
    /// reflection: a new constant is added here with its reader, in the same change.
    #[test]
    fn every_constant_has_a_reader() {
        // (name, is this constant still expected to exist?)
        let constants = [("DEFAULT_SOCKET_MARK", true), ("MAX_MATCH_SET_LEN", true)];

        let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(std::path::Path::parent)
            .expect("workspace root");
        let crates = workspace.join("crates");

        let mut sources = String::new();
        collect_rs(&crates, &mut sources);

        for (name, expected) in constants {
            // Count occurrences as a bare identifier, excluding this file's own
            // declaration and its doc comments.
            let needle = name;
            let hits: usize = sources
                .lines()
                .filter(|line| {
                    !line.trim_start().starts_with("///")
                        && !line.trim_start().starts_with("//!")
                        && !line.contains("pub const ")
                        && line.contains(needle)
                })
                .count();
            assert_eq!(
                hits > 0,
                expected,
                "constant {name}: expected a reader outside consts.rs, found {hits} mention(s). \
                 A constant with no reader is deleted, not kept (ADR-0023)."
            );
        }
    }

    fn collect_rs(dir: &std::path::Path, out: &mut String) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                // This crate's own tests are not readers.
                if path.file_name().is_some_and(|n| n == "target") {
                    continue;
                }
                collect_rs(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs")
                && path.file_name().is_some_and(|n| n != "consts.rs")
                && let Ok(text) = std::fs::read_to_string(&path)
            {
                out.push_str(&text);
                out.push('\n');
            }
        }
    }
}
