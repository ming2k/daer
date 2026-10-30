//! Shared constants for the daer workspace.
//!
//! Replaces the Go package `common/consts`. Values are kept identical to the Go
//! implementation, so a daer binary keeps the same kernel contract without changing
//! kernel-side behaviour.

use std::fmt;
use std::str::FromStr;
use std::time::Duration;

/// Binary name used by daer's own artifacts.
pub const APP_NAME: &str = "daer";

/// Default tproxy listen port. It is not an HTTP/SOCKS port; only eBPF uses it.
pub const TPROXY_PORT_DEFAULT: u16 = 12345;

/// skb mark used to identify daer-originated traffic (`TPROXY_MARK` in
/// `control/kern/tproxy.c`).
pub const TPROXY_MARK: u32 = 0x0800_0000;

/// Network namespace that hosts the tproxy listener.
pub const DAENS_NETNS: &str = "daens";

/// Virtual interface paired with `DAE0_IFNAME` (netkit/netdev pair).
pub const DAE0_IFNAME: &str = "dae0";

/// Peer of [`DAE0_IFNAME`] used as the redirect target.
pub const DAEPEER_IFNAME: &str = "dae0peer";

/// Ethernet MTU assumed while rewriting L2 headers.
pub const ETHERNET_MTU: usize = 1500;

/// Default bound for `MAX_MATCH_SET_LEN`, the number of 32-bit match words the
/// kernel routing program evaluates per packet. Overridable at build time in
/// the Go implementation via `make MAX_MATCH_SET_LEN=...`.
pub const MAX_MATCH_SET_LEN: usize = 1024;

/// Minimum supported kernel version; `bpf_loop` and the cgroup hooks daer relies
/// on require 5.17 or later.
pub const MIN_KERNEL_VERSION: (u16, u16) = (5, 17);

/// Backstop lifetime for UDP connection state entries.
pub const UDP_CONN_STATE_TIMEOUT: Duration = Duration::from_secs(300);

/// How the dial target is chosen for a matched flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DialMode {
    /// Route and dial by resolved IP only.
    Ip,
    /// Use the sniffed/cached domain when it is known to resolve.
    Domain,
    /// Always send the sniffed domain to the proxy server.
    DomainPlus,
    /// Route by sniffed domain without requiring DNS through daer.
    DomainCao,
}

impl DialMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ip => "ip",
            Self::Domain => "domain",
            Self::DomainPlus => "domain+",
            Self::DomainCao => "domain++",
        }
    }
}

impl fmt::Display for DialMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for DialMode {
    type Err = UnsupportedDialMode;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ip" => Ok(Self::Ip),
            "domain" => Ok(Self::Domain),
            "domain+" => Ok(Self::DomainPlus),
            "domain++" => Ok(Self::DomainCao),
            other => Err(UnsupportedDialMode {
                mode: other.to_owned(),
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsupportedDialMode {
    pub mode: String,
}

impl fmt::Display for UnsupportedDialMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unsupported dial mode: {}", self.mode)
    }
}

impl std::error::Error for UnsupportedDialMode {}

/// Routing function names accepted inside `routing { ... }` and `dns { ... }`.
pub mod function {
    pub const DOMAIN: &str = "domain";
    pub const IP: &str = "ip";
    pub const SOURCE_IP: &str = "sip";
    pub const PORT: &str = "port";
    pub const SOURCE_PORT: &str = "sport";
    pub const L4_PROTO: &str = "l4proto";
    pub const IP_VERSION: &str = "ipversion";
    pub const MAC: &str = "mac";
    pub const PROCESS_NAME: &str = "pname";
    pub const DSCP: &str = "dscp";

    pub const QNAME: &str = "qname";
    pub const QTYPE: &str = "qtype";
    pub const UPSTREAM: &str = "upstream";
}

/// Domain matcher key prefixes (`domain(suffix:...)`, `domain(keyword:...)`).
pub mod domain_key {
    pub const FULL: &str = "full";
    pub const KEYWORD: &str = "keyword";
    pub const SUFFIX: &str = "suffix";
    pub const REGEX: &str = "regex";
}

/// Outbound parameter keys.
pub mod outbound_param {
    pub const MARK: &str = "mark";
}

/// How a group picks a node for a new connection.
///
/// Mirrors `consts.DialerSelectionPolicy` in the Go implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum SelectionPolicy {
    /// Pick a random alive node.
    #[default]
    Random,
    /// Always use the configured node; connectivity checks are disabled.
    Fixed,
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
            Self::Fixed => "fixed",
            Self::MinLastLatency => "min",
            Self::MinAverage10 => "min_avg10",
            Self::MinMovingAverage => "min_moving_avg",
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
            "fixed" => Ok(Self::Fixed),
            "min" => Ok(Self::MinLastLatency),
            "min_avg10" => Ok(Self::MinAverage10),
            "min_moving_avg" => Ok(Self::MinMovingAverage),
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
