// SPDX-License-Identifier: AGPL-3.0-only

//! Attaching the kernel datapath: the step that makes `daer` a proxy rather than a library.
//!
//! # What has to be true before this runs
//!
//! * the private ingress namespace exists, `daer0peer` has moved into it, and the host end
//!   `daer0` is up; see [`crate::netns::PreparedIngress`];
//! * the transparent listeners are bound **inside that namespace**, because their fds go into
//!   `PARAM` and `listen_socket_map`;
//! * the process holds `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_PERFMON` (the verifier's
//!   `allow_ptr_leaks` gate) and `CAP_SYS_ADMIN` (the namespace).
//!
//! # Why the pair crosses a namespace
//!
//! The datapath redirects a matching flow onto `daer0`; its peer `daer0peer` is where the
//! packet must be assigned to the listener. A host-generated packet and a listener in the
//! same namespace can produce a successful `bpf_sk_assign` and still fail local delivery
//! with `NO_SOCKET`. The namespace boundary is therefore part of the datapath, not a
//! deployment preference (ADR-0038).
//!
//! # Why the policy routing is namespace-local
//!
//! `daer0peer` delivers a redirected packet with a **non-local** destination address. The
//! guest namespace only hands such a packet to the `bpf_sk_assign`-ed socket when a rule
//! sends it to a `local` route:
//!
//! ```text
//! ip rule  add iif daer0peer table 2023
//! ip route add local default dev lo table 2023
//! ```
//!
//! and the same pair for IPv6. The rule is keyed by the ingress interface, not by
//! `fwmark`: listener replies also carry the datapath's mark so the host recognises them as
//! daer's own egress, and a mark-keyed rule in this namespace would route those replies back
//! to `lo`. [`RouteTable`] installs and removes the state inside the namespace.
//!
//! # Why the link layer type decides the program
//!
//! The datapath has two variants of every hook: an `_l2` one that starts parsing after the
//! Ethernet header, and an `_l3` one that starts at the IP header. Attaching both to one
//! interface is not "belt and braces": the wrong variant reads the first bytes of the IP
//! header as a MAC address (or vice versa) and misclassifies every packet. [`LinkKind`] is
//! read from `/sys/class/net/<if>/type` and picks exactly one.

use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use daer_ebpf::loader;

/// The device the datapath redirects through.
pub const DEVICE: &str = "daer0";
/// Its peer, which the transparent listener is reachable through.
pub const PEER: &str = "daer0peer";

/// The ARPHRD type of an interface, which decides how many link-layer bytes precede the
/// IP header.
///
/// Only two answers matter to the datapath: a device that carries an Ethernet header
/// (`_l2`), and one that does not (`_l3` — TUN, WireGuard, PPP, and the `netkit`/`veth`
/// ends whose traffic is already L3). Anything else is refused rather than guessed: a
/// wrong guess misparses every packet on that interface, which is silent and total.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkKind {
    /// `ARPHRD_ETHER` (1): a 14-byte Ethernet header precedes the IP header.
    Ethernet,
    /// `ARPHRD_NONE` (0xFFFE), `ARPHRD_TUNNEL`, `ARPHRD_PPP`, ...: the packet starts at IP.
    RawIp,
}

impl LinkKind {
    /// Reads the link kind of `interface` from `/sys/class/net`.
    ///
    /// # Errors
    ///
    /// Returns [`DatapathError::Device`] when the interface does not exist or reports a
    /// hardware type the datapath has no parser for.
    pub fn of(interface: &str) -> Result<Self, DatapathError> {
        let path = format!("/sys/class/net/{interface}/type");
        let text = std::fs::read_to_string(&path)
            .map_err(|error| DatapathError::Device(format!("cannot read {path}: {error}")))?;
        let raw: u32 = text.trim().parse().map_err(|_| {
            DatapathError::Device(format!("{path} is not an ARPHRD type: {}", text.trim()))
        })?;
        Self::from_arphrd(interface, raw)
    }

    /// Maps an `ARPHRD_*` value, naming the interface when it is unsupported.
    ///
    /// Split from [`Self::of`] so the mapping is testable without a real device of every
    /// kind.
    ///
    /// # Errors
    ///
    /// Returns [`DatapathError::Device`] for a hardware type with no `_l2`/`_l3` variant.
    pub fn from_arphrd(interface: &str, arphrd: u32) -> Result<Self, DatapathError> {
        match arphrd {
            // ARPHRD_ETHER
            1 => Ok(Self::Ethernet),
            // ARPHRD_NONE (0xFFFE), ARPHRD_PPP (512), ARPHRD_TUNNEL (768),
            // ARPHRD_TUNNEL6 (769), ARPHRD_SIT (776), ARPHRD_IPGRE (778),
            // ARPHRD_RAWIP (519), ARPHRD_WIREGUARD (65534 == 0xFFFE is NONE).
            512 | 519 | 768 | 769 | 776 | 778 | 65_534 => Ok(Self::RawIp),
            other => Err(DatapathError::Device(format!(
                "{interface} has ARPHRD type {other}, which has no datapath parser; \
                 exclude it with `lan`/`wan` or use an Ethernet or L3 interface"
            ))),
        }
    }

    /// The `_l2` program when this is an Ethernet device, `_l3` otherwise.
    const fn pick(self, l2: &'static str, l3: &'static str) -> &'static str {
        match self {
            Self::Ethernet => l2,
            Self::RawIp => l3,
        }
    }
}

/// What went wrong while wiring the datapath.
#[derive(Debug)]
pub enum DatapathError {
    /// A required command is missing.
    Missing(String),
    /// A command ran and failed.
    Command {
        /// The command line, for the log.
        command: String,
        /// Its stderr.
        message: String,
    },
    /// The object could not be loaded or attached.
    Object(loader::LoadError),
    /// The device pair could not be prepared.
    Device(String),
}

impl std::fmt::Display for DatapathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing(command) => write!(f, "`{command}` is not installed"),
            Self::Command { command, message } => {
                write!(f, "`{command}` failed: {}", message.trim())
            }
            Self::Object(error) => write!(f, "{error}"),
            Self::Device(message) => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for DatapathError {}

/// The policy-routing state the datapath needs, installed once and removed on drop.
///
/// Two families, each with one `iif daer0peer` rule and one `local default` route, installed
/// in the private ingress namespace. The guard is deliberately not `Clone`: two owners would
/// remove the rules while the other was still redirecting. It holds an [`Arc`] to the
/// namespace so removal cannot run after the namespace has been deleted.
///
/// # Why removal is best effort
///
/// `Drop` cannot report, and a failure to remove is not worth aborting a shutdown for: the
/// next namespace is fresh, so a stale rule cannot survive a clean restart. If the process
/// dies without unwinding, the namespace is destroyed with it and the rules go with the
/// namespace.
#[derive(Debug)]
pub struct RouteTable {
    /// The families actually installed, so a partial failure removes only what it added.
    installed: Vec<Family>,
    /// The private ingress namespace whose table is owned. The guard keeps the namespace
    /// alive until the routes have been removed on drop.
    namespace: Arc<crate::netns::IngressNamespace>,
}

/// One address family's rule and route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Family {
    V4,
    V6,
}

impl Family {
    /// The `ip` family selector, `-4` or `-6`.
    const fn flag(self) -> &'static str {
        match self {
            Self::V4 => "-4",
            Self::V6 => "-6",
        }
    }
}

/// The routing table number, as `ip` spells it.
const TABLE_SPEC: &str = "2023";

impl Family {
    /// The full argument vector for `ip <flag> route add local default dev lo table 2023`.
    ///
    /// `dev lo` is required: the kernel rejects a `local` route with no output device, and
    /// `lo` is correct because a `local` route terminates in the host stack.
    const fn route(self) -> [&'static str; 9] {
        [
            "ip",
            self.flag(),
            "route",
            "add",
            "local",
            "default",
            "dev",
            "lo",
            "table",
        ]
    }

    /// The same vector with the table number appended, since [`Self::route`] ends on the
    /// `table` keyword for readability at the call site.
    fn route_with_table(self) -> Vec<&'static str> {
        let mut route = self.route().to_vec();
        route.push(TABLE_SPEC);
        route
    }

    /// The rule keyed by ingress interface rather than mark.
    ///
    /// Every packet arriving on `daer0peer` is a redirected one, and the mark would also
    /// match daer's own listener replies: those replies are intentionally marked so the
    /// host treats them as daer's egress, but in the ingress namespace a mark-keyed rule
    /// would route them back to `lo` instead of out through the peer. The interface is the
    /// property that distinguishes "came from the datapath" from "left the listener".
    fn iif_rule(self) -> Vec<String> {
        vec![
            "ip".to_owned(),
            self.flag().to_owned(),
            "rule".to_owned(),
            "add".to_owned(),
            "iif".to_owned(),
            PEER.to_owned(),
            "table".to_owned(),
            TABLE_SPEC.to_owned(),
        ]
    }

    /// The deletion form of [`Self::iif_rule`].
    fn iif_rule_del(self) -> Vec<String> {
        let mut rule = self.iif_rule();
        rule[3] = "del".to_owned();
        rule
    }

    /// The deletion form of [`Self::route`].
    fn route_del(self) -> Vec<&'static str> {
        let mut route = self.route().to_vec();
        route[3] = "del";
        route.push(TABLE_SPEC);
        route
    }
}

impl RouteTable {
    /// Installs `fwmark -> table 2023 -> local default` for IPv4 and IPv6.
    ///
    /// Idempotent: whatever a previous run left behind is deleted first, so a restart after
    /// a crash does not fail on "File exists".
    ///
    /// # Errors
    ///
    /// Returns [`DatapathError::Command`] naming the failing `ip` invocation. A family that
    /// fails removes the families that already succeeded before returning.
    pub fn install(namespace: &Arc<crate::netns::IngressNamespace>) -> Result<Self, DatapathError> {
        let mut installed = Vec::with_capacity(2);
        for family in [Family::V4, Family::V6] {
            if let Err(error) = install_family(namespace, family) {
                if family == Family::V6 {
                    // IPv6 is optional. An IPv4-only kernel has no `ip6tables` rules and no
                    // IPv6 table; failing the whole datapath for it would make the IPv4
                    // proxy unusable. The absence is logged, and IPv6 redirected traffic
                    // cannot be delivered without it.
                    daer_observe::warn!(daer_observe::EventCode::DatapathIpv6Unavailable,%error, "IPv6 policy routing is unavailable; IPv4 continues");
                    continue;
                }
                // Roll back what was installed: a half-configured table would send one
                // family's redirected traffic into the forward path.
                let guard = Self {
                    installed,
                    namespace: Arc::clone(namespace),
                };
                drop(guard);
                return Err(error);
            }
            installed.push(family);
        }
        Ok(Self {
            installed,
            namespace: Arc::clone(namespace),
        })
    }

    fn remove(&self) -> Result<(), DatapathError> {
        for family in &self.installed {
            // A missing rule or route is the state being asked for, so a failure here is
            // not an error worth surfacing.
            let _ = run_ip_in(Some(self.namespace.name()), &family.iif_rule_del());
            let _ = run_ip_in(Some(self.namespace.name()), &family.route_del());
        }
        Ok(())
    }
}

impl Drop for RouteTable {
    fn drop(&mut self) {
        if let Err(error) = self.remove() {
            daer_observe::warn!(daer_observe::EventCode::DatapathCleanupFailed,%error, "could not remove the datapath policy routing");
        }
    }
}

/// Installs one family's rule and route, replacing whatever was there.
fn install_family(
    namespace: &Arc<crate::netns::IngressNamespace>,
    family: Family,
) -> Result<(), DatapathError> {
    let name = Some(namespace.name());
    // Delete first so both commands are idempotent: `ip rule add` tolerates a duplicate
    // (it creates a second identical rule), while `ip route add` fails with EEXIST.
    let _ = run_ip_in(name, &family.iif_rule_del());
    let _ = run_ip_in(name, &family.route_del());
    run_ip_in(name, &family.iif_rule())?;
    run_ip_in(name, &family.route_with_table())?;
    Ok(())
}

fn run<S: AsRef<std::ffi::OsStr>>(line: &[S]) -> Result<String, DatapathError> {
    run_ip_in(None, line)
}

/// Runs an `ip` command in `namespace`, or in the current namespace when it is `None`.
fn run_ip_in<S: AsRef<std::ffi::OsStr>>(
    namespace: Option<&str>,
    line: &[S],
) -> Result<String, DatapathError> {
    let Some((program, arguments)) = line.split_first() else {
        return Err(DatapathError::Missing(String::new()));
    };
    let mut command = Command::new(program);
    if let Some(namespace) = namespace {
        command.args(["-n", namespace]);
    }
    let output = command
        .args(arguments)
        .output()
        .map_err(|_| DatapathError::Missing(program.as_ref().to_string_lossy().into_owned()))?;
    if !output.status.success() {
        let command = line
            .iter()
            .map(|part| part.as_ref().to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ");
        return Err(DatapathError::Command {
            command,
            message: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// True when `interface` exists in the current network namespace.
///
/// `/sys/class/net` is not namespace-aware on every kernel: a process that entered a netns
/// can still see the host's devices there, which would make a check resolve a host link from
/// the wrong namespace. `ip link show` resolves the interface through the current netns, so
/// the answer matches the commands that follow.
#[must_use]
pub fn interface_exists(interface: &str) -> bool {
    Command::new("ip")
        .args(["link", "show", "dev", interface])
        .output()
        .is_ok_and(|output| output.status.success())
}

/// Creates the veth pair with the peer already inside the private ingress namespace.
///
/// The namespace is created first, and the peer is placed in it in the same netlink
/// operation that creates the host end. That atomicity is the ownership boundary: there is
/// no interval in which both ends live in the host namespace, so a `SIGKILL` at any point
/// after this call leaves both ends owned by the namespace and the kernel removes the pair
/// when the namespace dies.
///
/// # Errors
///
/// Returns [`DatapathError`] naming the command that failed. `ip` is required; there is no
/// netlink fallback because a partial implementation of "create a veth pair" is a much
/// larger surface than one `ip` invocation.
pub fn create_device_pair(namespace: &str) -> Result<(), DatapathError> {
    // A pair in the host namespace cannot belong to this run: the peer is created inside
    // the namespace. It is either another daemon or state from a pre-TCX release. Fail with
    // an actionable message instead of letting netlink report EEXIST.
    if interface_exists(DEVICE) || interface_exists(PEER) {
        return Err(DatapathError::Device(format!(
            "{DEVICE}/{PEER} already exists in the host namespace; stop the other daemon or \
             remove the stale link with `ip link del {DEVICE}` before starting daer"
        )));
    }
    run(&[
        "ip", "link", "add", DEVICE, "type", "veth", "peer", "name", PEER, "netns", namespace,
    ])
    .map(|_| ())
}

/// Brings a host-visible link up.
///
/// # Errors
///
/// Returns [`DatapathError::Command`] naming the failing `ip` invocation.
pub fn link_up(interface: &str) -> Result<(), DatapathError> {
    run(&["ip", "link", "set", interface, "up"]).map(|_| ())
}

/// Adds the host end's IPv6 link-local next-hop address.
///
/// The ingress namespace's IPv6 default route points at this address, exactly as its IPv4
/// route points at [`crate::netns::HOST_IPV4`]. `nodad` is required: duplicate address
/// detection would leave the address tentative and the route unusable for the first
/// seconds of a run.
///
/// # Errors
///
/// Returns [`DatapathError::Command`] when the address cannot be added. IPv6 is optional at
/// the caller; IPv4 proxying must not depend on a kernel built without it.
pub fn add_ipv6_link_local(interface: &str) -> Result<(), DatapathError> {
    let address = format!("{}/128", crate::netns::HOST_IPV6);
    run(&[
        "ip", "-6", "addr", "add", &address, "dev", interface, "nodad",
    ])
    .map(|_| ())
}

/// The MAC address of a link in the current network namespace.
///
/// # Errors
///
/// Returns [`DatapathError::Device`] when the link does not exist, cannot be queried, or
/// does not report a six-octet Ethernet address.
pub fn link_mac(interface: &str) -> Result<[u8; 6], DatapathError> {
    let line = link_line(interface)?;
    let mac = line
        .split("link/ether ")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .ok_or_else(|| {
            DatapathError::Device(format!(
                "`ip link show {interface}` has no MAC address: {line}"
            ))
        })?;
    let parts: Vec<&str> = mac.split(':').collect();
    if parts.len() != 6 {
        return Err(DatapathError::Device(format!(
            "{interface} is not an Ethernet address: {mac}"
        )));
    }
    let mut octets = [0u8; 6];
    for (index, part) in parts.iter().enumerate() {
        octets[index] = u8::from_str_radix(part, 16).map_err(|_| {
            DatapathError::Device(format!("{interface} is not an Ethernet address: {mac}"))
        })?;
    }
    Ok(octets)
}

/// The ifindex of a link in the current network namespace.
///
/// # Errors
///
/// Returns [`DatapathError`] when the link does not exist or its ifindex is not a number.
pub fn ifindex(interface: &str) -> Result<u32, DatapathError> {
    let line = link_line(interface)?;
    line.split(':')
        .next()
        .and_then(|index| index.trim().parse().ok())
        .ok_or_else(|| {
            DatapathError::Device(format!("`ip link show {interface}` has no ifindex: {line}"))
        })
}

/// One `ip -o link show dev <interface>` line, resolved in the current netns.
///
/// One command rather than two: the peer is moved between namespaces, and a second lookup
/// after a move would resolve a different netns's device. The caller queries while the
/// link is still where it intends to use it.
fn link_line(interface: &str) -> Result<String, DatapathError> {
    let output = run(&["ip", "-o", "link", "show", "dev", interface])?;
    output.lines().next().map(str::to_owned).ok_or_else(|| {
        DatapathError::Device(format!("`ip link show {interface}` returned no link"))
    })
}

/// Loads the object, attaches every program, and returns the handle.
///
/// The handle must be kept alive for the lifetime of the daemon: dropping it detaches the
/// programs and removes the policy routing, and the box silently stops proxying.
///
/// # Errors
///
/// Returns [`DatapathError::Object`] for a load or attach failure; the message names the
/// program or map, because "eBPF failed" is not actionable.
pub fn attach(
    object: &std::path::Path,
    param: &daer_ebpf::RuntimeParam,
    lan: &[String],
    wan: &[String],
    listeners: Listeners,
    policy: &daer_routing::Policy,
    ingress: &crate::netns::PreparedIngress,
) -> Result<Attached, DatapathError> {
    use aya::programs::tc::TcAttachType;
    use daer_ebpf::loader::attach_tc;
    use daer_ebpf::names::program;

    loader::require_tcx().map_err(DatapathError::Object)?;
    let mut ebpf = loader::load_path(object, param).map_err(DatapathError::Object)?;

    // The map is the runtime source of truth for the redirect target. Leaving it at its
    // zero default makes `bpf_redirect(0, 0)` fail, and every control-plane flow is
    // dropped without a packet ever reaching the listener — the exact symptom of a
    // datapath that attaches cleanly but proxies nothing.
    daer_ebpf::set_device_ifindex(&mut ebpf, param.device_ifindex)
        .map_err(DatapathError::Object)?;

    // Resolved before anything is attached: a device with no parser must stop the run
    // rather than leave half the interfaces hooked and the rest silently direct.
    let lan_kinds = kinds(lan)?;
    let wan_kinds = kinds(wan)?;

    for (interface, kind) in &lan_kinds {
        // LAN ingress: traffic *from* the local network being proxied. LAN egress: the
        // reply direction of a proxied flow, and the box's own traffic on a LAN-facing
        // device.
        attach_tc(
            &mut ebpf,
            kind.pick(program::LAN_INGRESS_L2, program::LAN_INGRESS_L3),
            interface,
            TcAttachType::Ingress,
        )
        .map_err(DatapathError::Object)?;
        attach_tc(
            &mut ebpf,
            kind.pick(program::LAN_EGRESS_L2, program::LAN_EGRESS_L3),
            interface,
            TcAttachType::Egress,
        )
        .map_err(DatapathError::Object)?;
    }

    for (interface, kind) in &wan_kinds {
        // WAN ingress and egress: the box's own traffic and the return path of a proxied
        // flow. These two hooks are what make `daer` a gateway for the host itself.
        attach_tc(
            &mut ebpf,
            kind.pick(program::WAN_INGRESS_L2, program::WAN_INGRESS_L3),
            interface,
            TcAttachType::Ingress,
        )
        .map_err(DatapathError::Object)?;
        attach_tc(
            &mut ebpf,
            kind.pick(program::WAN_EGRESS_L2, program::WAN_EGRESS_L3),
            interface,
            TcAttachType::Egress,
        )
        .map_err(DatapathError::Object)?;
    }

    // The local device pair is split across two namespaces. `daer0` is the return path for
    // listener replies and stays in the host namespace; `daer0peer` and its ingress program
    // live in the private ingress namespace, where redirected packets are assigned.
    attach_tc(
        &mut ebpf,
        program::DEVICE_INGRESS,
        DEVICE,
        TcAttachType::Ingress,
    )
    .map_err(DatapathError::Object)?;
    // A redirected packet arrives on `daer0peer` with a non-local source *and*
    // destination, so reverse-path filtering would drop it before `bpf_sk_assign` could
    // matter. The peer's knobs and the `fwmark` table are namespace-scoped state owned by
    // the returned guards.
    let sysctls = Sysctl::apply(&ingress.namespace)?;
    let routes = RouteTable::install(&ingress.namespace)?;

    republish_policy(&mut ebpf, param.datapath_generation, policy)?;
    // Without this the datapath decides "proxy" and then has nowhere to send the packet:
    // `assign_listener` looks the socket up in `listen_socket_map` and returns -1 when it is
    // empty, so the flow dies with no diagnostic on either side.
    daer_ebpf::publish_listeners(&mut ebpf, listeners)
        .map_err(|error| DatapathError::Device(format!("cannot publish the listeners: {error}")))?;

    // The peer hook is attached last on purpose. A failure after this point must not leave
    // the object's host hooks alive without the peer hook; dropping `ebpf` closes every
    // TCX link, and dropping the namespace removes the pair.
    let peer_link = ingress
        .namespace
        .with(|| {
            attach_tc(
                &mut ebpf,
                program::PEER_INGRESS,
                PEER,
                TcAttachType::Ingress,
            )
        })
        .map_err(|error| {
            DatapathError::Device(format!(
                "cannot enter {}: {error}",
                ingress.namespace.name()
            ))
        })?
        .map_err(DatapathError::Object)?;

    Ok(Attached {
        ebpf: std::sync::Arc::new(crate::decide::HandoffObserver::new(ebpf)),
        peer_link: Some(peer_link),
        _routes: routes,
        _sysctls: sysctls,
        namespace: Arc::clone(&ingress.namespace),
    })
}

/// Everything an attached datapath holds open.
///
/// One value rather than three returns, because the three must have the same lifetime: a
/// dropped [`RouteTable`] with a live eBPF program leaves the kernel redirecting packets
/// into a table that no longer sends them local.
#[derive(Debug)]
pub struct Attached {
    /// The loaded object and the flow-fact observer over it.
    ///
    /// One field rather than two because they are the same resource: the observer reads
    /// `routing_handoff_map` out of this object, and republishing the policy on reload writes
    /// into it.
    ebpf: Arc<crate::decide::HandoffObserver>,
    /// The peer ingress link, detached explicitly inside the namespace before the object
    /// drops. The link is fd-owned, so process death detaches it even without this path.
    peer_link: Option<aya::programs::tc::SchedClassifierLinkId>,
    /// The `iif daer0peer` policy routing and local route.
    _routes: RouteTable,
    /// The host and ingress sysctls.
    _sysctls: Sysctl,
    /// The namespace that owns the peer link and policy. Held past every guard that uses it.
    namespace: Arc<crate::netns::IngressNamespace>,
}

impl Drop for Attached {
    fn drop(&mut self) {
        let Some(link) = self.peer_link.take() else {
            return;
        };
        let namespace = Arc::clone(&self.namespace);
        let result = namespace.with(move || {
            self.ebpf
                .with_ebpf(|ebpf| {
                    let Some(program) = ebpf.program_mut(daer_ebpf::names::program::PEER_INGRESS)
                    else {
                        return Err(
                            "the peer ingress program is no longer in the object".to_owned()
                        );
                    };
                    let classifier: &mut aya::programs::tc::SchedClassifier =
                        program.try_into().map_err(|error| {
                            format!("the peer ingress program is not a tc classifier: {error}")
                        })?;
                    classifier
                        .detach(link)
                        .map_err(|error| format!("cannot detach the peer ingress link: {error}"))
                })
                .map_err(|error| format!("cannot access the datapath object: {error}"))?
        });
        match result {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                daer_observe::warn!(daer_observe::EventCode::DatapathPeerDetachFailed,
                    %error,
                    "could not detach the peer ingress link inside the namespace"
                );
            }
            Err(error) => {
                daer_observe::warn!(daer_observe::EventCode::DatapathPeerDetachFailed,
                    %error,
                    "could not enter the ingress namespace to detach the peer link"
                );
            }
        }
    }
}

impl Attached {
    /// The observer the router should be built with.
    ///
    /// Returned as a trait object so `RouterOptions` does not have to name the eBPF type: the
    /// router only ever needs [`crate::decide::KernelObserver`].
    pub fn observer(&self) -> Arc<dyn crate::decide::KernelObserver> {
        Arc::clone(&self.ebpf) as Arc<dyn crate::decide::KernelObserver>
    }

    /// Runs `f` with the loaded object, for republishing a policy on reload.
    ///
    /// # Errors
    ///
    /// Returns a message when the object is no longer owned, which would be a shutdown race.
    pub fn with_ebpf<T>(&self, f: impl FnOnce(&mut aya::Ebpf) -> T) -> Result<T, String> {
        self.ebpf.with_ebpf(f)
    }

    /// Takes the telemetry maps out of the object.
    ///
    /// The caller owns the reader for the rest of the run. Taking the maps is deliberate:
    /// one reader, no aliasing of a ring-buffer fd, and no hidden second consumer.
    ///
    /// # Errors
    ///
    /// Returns a message when the object is gone or a map has the wrong type.
    pub fn take_telemetry(&mut self) -> Result<daer_ebpf::telemetry::DatapathTelemetry, String> {
        self.ebpf
            .with_ebpf(daer_ebpf::telemetry::DatapathTelemetry::attach)
            .map_err(|error| format!("cannot access the datapath object: {error}"))?
            .map_err(|error| format!("cannot take the datapath telemetry maps: {error}"))
    }
}

/// Resolves `(interface, link kind)` pairs, failing on the first unknown device.
fn kinds(interfaces: &[String]) -> Result<Vec<(&str, LinkKind)>, DatapathError> {
    interfaces
        .iter()
        .map(|interface| Ok((interface.as_str(), LinkKind::of(interface)?)))
        .collect()
}

/// The per-interface sysctls the datapath needs, restored on drop.
#[derive(Debug)]
struct Sysctl {
    /// `(path, previous contents, namespace)` for every value written. `path` is relative
    /// to `/proc/sys/net`; the namespace field says which `/proc/sys/net` it belongs to.
    written: Vec<(String, Option<String>, Scope)>,
    /// The private ingress namespace. The guard keeps it alive until restoration.
    namespace: Arc<crate::netns::IngressNamespace>,
}

#[derive(Debug, Clone, Copy)]
enum Scope {
    Host,
    Ingress,
}

/// Host-global settings the datapath needs but does not own.
///
/// These used to be written and restored by the daemon. A global forwarding policy is not
/// daer state: a `SIGKILL` left the daemon's value behind until the next start, and the next
/// start could mistake it for the operator's baseline. The operator sets them once; startup
/// refuses to change a single packet's path when they are missing.
const HOST_SYSCTL_PREREQUISITES: &[(&str, &str)] = &[
    ("net/ipv4/ip_forward", "1"),
    ("net/ipv4/conf/all/forwarding", "1"),
    ("net/ipv4/conf/all/rp_filter", "0"),
    ("net/ipv4/conf/all/arp_filter", "0"),
];

/// Checks the host-global settings the datapath needs but does not own.
///
/// IPv6 is optional: a kernel built without it has no
/// `/proc/sys/net/ipv6/conf/all/forwarding`; a dual-stack kernel must have forwarding on.
///
/// # Errors
///
/// Returns [`DatapathError::Device`] naming the first missing setting and how to set it.
pub fn check_host_sysctls() -> Result<(), DatapathError> {
    for (path, expected) in HOST_SYSCTL_PREREQUISITES {
        check_sysctl(path, expected)?;
    }
    if Path::new("/proc/sys/net/ipv6/conf/all/forwarding").exists() {
        check_sysctl("net/ipv6/conf/all/forwarding", "1")?;
    }
    Ok(())
}

fn check_sysctl(path: &str, expected: &str) -> Result<(), DatapathError> {
    let full = format!("/proc/sys/{path}");
    let current = std::fs::read_to_string(&full)
        .map_err(|error| DatapathError::Device(format!("cannot read {full}: {error}")))?;
    let current = current.trim();
    if current != expected {
        return Err(DatapathError::Device(format!(
            "{full} is `{current}`, but daer requires `{expected}`; add the value to \
             /etc/sysctl.d/99-daer.conf and run `sysctl --system`"
        )));
    }
    Ok(())
}

impl Sysctl {
    /// Disables reverse-path filtering on the peer and enables forwarding.
    ///
    /// `net.ipv4.conf.daer0peer.rp_filter = 0` is what lets a packet with a non-local
    /// source address be delivered locally; without it the redirect is dropped by the
    /// stack with an `rp_filter` counter and no other trace.
    ///
    /// The peer and the `all` knobs live in the private ingress namespace. `daer0` stays in
    /// the host namespace, so its knobs are written there. This split is deliberate: the
    /// namespace boundary is the reason a host-generated packet can be assigned to a
    /// listener in the first place, and writing the peer's knobs in the host namespace
    /// would configure a device that is no longer there.
    fn apply(namespace: &Arc<crate::netns::IngressNamespace>) -> Result<Self, DatapathError> {
        let mut guard = Self {
            written: Vec::new(),
            namespace: Arc::clone(namespace),
        };
        for (scope, path, value) in [
            // Host-global forwarding and martian settings are prerequisites, checked before
            // this guard runs (`check_host_sysctls`); they are not written here. What remains
            // in the host namespace is owned by `daer0`: the device disappears with the pair,
            // taking these per-device knobs with it.
            (Scope::Host, "net/ipv4/conf/daer0/rp_filter", "0"),
            (Scope::Host, "net/ipv4/conf/daer0/accept_local", "1"),
            (Scope::Host, "net/ipv4/conf/daer0/arp_filter", "0"),
            (Scope::Host, "net/ipv4/conf/daer0/forwarding", "1"),
            (Scope::Host, "net/ipv6/conf/daer0/disable_ipv6", "0"),
            (Scope::Host, "net/ipv6/conf/daer0/forwarding", "1"),
            // Ingress: a redirected packet arrives with a non-local source and destination.
            // `accept_local` is what lets the host-generated source survive the martian
            // check; `rp_filter` would drop the packet before `bpf_sk_assign` runs.
            (Scope::Ingress, "net/ipv4/conf/all/rp_filter", "0"),
            (Scope::Ingress, "net/ipv4/conf/all/arp_filter", "0"),
            (Scope::Ingress, "net/ipv4/conf/daer0peer/rp_filter", "0"),
            (Scope::Ingress, "net/ipv4/conf/daer0peer/accept_local", "1"),
            (Scope::Ingress, "net/ipv4/conf/daer0peer/arp_filter", "0"),
            (Scope::Ingress, "net/ipv4/conf/daer0peer/forwarding", "1"),
            (Scope::Ingress, "net/ipv6/conf/daer0peer/disable_ipv6", "0"),
            (Scope::Ingress, "net/ipv6/conf/daer0peer/forwarding", "1"),
        ] {
            if path.starts_with("net/ipv6/") {
                // IPv6 is optional for a box that only proxies IPv4. A kernel built without
                // IPv6 has no /proc/sys/net/ipv6 tree; refusing to attach would turn a
                // working IPv4 proxy into a startup failure.
                if let Err(error) = guard.write(path, value, scope) {
                    daer_observe::warn!(daer_observe::EventCode::DatapathIpv6Unavailable,%error, "IPv6 sysctl is unavailable; continuing with IPv4");
                }
                continue;
            }
            guard.write(path, value, scope)?;
        }
        Ok(guard)
    }

    fn write(&mut self, path: &str, value: &str, scope: Scope) -> Result<(), DatapathError> {
        let previous = match scope {
            Scope::Host => {
                let full = format!("/proc/sys/{path}");
                let previous = std::fs::read_to_string(&full).ok();
                if previous.as_deref().map(str::trim) == Some(value) {
                    // Already correct: record nothing, so drop does not restore a value it
                    // did not change.
                    return Ok(());
                }
                std::fs::write(&full, value).map_err(|error| {
                    DatapathError::Device(format!("cannot write {full} = {value}: {error}"))
                })?;
                previous
            }
            Scope::Ingress => {
                let key = path.strip_prefix("net/").unwrap_or(path);
                let previous = self.namespace.write_sysctl(key, value).map_err(|error| {
                    DatapathError::Device(format!(
                        "cannot write net/{key} = {value} in {}: {error}",
                        self.namespace.name()
                    ))
                })?;
                if previous.as_deref().map(str::trim) == Some(value) {
                    return Ok(());
                }
                previous
            }
        };
        self.written.push((path.to_owned(), previous, scope));
        Ok(())
    }
}

impl Drop for Sysctl {
    fn drop(&mut self) {
        for (path, previous, scope) in self.written.drain(..).rev() {
            let Some(value) = previous else {
                continue;
            };
            match scope {
                Scope::Host => {
                    if let Err(error) = std::fs::write(format!("/proc/sys/{path}"), value.trim()) {
                        daer_observe::warn!(daer_observe::EventCode::DatapathSysctlRestoreFailed,%error, path, "could not restore a host sysctl");
                    }
                }
                Scope::Ingress => {
                    let key = path.strip_prefix("net/").unwrap_or(&path);
                    // The namespace is deleted after this guard, so a failure here has no
                    // surviving state to restore.
                    let _ = self.namespace.write_sysctl(key, value.trim());
                }
            }
        }
    }
}

/// The listener file descriptors the datapath hands redirected flows to.
///
/// Re-exported from `daer-ebpf` rather than declared here: the keys are ABI, and a second
/// definition is a second thing that can drift.
pub use daer_ebpf::Listeners;

/// Publishes the epoch and rule count the datapath reads.
///
/// # What this writes
///
/// For a policy the encoder proved equivalent to userspace (ADR-0005), in this order:
///
/// 1. every entry's `struct match_set` into `routing_map[slot * MAX_MATCH_SET_LEN + index]`;
/// 2. every entry's prefixes into its own trie at `lpm_array_map[same key]`;
/// 3. the outbound ids the policy selects into `outbound_connectivity_map`, without which
///    `wan_outbound_is_alive` shoots every proxied SYN;
/// 4. `routing_meta_map[slot]` = the entry count, read back;
/// 5. `active_routing_epoch_map[0]` = the slot — the commit.
///
/// For a policy it could not prove equivalent, step 1 writes the **single** defer entry and
/// step 2 writes nothing: the kernel hands every flow to the control plane rather than deciding
/// it with a table that is missing rules. Both cases end with a non-empty table, which is the
/// property that matters — an attached datapath with `active_rules_len = 0` returns `-EPERM`
/// from `route()`, and every caller turns that into `DAER_TC_DROP`.
/// Publishes the epoch and rule count the datapath reads.
pub fn republish_policy(
    ebpf: &mut aya::Ebpf,
    generation: u16,
    policy: &daer_routing::Policy,
) -> Result<(), DatapathError> {
    use daer_ebpf::epoch::{Entry, Published, publish};
    use daer_ebpf::names::map;
    use daer_ebpf::publish::{AyaWriter, publish_lpm, publish_outbound_connectivity};

    // The active slot is read through a scope of its own: `AyaWriter` holds `&mut Ebpf` for as
    // long as it lives, so the trie and connectivity writes below could not otherwise happen.
    let active = {
        let writer = AyaWriter::new(ebpf);
        daer_ebpf::epoch::active_slot(&writer).unwrap_or(daer_ebpf::Slot::Zero)
    };
    let target = active.other();

    // Steps 1 and 2 run before the metadata, because the metadata is what makes them visible.
    let mut entries = Vec::with_capacity(policy.entries.len());
    for (index, entry) in policy.entries.iter().enumerate() {
        let index = u32::try_from(index).map_err(|_| {
            DatapathError::Device("the policy has more entries than a u32 can index".to_owned())
        })?;
        let key = daer_routing::Policy::key(target.index(), index);
        entries.push(Entry {
            map: map::ROUTING.to_owned(),
            key: key.to_be_bytes().to_vec(),
            value: entry.to_bytes().to_vec(),
        });
    }
    for (index, keys) in &policy.lpms {
        publish_lpm(ebpf, target, *index, keys).map_err(|error| {
            DatapathError::Device(format!(
                "cannot publish the trie for entry {index}: {error}"
            ))
        })?;
    }

    // Step 3: the ids this policy can select. A group id the datapath has no entry for is a
    // group whose every flow is dropped, so this is not optional.
    let ids: Vec<u8> = (daer_ebpf::abi::outbound::FIRST_GROUP
        ..=daer_ebpf::abi::outbound::LAST_GROUP)
        .filter(|id| policy.outbounds.name(*id).is_some())
        .collect();
    publish_outbound_connectivity(ebpf, &ids, true).map_err(|error| {
        DatapathError::Device(format!("cannot publish the outbound connectivity: {error}"))
    })?;

    let published: Published = {
        let writer = AyaWriter::new(ebpf);
        publish(&writer, u64::from(generation.max(1)), &entries, 0).map_err(|error| {
            DatapathError::Device(format!("cannot publish the routing epoch: {error}"))
        })?
    };

    if policy.equivalent {
        daer_observe::info!(
            daer_observe::EventCode::DatapathPolicyPublished,
            slot = target.index(),
            entries = published.entries,
            trie_entries = policy.lpms.len(),
            "datapath policy published: the kernel decides every flow itself"
        );
    } else {
        let reasons: Vec<String> = policy.reasons.iter().map(ToString::to_string).collect();
        daer_observe::warn!(
            daer_observe::EventCode::DatapathPolicyDeferred,
            slot = target.index(),
            entries = published.entries,
            reasons = ?reasons,
            "datapath policy published as a deferral: every flow is handed to the control \
             plane, because the kernel cannot reproduce these rules faithfully. Traffic is \
             correct; the kernel-side split is not in effect"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_command_is_reported_by_name() {
        let error =
            run(&["definitely-not-a-real-command-daer", "--version"]).expect_err("must fail");
        assert!(
            matches!(error, DatapathError::Missing(_)),
            "expected Missing, got {error}"
        );
    }

    #[test]
    fn every_policy_route_command_invokes_ip_first() {
        // The failure this pins: the vectors used to start with the family selector,
        // so `run` executed `-4` as a program and the daemon reported
        // "`-4` is not installed" before it ever tried `ip`.
        for family in [Family::V4, Family::V6] {
            for command in [family.iif_rule(), family.iif_rule_del()] {
                assert_eq!(
                    command.first().map(String::as_str),
                    Some("ip"),
                    "{command:?}"
                );
            }
            for command in [
                family.route().to_vec(),
                family.route_with_table(),
                family.route_del(),
            ] {
                assert_eq!(command.first().copied(), Some("ip"), "{command:?}");
            }
        }
    }

    #[test]
    fn the_policy_rule_is_keyed_by_ingress_not_by_mark() {
        // The falsifier for the listener-reply loop: a mark-keyed rule would also match
        // daer's own marked replies, which are routed back through `daer0peer`. The ingress
        // interface is the only property that distinguishes a redirected packet from a
        // listener reply.
        for family in [Family::V4, Family::V6] {
            let rule = family.iif_rule();
            assert!(rule.iter().any(|part| part == "iif"), "{rule:?}");
            assert!(rule.iter().any(|part| part == PEER), "{rule:?}");
            assert!(!rule.iter().any(|part| part == "fwmark"), "{rule:?}");
            let delete = family.iif_rule_del();
            assert!(delete.iter().any(|part| part == "del"), "{delete:?}");
        }
    }

    #[test]
    fn a_failing_command_carries_its_stderr() {
        // `false` exits 1 without output; the point is that the error is a `Command`, not a
        // panic and not a swallowed success.
        let error = run(&["false"]).expect_err("must fail");
        assert!(matches!(error, DatapathError::Command { .. }), "{error}");
    }

    #[test]
    fn an_absent_interface_is_not_reported_as_present() {
        assert!(!interface_exists("definitely-not-an-interface"));
    }

    #[test]
    fn the_loopback_interface_is_present() {
        // An environment without `lo` cannot run any of this, so the assertion doubles as a
        // sanity check on `/sys/class/net` being readable in a sandbox.
        assert!(interface_exists("lo"));
        assert!(ifindex("lo").expect("lo has an ifindex") > 0);
    }
}
