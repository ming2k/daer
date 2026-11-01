// SPDX-License-Identifier: AGPL-3.0-only

//! Attaching the kernel datapath: the step that makes `daer` a proxy rather than a library.
//!
//! # What has to be true before this runs
//!
//! * a network device exists with the daer-side name (`daer0`) and its peer (`daer0peer`),
//!   both up, the peer carrying the address the redirect targets;
//! * the transparent listener is bound, because its port goes into `PARAM`;
//! * the process holds `CAP_BPF` and `CAP_NET_ADMIN`.
//!
//! # Why the device is created here
//!
//! The datapath redirects a matching flow out of the stack onto `daer0`, and the listener
//! is reachable through `daer0peer`. Both are plain veth ends: the kernel program matches on
//! whichever interface the packet is about to leave through, so the pair is how "this flow
//! is ours" is expressed. Creating it lazily keeps `daer run` from needing an external
//! setup script, and reusing an existing pair keeps a restart from breaking live flows.
//!
//! # Why the policy routing is installed here too
//!
//! `daer0peer` delivers a redirected packet into the local stack with a **non-local**
//! destination address and `fwmark = TPROXY_MARK`. The kernel only hands such a packet to
//! the `bpf_sk_assign`-ed socket when a rule sends it to a `local` route, so the datapath is
//! incomplete without:
//!
//! ```text
//! ip rule  add fwmark 0x8000000/0x8000000 table 2023
//! ip route add local default dev lo table 2023
//! ```
//!
//! and the same pair for IPv6. This used to be documentation-only, which made an attached
//! datapath silently fail to deliver: the redirect happened, the packet reached
//! `daer0peer`, and the stack routed it onward as a *forwarded* packet instead of a local
//! one. [`RouteTable`] owns that state and removes it on drop.
//!
//! # Why the link layer type decides the program
//!
//! The datapath has two variants of every hook: an `_l2` one that starts parsing after the
//! Ethernet header, and an `_l3` one that starts at the IP header. Attaching both to one
//! interface is not "belt and braces": the wrong variant reads the first bytes of the IP
//! header as a MAC address (or vice versa) and misclassifies every packet. [`LinkKind`] is
//! read from `/sys/class/net/<if>/type` and picks exactly one.

use std::process::Command;
use std::sync::Arc;

use daer_ebpf::loader;

/// The device the datapath redirects through.
pub const DEVICE: &str = "daer0";
/// Its peer, which the transparent listener is reachable through.
pub const PEER: &str = "daer0peer";

/// The `fwmark` the datapath stamps on a redirected packet, and the routing table that
/// sends it to `local`. Both are part of the kernel contract: `tproxy.c` sets
/// `skb->mark = TPROXY_MARK` and documents this exact rule/route pair.
pub const TPROXY_ROUTE_TABLE: u32 = 2023;

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
/// Two families, each with one rule and one route. The guard is deliberately not
/// `Clone`: the rules are box-global state, and two owners would remove them while the
/// other was still redirecting.
///
/// # Why removal is best effort
///
/// `Drop` cannot report, and a failure to remove is not worth aborting a shutdown for: a
/// stale `local default` rule is harmless when no datapath is attached (nothing sets the
/// mark), and the next `daer run` re-installs it idempotently.
#[derive(Debug)]
pub struct RouteTable {
    /// The families actually installed, so a partial failure removes only what it added.
    installed: Vec<Family>,
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

/// The `fwmark` selector the datapath's redirected packets carry.
const MARK_SPEC: &str = "0x8000000/0x8000000";
/// The routing table number, as `ip` spells it.
const TABLE_SPEC: &str = "2023";

impl Family {
    /// The full argument vector for `ip <flag> rule add ...`.
    const fn rule(self) -> [&'static str; 7] {
        [
            self.flag(),
            "rule",
            "add",
            "fwmark",
            MARK_SPEC,
            "table",
            TABLE_SPEC,
        ]
    }

    /// The full argument vector for `ip <flag> route add local default dev lo table 2023`.
    ///
    /// `dev lo` is required: the kernel rejects a `local` route with no output device, and
    /// `lo` is correct because a `local` route terminates in the host stack.
    const fn route(self) -> [&'static str; 8] {
        [
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

    /// The deletion form of [`Self::rule`].
    const fn rule_del(self) -> [&'static str; 7] {
        [
            self.flag(),
            "rule",
            "del",
            "fwmark",
            MARK_SPEC,
            "table",
            TABLE_SPEC,
        ]
    }

    /// The deletion form of [`Self::route`].
    fn route_del(self) -> Vec<&'static str> {
        let mut route = self.route().to_vec();
        route[2] = "del";
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
    pub fn install() -> Result<Self, DatapathError> {
        let mut installed = Vec::with_capacity(2);
        for family in [Family::V4, Family::V6] {
            if let Err(error) = install_family(family) {
                // Roll back what was installed: a half-configured table would send one
                // family's redirected traffic into the forward path.
                let guard = Self { installed };
                drop(guard);
                return Err(error);
            }
            installed.push(family);
        }
        Ok(Self { installed })
    }

    fn remove(&self) -> Result<(), DatapathError> {
        for family in &self.installed {
            // A missing rule or route is the state being asked for, so a failure here is
            // not an error worth surfacing.
            let _ = run(&family.rule_del());
            let _ = run(&family.route_del());
        }
        Ok(())
    }
}

impl Drop for RouteTable {
    fn drop(&mut self) {
        if let Err(error) = self.remove() {
            tracing::debug!(%error, "could not remove the datapath policy routing");
        }
    }
}

/// Installs one family's rule and route, replacing whatever was there.
fn install_family(family: Family) -> Result<(), DatapathError> {
    // Delete first so both commands are idempotent: `ip rule add` tolerates a duplicate
    // (it creates a second identical rule), while `ip route add` fails with EEXIST.
    let _ = run(&family.rule_del());
    let _ = run(&family.route_del());
    run(&family.rule())?;
    run(&family.route_with_table())?;
    Ok(())
}

fn run(line: &[&str]) -> Result<String, DatapathError> {
    let Some((program, arguments)) = line.split_first() else {
        return Err(DatapathError::Missing(String::new()));
    };
    let output = Command::new(program)
        .args(arguments)
        .output()
        .map_err(|_| DatapathError::Missing((*program).to_owned()))?;
    if !output.status.success() {
        return Err(DatapathError::Command {
            command: line.join(" "),
            message: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// True when `interface` exists.
#[must_use]
pub fn interface_exists(interface: &str) -> bool {
    std::path::Path::new(&format!("/sys/class/net/{interface}")).exists()
}

/// Creates the veth pair if it is not already there, and leaves both ends up.
///
/// # Errors
///
/// Returns [`DatapathError`] naming the command that failed. `ip` is required; there is no
/// netlink fallback because a partial implementation of "create a veth pair" is a much
/// larger surface than one `ip` invocation.
pub fn ensure_device_pair() -> Result<(), DatapathError> {
    // Both ends are checked, not just one: a half-created pair (one end removed by hand, or
    // a `veth` whose peer was renamed) would make `ip link add` fail with "File exists" on
    // the end that is still there, and the daemon would refuse to start on a box that only
    // needs the missing half recreated.
    if !(interface_exists(PEER) && interface_exists(DEVICE)) {
        if interface_exists(PEER) {
            run(&["ip", "link", "del", PEER])?;
        } else if interface_exists(DEVICE) {
            run(&["ip", "link", "del", DEVICE])?;
        }
        run(&[
            "ip", "link", "add", PEER, "type", "veth", "peer", "name", DEVICE,
        ])?;
    }
    // `up` is idempotent, so both ends are set every time: a reboot or a previous run may
    // have left them down, and a down peer means the listener is unreachable.
    run(&["ip", "link", "set", DEVICE, "up"])?;
    run(&["ip", "link", "set", PEER, "up"])?;
    Ok(())
}

/// The peer's MAC, which the datapath writes into replies.
///
/// # Errors
///
/// Returns [`DatapathError`] when the peer does not exist or has no address.
pub fn peer_mac() -> Result<[u8; 6], DatapathError> {
    let path = format!("/sys/class/net/{PEER}/address");
    let text = std::fs::read_to_string(&path)
        .map_err(|error| DatapathError::Device(format!("cannot read {path}: {error}")))?;
    let mut mac = [0u8; 6];
    let parts: Vec<&str> = text.trim().split(':').collect();
    if parts.len() != 6 {
        return Err(DatapathError::Device(format!(
            "{path} is not a MAC address: {}",
            text.trim()
        )));
    }
    for (index, part) in parts.iter().enumerate() {
        mac[index] = u8::from_str_radix(part, 16).map_err(|_| {
            DatapathError::Device(format!("{path} is not a MAC address: {}", text.trim()))
        })?;
    }
    Ok(mac)
}

/// The ifindex of `interface`.
///
/// # Errors
///
/// Returns [`DatapathError`] when the interface does not exist.
pub fn ifindex(interface: &str) -> Result<u32, DatapathError> {
    std::fs::read_to_string(format!("/sys/class/net/{interface}/ifindex"))
        .map_err(|error| DatapathError::Device(format!("{interface}: {error}")))?
        .trim()
        .parse()
        .map_err(|_| DatapathError::Device(format!("{interface}: ifindex is not a number")))
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
) -> Result<Attached, DatapathError> {
    use aya::programs::tc::TcAttachType;
    use daer_ebpf::loader::attach_tc;
    use daer_ebpf::names::program;

    let mut ebpf = loader::load_path(object, param).map_err(DatapathError::Object)?;

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

    // The local device pair. `daer0peer` is where a redirected packet is assigned to the
    // transparent listener; `daer0` is the return path of the listener's replies.
    for (interface, direction, name) in [
        (DEVICE, TcAttachType::Ingress, program::DEVICE_INGRESS),
        (PEER, TcAttachType::Ingress, program::PEER_INGRESS),
    ] {
        attach_tc(&mut ebpf, name, interface, direction).map_err(DatapathError::Object)?;
    }

    // A redirected packet arrives on `daer0peer` with a non-local source *and*
    // destination, so reverse-path filtering would drop it before `bpf_sk_assign` could
    // matter. Both sysctls and the `fwmark` table are box-global state owned by the
    // returned guard.
    let sysctls = Sysctl::apply()?;
    let routes = RouteTable::install()?;

    republish_policy(&mut ebpf, param.datapath_generation, policy)?;
    // Without this the datapath decides "proxy" and then has nowhere to send the packet:
    // `assign_listener` looks the socket up in `listen_socket_map` and returns -1 when it is
    // empty, so the flow dies with no diagnostic on either side.
    daer_ebpf::publish_listeners(&mut ebpf, listeners)
        .map_err(|error| DatapathError::Device(format!("cannot publish the listeners: {error}")))?;
    Ok(Attached {
        ebpf: std::sync::Arc::new(crate::decide::HandoffObserver::new(ebpf)),
        _routes: routes,
        _sysctls: sysctls,
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
    /// The `fwmark` policy routing.
    _routes: RouteTable,
    /// The per-interface sysctls.
    _sysctls: Sysctl,
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
}

/// Resolves `(interface, link kind)` pairs, failing on the first unknown device.
fn kinds(interfaces: &[String]) -> Result<Vec<(&str, LinkKind)>, DatapathError> {
    interfaces
        .iter()
        .map(|interface| Ok((interface.as_str(), LinkKind::of(interface)?)))
        .collect()
}

/// The per-interface sysctls the datapath needs, restored on drop.
#[derive(Debug, Default)]
struct Sysctl {
    /// `(path, previous contents)` for every value written.
    written: Vec<(String, Option<String>)>,
}

impl Sysctl {
    /// Disables reverse-path filtering on the peer and enables forwarding.
    ///
    /// `net.ipv4.conf.daer0peer.rp_filter = 0` is what lets a packet with a non-local
    /// source address be delivered locally; without it the redirect is dropped by the
    /// stack with an `rp_filter` counter and no other trace.
    fn apply() -> Result<Self, DatapathError> {
        let mut guard = Self::default();
        for (path, value) in [
            ("net/ipv4/conf/daer0peer/rp_filter", "0"),
            ("net/ipv4/conf/daer0peer/forwarding", "1"),
            ("net/ipv4/conf/all/forwarding", "1"),
        ] {
            guard.write(path, value)?;
        }
        Ok(guard)
    }

    fn write(&mut self, path: &str, value: &str) -> Result<(), DatapathError> {
        let full = format!("/proc/sys/{path}");
        let previous = std::fs::read_to_string(&full).ok();
        if previous.as_deref().map(str::trim) == Some(value) {
            // Already correct: record nothing, so drop does not restore a value it did
            // not change.
            return Ok(());
        }
        std::fs::write(&full, value).map_err(|error| {
            DatapathError::Device(format!("cannot write {full} = {value}: {error}"))
        })?;
        self.written.push((full, previous));
        Ok(())
    }
}

impl Drop for Sysctl {
    fn drop(&mut self) {
        for (path, previous) in self.written.drain(..).rev() {
            if let Some(value) = previous {
                let _ = std::fs::write(&path, value.trim());
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
/// from `route()`, and every caller turns that into `TC_ACT_SHOT`.
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
        tracing::info!(
            slot = target.index(),
            entries = published.entries,
            trie_entries = policy.lpms.len(),
            "datapath policy published: the kernel decides every flow itself"
        );
    } else {
        let reasons: Vec<String> = policy.reasons.iter().map(ToString::to_string).collect();
        tracing::warn!(
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

    #[test]
    fn a_mac_address_is_read_or_the_error_names_the_path() {
        let result = peer_mac();
        match result {
            Ok(mac) => assert_eq!(mac.len(), 6),
            Err(error) => assert!(
                error.to_string().contains("daer0peer"),
                "the error must name the interface: {error}"
            ),
        }
    }
}
