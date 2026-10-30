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

use std::process::Command;

use daer_ebpf::loader;

/// The device the datapath redirects through.
pub const DEVICE: &str = "daer0";
/// Its peer, which the transparent listener is reachable through.
pub const PEER: &str = "daer0peer";

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
/// programs, and the box silently stops proxying.
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
) -> Result<aya::Ebpf, DatapathError> {
    use aya::programs::tc::TcAttachType;
    use daer_ebpf::loader::attach_tc;
    use daer_ebpf::names::program;

    let mut ebpf = loader::load_path(object, param).map_err(DatapathError::Object)?;

    // LAN side: traffic *from* the local network being proxied. Both the L2 and the L3
    // program are attached because the datapath picks between them per packet; attaching
    // one would leave the other half of the traffic on the direct path.
    for interface in lan {
        let _ = attach_tc(
            &mut ebpf,
            program::LAN_INGRESS_L2,
            interface,
            TcAttachType::Ingress,
        )
        .map_err(DatapathError::Object)?;
        let _ = attach_tc(
            &mut ebpf,
            program::LAN_INGRESS_L3,
            interface,
            TcAttachType::Ingress,
        )
        .map_err(DatapathError::Object)?;
        let _ = attach_tc(
            &mut ebpf,
            program::LAN_EGRESS_L2,
            interface,
            TcAttachType::Egress,
        )
        .map_err(DatapathError::Object)?;
        let _ = attach_tc(
            &mut ebpf,
            program::LAN_EGRESS_L3,
            interface,
            TcAttachType::Egress,
        )
        .map_err(DatapathError::Object)?;
    }

    // WAN side: the box's own traffic, and the return path of a proxied flow.
    for interface in wan {
        let _ = attach_tc(
            &mut ebpf,
            program::WAN_INGRESS_L2,
            interface,
            TcAttachType::Ingress,
        )
        .map_err(DatapathError::Object)?;
        let _ = attach_tc(
            &mut ebpf,
            program::WAN_INGRESS_L3,
            interface,
            TcAttachType::Ingress,
        )
        .map_err(DatapathError::Object)?;
        let _ = attach_tc(
            &mut ebpf,
            program::WAN_EGRESS_L2,
            interface,
            TcAttachType::Egress,
        )
        .map_err(DatapathError::Object)?;
        let _ = attach_tc(
            &mut ebpf,
            program::WAN_EGRESS_L3,
            interface,
            TcAttachType::Egress,
        )
        .map_err(DatapathError::Object)?;
        // The pair programs handle traffic between our two devices: this is what makes a
        // redirected flow reach the listener instead of looping.
        let _ = attach_tc(
            &mut ebpf,
            program::WAN_LAN_INGRESS_L2,
            interface,
            TcAttachType::Ingress,
        )
        .map_err(DatapathError::Object)?;
        let _ = attach_tc(
            &mut ebpf,
            program::WAN_LAN_INGRESS_L3,
            interface,
            TcAttachType::Ingress,
        )
        .map_err(DatapathError::Object)?;
    }

    // The local device pair.
    for (interface, direction, name) in [
        (DEVICE, TcAttachType::Ingress, program::DEVICE_INGRESS),
        (PEER, TcAttachType::Ingress, program::PEER_INGRESS),
    ] {
        let _ = attach_tc(&mut ebpf, name, interface, direction).map_err(DatapathError::Object)?;
    }

    republish_policy(&mut ebpf, param.datapath_generation, policy)?;
    // Without this the datapath decides "proxy" and then has nowhere to send the packet:
    // `assign_listener` looks the socket up in `listen_socket_map` and returns -1 when it is
    // empty, so the flow dies with no diagnostic on either side.
    daer_ebpf::publish_listeners(&mut ebpf, listeners.tcp4, listeners.tcp6)
        .map_err(|error| DatapathError::Device(format!("cannot publish the listeners: {error}")))?;
    Ok(ebpf)
}

/// The listener file descriptors the datapath hands redirected flows to.
#[derive(Debug, Clone, Copy)]
pub struct Listeners {
    /// IPv4 listener, key `0` in the datapath's `SOCKMAP`.
    pub tcp4: std::os::fd::RawFd,
    /// IPv6 listener, key `2`.
    pub tcp6: std::os::fd::RawFd,
}

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
