// SPDX-License-Identifier: AGPL-3.0-only

//! The private network namespace that owns daer's ingress half.
//!
//! # Why a namespace, and why this one
//!
//! A host-generated packet still carries the originating socket's context when it is
//! redirected into a veth peer. `bpf_sk_assign` can return success on that packet while the
//! transport stack refuses to hand it to a listener in the *same* network namespace; the
//! drop is observable as `tcp_v4_rcv: NO_SOCKET`, even though the listener itself accepts a
//! direct connection. The reference implementation avoids this by putting its peer device,
//! its transparent listeners, and the local-delivery policy into a private namespace.
//!
//! `daer` does the same, explicitly:
//!
//! ```text
//!   host netns                              daer0ns
//!   ┌──────────────────────────┐            ┌──────────────────────────────┐
//!   │ wlan0 ── tc egress       │            │ daer0peer ── tc ingress      │
//!   │ daer0 (veth, no address) │◀── veth ──▶│ tproxy listeners             │
//!   │ policy + tc attach       │            │ table 2023, accept_local     │
//!   └──────────────────────────┘            └──────────────────────────────┘
//! ```
//!
//! The host end stays where the redirect source is; the peer, the listener sockets and the
//! local route live in the namespace. Crossing the namespace boundary is what makes the
//! redirected skb a normal ingress skb before `bpf_sk_assign` runs.
//!
//! # Ownership
//!
//! [`IngressNamespace`] is a guard: creating it creates the named namespace, and dropping
//! it deletes the namespace and with it the peer end of the veth pair. The host end
//! disappears with its peer, so a clean shutdown leaves no half-pair behind. A stale
//! namespace from a crashed run is deleted before a new one is created: daer runs one
//! ingress, and inheriting an older one would inherit its devices and policy state.
//!
//! # Privilege
//!
//! Creating a named netns, moving a link into it and `setns(2)` all require
//! `CAP_SYS_ADMIN`. The shipped unit carries it; `daer run --no-datapath` does not touch
//! this module.

use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;

use crate::datapath::{self, DEVICE, DatapathError, PEER};

/// The namespace name. This is part of the operator-visible topology (`ip netns list`).
pub const INGRESS_NETNS: &str = "daer0ns";

/// The peer's IPv4 address inside the ingress namespace.
///
/// It is not used by transparent sockets, which bind original destinations; it exists so
/// replies have an L3 source interface and a route toward the host end. A link-local
/// address would work too, but a fixed private address makes the route and neighbor state
/// easy to identify in a packet capture.
pub const PEER_IPV4: &str = "169.254.0.11";
/// The host-end next hop used by the ingress namespace's default route.
pub const HOST_IPV4: &str = "169.254.0.1";
/// The host-end next hop used by the ingress namespace's IPv6 default route.
pub const HOST_IPV6: &str = "fe80::ecee:eeff:feee:eeee";
/// The peer's IPv6 link-local address, which gives IPv6 replies a source interface.
pub const PEER_IPV6: &str = "fe80::ecee:eeff:feee:eeef";

/// The host path `ip netns` mounts the namespace on.
fn namespace_path(name: &str) -> PathBuf {
    Path::new("/run/netns").join(name)
}

fn format_mac(mac: [u8; 6]) -> String {
    mac.iter()
        .map(|octet| format!("{octet:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// A named network namespace owned by this daemon.
#[derive(Debug)]
pub struct IngressNamespace {
    name: String,
    path: PathBuf,
}

impl IngressNamespace {
    /// Creates a fresh namespace and brings its loopback up.
    ///
    /// A namespace with the same name from an earlier crash is deleted first. That is
    /// deliberate: the devices and policy inside it belong to an ingress that no longer
    /// exists, and adopting them would make the new run inherit stale state.
    ///
    /// # Errors
    ///
    /// Returns [`DatapathError::Device`] with the failing `ip` command when the namespace
    /// cannot be created, or when its loopback cannot be brought up.
    pub fn create() -> Result<Self, DatapathError> {
        let stale = namespace_path(INGRESS_NETNS);
        if stale.exists() {
            let output = Command::new("ip")
                .args(["netns", "del", INGRESS_NETNS])
                .output()
                .map_err(|error| {
                    DatapathError::Device(format!(
                        "cannot run `ip netns del {INGRESS_NETNS}` for the stale ingress: {error}"
                    ))
                })?;
            if !output.status.success() {
                return Err(DatapathError::Device(format!(
                    "cannot remove the stale ingress namespace {INGRESS_NETNS}: {}; \
                     unmount {} or reboot, then start daer again",
                    String::from_utf8_lossy(&output.stderr).trim(),
                    stale.display()
                )));
            }
        }
        let output = Command::new("ip")
            .args(["netns", "add", INGRESS_NETNS])
            .output()
            .map_err(|error| {
                DatapathError::Device(format!(
                    "cannot run `ip netns add {INGRESS_NETNS}`: {error}"
                ))
            })?;
        if !output.status.success() {
            return Err(DatapathError::Device(format!(
                "`ip netns add {INGRESS_NETNS}` failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        let namespace = Self {
            name: INGRESS_NETNS.to_owned(),
            path: namespace_path(INGRESS_NETNS),
        };
        namespace.link_up("lo")?;
        Ok(namespace)
    }

    /// The namespace name, for commands and logs.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Moves a host link into this namespace.
    ///
    /// # Errors
    ///
    /// Returns [`DatapathError::Device`] when `ip link set` fails. On failure the caller's
    /// guard still owns and removes the namespace.
    pub fn move_link(&self, link: &str) -> Result<(), DatapathError> {
        let output = Command::new("ip")
            .args(["link", "set", link, "netns", &self.name])
            .output()
            .map_err(|error| {
                DatapathError::Device(format!(
                    "cannot run `ip link set {link} netns {}`: {error}",
                    self.name
                ))
            })?;
        if !output.status.success() {
            return Err(DatapathError::Device(format!(
                "`ip link set {link} netns {}` failed: {}",
                self.name,
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        Ok(())
    }

    /// Brings one link in this namespace up.
    ///
    /// # Errors
    ///
    /// Returns [`DatapathError::Device`] with the failing `ip` command.
    pub fn link_up(&self, link: &str) -> Result<(), DatapathError> {
        let output = self
            .command("ip", &["link", "set", link, "up"])
            .map_err(|error| DatapathError::Device(format!("network namespace: {error}")))?;
        if !output.status.success() {
            return Err(DatapathError::Device(format!(
                "`ip -n {} link set {link} up` failed: {}",
                self.name,
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        Ok(())
    }

    /// Runs a command inside this namespace and returns its output.
    ///
    /// # Errors
    ///
    /// Returns the `setns(2)` or spawn error. A command that ran and failed is returned in
    /// the [`Output`] so the caller can attach the command line to the error.
    pub fn command(&self, program: &str, args: &[&str]) -> io::Result<Output> {
        self.with(move || {
            Command::new(program)
                .args(args)
                .output()
                .map_err(|error| io::Error::other(format!("cannot run {program}: {error}")))
        })?
    }

    /// Runs an `ip` invocation in this namespace and requires success.
    fn ip(&self, args: &[&str]) -> Result<(), DatapathError> {
        let output = self
            .command("ip", args)
            .map_err(|error| DatapathError::Device(format!("network namespace: {error}")))?;
        if output.status.success() {
            return Ok(());
        }
        Err(DatapathError::Device(format!(
            "`ip {}` failed in {}: {}",
            args.join(" "),
            self.name,
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }

    /// Gives the peer an address and a default route back through the host end.
    ///
    /// The listener replies from the original destination address, which is not an address
    /// assigned in this namespace. A transparent socket may still bind it, but the packet
    /// needs an output route and a next-hop link address. The host end is addressed with a
    /// link-local IPv4 next hop, its MAC is installed as a permanent neighbor, and the
    /// default route goes through it; the host then forwards the reply to the client.
    ///
    /// # Errors
    ///
    /// IPv4 is required. IPv6 is configured best-effort: a host with IPv6 disabled must
    /// still proxy IPv4, so its failure is logged rather than fatal.
    pub fn configure_peer(&self, host_mac: [u8; 6]) -> Result<(), DatapathError> {
        self.ip(&["addr", "add", &format!("{PEER_IPV4}/32"), "dev", PEER])?;
        self.ip(&[
            "route",
            "add",
            &format!("{HOST_IPV4}/32"),
            "dev",
            PEER,
            "scope",
            "link",
        ])?;
        self.ip(&["route", "add", "default", "via", HOST_IPV4, "dev", PEER])?;
        let mac = format_mac(host_mac);
        self.ip(&[
            "neigh",
            "replace",
            HOST_IPV4,
            "lladdr",
            &mac,
            "dev",
            PEER,
            "nud",
            "permanent",
        ])?;

        // IPv6 follows the same shape. The host end's link-local address is added by
        // `PreparedIngress::prepare`; here the namespace needs a default route and a
        // permanent neighbor for it. A kernel built without IPv6 rejects these commands,
        // and that must not prevent IPv4 proxying.
        let _ = self.write_sysctl("ipv6/conf/daer0peer/disable_ipv6", "0");
        if let Err(error) = self.ip(&[
            "-6",
            "addr",
            "add",
            &format!("{PEER_IPV6}/64"),
            "dev",
            PEER,
            "nodad",
        ]) {
            tracing::warn!(%error, "IPv6 ingress address is unavailable");
        }
        if let Err(error) = self.ip(&["route", "add", "default", "via", HOST_IPV6, "dev", PEER]) {
            tracing::warn!(%error, "IPv6 ingress route is unavailable");
        }
        if let Err(error) = self.ip(&[
            "neigh",
            "replace",
            HOST_IPV6,
            "lladdr",
            &mac,
            "dev",
            PEER,
            "nud",
            "permanent",
        ]) {
            tracing::warn!(%error, "IPv6 ingress neighbor is unavailable");
        }
        Ok(())
    }

    /// Writes a sysctl in this namespace, returning its previous value.
    ///
    /// The caller restores the value on drop. `/proc/sys/net` is namespace-scoped, so the
    /// write has to happen from a thread that has entered the namespace.
    ///
    /// # Errors
    ///
    /// Returns the `setns(2)` error, or the read/write error from the sysctl file.
    pub fn write_sysctl(&self, key: &str, value: &str) -> io::Result<Option<String>> {
        let key = key.to_owned();
        let value = value.to_owned();
        self.with(move || -> io::Result<Option<String>> {
            let full = format!("/proc/sys/net/{key}");
            let previous = std::fs::read_to_string(&full).ok();
            std::fs::write(&full, &value)?;
            Ok(previous)
        })?
    }

    /// Runs `f` on a scoped thread that has entered this namespace.
    ///
    /// # Errors
    ///
    /// Returns the `setns(2)` error when the namespace cannot be entered, or an error from
    /// the namespace mount. A panic in `f` is reported as an [`io::Error`] rather than
    /// propagated, because callers are datapath setup paths with their own error type.
    pub fn with<T, F>(&self, f: F) -> io::Result<T>
    where
        T: Send,
        F: FnOnce() -> T + Send,
    {
        let namespace = File::open(&self.path)?;
        let fd = namespace.as_raw_fd();
        std::thread::scope(|scope| {
            scope
                .spawn(move || {
                    // SAFETY: `fd` refers to the live `/run/netns/<name>` mount for the
                    // duration of this thread; `CLONE_NEWNET` asks the kernel to switch this
                    // thread only, which is why the work runs on a scoped thread rather than
                    // the daemon's main thread.
                    let result = unsafe { libc::setns(fd, libc::CLONE_NEWNET) };
                    if result != 0 {
                        return Err(io::Error::last_os_error());
                    }
                    Ok(f())
                })
                .join()
                .map_err(|_| io::Error::other("network-namespace thread panicked"))?
        })
    }
}

/// Deletes the named ingress namespace, including the fallback for a missing `ip`.
///
/// `ip netns del` is the normal path: it unmounts `/run/netns/daer0ns` and unlinks the mount
/// point. If `ip` is unavailable, the namespace is still a bind mount; detaching it and
/// unlinking the path is the same operation the tool performs. The function is deliberately
/// idempotent so both the RAII guard and the post-crash cleanup can call it.
pub(crate) fn remove_ingress_namespace() {
    let path = namespace_path(INGRESS_NETNS);
    let output = Command::new("ip")
        .args(["netns", "del", INGRESS_NETNS])
        .output();
    if output.is_ok_and(|output| output.status.success()) && !path.exists() {
        return;
    }

    // The namespace is mounted by `ip netns add`; a plain `remove_file` would fail with
    // EBUSY. `MNT_DETACH` is what `ip netns del` uses, and it releases the mount even when a
    // process still holds a reference to the namespace.
    if let Ok(path_c) = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()) {
        // SAFETY: `path_c` is a valid NUL-terminated path for the duration of the call.
        unsafe {
            libc::umount2(path_c.as_ptr(), libc::MNT_DETACH);
        }
    }
    let _ = std::fs::remove_file(&path);
    if path.exists() {
        tracing::warn!(
            path = %path.display(),
            "could not remove the ingress namespace mount; a stale mount may remain"
        );
    }
}

impl Drop for IngressNamespace {
    fn drop(&mut self) {
        remove_ingress_namespace();
    }
}

/// Removes the host-visible pair if preparation fails before the namespace owns the peer.
///
/// `reset_device_pair` creates both ends before the namespace exists. Every later step can
/// fail (`ip netns add`, moving the peer, configuring it), and without this guard a failed
/// start leaves `daer0`/`daer0peer` in the host namespace even though no daemon is running.
#[derive(Debug)]
struct DevicePairGuard {
    armed: bool,
}

impl DevicePairGuard {
    const fn armed() -> Self {
        Self { armed: true }
    }

    fn disarm(mut self) {
        self.armed = false;
    }
}

impl Drop for DevicePairGuard {
    fn drop(&mut self) {
        if self.armed {
            datapath::remove_device_pair();
        }
    }
}

/// Everything the host needs after the private ingress has been prepared.
#[derive(Debug)]
pub struct PreparedIngress {
    /// The namespace guard. Hold it for the daemon's lifetime; dropping it tears down the
    /// peer device and the namespace.
    pub namespace: Arc<IngressNamespace>,
    /// The peer MAC captured before the peer was moved out of the host namespace.
    pub peer_mac: [u8; 6],
    /// The host-side `daer0` ifindex, the datapath's redirect target.
    pub device_ifindex: u32,
}

impl PreparedIngress {
    /// Creates the veth pair, captures its host facts, creates the namespace and moves the
    /// peer into it.
    ///
    /// # Errors
    ///
    /// Returns [`DatapathError`] naming the failing step. A partially prepared namespace is
    /// removed by its guard on drop; the host end is removed with its peer.
    pub fn prepare() -> Result<Self, DatapathError> {
        // Remove host policy state from a pre-namespace daer run before any listener binds.
        // The current table is installed inside the namespace, so leaving a host-level
        // mark rule in place would route the listener's own marked replies to `lo`.
        datapath::clear_host_policy_routing();
        datapath::reset_device_pair()?;
        // From here until the namespace owns the peer, a failure must not leave the pair
        // behind. Disarmed only after the peer is inside the namespace, where deleting the
        // namespace removes both ends.
        let pair = DevicePairGuard::armed();
        let peer_mac = datapath::peer_mac()?;
        let device_mac = datapath::link_mac(DEVICE)?;
        let device_ifindex = datapath::ifindex(DEVICE)?;

        let namespace = IngressNamespace::create()?;
        namespace.move_link(PEER)?;
        namespace.link_up(PEER)?;
        datapath::link_up(DEVICE)?;

        if let Err(error) = datapath::add_ipv6_link_local(DEVICE) {
            tracing::warn!(%error, "IPv6 host-side next hop is unavailable");
        }
        namespace.configure_peer(device_mac)?;
        pair.disarm();

        Ok(Self {
            namespace: Arc::new(namespace),
            peer_mac,
            device_ifindex,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_namespace_path_is_the_iproute2_mount_point() {
        assert_eq!(
            namespace_path(INGRESS_NETNS),
            Path::new("/run/netns/daer0ns")
        );
    }

    #[test]
    fn a_neighbor_mac_is_formatted_for_ip_neigh() {
        assert_eq!(
            format_mac([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]),
            "02:00:00:00:00:01"
        );
    }
}
