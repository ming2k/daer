// SPDX-License-Identifier: AGPL-3.0-only

//! The unprivileged preflight: everything the daemon can decide without touching the box.
//!
//! ADR-0029 splits verification at the privilege boundary. This module is the unprivileged
//! half: it builds the generation the daemon *would* serve, validates the compiled object
//! against the ABI, computes the runtime parameter that *would* be published, and reports
//! whether the capabilities the next phase needs are present.
//!
//! # What it must not do
//!
//! Nothing here may bind a port, create a device, write a sysctl, install a route, or call
//! `bpf()`. That is not a style rule: `--dry-run` returns after printing this report, so any
//! mutation reachable from here would happen on a run that promised to change nothing. The
//! separation is enforced by the type system rather than by ordering discipline — [`Plan`] is
//! a plain value, and the mutating calls live behind `Daemon::bind` and
//! `datapath::attach`, which this module never names.

use std::path::{Path, PathBuf};

use daer_control::RouterOptions;
use daer_control::generation::{Generation, GenerationId};

/// What the daemon would do, computed without doing any of it.
#[derive(Debug)]
pub struct Plan {
    /// The generation that would serve, fully built.
    pub generation: Generation,
    /// The interfaces the attachment would use.
    pub lan: Vec<String>,
    pub wan: Vec<String>,
    /// The socket mark the dialers and the datapath would both carry.
    pub socket_mark: Option<u32>,
    /// The datapath object, once validated.
    pub object: Option<ObjectReport>,
    /// Why the object could not be validated, if it could not.
    pub object_error: Option<String>,
    /// The capabilities the next phase needs.
    pub capabilities: Capabilities,
}

/// What the object looks like, as far as `aya` is concerned.
///
/// A thin wrapper rather than a copy: [`daer_ebpf::ObjectReport`] is produced by the same
/// code path the loader uses, and re-shaping it here would be a second place for the counts
/// to disagree. The path is carried because the report is printed.
#[derive(Debug, Clone)]
pub struct ObjectReport {
    pub path: PathBuf,
    pub detail: daer_ebpf::ObjectReport,
}

/// Which capabilities the privileged phase would need, and whether they are present.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities {
    pub bpf: bool,
    pub net_admin: bool,
    /// `CAP_PERFMON` enables the verifier's `allow_ptr_leaks`, which the
    /// variable-offset packet parser needs (IPv4 IHL, IPv6 extension headers).
    pub perfmon: bool,
    /// `CAP_SYS_ADMIN` creates the private ingress namespace and enters it to bind the
    /// transparent listeners and attach the peer program.
    pub sys_admin: bool,
}

impl Capabilities {
    /// Reads `CapEff` from `/proc/self/status`.
    ///
    /// A read-only probe: it does not attempt a `bpf()` call to find out, because a refused
    /// syscall cannot distinguish "no capability" from "`unprivileged_bpf_disabled`" and the
    /// two need different fixes. Bit 39 is `CAP_BPF`, bit 38 is
    /// `CAP_PERFMON`, bit 21 is `CAP_SYS_ADMIN`, bit 12 is `CAP_NET_ADMIN`
    /// (`include/uapi/linux/capability.h`).
    #[must_use]
    pub fn detect() -> Self {
        let effective = std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|status| {
                status
                    .lines()
                    .find(|line| line.starts_with("CapEff:"))
                    .and_then(|line| line["CapEff:".len()..].trim().parse::<u64>().ok())
            })
            .unwrap_or(0);
        Self {
            bpf: effective & (1 << 39) != 0,
            net_admin: effective & (1 << 12) != 0,
            perfmon: effective & (1 << 38) != 0,
            sys_admin: effective & (1 << 21) != 0,
        }
    }

    /// True when the kernel datapath can be loaded and attached here.
    #[must_use]
    pub const fn can_attach_datapath(self) -> bool {
        self.bpf && self.net_admin && self.perfmon && self.sys_admin
    }
}

/// Builds the plan: the generation, the parameter, and the object report.
///
/// `object` is the path `run` would resolve; `None` means the caller does not want the object
/// checked (there is none, or `--no-datapath` was passed).
///
/// # Errors
///
/// Returns the routing error when the configuration does not compile. A preflight that
/// cannot build a generation has nothing to report: the configuration is the input to
/// everything else.
pub fn plan(
    config: &daer_config::Config,
    options: &RouterOptions,
    lan: &[String],
    wan: &[String],
    object: Option<&Path>,
) -> Result<Plan, daer_control::ReloadError> {
    // Built through `Generation::build` rather than `Generations::new`: the latter requires a
    // `Daemon`, and a `Daemon` binds a port. A preflight must not.
    let generation =
        Generation::build(GenerationId::new(1), config, options).map_err(|source| {
            daer_control::ReloadError {
                source,
                serving: None,
            }
        })?;

    let socket_mark = Some(
        config
            .global
            .so_mark
            .unwrap_or(crate::run::DEFAULT_SOCKET_MARK),
    );
    let (object, object_error) = match object {
        Some(path) => match validate_object(path) {
            Ok(report) => (Some(report), None),
            Err(error) => (None, Some(error)),
        },
        None => (None, None),
    };

    Ok(Plan {
        lan: lan.to_vec(),
        wan: wan.to_vec(),
        socket_mark,
        object,
        object_error,
        generation,
        capabilities: Capabilities::detect(),
    })
}

/// Validates a compiled object against the ABI, without loading it.
///
/// The checks are the ones that otherwise fail inside the kernel, where the message names a
/// map or an instruction offset rather than the build step that produced it.
///
/// # Errors
///
/// Returns a message naming the first invariant the object violates.
pub fn validate_object(path: &Path) -> Result<ObjectReport, String> {
    if !path.is_file() {
        return Err(format!(
            "{} does not exist; build it with `cargo xtask ebpf`",
            path.display()
        ));
    }
    let detail = daer_ebpf::inspect_object(path)?;
    Ok(ObjectReport {
        path: path.to_path_buf(),
        detail,
    })
}

/// The runtime parameter that would be published, for the report.
///
/// The real one is built in `attach` after the device pair exists, because it carries the
/// peer MAC and the `daer0` ifindex. This is the same struct with the values that are known
/// before either exists, so the report can show the parts an operator would get wrong.
#[must_use]
pub fn planned_param(socket_mark: Option<u32>) -> daer_ebpf::RuntimeParam {
    daer_ebpf::RuntimeParam {
        control_plane_pid: std::process::id(),
        device_ifindex: 0,
        netns_id: 0,
        peer_mac: [0; 6],
        padding_after_mac: [0, 0],
        use_redirect_peer: false,
        has_bpf_get_current_task: true,
        datapath_generation: 1,
        socket_mark: socket_mark.unwrap_or(0),
    }
}

/// Whether the device pair already exists, reported as a fact.
///
/// This is a read-only `ip link show`, not a mutation, so a preflight may answer it. It does
/// not create anything: that is `PreparedIngress::prepare`, which only `run` calls.
#[must_use]
pub fn device_pair_present() -> (bool, bool) {
    (
        daer_control::datapath::interface_exists(daer_control::DEVICE),
        daer_control::datapath::interface_exists(daer_control::PEER),
    )
}

/// Names why the privileged phase cannot run here, if it cannot.
#[must_use]
pub fn privileged_blocker(capabilities: Capabilities) -> Option<String> {
    if capabilities.can_attach_datapath() {
        return None;
    }
    let mut missing = Vec::new();
    if !capabilities.bpf {
        missing.push("CAP_BPF");
    }
    if !capabilities.net_admin {
        missing.push("CAP_NET_ADMIN");
    }
    if !capabilities.perfmon {
        missing.push("CAP_PERFMON");
    }
    if !capabilities.sys_admin {
        missing.push("CAP_SYS_ADMIN");
    }
    Some(format!(
        "the kernel datapath cannot be attached here: {} not in the effective capability set \
         (this is the privilege boundary, not a defect — run `sudo ./scripts/verify/kernel-check.sh` \
         or `sudo daer run` on a machine with them)",
        missing.join(" and ")
    ))
}

/// The reason the datapath would defer every flow to userspace, if it would.
///
/// `None` means the kernel reproduces userspace's verdict exactly (`[INV-KERNEL-01]`).
#[must_use]
pub fn deferral_reason(plan: &Plan) -> Option<String> {
    let policy = plan.generation.router().kernel_policy();
    if policy.equivalent {
        return None;
    }
    let reasons: Vec<String> = policy
        .reasons
        .iter()
        .map(|reason| format!("{reason:?}"))
        .collect();
    Some(if reasons.is_empty() {
        "the kernel policy is not provably equivalent, and no reason was recorded".to_owned()
    } else {
        reasons.join(", ")
    })
}
