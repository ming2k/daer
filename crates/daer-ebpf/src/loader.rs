// SPDX-License-Identifier: AGPL-3.0-only

//! Loading the datapath object and wiring its runtime parameters.
//!
//! The object is compiled from `control/kern/tproxy.c` by
//! `cargo xtask ebpf`; this module does not compile it, so building daer
//! never needs a clang toolchain or the kernel headers.
//!
//! Attachment needs `CAP_BPF`/`CAP_NET_ADMIN`/`CAP_PERFMON`, so the tests that attach are
//! `#[ignore]`d. The name/ABI checks in `tests/object.rs` run unprivileged.

use std::fmt;

use aya::Ebpf;
use aya::EbpfError;
use aya::EbpfLoader;
use aya::maps::Array;
use aya::maps::MapError;
use aya::programs::LinkOrder;
use aya::programs::ProgramError;
use aya::programs::tc::NlOptions;
use aya::programs::tc::SchedClassifier;
use aya::programs::tc::SchedClassifierLinkId;
use aya::programs::tc::TcAttachOptions;
use aya::programs::tc::TcAttachType;
use aya::programs::tc::TcError;
use aya::programs::tc::qdisc_add_clsact;
use aya::util::KernelVersion;

use crate::abi::RuntimeParam;
use crate::names;

#[derive(Debug)]
pub enum LoadError {
    /// The object file could not be read.
    Io(std::io::Error),
    /// The kernel verifier or the ELF loader rejected the object.
    Load(EbpfError),
    /// A program could not be loaded or attached.
    Program(ProgramError),
    /// A map operation failed.
    Map(MapError),
    /// The clsact qdisc could not be installed or a filter could not attach.
    Tc(TcError),
    /// The object is missing a map, program or global this crate references.
    NotFound(String),
    /// The requested attachment mode is not available on this kernel.
    Unsupported(String),
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "failed to read eBPF object: {err}"),
            Self::Load(err) => write!(f, "failed to load eBPF object: {err}"),
            Self::Program(err) => write!(f, "eBPF program error: {err}"),
            Self::Map(err) => write!(f, "eBPF map error: {err}"),
            Self::Tc(err) => write!(f, "tc error: {err}"),
            Self::NotFound(name) => write!(f, "eBPF object is missing \"{name}\""),
            Self::Unsupported(message) => write!(f, "unsupported attachment: {message}"),
        }
    }
}

impl std::error::Error for LoadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::Load(err) => Some(err),
            Self::Program(err) => Some(err),
            Self::Map(err) => Some(err),
            Self::Tc(err) => Some(err),
            Self::NotFound(_) => None,
            Self::Unsupported(_) => None,
        }
    }
}

impl From<EbpfError> for LoadError {
    fn from(err: EbpfError) -> Self {
        Self::Load(err)
    }
}

impl From<std::io::Error> for LoadError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

/// Loads the datapath object with `PARAM` already rewritten.
///
/// `PARAM` is a `const volatile` global in `.rodata`; the kernel copies it at
/// load time, so it must be set through the loader and cannot be patched later.
///
/// The bytes are handed to `aya` unchanged (ADR-0020). Section names, map names and
/// program names are daer's own and are spelled the way `aya` parses them, so there
/// is nothing to normalize here: an object that needs repair is a build failure that
/// `tests/object.rs` catches, not something to guess at during startup.
pub fn load(object: &[u8], param: &RuntimeParam) -> Result<Ebpf, LoadError> {
    let mut loader = EbpfLoader::new();
    loader.override_global(names::PARAM_GLOBAL, param.as_bytes(), true);
    Ok(loader.load(object)?)
}

/// Loads the datapath object from disk.
pub fn load_path(
    path: impl AsRef<std::path::Path>,
    param: &RuntimeParam,
) -> Result<Ebpf, LoadError> {
    let bytes = std::fs::read(path)?;
    load(&bytes, param)
}

/// What an object looks like to `aya`, without loading it into the kernel.
///
/// This is the unprivileged half of ADR-0029: it answers "will `BPF_PROG_LOAD` accept the
/// names and the BTF metadata" by running the same parse and the same call relocation that
/// the loader runs, and then asserting the invariant the kernel enforces. It needs no
/// capability, so `daer check` can gate a packaged artifact with it.
#[derive(Debug, Clone)]
pub struct ObjectReport {
    /// Maps the object declares, as `aya` counts them (`.maps` plus the data sections).
    pub maps: usize,
    /// Programs the object declares.
    pub programs: usize,
}

impl ObjectReport {
    /// A one-line description for a preflight report.
    #[must_use]
    pub fn describe(&self) -> String {
        format!("{} maps, {} programs", self.maps, self.programs)
    }
}

/// Inspects a compiled object against this crate's ABI.
///
/// The three checks are exactly the ones that otherwise fail inside the kernel, where the
/// message names a map or an instruction offset instead of the build step that produced it:
///
/// 1. every name in [`names::map::ALL`] and [`names::program::ALL`] exists;
/// 2. every program's section is one `aya` parses — a `tc/<name>` section is rejected by
///    `ProgramSection::from_str`, and is a build error rather than a load-time surprise;
/// 3. after reproducing `aya`'s call relocation, every program's first `func_info` record is
///    at instruction 0. This is the invariant that took `daer.service` down in production
///    with `nonzero insn_off 3 for the first func info record`.
///
/// # Errors
///
/// Returns a message naming the first invariant the object violates, or the parse error.
pub fn inspect_object(path: &std::path::Path) -> Result<ObjectReport, String> {
    let bytes = std::fs::read(path).map_err(|error| format!("cannot read the object: {error}"))?;
    inspect_bytes(&bytes)
}

/// [`inspect_object`] over an in-memory object.
///
/// # Errors
///
/// Returns a message naming the first invariant the object violates.
pub fn inspect_bytes(bytes: &[u8]) -> Result<ObjectReport, String> {
    use aya_obj::Object;

    let mut object =
        Object::parse(bytes).map_err(|error| format!("not a loadable eBPF ELF: {error}"))?;

    let maps = object.maps.len();
    let programs = object.programs.len();

    for name in names::map::ALL {
        if !object.maps.contains_key(name) {
            return Err(format!(
                "the object is missing map {name}; it and ebpf/abi.toml disagree — \
                 run `cargo xtask abi` and rebuild"
            ));
        }
    }
    for name in names::program::ALL {
        if !object.programs.contains_key(name) {
            return Err(format!(
                "the object is missing program {name}; it and ebpf/abi.toml disagree — \
                 run `cargo xtask abi` and rebuild"
            ));
        }
    }

    // The relocation aya performs before BPF_PROG_LOAD: every section that holds a function
    // is a "text" section, and linking a callee appends its func_info rebased to the callee's
    // instruction offset. If the program's own record is absent, the first surviving one sits
    // at that offset and the kernel refuses the load.
    let text_sections: std::collections::HashSet<usize> = object
        .functions
        .keys()
        .map(|(section_index, _)| *section_index)
        .collect();
    object
        .relocate_calls(&text_sections)
        .map_err(|error| format!("call relocation failed: {error}"))?;

    for name in names::program::ALL {
        let program = &object.programs[name];
        let function = &object.functions[&program.function_key()];
        let Some(first) = function.func_info.func_info.first() else {
            return Err(format!(
                "program {name} has no BTF func_info, so the kernel will reject the load with \
                 \"nonzero insn_off ... for the first func info record\""
            ));
        };
        if first.insn_off != 0 {
            return Err(format!(
                "program {name} has its first func_info at instruction {} instead of 0; the \
                 kernel rejects this with EINVAL",
                first.insn_off
            ));
        }
    }

    Ok(ObjectReport { maps, programs })
}

/// Updates the runtime ifindex map.
///
/// It exists so a recreated local device gets a new ifindex without reloading the
/// programs; the parameter global is only the fallback.
pub fn set_device_ifindex(ebpf: &mut Ebpf, ifindex: u32) -> Result<(), LoadError> {
    let map = ebpf
        .map_mut(names::map::DEVICE_IFINDEX)
        .ok_or_else(|| LoadError::NotFound(names::map::DEVICE_IFINDEX.to_owned()))?;
    let mut array: Array<_, u32> = Array::try_from(map).map_err(LoadError::Map)?;
    array.set(0, ifindex, 0).map_err(LoadError::Map)?;
    Ok(())
}

/// Ensures the `clsact` qdisc exists on `interface`.
///
/// Returns `true` when **this call created it**, so the owner can remove exactly the qdisc it
/// added when the datapath detaches. A pre-existing qdisc belongs to the operator (or another
/// program) and must survive a daer stop; deleting it would remove that program's filters too.
///
/// # Errors
///
/// Returns [`LoadError::Tc`] for a failure other than the qdisc already existing.
pub fn ensure_clsact(interface: &str) -> Result<bool, LoadError> {
    match qdisc_add_clsact(interface) {
        Ok(()) => Ok(true),
        // `ip link` and `tc` report an existing qdisc as EEXIST. Aya exposes the raw errno
        // on its netlink error; matching the error kind alone is not enough because the
        // netlink wrapper does not preserve a synthetic `AlreadyExists`.
        Err(TcError::NetlinkError(error)) if error.raw_os_error() == Some(libc::EEXIST) => {
            Ok(false)
        }
        Err(TcError::AlreadyAttached) => Ok(false),
        Err(error) => Err(LoadError::Tc(error)),
    }
}

/// How a `SchedClassifier` is attached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcMode {
    /// Classic `cls_bpf` through netlink. The filter outlives the process and is removed by
    /// the crash journal or the next start.
    Netlink,
    /// TCX through `bpf_link`. The link is fd-owned, so closing it detaches the program,
    /// including when the process is killed.
    Tcx,
}

/// Whether the running kernel has the TCX link type.
fn tcx_supported() -> Result<bool, LoadError> {
    let current = KernelVersion::current().map_err(|error| {
        LoadError::Unsupported(format!("cannot read the kernel version: {error}"))
    })?;
    Ok(current >= KernelVersion::new(6, 6, 0))
}

/// Attaches one tc program to `interface` in `direction`.
///
/// The classic path creates the `clsact` qdisc on demand; an existing qdisc is not an error.
/// TCX is a `bpf_link` on the netdev and creates no qdisc.
pub fn attach_tc(
    ebpf: &mut Ebpf,
    program_name: &str,
    interface: &str,
    direction: TcAttachType,
    mode: TcMode,
) -> Result<SchedClassifierLinkId, LoadError> {
    let program = ebpf
        .program_mut(program_name)
        .ok_or_else(|| LoadError::NotFound(program_name.to_owned()))?;
    let classifier: &mut SchedClassifier = program.try_into().map_err(LoadError::Program)?;
    classifier.load().map_err(LoadError::Program)?;
    match mode {
        TcMode::Netlink => {
            ensure_clsact(interface)?;
            // The classic TC-ingress path is the one this data path was proven on:
            // `bpf_sk_assign` is a classic TC helper, and a TCX attach was observed to leave
            // the assigned packet without reaching the listener's accept queue. TCX is
            // opt-in until the privileged transparent-path gate proves otherwise.
            classifier
                .attach_with_options(
                    interface,
                    direction,
                    TcAttachOptions::Netlink(NlOptions::default()),
                )
                .map_err(LoadError::Program)
        }
        TcMode::Tcx => {
            if !tcx_supported()? {
                return Err(LoadError::Unsupported(
                    "TCX attachment requires Linux 6.6 or newer".to_owned(),
                ));
            }
            classifier
                .attach_with_options(
                    interface,
                    direction,
                    TcAttachOptions::TcxOrder(LinkOrder::default()),
                )
                .map_err(LoadError::Program)
        }
    }
}

/// Map names present in a loaded object.
pub fn map_names(ebpf: &Ebpf) -> Vec<&str> {
    ebpf.maps().map(|(name, _)| name).collect()
}

/// Program names present in a loaded object.
pub fn program_names(ebpf: &Ebpf) -> Vec<&str> {
    ebpf.programs().map(|(name, _)| name).collect()
}
