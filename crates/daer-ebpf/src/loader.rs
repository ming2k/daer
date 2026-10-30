// SPDX-License-Identifier: AGPL-3.0-only

//! Loading the datapath object and wiring its runtime parameters.
//!
//! The object is compiled from `control/kern/tproxy.c` by
//! `scripts/build-ebpf.sh`; this module does not compile it, so building daer
//! never needs a clang toolchain or the kernel headers.
//!
//! Attachment needs `CAP_BPF`/`CAP_NET_ADMIN`, so the tests that attach are
//! `#[ignore]`d. The name/ABI checks in `tests/object.rs` run unprivileged.

use std::fmt;

use aya::Ebpf;
use aya::EbpfError;
use aya::EbpfLoader;
use aya::maps::Array;
use aya::maps::MapError;
use aya::programs::ProgramError;
use aya::programs::tc::SchedClassifier;
use aya::programs::tc::SchedClassifierLinkId;
use aya::programs::tc::TcAttachType;
use aya::programs::tc::TcError;
use aya::programs::tc::qdisc_add_clsact;

use crate::abi::RuntimeParam;
use crate::elf::{self, ElfError};
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
    /// The object is a malformed ELF.
    Elf(ElfError),
    /// The object is missing a map, program or global this crate references.
    NotFound(String),
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "failed to read eBPF object: {err}"),
            Self::Load(err) => write!(f, "failed to load eBPF object: {err}"),
            Self::Program(err) => write!(f, "eBPF program error: {err}"),
            Self::Map(err) => write!(f, "eBPF map error: {err}"),
            Self::Tc(err) => write!(f, "tc error: {err}"),
            Self::Elf(err) => write!(f, "eBPF object: {err}"),
            Self::NotFound(name) => write!(f, "eBPF object is missing \"{name}\""),
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
            Self::Elf(_) | Self::NotFound(_) => None,
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
/// Section names are normalized first: the shared C datapath is compiled for
/// `ebpf-go`, whose section syntax is not what `aya` accepts. See
/// [`crate::elf`] for the mapping.
pub fn load(object: &[u8], param: &RuntimeParam) -> Result<Ebpf, LoadError> {
    let object = elf::normalize_section_names(object).map_err(LoadError::Elf)?;
    let mut loader = EbpfLoader::new();
    loader.override_global(names::PARAM_GLOBAL, param.as_bytes(), true);
    Ok(loader.load(&object)?)
}

/// Loads the datapath object from disk.
pub fn load_path(
    path: impl AsRef<std::path::Path>,
    param: &RuntimeParam,
) -> Result<Ebpf, LoadError> {
    let bytes = std::fs::read(path)?;
    load(&bytes, param)
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

/// Attaches one tc program to `interface` in `direction`.
///
/// The clsact qdisc is created on demand. An existing qdisc is not an error:
/// a reload keeps the qdisc of the previous generation, and the attach below is
/// what actually has to succeed.
pub fn attach_tc(
    ebpf: &mut Ebpf,
    program_name: &str,
    interface: &str,
    direction: TcAttachType,
) -> Result<SchedClassifierLinkId, LoadError> {
    let program = ebpf
        .program_mut(program_name)
        .ok_or_else(|| LoadError::NotFound(program_name.to_owned()))?;
    let classifier: &mut SchedClassifier = program.try_into().map_err(LoadError::Program)?;
    classifier.load().map_err(LoadError::Program)?;
    let _ = qdisc_add_clsact(interface);
    classifier
        .attach(interface, direction)
        .map_err(LoadError::Program)
}

/// Map names present in a loaded object.
pub fn map_names(ebpf: &Ebpf) -> Vec<&str> {
    ebpf.maps().map(|(name, _)| name).collect()
}

/// Program names present in a loaded object.
pub fn program_names(ebpf: &Ebpf) -> Vec<&str> {
    ebpf.programs().map(|(name, _)| name).collect()
}
