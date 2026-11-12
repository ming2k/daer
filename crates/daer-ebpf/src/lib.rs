// SPDX-License-Identifier: AGPL-3.0-only

//! eBPF integration for daer.
//!
//! `ebpf/kern/datapath.bpf.c` is daer's own datapath (ADR-0020). It is compiled into
//! `target/ebpf/datapath.bpf.o` by `cargo xtask ebpf` and loaded here through `aya`;
//! this crate owns the userspace side of that boundary — the ABI types, the map and
//! program names, and the operations on the maps.
//!
//! # The loader loads, it does not repair
//!
//! The object this crate is handed is the object this repository built. Its section
//! names are already what `aya` parses (`classifier/<name>`, `sk_skb/stream_verdict`),
//! so [`loader::load`] overrides the runtime parameter global and nothing else. There
//! is deliberately no ELF or BTF rewriting step: a previous one renamed sections in
//! the ELF header without renaming them in `.BTF.ext`, which dropped every program's
//! `func_info` and made the kernel reject the load with
//! `nonzero insn_off 3 for the first func info record`.
//!
//! `tests/object.rs` is the guard: it reproduces `aya`'s call relocation and asserts
//! the invariant the kernel checks, unprivileged.

pub mod abi;
pub mod epoch;
/// The kernel ABI constants and layout assertions, generated from `ebpf/abi.toml`.
pub mod generated;
#[cfg(feature = "loader")]
pub mod handoff;
pub mod listeners;
pub mod names;

#[cfg(feature = "loader")]
pub mod loader;
#[cfg(feature = "loader")]
pub mod publish;
pub mod telemetry;

pub use abi::{PortRange, RuntimeParam, TuplesKey};
pub use epoch::{
    Entry, MapWriter, PublishError, Published, Slot, Stamp, active_slot, publish, rollback,
};
#[cfg(feature = "loader")]
pub use handoff::Handoff;
pub use listeners::Listeners;

#[cfg(feature = "loader")]
pub use loader::{
    LoadError, ObjectReport, attach_tc, inspect_bytes, inspect_object, load, load_path,
    require_tcx, set_device_ifindex,
};
#[cfg(feature = "loader")]
pub use publish::{AyaWriter, publish_listeners, publish_lpm, publish_outbound_connectivity};
