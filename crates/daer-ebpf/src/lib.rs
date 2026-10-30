// SPDX-License-Identifier: AGPL-3.0-only

//! eBPF integration for daer.
//!
//! The kernel datapath (`control/kern/tproxy.c`) stays in C during the
//! migration; this crate owns the userspace side: loading the object, naming the
//! maps and programs, and the ABI types shared across the boundary.

pub mod abi;
pub mod elf;
pub mod epoch;
pub mod names;

#[cfg(feature = "loader")]
pub mod loader;
#[cfg(feature = "loader")]
pub mod publish;

pub use abi::{PortRange, RuntimeParam, TuplesKey};
pub use elf::{ElfError, normalize_section_names};
pub use epoch::{
    Entry, MapWriter, PublishError, Published, Slot, Stamp, active_slot, publish, rollback,
};

#[cfg(feature = "loader")]
pub use loader::{LoadError, attach_tc, load, load_path, set_device_ifindex};
#[cfg(feature = "loader")]
pub use publish::{AyaWriter, publish_listeners, publish_lpm, publish_outbound_connectivity};
