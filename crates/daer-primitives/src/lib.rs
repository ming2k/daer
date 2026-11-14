//! Zero-dependency shared primitives and constants for the daer workspace.
//!
//! Holds only value types and constants that multiple otherwise-independent crates
//! need, keeping the dependency graph acyclic and free of heavy dependencies.

pub mod consts;
pub mod net;

pub use consts::{DEFAULT_SOCKET_MARK, SelectionPolicy};
pub use net::{MacAddr, PortRange};
