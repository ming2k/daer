//! Shared primitives for the daer workspace.
//!
//! This crate replaces the Go package `common/...`. It holds only types and
//! constants that every other crate needs, so it stays dependency-free.

pub mod consts;
pub mod net;

pub use consts::{DialMode, SelectionPolicy};
pub use net::{MacAddr, PortRange};
