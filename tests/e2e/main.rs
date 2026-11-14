// SPDX-License-Identifier: AGPL-3.0-only

//! Privileged end-to-end tests: a real daemon, a real redirect, the real kernel.
//!
//! Every module here skips with a reason when the host cannot supply the capability it needs.
//! The privileged CI jobs run this binary as root and fail on a `skipped: ` line, because a
//! suite that skips is not coverage (ADR-0007). Keeping every case in one binary means one
//! link step for the layer; tests that must not run concurrently use `--test-threads=1` in
//! those jobs or the nextest `e2e` test group.

#[path = "../common/mod.rs"]
mod common;

mod cli_reload;
mod control_netns_lifecycle;
mod control_transparent;
mod control_transparent_udp4;
mod control_transparent_udp6;
mod ebpf_datapath;
mod ebpf_kernel;
mod protocols_anytls_interop;
mod protocols_client_hello_probe;
mod protocols_hysteria2_interop;
mod protocols_hysteria2_live;
mod protocols_layer_matrix;
mod protocols_reality_interop;
mod protocols_reality_live;
mod protocols_reality_tag_audit;
mod protocols_shadowsocks_interop;
mod protocols_trojan_interop;
mod protocols_vision_lab;
mod protocols_vision_tls_inside;
mod protocols_vmess_live;
mod protocols_ws_upgrade;
