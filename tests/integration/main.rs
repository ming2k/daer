// SPDX-License-Identifier: AGPL-3.0-only

//! Workspace-level integration tests: real components composed over loopback.
//!
//! This binary contains every unprivileged `tests/*.rs` module that used to live beside a
//! crate. One entry point means one link step for the layer instead of one per crate, and a
//! shared `common` module means fixtures are not copied five times.
//!
//! Privileged tests (real daemon, `tproxy`, network namespaces, kernel object attachment) are
//! in the sibling `e2e` target.

#[path = "../common/mod.rs"]
mod common;

mod cli_architecture;
mod cli_domain_policy;
mod cli_logging;
mod cli_preflight;
mod cli_route;
mod cli_runtime;
mod cli_schema;
mod cli_status;
mod cli_surface;
mod config_keys;
mod control_handover;
mod control_router;
mod control_sniff_route;
mod control_subscription;
mod dns_architecture;
mod dns_end_to_end;
mod drb_dat_unpack;
mod drb_workflow;
mod ebpf_object;
mod observe_catalog_contract;
mod outbound_architecture;
mod protocols_architecture;
mod relay_architecture;
mod relay_tcp;
mod routing_artifact_budget;
mod routing_ast_boundary;
mod routing_hot_path;
mod routing_kernel_policy;
mod routing_rules;
mod rule_ast_canonical_contract;
mod sniff_hostile_input;
mod test_architecture;
