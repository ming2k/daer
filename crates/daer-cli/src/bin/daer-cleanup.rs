// SPDX-License-Identifier: AGPL-3.0-only

//! Reverts system state left by an interrupted daemon run.
//!
//! This is deliberately a separate binary rather than a hidden subcommand of `daer`. The
//! operator-facing CLI is the six verbs in ADR-0015; a lifecycle hook that systemd invokes
//! after the daemon has exited is not one of them. Keeping it separate also means the helper
//! cannot accidentally acquire the daemon's configuration or runtime dependencies.
//!
//! The unit calls it from `ExecStopPost=`, which runs after both a clean stop and a failed or
//! killed one. The daemon's normal `Drop` path is still the primary cleanup; this helper
//! replays the recovery journal only when Rust destructors did not get the chance to run.

use std::process::ExitCode;

fn main() -> ExitCode {
    match daer_control::datapath::cleanup_system_state() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("daer-cleanup: {error}");
            ExitCode::FAILURE
        }
    }
}
