// SPDX-License-Identifier: AGPL-3.0-only

//! Reverts system state left by an interrupted daemon run and preserves incident evidence.
//!
//! This is deliberately a separate binary rather than a hidden subcommand of `daer`. The
//! operator-facing CLI is the seven verbs in ADR-0015/ADR-0041; a lifecycle hook that systemd
//! invokes after the daemon has exited is not one of them. Keeping it separate also means the
//! helper cannot accidentally acquire the daemon's configuration or runtime dependencies.
//!
//! The unit calls it from `ExecStopPost=`, which runs after both a clean stop and a failed or
//! killed one. The daemon's normal `Drop` path is still the primary cleanup; this helper
//! replays the recovery journal only when Rust destructors did not get the chance to run.
//!
//! For a current journal it removes the host TC filters and qdiscs only. The ingress
//! namespace, the veth pair and the ingress sysctls are released with the process, and
//! host-global forwarding sysctls are operator prerequisites the daemon never writes. A
//! pre-v2 journal still triggers the full legacy restore, including those host values.

use std::process::ExitCode;

fn main() -> ExitCode {
    let cleanup = daer_control::datapath::cleanup_system_state();
    preserve_incidents();
    match cleanup {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("daer-cleanup: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Copies the tmpfs incident bundles to the persistent state directory.
///
/// The daemon prefers `/var/lib/daer/incidents`; this is the fallback for a run that could
/// only write `/run/daer/incidents` (for example, before the unit's `StateDirectory` existed).
/// A failed copy is reported on stderr, never silently discarded: the bundle is the evidence.
fn preserve_incidents() {
    let from = std::path::Path::new("/run/daer/incidents");
    let to = std::path::Path::new("/var/lib/daer/incidents");
    if !from.is_dir() {
        return;
    }
    if let Err(error) = std::fs::create_dir_all(to) {
        eprintln!(
            "daer-cleanup: cannot create {} for incident preservation: {error}",
            to.display()
        );
        return;
    }
    let Ok(entries) = std::fs::read_dir(from) else {
        return;
    };
    for entry in entries.flatten() {
        let source = entry.path();
        if !source.is_dir() {
            continue;
        }
        let Some(name) = source.file_name() else {
            continue;
        };
        let target = to.join(name);
        if target.exists() {
            continue;
        }
        if let Err(error) = copy_directory(&source, &target) {
            eprintln!(
                "daer-cleanup: cannot preserve incident bundle {}: {error}",
                source.display()
            );
        }
    }
}

fn copy_directory(from: &std::path::Path, to: &std::path::Path) -> std::io::Result<()> {
    std::fs::create_dir_all(to)?;
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        let source = entry.path();
        let target = to.join(entry.file_name());
        if source.is_dir() {
            copy_directory(&source, &target)?;
        } else {
            std::fs::copy(&source, &target)?;
        }
    }
    Ok(())
}
