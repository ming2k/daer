// SPDX-License-Identifier: AGPL-3.0-only

//! Incident artifacts: the panic hook and the `SIGUSR1` snapshot (ADR-0040).
//!
//! A production failure must leave a self-contained artifact. The daemon cannot rely on a
//! human running `journalctl` while the process is gone, and a `panic = "abort"` build cannot
//! run destructors that would collect state. This module writes the bundle from the panic
//! hook (which runs before abort) and from a signal handler.
//!
//! The bundle never contains a configuration value or a proxy link. It copies the status
//! snapshot (already credential-free) and the JSON event stream.

use std::io::{Read as _, Seek as _, SeekFrom};
use std::path::{Path, PathBuf};

/// The JSON event stream written by the daemon's subscriber.
pub const EVENT_LOG_PATH: &str = "/run/daer/events.jsonl";

/// The persistent incident root, when the daemon can write it.
pub const INCIDENT_ROOT: &str = "/var/lib/daer/incidents";

const MAX_EVENT_TAIL: u64 = 4 * 1024 * 1024;

static CONFIG_PATH: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();

/// Records the configuration path for the next bundle.
///
/// The path is metadata; the file itself is deliberately not copied. A bundle is not a
/// configuration backup, and a heuristic redactor is not a safe one.
pub fn set_config_path(path: &Path) {
    let _ = CONFIG_PATH.set(path.to_path_buf());
}

/// Installs the process-wide panic hook.
///
/// The hook runs even with `panic = "abort"`, before the runtime aborts. It writes a bundle
/// and then calls the previous hook so the normal panic message and backtrace still reach
/// stderr/journald. Calling the previous hook is deliberate: replacing it without forwarding
/// would make the journal less useful, not more.
pub fn install_panic_hook() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let message = info
            .payload()
            .downcast_ref::<&str>()
            .map(|value| (*value).to_owned())
            .or_else(|| info.payload().downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "<non-string panic payload>".to_owned());
        let location = info
            .location()
            .map(|location| {
                format!(
                    "{}:{}:{}",
                    location.file(),
                    location.line(),
                    location.column()
                )
            })
            .unwrap_or_else(|| "<unknown>".to_owned());
        let thread = std::thread::current()
            .name()
            .unwrap_or("<unnamed>")
            .to_owned();
        let backtrace = std::backtrace::Backtrace::force_capture().to_string();
        let detail = serde_json::json!({
            // A panic payload is free-form and can contain a user-supplied URL. Redact the
            // URI-shaped tokens even though the rest of the bundle is typed and credential-free.
            "message": daer_observe::redact::redact_text(&message),
            "location": location,
            "thread": thread,
            "backtrace": backtrace,
        });
        if let Err(error) = capture("panic", detail) {
            eprintln!("daer: could not write the panic incident bundle: {error}");
        }
        previous(info);
    }));
}

/// Writes an incident bundle now.
///
/// # Errors
///
/// Returns a message when no incident directory is writable or a bundle file cannot be
/// written. A diagnostic failure must never replace the original failure, so callers report
/// this on stderr and continue.
pub fn capture(trigger: &str, detail: serde_json::Value) -> Result<PathBuf, String> {
    let root = incident_root()?;
    crate::private_fs::ensure_dir(&root)
        .map_err(|error| format!("cannot create {}: {error}", root.display()))?;
    let id = format!(
        "{}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs()),
        std::process::id()
    );
    let directory = root.join(id);
    crate::private_fs::ensure_dir(&directory)
        .map_err(|error| format!("cannot create {}: {error}", directory.display()))?;

    let manifest = serde_json::json!({
        "schema": 1,
        "trigger": trigger,
        "created_at": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs()),
        "build": {
            "version": env!("CARGO_PKG_VERSION"),
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
        },
        "detail": detail,
        "config": CONFIG_PATH.get().map(|path| serde_json::json!({
            "path": path.display().to_string(),
            "included": false,
            "reason": "configuration is never copied into a bundle; attach it deliberately",
        })),
        "redaction": {
            "policy": "incident-v1",
            "secrets_removed": true,
        },
    });
    crate::private_fs::write_private(
        &directory.join("manifest.json"),
        &serde_json::to_vec_pretty(&manifest)
            .map_err(|error| format!("cannot encode manifest: {error}"))?,
    )
    .map_err(|error| format!("cannot write manifest: {error}"))?;

    if let Ok(snapshot) = std::fs::read(crate::status::STATE_PATH) {
        let _ = crate::private_fs::write_private(&directory.join("snapshot.json"), &snapshot);
    }
    if let Err(error) = copy_tail(
        Path::new(EVENT_LOG_PATH),
        &directory.join("events.jsonl"),
        MAX_EVENT_TAIL,
    ) {
        crate::private_fs::write_private(
            &directory.join("events.jsonl"),
            format!("event stream unavailable: {error}\n").as_bytes(),
        )
        .map_err(|write| format!("cannot write events placeholder: {write}"))?;
    }
    crate::private_fs::write_private(
        &directory.join("README.txt"),
        b"daer incident bundle.\n\
          Contains the panic/signal manifest, the last status snapshot and the tail of the JSON\n\
          event stream. It contains no configuration file, proxy link or credential. A full\n\
          per-flow record is produced by the event stream; the `flow_id` fields join it.\n",
    )
    .map_err(|error| format!("cannot write README: {error}"))?;
    Ok(directory)
}

fn incident_root() -> Result<PathBuf, String> {
    if let Some(root) = std::env::var_os("DAER_INCIDENT_DIR") {
        return Ok(PathBuf::from(root));
    }
    // There is no tmpfs fallback: an incident that is copied later by a post-stop helper is
    // not self-contained (ADR-0042). The systemd unit's `StateDirectory=daer` creates this
    // tree; a foreground run must be able to write it.
    crate::private_fs::ensure_dir(Path::new(INCIDENT_ROOT))
        .map_err(|error| format!("cannot create {INCIDENT_ROOT}: {error}"))?;
    Ok(PathBuf::from(INCIDENT_ROOT))
}

/// Copies at most `max_bytes` from the end of `source`.
fn copy_tail(source: &Path, destination: &Path, max_bytes: u64) -> std::io::Result<()> {
    let mut file = std::fs::File::open(source)?;
    let len = file.metadata()?.len();
    if len > max_bytes {
        file.seek(SeekFrom::Start(len - max_bytes))?;
    }
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    crate::private_fs::write_private(destination, &buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bundle_contains_the_manifest_and_a_redacted_readme() {
        let dir = std::env::temp_dir().join(format!("daer-incident-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        // Safety: this test owns the process-wide variable for its duration.
        unsafe {
            std::env::set_var("DAER_INCIDENT_DIR", &dir);
        }
        let path = capture("test", serde_json::json!({"message": "test panic"})).expect("captures");
        let manifest = std::fs::read_to_string(path.join("manifest.json")).expect("manifest");
        assert!(manifest.contains("\"trigger\": \"test\""));
        assert!(manifest.contains("incident-v1"));
        let readme = std::fs::read_to_string(path.join("README.txt")).expect("readme");
        assert!(readme.contains("credential"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
