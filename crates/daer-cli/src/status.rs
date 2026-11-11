// SPDX-License-Identifier: AGPL-3.0-only

//! `daer status`: the read-only runtime inspector (ADR-0041).
//!
//! The daemon owns the snapshot; this module is a client. It never writes configuration,
//! kernel state or a signal. The transport order is deliberate:
//!
//! 1. `/run/daer/control.sock` — the live snapshot;
//! 2. `/run/daer/state.json` — the last written snapshot, used when the daemon is gone.
//!
//! A status command that cannot tell a live answer from a stale file is worse than no status
//! command, so the source and age are printed in both modes.

use std::path::{Path, PathBuf};

use anyhow::Context as _;

/// The daemon's read-only Unix socket.
pub const SOCKET_PATH: &str = "/run/daer/control.sock";

/// The last snapshot, written atomically by the daemon.
pub const STATE_PATH: &str = "/run/daer/state.json";

/// What `daer status` was asked to produce.
#[derive(Debug, Clone)]
pub struct StatusOptions {
    /// Print the raw versioned JSON snapshot.
    pub json: bool,
    /// Write an incident bundle to this directory.
    pub bundle: Option<PathBuf>,
    /// Print every recorded event for one flow/session ID.
    pub flow: Option<String>,
}

/// One snapshot and where it came from.
#[derive(Debug)]
struct Snapshot {
    value: serde_json::Value,
    source: Source,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Source {
    Socket,
    File,
}

impl Source {
    const fn describe(self) -> &'static str {
        match self {
            Self::Socket => "live (/run/daer/control.sock)",
            Self::File => "file (/run/daer/state.json; the daemon may not be running)",
        }
    }
}

/// Runs the status verb.
///
/// # Errors
///
/// Returns when neither the socket nor the state file answers, or when a bundle cannot be
/// written. "No running daemon" is a normal operator condition, so the message names the two
/// paths instead of looking like a panic.
pub async fn run(options: StatusOptions) -> anyhow::Result<()> {
    if let Some(flow) = options.flow {
        return print_flow(&flow);
    }
    let snapshot = read_snapshot().await?;

    if let Some(directory) = options.bundle {
        let path = write_bundle(&directory, &snapshot)?;
        println!("wrote incident bundle to {}", path.display());
        if options.json {
            println!("{}", snapshot.value);
        }
        return Ok(());
    }

    if options.json {
        println!("{}", serde_json::to_string_pretty(&snapshot.value)?);
        return Ok(());
    }

    print_human(&snapshot);
    Ok(())
}

/// The state path, with a test-only override.
fn state_path() -> PathBuf {
    std::env::var_os("DAER_STATUS_STATE").map_or_else(|| PathBuf::from(STATE_PATH), PathBuf::from)
}

/// The socket path, with a test-only override.
fn socket_path() -> PathBuf {
    std::env::var_os("DAER_STATUS_SOCKET").map_or_else(|| PathBuf::from(SOCKET_PATH), PathBuf::from)
}

async fn read_snapshot() -> anyhow::Result<Snapshot> {
    match read_socket().await {
        Ok(value) => Ok(Snapshot {
            value,
            source: Source::Socket,
        }),
        Err(socket_error) => {
            let text = std::fs::read_to_string(state_path()).with_context(|| {
                format!(
                    "the daemon did not answer on {} ({socket_error}) and {} is unreadable; \
                     is `daer run` running?",
                    socket_path().display(),
                    state_path().display()
                )
            })?;
            let value = serde_json::from_str(&text)
                .with_context(|| format!("{} is not a JSON snapshot", state_path().display()))?;
            Ok(Snapshot {
                value,
                source: Source::File,
            })
        }
    }
}

async fn read_socket() -> anyhow::Result<serde_json::Value> {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let mut stream = tokio::net::UnixStream::connect(socket_path()).await?;
    stream.write_all(b"snapshot\n").await?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    if response.is_empty() {
        anyhow::bail!("the control socket returned no snapshot");
    }
    serde_json::from_slice(&response).context("the control socket returned invalid JSON")
}

fn events_path() -> PathBuf {
    std::env::var_os("DAER_STATUS_EVENTS").map_or_else(
        || PathBuf::from(crate::incident::EVENT_LOG_PATH),
        PathBuf::from,
    )
}

/// Prints every JSON event whose `fields.flow_id` equals `flow`.
///
/// The flow record is not a second store: it is the same event stream, filtered by the one
/// field that makes a trace joinable. A missing ID is a named answer, not an empty page.
fn print_flow(flow: &str) -> anyhow::Result<()> {
    let path = events_path();
    let text = std::fs::read_to_string(&path).with_context(|| {
        format!(
            "cannot read {}; start `daer run` with the JSON event stream enabled",
            path.display()
        )
    })?;
    let mut found = false;
    println!(
        "flow {flow}: events from {} (historical if the generation is no longer serving)",
        path.display()
    );
    for line in text.lines() {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if value
            .pointer("/fields/flow_id")
            .and_then(serde_json::Value::as_str)
            == Some(flow)
        {
            println!("{line}");
            found = true;
        }
    }
    if !found {
        anyhow::bail!(
            "no events for flow {flow:?} in {}; the flow may be older than this run",
            path.display()
        );
    }
    Ok(())
}

fn print_human(snapshot: &Snapshot) {
    let value = &snapshot.value;
    let get = |path: &str| -> String {
        value
            .pointer(path)
            .map_or_else(|| "—".to_owned(), serde_json::Value::to_string)
    };
    println!("daer status (source: {})", snapshot.source.describe());
    println!();
    println!("  run        : {}", get("/run_id"));
    println!("  pid        : {}", get("/pid"));
    println!("  uptime     : {}s", get("/uptime_secs"));
    println!("  generation : {}", get("/generation/id"));
    println!("  policy     : {}", get("/generation/policy_hash"));
    println!("  rules      : {}", get("/generation/rules"));
    println!("  datapath   : {}", get("/datapath/attached"));
    println!("  namespace  : {}", get("/datapath/namespace"));
    println!("  port       : {}", get("/datapath/port"));
    println!(
        "  flows      : in_flight={} accepted={} failed={} rejected={} exhausted={}",
        get("/flows/in_flight"),
        get("/flows/accepted"),
        get("/flows/failed"),
        get("/flows/rejected"),
        get("/flows/exhausted"),
    );
    println!(
        "  dns        : hits={} stale={} misses={} upstream_errors={}",
        get("/dns/hits"),
        get("/dns/stale_hits"),
        get("/dns/misses"),
        get("/dns/upstream_errors"),
    );
    println!(
        "  events     : {} counter(s) incremented",
        value
            .pointer("/event_counters")
            .and_then(serde_json::Value::as_object)
            .map_or(0, serde_json::Map::len)
    );
    println!(
        "  datagram   : sessions={} to_upstream={} to_client={} dropped_full={} dropped_failed={}",
        get("/datagram/sessions_opened"),
        get("/datagram/to_upstream"),
        get("/datagram/to_client"),
        get("/datagram/dropped_full"),
        get("/datagram/dropped_failed"),
    );
    if let Some(warnings) = value
        .pointer("/generation/warnings")
        .and_then(|v| v.as_array())
        && !warnings.is_empty()
    {
        println!("  warnings   :");
        for warning in warnings {
            println!("    - {}", warning.as_str().unwrap_or("<non-string>"));
        }
    }
}

/// Removes the status socket on shutdown.
pub fn remove_socket() {
    let _ = std::fs::remove_file(socket_path());
}

/// Binds the read-only status socket and serves the last snapshot.
///
/// The daemon calls this once. A failure is not fatal: `daer status` falls back to the state
/// file, which is exactly the path a crash leaves behind. The socket is root-owned and
/// `0600`; there is no network listener and no authentication layer to get wrong.
pub fn spawn_socket() -> Option<tokio::task::JoinHandle<()>> {
    let socket_path = socket_path();
    let _ = std::fs::remove_file(&socket_path);
    let listener = match std::os::unix::net::UnixListener::bind(&socket_path) {
        Ok(listener) => listener,
        Err(error) => {
            daer_observe::debug!(
                daer_observe::EventCode::DaemonStatusSocketFailed,
                path = %socket_path.display(),
                %error,
                "could not bind the read-only status socket"
            );
            return None;
        }
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600));
    }
    if listener.set_nonblocking(true).is_err() {
        return None;
    }
    Some(tokio::spawn(async move {
        let Ok(listener) = tokio::net::UnixListener::from_std(listener) else {
            return;
        };
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                continue;
            };
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
                let mut request = [0u8; 64];
                let Ok(read) = stream.read(&mut request).await else {
                    return;
                };
                if !request[..read].starts_with(b"snapshot") {
                    let _ = stream.write_all(b"{\"error\":\"unknown request\"}\n").await;
                    return;
                }
                match std::fs::read(state_path()) {
                    Ok(mut snapshot) => {
                        snapshot.push(b'\n');
                        let _ = stream.write_all(&snapshot).await;
                    }
                    Err(error) => {
                        let body = serde_json::json!({
                            "error": "state snapshot is not readable",
                            "path": state_path().display().to_string(),
                            "detail": error.to_string(),
                        });
                        let _ = stream.write_all(body.to_string().as_bytes()).await;
                    }
                }
            });
        }
    }))
}

fn write_bundle(directory: &Path, snapshot: &Snapshot) -> anyhow::Result<PathBuf> {
    let directory = directory.to_path_buf();
    std::fs::create_dir_all(&directory)
        .with_context(|| format!("cannot create bundle directory {}", directory.display()))?;
    let state = serde_json::to_vec_pretty(&snapshot.value)?;
    std::fs::write(directory.join("snapshot.json"), state)?;

    // The event stream is the machine-readable half of the same run. Copy it when it is
    // readable; a bundle without it still has the snapshot and an explicit manifest.
    if let Ok(events) = std::fs::read(events_path()) {
        std::fs::write(directory.join("events.jsonl"), events)?;
    }

    let manifest = serde_json::json!({
        "schema": 1,
        "created_at": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs()),
        "source": snapshot.source.describe(),
        "build": {
            "version": env!("CARGO_PKG_VERSION"),
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
        },
        "redaction": {
            "policy": "status-v1",
            "secrets_removed": true,
        },
    });
    std::fs::write(
        directory.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )?;
    std::fs::write(
        directory.join("README.txt"),
        "daer incident bundle (status snapshot).\n\
         This bundle contains the versioned status snapshot and build identity. It does not\n\
         contain configuration secrets, subscription links or proxy credentials.\n\
         A full bundle (event ring, per-flow records) is written by the daemon's incident\n\
         recorder; this file is the read-only client fallback.\n",
    )?;
    Ok(directory)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_snapshot_paths_are_the_documented_ones() {
        assert_eq!(SOCKET_PATH, "/run/daer/control.sock");
        assert_eq!(STATE_PATH, "/run/daer/state.json");
    }

    #[test]
    fn a_bundle_never_copies_a_config_or_a_link() {
        let dir = std::env::temp_dir().join(format!(
            "daer-status-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let snapshot = Snapshot {
            value: serde_json::json!({"run_id": "r01", "flows": {"accepted": 0}}),
            source: Source::File,
        };
        let path = write_bundle(&dir, &snapshot).expect("writes bundle");
        let manifest = std::fs::read_to_string(path.join("manifest.json")).expect("manifest");
        assert!(manifest.contains("status-v1"));
        let readme = std::fs::read_to_string(path.join("README.txt")).expect("readme");
        assert!(readme.contains("credentials"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
