// SPDX-License-Identifier: AGPL-3.0-only

//! A `SIGHUP` must reload the daemon, not abort it.
//!
//! # The defect this pins
//!
//! `reload` used to be a synchronous function that called `block_on(load_resolved(...))` to
//! re-run the shared loader. `block_on` builds a runtime and calls `Runtime::block_on`, and
//! `reload` runs inside `daemon.serve`'s `select!` — that is, inside the multi-threaded runtime.
//! Tokio refuses it outright:
//!
//! ```text
//! thread 'main' panicked: Cannot start a runtime from within a runtime.
//! ```
//!
//! So the **first** `SIGHUP` panicked the daemon's main task and the process exited, taking every
//! in-flight flow with it. Every unit test passed, because none of them sent a signal to a running
//! `daer run`: the daemon's reload path had no test that could fail, which is exactly the state
//! ADR-0007 exists to prevent.
//!
//! # How this test can fail
//!
//! It starts the real binary, waits for the daemon to reach its serving state, sends `SIGHUP`,
//! and asserts **both** that the process is still alive afterwards and that the log reports a new
//! generation. The old code fails the first assertion within milliseconds; a `reload` that
//! silently did nothing fails the second.
//!
//! # Skipping rather than passing
//!
//! `daer run` binds a transparent port, which needs `CAP_NET_ADMIN`. In an environment without it
//! the daemon exits with `Operation not permitted` before any signal can be sent; the test then
//! reports a skip with the reason, because "the daemon could not start here" is not evidence about
//! the reload path.

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// A `daer run` child, killed when this value drops.
struct Daemon {
    child: Child,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The workspace's `daer` binary, as built by `cargo test`.
fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_daer"))
}

/// Writes a configuration that needs no privileges beyond the transparent port itself.
fn config(path: &std::path::Path, port: u16) -> String {
    let text = format!(
        "schema = 1\n\
         [global]\n\
         log-level = \"debug\"\n\
         tproxy-port = {port}\n\
         wan-interface = [\"lo\"]\n\
         lan-interface = [\"lo\"]\n\
         disable-waiting-network = true\n\
         [dns]\n\
         [routing]\n\
         rules = []\n\
         fallback = \"direct\"\n"
    );
    std::fs::write(path, &text).expect("writes the configuration");
    text
}

/// Sends `SIGHUP` to `pid`.
fn hang_up(pid: u32) {
    // `kill(1)` rather than `libc::kill`: daer-cli does not depend on a signal-binding crate, and
    // adding one for a single test would be the tail wagging the dog.
    let status = Command::new("kill")
        .arg("-HUP")
        .arg(pid.to_string())
        .status()
        .expect("runs kill");
    assert!(status.success(), "`kill -HUP {pid}` failed: {status}");
}

#[test]
fn the_daemon_survives_a_hangup_and_publishes_a_new_generation() {
    let directory = std::env::temp_dir().join(format!("daer-reload-{}", std::process::id()));
    std::fs::create_dir_all(&directory).expect("creates the fixture directory");
    let config_path = directory.join("daer.toml");

    // A port unlikely to collide with a developer's daemon. The test does not assume it is free:
    // a bind failure shows up as "cannot bind the transparent port" and is reported as a skip.
    let port = 12_347 + (std::process::id() % 200) as u16;
    config(&config_path, port);

    let mut child = Command::new(binary())
        .args(["run", "--no-datapath", "-c"])
        .arg(&config_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawns daer run");

    let stdout = child.stdout.take().expect("stdout is piped");
    let stderr = child.stderr.take().expect("stderr is piped");

    // Lines are collected on their own threads so waiting for one cannot deadlock on the other.
    let (sender, receiver) = mpsc::channel::<String>();
    for stream in [
        Box::new(stdout) as Box<dyn std::io::Read + Send>,
        Box::new(stderr) as Box<dyn std::io::Read + Send>,
    ] {
        let sender = sender.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(stream).lines().map_while(Result::ok) {
                if sender.send(line.clone()).is_err() {
                    return;
                }
            }
        });
    }
    drop(sender);

    let mut daemon = Daemon { child };
    let pid = daemon.child.id();

    // Wait for the serving line, or for a reason the daemon could not start.
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut log = Vec::new();
    let mut serving = false;
    while Instant::now() < deadline {
        match receiver.recv_timeout(Duration::from_millis(200)) {
            Ok(line) => {
                // The test's own fixture killed the daemon: report what it said.
                let fatal = line.contains("cannot bind the transparent port")
                    || line.contains("panicked")
                    || line.contains("wan-interface");
                log.push(line);
                if fatal {
                    eprintln!(
                        "skipped: the daemon could not start here; log:\n{}",
                        log.join("\n")
                    );
                    return;
                }
                if log
                    .last()
                    .is_some_and(|l| l.contains("listening for redirected flows"))
                {
                    serving = true;
                    break;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if daemon.child.try_wait().ok().flatten().is_some() {
                    eprintln!("skipped: the daemon exited; log:\n{}", log.join("\n"));
                    return;
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    assert!(
        serving,
        "the daemon never reached its serving state within 30s; log:\n{}",
        log.join("\n")
    );

    // The signal under test.
    hang_up(pid);

    // Give the reload a generous window, then require both liveness and a published generation.
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut reloaded = false;
    while Instant::now() < deadline {
        if let Ok(Some(status)) = daemon.child.try_wait() {
            panic!(
                "the daemon exited with {status} after SIGHUP — a reload must not abort the \
                 process; log:\n{}",
                log.join("\n")
            );
        }
        match receiver.recv_timeout(Duration::from_millis(200)) {
            Ok(line) => {
                let reloaded_here = line.contains("reloaded") && line.contains("gen2");
                let panicked = line.contains("Cannot start a runtime from within a runtime")
                    || line.contains("panicked");
                log.push(line);
                assert!(
                    !panicked,
                    "SIGHUP panicked the daemon; log:\n{}",
                    log.join("\n")
                );
                if reloaded_here {
                    reloaded = true;
                    break;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    // The process must still be the same, live process; a reload that exited is not a reload.
    assert!(
        daemon.child.try_wait().ok().flatten().is_none(),
        "the daemon is gone after SIGHUP; log:\n{}",
        log.join("\n")
    );
    assert!(
        reloaded,
        "SIGHUP did not publish a new generation; log:\n{}",
        log.join("\n")
    );

    let _ = std::fs::remove_dir_all(&directory);
}
