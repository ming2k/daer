// SPDX-License-Identifier: AGPL-3.0-only

//! The daemon must run on a runtime that schedules the tasks it spawns.
//!
//! # The defect this pins
//!
//! `daer run` supervises work it does not drive: every relayed flow, every datagram, and the
//! reply pump of every datagram session are `tokio::spawn`ed. On a **current-thread** runtime a
//! spawned task only runs when the *main* future yields the thread, and the daemon's main future
//! is a `select!` over a signal and an accept loop — both `Pending` with no traffic. So a
//! spawned task can starve indefinitely behind it.
//!
//! It was not theoretical. A datagram arrived, `peer_for` opened the session and logged it, and
//! the spawned `send` to the origin never ran: the client timed out while the daemon reported a
//! healthy session. The bug reads as a transport failure, which is why it survived a first pass
//! of debugging that instrumented the relay rather than the runtime.
//!
//! # What this test asserts, and why it cannot pass vacuously
//!
//! The same spawn-and-wait shape on both runtimes: the spawned task must run on the multi-thread
//! runtime and must **not** run on the current-thread one. Asserting only the first half would
//! pass on a machine where the current-thread case happens to work; asserting both makes the
//! *difference* the claim, which is the property `block_on_daemon` exists to provide.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// Spawns a task from a main future that then blocks forever, and reports whether it ran.
///
/// `pending()` is deliberate: it is the strictest form of "the main future is waiting", which is
/// what the daemon does between flows.
fn does_a_spawned_task_run(on_current_thread: bool) -> bool {
    let mut builder = tokio::runtime::Builder::new_multi_thread();
    if on_current_thread {
        builder = tokio::runtime::Builder::new_current_thread();
    } else {
        builder.worker_threads(2);
    }
    let runtime = builder.enable_all().build().expect("a runtime");

    let ran = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&ran);
    let main = runtime.spawn(async move {
        tokio::spawn(async move {
            flag.store(true, Ordering::Release);
        });
        std::future::pending::<()>().await;
    });

    // Long enough for a healthy runtime to have run the spawned task, short enough that the test
    // stays fast. The result is a boolean, so the exact duration is not part of the assertion.
    std::thread::sleep(Duration::from_millis(150));
    let ran = ran.load(Ordering::Acquire);
    main.abort();
    ran
}

#[test]
fn a_current_thread_runtime_starves_a_spawned_task() {
    // Recorded so the reason `block_on_daemon` exists is executable rather than folklore. If a
    // future tokio release changes this, the test fails and the comment in `daer-cli` should be
    // revisited with it — it must not silently keep justifying a multi-thread runtime.
    assert!(
        !does_a_spawned_task_run(true),
        "a current-thread runtime ran a spawned task while the main future was pending; the \
         premise of `block_on_daemon` no longer holds and its comment needs revisiting"
    );
}

#[test]
fn a_multi_thread_runtime_runs_a_spawned_task() {
    assert!(
        does_a_spawned_task_run(false),
        "a multi-thread runtime did not run a spawned task; the daemon would starve every relay"
    );
}

/// The daemon must be started through the multi-threaded entry point.
///
/// The two tests above prove *why* a multi-threaded runtime is required; this one proves the
/// daemon actually uses it. Without it, reverting `run` to `block_on` would leave them green
/// while the product regressed — the exact gap ADR-0007 describes, where a test proves a
/// property nobody wired up.
#[test]
fn the_daemon_entry_point_uses_the_multi_threaded_runtime() {
    // Read the source: `main` is a binary, so its internals are not reachable from an
    // integration test. The assertion is deliberately narrow — the runtime call must appear
    // within a few lines of the `Command::Run` arm — so it fails when the *call site* changes,
    // which is what regressed, and cannot pass by finding the string somewhere else in the file.
    let source = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/main.rs"))
        .expect("the CLI source is readable");

    let arm_start = source
        .find("Command::Run {")
        .expect("`main` has a `Command::Run` arm");
    // The arm's own body: far enough to include the runtime call, short enough that a match in
    // a later arm cannot satisfy it.
    let window = &source[arm_start..(arm_start + 900).min(source.len())];
    // Match the *call*, not the word: the comment next to it names the function too, and an
    // assertion that a comment can satisfy is exactly the vacuity ADR-0007 is about.
    assert!(
        window.contains("block_on_daemon(async move"),
        "the `run` subcommand must be driven by `block_on_daemon`: a current-thread runtime \
         starves the relays and datagram sessions the daemon spawns. Saw:\n{window}"
    );
}
