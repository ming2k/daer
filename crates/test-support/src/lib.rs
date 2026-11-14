// SPDX-License-Identifier: AGPL-3.0-only

//! Dev-only test infrastructure.
//!
//! This crate is a **dev-dependency**. It must never appear in a production crate's normal
//! dependency closure; `tests/integration/test_architecture.rs` asserts that.
//!
//! The helpers here are deliberately small and dependency-free: a scratch directory that is
//! unique per test (Cargo runs a test binary's tests as threads, so `process::id()` alone is
//! not unique), a per-run nonce, workspace/binary paths, and a bounded polling helper. A
//! fixture that needs a protocol or a runtime belongs in the test that owns it, not here.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// The workspace root, from this crate's manifest path.
#[must_use]
pub fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crates/test-support is two levels below the workspace root")
        .to_path_buf()
}

/// A path under the workspace root.
#[must_use]
pub fn workspace_path(relative: impl AsRef<Path>) -> PathBuf {
    workspace_root().join(relative)
}

/// Reads a file under the workspace root, naming the path in the failure.
///
/// # Panics
///
/// Panics when the file is missing or not UTF-8; a source fixture that disappeared is a test
/// failure, not a skip.
#[must_use]
pub fn read_workspace(relative: impl AsRef<Path>) -> String {
    let path = workspace_path(relative.as_ref());
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()))
}

/// The directory containing the current test binary's Cargo artifacts.
///
/// Test binaries are normally in `target/<profile>/deps/`, but nextest and build-script
/// output can place them under `target/<profile>/build/<package>/.../out/`. Searching the
/// ancestors for the profile directory handles both without guessing from `process::id()` or
/// the current working directory.
#[must_use]
pub fn target_dir() -> PathBuf {
    if let Ok(exe) = std::env::current_exe() {
        for ancestor in exe.ancestors() {
            if ancestor
                .file_name()
                .is_some_and(|name| matches!(name.to_str(), Some("debug" | "release" | "forensic")))
            {
                return ancestor.to_path_buf();
            }
        }
    }
    workspace_path("target/debug")
}

/// Locates a built binary without assuming the test's own package owns it.
///
/// A workspace-level test package cannot use `CARGO_BIN_EXE_<name>`: that variable is only
/// defined for integration tests of the package that owns the binary. Resolving relative to
/// the running test binary works for both `cargo test` and `cargo nextest`.
///
/// # Panics
///
/// Panics with the build command when the binary is absent. A missing fixture must fail
/// loudly; a test that silently skips here would leave the CLI surface unverified.
#[must_use]
pub fn binary(name: &str) -> PathBuf {
    let path = target_dir().join(name);
    assert!(
        path.is_file(),
        "{} is missing; build it with `cargo build --bins` before running this test",
        path.display()
    );
    path
}

/// The `daer` binary under test.
#[must_use]
pub fn daer() -> PathBuf {
    binary("daer")
}

/// The `daer-drb` producer binary under test.
#[must_use]
pub fn daer_drb() -> PathBuf {
    binary("daer-drb")
}

/// A per-run value no hard-coded fixture can satisfy.
///
/// Data-path tests put this in the origin's response and assert it comes back through the
/// proxy. The counter keeps two calls in one process distinct even when the clock has coarse
/// resolution.
#[must_use]
pub fn nonce() -> String {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    format!(
        "daer-nonce-{nanos:032x}-{:08x}-{:08x}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )
}

/// A scratch directory that removes itself.
///
/// The tag distinguishes tests; the counter and timestamp distinguish two tests that pass the
/// same tag in one process. This is the failure the older per-file helpers had: a shared
/// `process::id()` path let one test's `Drop` delete another test's directory.
#[derive(Debug)]
pub struct Scratch {
    path: PathBuf,
}

impl Scratch {
    /// Creates a unique scratch directory named after `tag`.
    #[must_use]
    pub fn new(tag: &str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default();
        let path = std::env::temp_dir().join(format!(
            "daer-test-{tag}-{}-{nanos:032x}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("creates the scratch directory");
        Self { path }
    }

    /// The directory path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// A path inside the directory.
    #[must_use]
    pub fn join(&self, name: impl AsRef<Path>) -> PathBuf {
        self.path.join(name)
    }

    /// Writes a file inside the directory and returns its path.
    pub fn write(&self, name: impl AsRef<Path>, contents: impl AsRef<[u8]>) -> PathBuf {
        let path = self.join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("creates the scratch parent directory");
        }
        std::fs::write(&path, contents).expect("writes the scratch file");
        path
    }

    /// Writes a file with mode `0600` on Unix.
    ///
    /// Config fixtures contain credentials; a test that writes a world-readable secret is
    /// the same defect as a daemon that does.
    pub fn write_private(&self, name: impl AsRef<Path>, contents: impl AsRef<[u8]>) -> PathBuf {
        let path = self.write(name, contents);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .expect("sets the scratch file mode");
        }
        path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Polls `predicate` until it returns true or `timeout` elapses.
///
/// Returns whether it became true. Use this for a fixture that starts a listener in a task;
/// never for a correctness assertion whose timing is the property under test.
pub fn wait_until(
    timeout: Duration,
    interval: Duration,
    mut predicate: impl FnMut() -> bool,
) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if predicate() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(interval);
    }
}

/// Reserves a loopback TCP port by binding and immediately releasing it.
///
/// A port cannot be reserved by dropping the listener, so an external fixture that needs the
/// number before it spawns is inherently racy. Prefer binding port 0 inside the fixture when
/// it can report the assigned port; use this only for a process that must be configured with
/// a port before it starts.
#[must_use]
pub fn unused_port() -> u16 {
    let listener =
        std::net::TcpListener::bind(("127.0.0.1", 0)).expect("binds an ephemeral loopback port");
    listener
        .local_addr()
        .expect("the bound listener has an address")
        .port()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonces_are_unique_within_a_run() {
        assert_ne!(nonce(), nonce());
    }

    #[test]
    fn scratch_directories_are_unique_and_removed() {
        let first = Scratch::new("same-tag");
        let second = Scratch::new("same-tag");
        assert_ne!(first.path(), second.path());
        let path = first.path().to_path_buf();
        drop(first);
        assert!(!path.exists(), "Scratch::drop must remove its directory");
        assert!(second.path().exists());
    }

    #[test]
    fn wait_until_observes_a_later_change() {
        let start = Instant::now();
        let became_true = wait_until(Duration::from_secs(1), Duration::from_millis(5), || {
            start.elapsed() >= Duration::from_millis(20)
        });
        assert!(became_true);
    }

    #[test]
    fn the_workspace_root_contains_the_manifest() {
        assert!(workspace_path("Cargo.toml").is_file());
    }
}
