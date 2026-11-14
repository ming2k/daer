// SPDX-License-Identifier: AGPL-3.0-only

//! Private filesystem helpers for daemon-written artifacts.
//!
//! Runtime snapshots, incident bundles, and subscription caches can contain node
//! credentials or per-flow metadata. The systemd unit sets `UMask=0077`, but a
//! foreground `daer run` or `daer check` does not inherit that setting, so the
//! daemon must set the mode itself rather than relying on the caller's umask.
//!
//! These helpers are deliberately narrow: they create directories with `0700`
//! and files with `0600`, and they register the mode on the file descriptor at
//! creation time so a short window with `0666 & !umask` does not exist.

use std::fs::{File, OpenOptions, Permissions};
use std::io::{self, Write as _};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::Path;

/// Creates `path` if needed and makes it private (`0700`).
///
/// # Errors
///
/// Returns the `mkdir` or `chmod` failure. A daemon that cannot make its runtime
/// directory private must not continue writing credentials into it.
pub(crate) fn ensure_dir(path: &Path) -> io::Result<()> {
    std::fs::create_dir_all(path)?;
    std::fs::set_permissions(path, Permissions::from_mode(0o700))
}

/// Opens `path` for writing with mode `0600`.
///
/// `truncate` is explicit because the event stream is truncated on every daemon
/// start while a cache file is replaced atomically. The mode is applied both at
/// creation and to an existing file, so a file created by an older build is
/// tightened the next time it is written.
pub(crate) fn open_private(path: &Path, truncate: bool) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).write(true).mode(0o600);
    if truncate {
        options.truncate(true);
    } else {
        options.append(true);
    }
    let file = options.open(path)?;
    std::fs::set_permissions(path, Permissions::from_mode(0o600))?;
    Ok(file)
}

/// Writes `bytes` to `path`, creating parent directories as private and the file
/// as `0600`.
///
/// # Errors
///
/// Returns the first directory, open, write, or sync failure.
pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        ensure_dir(parent)?;
    }
    let mut file = open_private(path, true)?;
    file.write_all(bytes)?;
    file.sync_all()
}

/// Writes `bytes` through a same-directory temporary file and renames it into
/// place, so a crash cannot leave a truncated snapshot.
///
/// # Errors
///
/// Returns the first directory, open, write, sync, or rename failure.
pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        ensure_dir(parent)?;
    }
    let temporary = path.with_extension(format!(
        "{}tmp.{}",
        path.extension()
            .and_then(|extension| extension.to_str())
            .map_or_else(String::new, |extension| format!("{extension}.")),
        std::process::id()
    ));
    let result = write_private(&temporary, bytes).and_then(|()| std::fs::rename(&temporary, path));
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_private_file_and_its_directory_are_not_group_or_world_accessible() {
        let directory = std::env::temp_dir().join(format!(
            "daer-private-fs-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let _ = std::fs::remove_dir_all(&directory);
        let file = directory.join("state.json");
        write_atomic(&file, b"{}").expect("writes");

        let directory_mode = std::fs::metadata(&directory)
            .expect("directory metadata")
            .permissions()
            .mode()
            & 0o777;
        let file_mode = std::fs::metadata(&file)
            .expect("file metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(directory_mode, 0o700, "directory mode");
        assert_eq!(file_mode, 0o600, "file mode");
        let _ = std::fs::remove_dir_all(&directory);
    }
}
