// SPDX-License-Identifier: AGPL-3.0-only

//! Runtime election overrides: `daer elect <election> <node>`.
//!
//! An override is deliberately not a second configuration. It records that an
//! operator has chosen a node for one election, survives reloads by name, and is
//! cleared by `daer elect --reset`. The file lives under `/var/lib/daer` because it
//! is persistent variable state, not configuration and not runtime scratch.
//!
//! # Why the daemon owns the file
//!
//! A non-root operator must not be able to edit this file directly: that would
//! bypass the admin socket and make the socket's authorization meaningless. The
//! daemon writes it atomically; the CLI only asks the daemon to change it.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, RwLock};

const SCHEMA: u32 = 1;

/// The persistent path chosen by the FHS.
pub const DEFAULT_STATE_PATH: &str = "/var/lib/daer/elections.json";

/// The file format. Only overrides are stored; absence means "follow the configured
/// election".
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct State {
    schema: u32,
    #[serde(default)]
    elections: Vec<Entry>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct Entry {
    election: String,
    node: String,
}

/// The in-memory override map plus the file that backs it.
#[derive(Debug)]
pub struct ElectionOverrides {
    inner: RwLock<HashMap<String, String>>,
    path: Option<PathBuf>,
    write: Mutex<()>,
}

impl Default for ElectionOverrides {
    fn default() -> Self {
        Self::memory()
    }
}

impl ElectionOverrides {
    /// Overrides that never touch the filesystem. Tests and diagnostics use this.
    #[must_use]
    pub fn memory() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
            path: None,
            write: Mutex::new(()),
        }
    }

    /// Loads overrides from `path`, or the FHS default when `None`.
    ///
    /// A missing file is the normal "nothing pinned" state. A corrupt or
    /// unknown-schema file is reported and ignored: a state file must never be able
    /// to take the proxy down. It is not overwritten until the next successful
    /// election change.
    #[must_use]
    pub fn load(path: Option<PathBuf>) -> Self {
        let path = path.or_else(default_path);
        let mut map = HashMap::new();
        if let Some(path) = &path
            && let Ok(text) = std::fs::read_to_string(path)
        {
            match serde_json::from_str::<State>(&text) {
                Ok(state) if state.schema == SCHEMA => {
                    for entry in state.elections {
                        map.insert(entry.election, entry.node);
                    }
                }
                Ok(state) => daer_observe::warn!(
                    daer_observe::EventCode::ElectionStateRejected,
                    path = %path.display(),
                    schema = state.schema,
                    expected = SCHEMA,
                    "election state has an unknown schema; ignoring it"
                ),
                Err(error) => daer_observe::warn!(
                    daer_observe::EventCode::ElectionStateRejected,
                    path = %path.display(),
                    %error,
                    "election state is not readable JSON; ignoring it"
                ),
            }
        }
        Self {
            inner: RwLock::new(map),
            path,
            write: Mutex::new(()),
        }
    }

    /// Builds a memory-backed set with the given entries, for tests and fixtures.
    #[must_use]
    pub fn from_entries(entries: impl IntoIterator<Item = (String, String)>) -> Self {
        Self {
            inner: RwLock::new(entries.into_iter().collect()),
            path: None,
            write: Mutex::new(()),
        }
    }

    /// The node pinned for `election`, if any.
    #[must_use]
    pub fn get(&self, election: &str) -> Option<String> {
        self.inner
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .get(election)
            .cloned()
    }

    /// Every override, sorted by election name.
    #[must_use]
    pub fn snapshot(&self) -> Vec<(String, String)> {
        let map = self.inner.read().unwrap_or_else(|error| error.into_inner());
        let mut out: Vec<(String, String)> = map
            .iter()
            .map(|(election, node)| (election.clone(), node.clone()))
            .collect();
        out.sort();
        out
    }

    /// Replaces the override for `election` and persists the whole map.
    ///
    /// Persistence happens before the in-memory change. If the write fails, the
    /// caller sees an error and the running election is unchanged; a command that
    /// says "pinned" must mean "pinned and remembered".
    pub fn set(&self, election: &str, node: &str) -> Result<(), String> {
        let _guard = self.write.lock().unwrap_or_else(|error| error.into_inner());
        let mut next = self.snapshot_map();
        next.insert(election.to_owned(), node.to_owned());
        self.persist(&next)?;
        *self
            .inner
            .write()
            .unwrap_or_else(|error| error.into_inner()) = next;
        Ok(())
    }

    /// Removes the override for `election` and persists the map.
    pub fn remove(&self, election: &str) -> Result<(), String> {
        let _guard = self.write.lock().unwrap_or_else(|error| error.into_inner());
        let mut next = self.snapshot_map();
        if next.remove(election).is_none() {
            return Ok(());
        }
        self.persist(&next)?;
        *self
            .inner
            .write()
            .unwrap_or_else(|error| error.into_inner()) = next;
        Ok(())
    }

    /// Drops entries that the current generation cannot honour, then persists.
    ///
    /// This is called after a reload. A pin whose election or node disappeared must
    /// not survive as an invisible failure; it is removed and reported. A persist
    /// failure here is a warning rather than a startup failure: the proxy still
    /// serves, and the next change retries the write.
    pub fn retain_valid(&self, mut valid: impl FnMut(&str, &str) -> bool) {
        let _guard = self.write.lock().unwrap_or_else(|error| error.into_inner());
        let mut next = self.snapshot_map();
        let before = next.len();
        next.retain(|election, node| valid(election, node));
        if next.len() == before {
            return;
        }
        for (election, node) in self.snapshot_map() {
            if !next.contains_key(&election) {
                daer_observe::warn!(
                    daer_observe::EventCode::ElectionOverridePruned,
                    election = %election,
                    node = %node,
                    "election override no longer names a valid candidate; cleared"
                );
            }
        }
        if let Err(error) = self.persist(&next) {
            daer_observe::warn!(
                daer_observe::EventCode::ElectionStateWriteFailed,
                %error,
                "could not persist the pruned election state; the running map is still corrected"
            );
        }
        *self
            .inner
            .write()
            .unwrap_or_else(|error| error.into_inner()) = next;
    }

    fn snapshot_map(&self) -> HashMap<String, String> {
        self.inner
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
    }

    fn persist(&self, map: &HashMap<String, String>) -> Result<(), String> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let mut elections: Vec<Entry> = map
            .iter()
            .map(|(election, node)| Entry {
                election: election.clone(),
                node: node.clone(),
            })
            .collect();
        elections.sort_by(|a, b| a.election.cmp(&b.election));
        let state = State {
            schema: SCHEMA,
            elections,
        };
        let text = serde_json::to_vec_pretty(&state)
            .map_err(|error| format!("could not encode election state: {error}"))?;
        write_atomic(path, &text)
    }
}

fn default_path() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("DAER_ELECTION_STATE")
        && !path.is_empty()
    {
        return Some(PathBuf::from(path));
    }
    Some(PathBuf::from(DEFAULT_STATE_PATH))
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)
        .map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
    let temporary = path.with_extension(format!("json.tmp.{}", std::process::id()));
    let result = (|| {
        std::fs::write(&temporary, bytes)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600))?;
        }
        std::fs::rename(&temporary, path)?;
        Ok::<(), std::io::Error>(())
    })();
    if let Err(error) = result {
        let _ = std::fs::remove_file(&temporary);
        return Err(format!("cannot write {}: {error}", path.display()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "daer-election-{name}-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ))
    }

    #[test]
    fn an_override_round_trips_through_the_file() {
        let path = temp_path("roundtrip");
        let state = ElectionOverrides::load(Some(path.clone()));
        state.set("proxy", "hk-01").expect("persists");
        let loaded = ElectionOverrides::load(Some(path.clone()));
        assert_eq!(loaded.get("proxy").as_deref(), Some("hk-01"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn a_corrupt_file_is_ignored_not_fatal() {
        let path = temp_path("corrupt");
        std::fs::write(&path, b"{not json").expect("writes");
        let state = ElectionOverrides::load(Some(path.clone()));
        assert!(state.snapshot().is_empty());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn removing_an_absent_override_is_idempotent() {
        let state = ElectionOverrides::memory();
        state.remove("proxy").expect("no-op");
        assert!(state.snapshot().is_empty());
    }

    #[test]
    fn retain_valid_prunes_invalid_entries() {
        let state = ElectionOverrides::from_entries([
            ("proxy".to_owned(), "hk-01".to_owned()),
            ("gone".to_owned(), "jp-02".to_owned()),
        ]);
        state.retain_valid(|election, _| election == "proxy");
        assert_eq!(
            state.snapshot(),
            vec![("proxy".to_owned(), "hk-01".to_owned())]
        );
    }
}
