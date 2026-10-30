// SPDX-License-Identifier: AGPL-3.0-only

//! Locating geodata files, mirroring `common/assets/assets.go`.
//!
//! Search order:
//!
//! 1. `$DAER_LOCATION_ASSET`, then the caller's directories, then the system
//!    directories.
//! 2. Without that variable: the caller's directories (for daer, the config
//!    file's directory), then the XDG data directories.
//!
//! Only `daer` directory names are searched: the assets are daer's, and finding
//! someone else's copy by accident is exactly the kind of implicit dependency
//! this project does not want.

use std::env;
use std::path::{Component, Path, PathBuf};

use crate::error::GeoDataError;

const ASSET_DIR_NAMES: [&str; 1] = ["daer"];
const LOCATION_ENV: &str = "DAER_LOCATION_ASSET";

#[derive(Debug, Clone, Default)]
pub struct LocationFinder {
    extern_dirs: Vec<PathBuf>,
}

impl LocationFinder {
    pub fn new(extern_dirs: Vec<PathBuf>) -> Self {
        Self { extern_dirs }
    }

    /// Returns the first existing `filename` in the search path.
    pub fn find(&self, filename: &str) -> Result<PathBuf, GeoDataError> {
        if filename
            .split(['/', '\\'])
            .any(|component| component == ".." || component == ".")
        {
            return Err(GeoDataError::EscapingFilename(filename.to_owned()));
        }
        if Path::new(filename)
            .components()
            .any(|component| matches!(component, Component::RootDir | Component::Prefix(_)))
        {
            return Err(GeoDataError::EscapingFilename(filename.to_owned()));
        }

        let dirs = self.search_dirs();
        for dir in &dirs {
            let candidate = dir.join(filename);
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
        Err(GeoDataError::NotFound {
            filename: filename.to_owned(),
            dirs,
        })
    }

    fn search_dirs(&self) -> Vec<PathBuf> {
        let mut dirs = Vec::new();
        let location = env::var_os(LOCATION_ENV).filter(|value| !value.is_empty());

        if let Some(location) = location {
            dirs.push(PathBuf::from(location));
            dirs.extend(self.extern_dirs.iter().cloned());
            for base in ["/usr/local/share", "/usr/share"] {
                for name in ASSET_DIR_NAMES {
                    dirs.push(PathBuf::from(base).join(name));
                }
            }
            dirs.extend(self.extern_dirs.iter().cloned());
        } else {
            dirs.extend(self.extern_dirs.iter().cloned());
            dirs.extend(xdg_asset_dirs());
        }

        dirs
    }
}

fn xdg_asset_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();

    let data_home = env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/share")));
    if let Some(data_home) = data_home {
        for name in ASSET_DIR_NAMES {
            dirs.push(data_home.join(name));
        }
    }

    let data_dirs: Vec<PathBuf> = env::var_os("XDG_DATA_DIRS")
        .map(|value| env::split_paths(&value).collect())
        .filter(|dirs: &Vec<PathBuf>| !dirs.is_empty())
        .unwrap_or_else(|| {
            vec![
                PathBuf::from("/usr/local/share"),
                PathBuf::from("/usr/share"),
            ]
        });
    for base in data_dirs {
        for name in ASSET_DIR_NAMES {
            dirs.push(base.join(name));
        }
    }

    dirs
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn finds_files_in_external_directories() {
        let dir = std::env::temp_dir().join(format!("daer-geodata-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("creates dir");
        let path = dir.join("geosite.dat");
        std::fs::File::create(&path)
            .expect("creates file")
            .write_all(b"x")
            .expect("writes");

        let finder = LocationFinder::new(vec![dir.clone()]);
        assert_eq!(finder.find("geosite.dat").expect("finds"), path);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_traversing_filenames() {
        let finder = LocationFinder::new(vec![PathBuf::from("/tmp")]);
        assert!(matches!(
            finder.find("../geosite.dat"),
            Err(GeoDataError::EscapingFilename(_))
        ));
        assert!(matches!(
            finder.find("/etc/geosite.dat"),
            Err(GeoDataError::EscapingFilename(_))
        ));
    }

    #[test]
    fn reports_the_searched_directories() {
        let error = LocationFinder::new(vec![PathBuf::from("/nonexistent-daed")])
            .find("missing.dat")
            .expect_err("must fail");
        let message = error.to_string();
        assert!(message.contains("missing.dat: not found in ["), "{message}");
        assert!(message.contains("/nonexistent-daed"), "{message}");
    }
}
