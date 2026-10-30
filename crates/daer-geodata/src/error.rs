// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub enum GeoDataError {
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    Invalid(String),
    CodeNotFound {
        label: &'static str,
        code: String,
        path: PathBuf,
    },
    NotFound {
        filename: String,
        dirs: Vec<PathBuf>,
    },
    EscapingFilename(String),
    InverseMatch,
}

impl GeoDataError {
    pub(crate) fn invalid(reason: &str) -> Self {
        Self::Invalid(reason.to_owned())
    }

    pub(crate) fn invalid_owned(reason: String) -> Self {
        Self::Invalid(reason)
    }
}

impl fmt::Display for GeoDataError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(f, "failed to open file: {}: {source}", path.display())
            }
            Self::Invalid(reason) => write!(f, "invalid geodata file: {reason}"),
            Self::CodeNotFound { label, code, path } => {
                write!(f, "{label} {code} not found in {}", path.display())
            }
            Self::NotFound { filename, dirs } => {
                let dirs: Vec<String> = dirs.iter().map(|dir| dir.display().to_string()).collect();
                write!(f, "{filename}: not found in [{}]", dirs.join(", "))
            }
            Self::EscapingFilename(filename) => {
                write!(f, "asset filename escapes search directory: {filename}")
            }
            Self::InverseMatch => f.write_str("not support inverse match yet"),
        }
    }
}

impl std::error::Error for GeoDataError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

pub(crate) fn read_file(path: &Path) -> Result<Vec<u8>, GeoDataError> {
    std::fs::read(path).map_err(|source| GeoDataError::Io {
        path: path.to_path_buf(),
        source,
    })
}
