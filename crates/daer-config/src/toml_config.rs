// SPDX-License-Identifier: AGPL-3.0-only

//! The native TOML frontend.
//!
//! # Layout of a configuration
//!
//! Every table is optional and defaults apply, so the smallest valid file is
//! empty. Unknown keys are rejected at every level.
//!
//! ```toml
//! schema = 1
//! include = ["conf.d/*.toml"]
//!
//! [global]
//! tproxy-port = 12345
//! dial-mode = "domain"
//! lan-interface = ["docker0"]
//!
//! [[node]]
//! tag = "edge"
//! url = "vless://…"
//!
//! [[group]]
//! name = "proxy"
//! policy = "min-moving-avg"
//! filters = ["subtag(sub) && !name(keyword: 'ExpireAt:')"]
//!
//! [routing]
//! rules = ["dip(geoip:private) -> direct", "domain(geosite:cn) -> direct"]
//! fallback = "proxy"
//! ```
//!
//! # `include`
//!
//! Each glob is resolved **relative to the file that names it**, and only files
//! under the entry file's directory are accepted — a configuration tree cannot
//! reach out of its own directory. Tables are merged key by key, arrays are
//! concatenated, and a scalar defined twice is an error rather than a silent
//! winner, so an override is always explicit.
//!
//! Merged files lose byte-offset precision: a semantic error found after merging
//! reports the key path, not a line and column. A configuration without
//! `include` keeps full `line:column` diagnostics.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::model::Config;
use crate::validate::{self, ConfigError};

const MAX_INCLUDE_DEPTH: usize = 32;

/// A fully loaded, validated configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Loaded {
    /// The file that was named on the command line.
    pub entry: PathBuf,
    /// Every file that contributed, entry first.
    pub files: Vec<PathBuf>,
    pub config: Config,
    pub warnings: Vec<String>,
}

#[derive(Debug)]
pub enum LoadError {
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    /// `line:column` is embedded in the rendered `toml` error.
    Syntax {
        path: PathBuf,
        source: Box<toml::de::Error>,
    },
    Include {
        path: PathBuf,
        message: String,
    },
    /// A scalar defined by two files of the same tree.
    Conflict {
        key: String,
        first: PathBuf,
        second: PathBuf,
    },
    Invalid {
        path: Option<PathBuf>,
        source: ConfigError,
    },
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(f, "failed to read {}: {source}", path.display())
            }
            Self::Syntax { path, source } => {
                write!(f, "failed to parse {}\n{source}", path.display())
            }
            Self::Include { path, message } => {
                write!(f, "in {}: {message}", path.display())
            }
            Self::Conflict { key, first, second } => write!(
                f,
                "`{key}` is set by both {} and {}; keep it in one file",
                first.display(),
                second.display()
            ),
            Self::Invalid { path, source } => match path {
                Some(path) => write!(f, "invalid configuration in {}: {source}", path.display()),
                None => write!(f, "invalid configuration: {source}"),
            },
        }
    }
}

impl std::error::Error for LoadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Syntax { source, .. } => Some(source),
            Self::Invalid { source, .. } => Some(source),
            Self::Include { .. } | Self::Conflict { .. } => None,
        }
    }
}

/// Reads, merges and validates a configuration tree.
///
/// # Errors
///
/// Returns [`LoadError`] for I/O, TOML syntax, merge conflicts and semantic
/// validation failures.
pub fn load(path: impl AsRef<Path>) -> Result<Loaded, LoadError> {
    let entry = path.as_ref().to_path_buf();
    let root = entry_dir(&entry)?;

    let mut files = vec![entry.clone()];
    let mut seen = HashSet::from([entry.canonicalize().map_err(|source| LoadError::Io {
        path: entry.clone(),
        source,
    })?]);
    let src = read(&entry)?;

    let includes = peek_includes(&src, &entry)?;
    let mut config: Config = if includes.is_empty() {
        toml::from_str(&src).map_err(|source| LoadError::Syntax {
            path: entry.clone(),
            source: Box::new(source),
        })?
    } else {
        let mut owners = HashMap::new();
        let document = parse_value(&src, &entry)?;
        let mut value = Value::Table(toml::Table::new());
        let mut context = Merge {
            root: &root,
            files: &mut files,
            seen: &mut seen,
            owners: &mut owners,
        };
        merge(&mut value, document, "", &entry, 0, &mut context)?;
        Config::deserialize(value).map_err(|source| LoadError::Invalid {
            path: Some(entry.clone()),
            source: ConfigError::new("include", source.to_string()),
        })?
    };
    // `include` is a loader directive: it is kept on the model only so that a
    // round trip through [`to_string`] does not drop it.
    config.include = includes;

    let warnings = validate::normalize(&mut config)
        .map_err(|source| LoadError::Invalid { path: None, source })?;

    Ok(Loaded {
        entry,
        files,
        config,
        warnings,
    })
}

/// Parses a configuration from text, without touching the filesystem.
///
/// `include` is rejected here: it needs a file to be resolved against.
///
/// # Errors
///
/// Returns [`LoadError`] for syntax and semantic errors.
pub fn load_str(src: &str) -> Result<Config, LoadError> {
    let mut config: Config = toml::from_str(src).map_err(|source| LoadError::Syntax {
        path: PathBuf::from("<memory>"),
        source: Box::new(source),
    })?;
    if !config.include.is_empty() {
        return Err(LoadError::Include {
            path: PathBuf::from("<memory>"),
            message: "`include` needs a file to be resolved against".to_owned(),
        });
    }
    validate::normalize(&mut config).map_err(|source| LoadError::Invalid { path: None, source })?;
    Ok(config)
}

/// Renders a configuration in canonical TOML.
///
/// # Panics
///
/// Never in practice: every value in the model is TOML-representable.
#[must_use]
pub fn to_string(config: &Config) -> String {
    toml::to_string_pretty(config).expect("the configuration model is TOML-representable")
}

fn entry_dir(entry: &Path) -> Result<PathBuf, LoadError> {
    let parent = entry
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    parent.canonicalize().map_err(|source| LoadError::Io {
        path: parent,
        source,
    })
}

fn read(path: &Path) -> Result<String, LoadError> {
    fs::read_to_string(path).map_err(|source| LoadError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn parse_value(src: &str, path: &Path) -> Result<Value, LoadError> {
    toml::from_str(src).map_err(|source| LoadError::Syntax {
        path: path.to_path_buf(),
        source: Box::new(source),
    })
}

type Value = toml::Value;

fn peek_includes(src: &str, path: &Path) -> Result<Vec<String>, LoadError> {
    let value = parse_value(src, path)?;
    includes_of(value, path)
}

fn includes_of(mut value: Value, path: &Path) -> Result<Vec<String>, LoadError> {
    let Some(table) = value.as_table_mut() else {
        return Ok(Vec::new());
    };
    let Some(includes) = table.remove("include") else {
        return Ok(Vec::new());
    };
    let array = includes.as_array().ok_or_else(|| LoadError::Include {
        path: path.to_path_buf(),
        message: "`include` must be an array of globs".to_owned(),
    })?;
    array
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or_else(|| LoadError::Include {
                    path: path.to_path_buf(),
                    message: "`include` entries must be strings".to_owned(),
                })
        })
        .collect()
}

/// Ownership of every leaf key, so a conflict can name both files.
type Owners = HashMap<String, PathBuf>;

/// Everything the recursive merge needs besides the two values.
struct Merge<'a> {
    root: &'a Path,
    files: &'a mut Vec<PathBuf>,
    seen: &'a mut HashSet<PathBuf>,
    owners: &'a mut Owners,
}

fn merge(
    target: &mut Value,
    incoming: Value,
    prefix: &str,
    path: &Path,
    depth: usize,
    context: &mut Merge<'_>,
) -> Result<(), LoadError> {
    if depth > MAX_INCLUDE_DEPTH {
        return Err(LoadError::Include {
            path: path.to_path_buf(),
            message: format!("`include` nested deeper than {MAX_INCLUDE_DEPTH} levels"),
        });
    }

    let includes = includes_of(incoming.clone(), path)?;
    // `include` is a loader directive, not part of the configuration: it must
    // not take part in the merge or the conflict checks.
    let mut own = incoming;
    if let Some(table) = own.as_table_mut() {
        table.remove("include");
    }
    merge_values(target, own, prefix, path, context.owners)?;
    if includes.is_empty() {
        return Ok(());
    }

    let base = path.parent().unwrap_or(context.root);
    for glob in includes {
        let pattern = base.join(&glob).to_string_lossy().into_owned();
        let matched = glob::glob(&pattern)
            .map_err(|error| LoadError::Include {
                path: path.to_path_buf(),
                message: format!("invalid include pattern {glob:?}: {error}"),
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| LoadError::Include {
                path: path.to_path_buf(),
                message: format!("cannot read {pattern}: {error}"),
            })?;
        if matched.is_empty() {
            return Err(LoadError::Include {
                path: path.to_path_buf(),
                message: format!("include pattern {glob:?} matched no file"),
            });
        }
        let mut matched = matched;
        matched.sort();
        for file in matched {
            let canonical = file.canonicalize().map_err(|source| LoadError::Io {
                path: file.clone(),
                source,
            })?;
            if !canonical.starts_with(context.root) {
                return Err(LoadError::Include {
                    path: file.clone(),
                    message: format!(
                        "included file is outside the configuration directory {}",
                        context.root.display()
                    ),
                });
            }
            if !context.seen.insert(canonical.clone()) {
                return Err(LoadError::Include {
                    path: file.clone(),
                    message: format!("`include` cycle through {}", canonical.display()),
                });
            }
            context.files.push(canonical.clone());
            let src = read(&canonical)?;
            let document = parse_value(&src, &canonical)?;
            merge(target, document, prefix, &canonical, depth + 1, context)?;
            context.seen.remove(&canonical);
        }
    }
    Ok(())
}

fn merge_values(
    target: &mut Value,
    incoming: Value,
    prefix: &str,
    path: &Path,
    owners: &mut Owners,
) -> Result<(), LoadError> {
    match (target, incoming) {
        (Value::Table(target), Value::Table(source)) => {
            for (key, value) in source {
                let key_path = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                match target.get_mut(&key) {
                    Some(existing) => merge_values(existing, value, &key_path, path, owners)?,
                    None => {
                        target.insert(key, value);
                        record_owner(&key_path, path, owners);
                    }
                }
            }
            Ok(())
        }
        (Value::Array(target), Value::Array(source)) => {
            target.extend(source);
            record_owner(prefix, path, owners);
            Ok(())
        }
        (existing, incoming) => {
            if *existing == incoming {
                return Ok(());
            }
            let key = if prefix.is_empty() { "<root>" } else { prefix };
            Err(LoadError::Conflict {
                key: key.to_owned(),
                first: owners
                    .get(key)
                    .cloned()
                    .unwrap_or_else(|| path.to_path_buf()),
                second: path.to_path_buf(),
            })
        }
    }
}

fn record_owner(key: &str, path: &Path, owners: &mut Owners) {
    owners.insert(key.to_owned(), path.to_path_buf());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_minimal_document_is_valid() {
        let config = load_str("").expect("empty config");
        assert_eq!(config.routing.fallback.to_string(), "direct");
    }

    #[test]
    fn a_syntax_error_carries_a_position() {
        let error = load_str("[global]\ntproxy-port =\n").expect_err("must fail");
        let rendered = error.to_string();
        assert!(rendered.contains("line 2"), "{rendered}");
    }

    #[test]
    fn a_semantic_error_names_the_field() {
        let error = load_str("[dns]\nipversion-prefer = 5\n").expect_err("must fail");
        assert!(
            error.to_string().contains("dns.ipversion-prefer"),
            "{error}"
        );
    }

    #[test]
    fn include_is_rejected_without_a_file() {
        let error = load_str("include = [\"a.toml\"]\n").expect_err("must fail");
        assert!(error.to_string().contains("include"), "{error}");
    }

    #[test]
    fn rendering_round_trips() {
        let config = load_str(
            "[global]\ntproxy-port = 1234\n[[node]]\ntag = \"n\"\nurl = \"ss://x\"\n\
             [routing]\nrules = [\"pname(NetworkManager) -> direct\"]\nfallback = \"direct\"\n",
        )
        .expect("valid");
        let rendered = to_string(&config);
        let reparsed = load_str(&rendered).expect("round trip parses");
        assert_eq!(config, reparsed, "rendered:\n{rendered}");
    }
}
