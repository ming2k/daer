// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt;

/// A routing configuration error.
///
/// Messages mirror the Go implementation where a user can see them (rule
/// lowering happens during `validate` and `run`), so that switching binaries
/// does not change the diagnosis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingError {
    pub message: String,
}

impl RoutingError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    pub(crate) fn context(self, prefix: impl fmt::Display) -> Self {
        Self {
            message: format!("{prefix}: {}", self.message),
        }
    }
}

impl fmt::Display for RoutingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for RoutingError {}
