// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt;

/// A rule set that could not be represented, or text that could not be read.
///
/// Every message names the line when the input was text, because a 100,000-line rule
/// dump is only actionable if the failure says where it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AstError {
    line: Option<usize>,
    message: String,
}

impl AstError {
    /// An error about the whole set rather than one line.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            line: None,
            message: message.into(),
        }
    }

    /// An error attributable to `line` (1-based) of a text rule set.
    pub fn at_line(line: usize, message: impl Into<String>) -> Self {
        Self {
            line: Some(line),
            message: message.into(),
        }
    }

    /// The 1-based source line, when the error has one.
    #[must_use]
    pub fn line(&self) -> Option<usize> {
        self.line
    }

    /// The message without the line prefix.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for AstError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.line {
            Some(line) => write!(f, "line {line}: {}", self.message),
            None => f.write_str(&self.message),
        }
    }
}

impl std::error::Error for AstError {}
