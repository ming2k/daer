// SPDX-License-Identifier: AGPL-3.0-only

//! Domain pattern representation for Canonical Rule Source (CRS v1).
//!
//! Under ADR-0031, domain routing patterns are strictly hierarchical:
//! * `Suffix(SelfAndSubdomains)`: matches `example.com` and `*.example.com`.
//! * `Suffix(SubdomainsOnly)`: matches `*.example.com` only (written as `suffix: .example.com`).
//! * `Full`: matches `example.com` exactly.
//!
//! Keyword and Regex matching are removed from the core specification: routing decisions
//! on the line-rate hot path require reverse label walk without the negative lookup fallacy.

use std::fmt;
use std::str::FromStr;

use crate::error::AstError;

/// Whether a suffix pattern also matches the bare name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SuffixScope {
    /// `example.com`: matches `example.com` and `a.example.com`.
    SelfAndSubdomains,
    /// `.example.com`: matches only `a.example.com`.
    SubdomainsOnly,
}

impl SuffixScope {
    /// The wider of two scopes. A key declared both ways matches both ways.
    #[must_use]
    pub fn widen(self, other: Self) -> Self {
        if self == Self::SelfAndSubdomains || other == Self::SelfAndSubdomains {
            Self::SelfAndSubdomains
        } else {
            Self::SubdomainsOnly
        }
    }

    /// The marker this scope is written with in text rules.
    #[must_use]
    pub fn marker(self) -> &'static str {
        match self {
            Self::SelfAndSubdomains => "",
            Self::SubdomainsOnly => ".",
        }
    }
}

/// A hierarchical domain pattern.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DomainPattern {
    /// Suffix match, with scope indicating whether bare domain is included.
    Suffix(String, SuffixScope),
    /// Exact full domain match.
    Full(String),
}

impl DomainPattern {
    /// The normalized domain string (without leading scope dots).
    #[must_use]
    pub fn value(&self) -> &str {
        match self {
            Self::Suffix(val, _) | Self::Full(val) => val,
        }
    }

    /// The directive keyword.
    #[must_use]
    pub fn keyword(&self) -> &'static str {
        match self {
            Self::Suffix(..) => "suffix",
            Self::Full(..) => "full",
        }
    }

    /// Validates and lowercases the domain pattern.
    pub fn canonical(self) -> Result<Self, AstError> {
        match self {
            Self::Full(val) => Ok(Self::Full(fold_domain(val, "full")?)),
            Self::Suffix(val, scope) => {
                let trimmed = val.trim();
                let (bare, effective_scope) = match trimmed.strip_prefix('.') {
                    Some(rest) => (rest, SuffixScope::SubdomainsOnly),
                    None => (trimmed, scope),
                };
                Ok(Self::Suffix(fold_domain(bare, "suffix")?, effective_scope))
            }
        }
    }

    /// Builds a pattern from directive kind and value.
    pub fn from_kind(kind: &str, value: &str) -> Result<Self, AstError> {
        let kind = kind.strip_prefix("domain:").unwrap_or(kind);
        let value = value.trim();
        match kind {
            "full" => Ok(Self::Full(value.to_owned())),
            "suffix" | "domain" => {
                let (scope, rest) = match value.strip_prefix('.') {
                    Some(rest) if !rest.starts_with('.') => (SuffixScope::SubdomainsOnly, rest),
                    _ => (SuffixScope::SelfAndSubdomains, value),
                };
                let rest = rest.strip_prefix('+').unwrap_or(rest);
                Ok(Self::Suffix(rest.trim().to_owned(), scope))
            }
            "keyword" | "regex" => Err(AstError::new(format!(
                "'{kind}:' is removed (ADR-0031, ADR-0033); write explicit 'suffix:' or 'full:' patterns."
            ))),
            other => Err(AstError::new(format!(
                "unknown domain rule kind {other:?}; expected 'suffix' or 'full'"
            ))),
        }
    }
}

fn fold_domain(value: impl AsRef<str>, kind: &str) -> Result<String, AstError> {
    let trimmed = value.as_ref().trim().to_ascii_lowercase();
    if trimmed.is_empty() {
        return Err(AstError::new(format!("a {kind} pattern is empty")));
    }
    if let Some(bad) = trimmed.chars().find(|ch| !is_valid_domain_char(*ch)) {
        return Err(AstError::new(format!(
            "{kind} pattern {trimmed:?} contains illegal character {bad:?}"
        )));
    }
    Ok(trimmed)
}

pub fn is_valid_domain_char(ch: char) -> bool {
    (ch.is_ascii() && (ch.is_ascii_lowercase() || ch.is_ascii_digit()))
        || matches!(ch, '.' | '-' | '_' | '^')
}

impl fmt::Display for DomainPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Full(val) => write!(f, "full: {val}"),
            Self::Suffix(val, scope) => write!(f, "suffix: {}{val}", scope.marker()),
        }
    }
}

impl FromStr for DomainPattern {
    type Err = AstError;

    fn from_str(line: &str) -> Result<Self, Self::Err> {
        let Some((key, value)) = line.split_once(':') else {
            return Err(AstError::new(format!(
                "{line:?} is not a domain rule: missing 'suffix:' or 'full:' prefix"
            )));
        };
        Self::from_kind(key.trim(), value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_suffixes_with_scopes() {
        assert_eq!(
            "suffix: example.com".parse::<DomainPattern>().unwrap(),
            DomainPattern::Suffix("example.com".into(), SuffixScope::SelfAndSubdomains)
        );
        assert_eq!(
            "suffix: .example.com".parse::<DomainPattern>().unwrap(),
            DomainPattern::Suffix("example.com".into(), SuffixScope::SubdomainsOnly)
        );
    }

    #[test]
    fn rejects_keyword_and_regex() {
        assert!("keyword: google".parse::<DomainPattern>().is_err());
        assert!("regex: ^.*\\.com$".parse::<DomainPattern>().is_err());
    }
}
