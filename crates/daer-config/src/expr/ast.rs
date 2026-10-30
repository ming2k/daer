// SPDX-License-Identifier: AGPL-3.0-only

//! The rule expression AST.
//!
//! Deliberately small: a [`Function`] is a name, an optional negation and its
//! parameters; a [`RoutingRule`] joins a conjunction of functions to an outbound.
//! There is no document-level node type, because a document is TOML.

use std::fmt;

use super::lexer::{Lexer, TokenKind};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Param {
    /// Empty for positional params, e.g. the `geosite:cn` in `domain(geosite:cn)`
    /// has a key while the `cn` in `domain(cn)` does not.
    pub key: String,
    pub value: ParamValue,
    /// Trailing `[...]` annotation, e.g. `-> direct [# comment]`.
    pub annotation: Vec<Param>,
}

impl Param {
    pub fn bare(value: impl Into<String>) -> Self {
        Self {
            key: String::new(),
            value: ParamValue::Literal(value.into()),
            annotation: Vec::new(),
        }
    }

    pub fn literal(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            value: ParamValue::Literal(value.into()),
            annotation: Vec::new(),
        }
    }

    pub fn functions(key: impl Into<String>, functions: Vec<Function>) -> Self {
        Self {
            key: key.into(),
            value: ParamValue::Functions(functions),
            annotation: Vec::new(),
        }
    }

    /// The literal value, when this param is a literal rather than a function
    /// expression.
    pub fn as_literal(&self) -> Option<&str> {
        match &self.value {
            ParamValue::Literal(value) => Some(value),
            ParamValue::Functions(_) => None,
        }
    }

    /// The value without the key, rendered compactly.
    pub fn compact_value(&self) -> String {
        match &self.value {
            ParamValue::Literal(value) => value.clone(),
            ParamValue::Functions(functions) => functions
                .iter()
                .map(|function| function.compact_with(false))
                .collect::<Vec<_>>()
                .join("&&"),
        }
    }

    /// Compact rendering, matching `Param.String(true, false)` in the Go
    /// implementation. Used to flatten list entries such as
    /// `alldns: udp://1.1.1.1:53` into `alldns:udp://1.1.1.1:53`.
    pub fn compact(&self) -> String {
        let mut out = String::new();
        if !self.key.is_empty() {
            out.push_str(&self.key);
            out.push(':');
        }
        out.push_str(&self.compact_value());
        if !self.annotation.is_empty() {
            out.push_str(" [");
            for (index, param) in self.annotation.iter().enumerate() {
                if index != 0 {
                    out.push(',');
                }
                out.push_str(&param.compact());
            }
            out.push(']');
        }
        out
    }
}

impl fmt::Display for Param {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.key.is_empty() {
            write!(f, "{}", self.value)?;
        } else {
            write!(f, "{}: {}", self.key, self.value)?;
        }
        if !self.annotation.is_empty() {
            f.write_str(" [")?;
            for (index, param) in self.annotation.iter().enumerate() {
                if index != 0 {
                    f.write_str(", ")?;
                }
                write!(f, "{param}")?;
            }
            f.write_str("]")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParamValue {
    Literal(String),
    Functions(Vec<Function>),
}

impl fmt::Display for ParamValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Literal(value) => write_literal(f, value),
            Self::Functions(functions) => {
                for (index, function) in functions.iter().enumerate() {
                    if index != 0 {
                        f.write_str(" && ")?;
                    }
                    write!(f, "{function}")?;
                }
                Ok(())
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Function {
    pub name: String,
    pub negated: bool,
    pub params: Vec<Param>,
}

impl Function {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            negated: false,
            params: Vec::new(),
        }
    }

    pub fn with_params(name: impl Into<String>, params: Vec<Param>) -> Self {
        Self {
            name: name.into(),
            negated: false,
            params,
        }
    }

    /// Compact marshalling that also omits empty parameter lists, matching
    /// `MarshalString(true, false, true)` in Go.
    pub fn compact_omit_empty(&self) -> String {
        self.compact_with(true)
    }

    fn compact_with(&self, omit_empty: bool) -> String {
        let mut out = String::new();
        if self.negated {
            out.push('!');
        }
        out.push_str(&self.name);
        if !omit_empty || !self.params.is_empty() {
            out.push('(');
            for (index, param) in self.params.iter().enumerate() {
                if index != 0 {
                    out.push(',');
                }
                out.push_str(&param.compact());
            }
            out.push(')');
        }
        out
    }

    fn write(&self, f: &mut fmt::Formatter<'_>, omit_empty_params: bool) -> fmt::Result {
        if self.negated {
            f.write_str("!")?;
        }
        f.write_str(&self.name)?;
        if !omit_empty_params || !self.params.is_empty() {
            f.write_str("(")?;
            for (index, param) in self.params.iter().enumerate() {
                if index != 0 {
                    f.write_str(", ")?;
                }
                write!(f, "{param}")?;
            }
            f.write_str(")")?;
        }
        Ok(())
    }
}

impl fmt::Display for Function {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.write(f, false)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingRule {
    pub and_functions: Vec<Function>,
    pub outbound: Function,
}

impl fmt::Display for RoutingRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, function) in self.and_functions.iter().enumerate() {
            if index != 0 {
                f.write_str(" && ")?;
            }
            write!(f, "{function}")?;
        }
        f.write_str(" -> ")?;
        self.outbound.write(f, true)
    }
}

fn write_literal(f: &mut fmt::Formatter<'_>, value: &str) -> fmt::Result {
    if is_bare_literal(value) {
        f.write_str(value)
    } else {
        write_quoted(f, value)
    }
}

/// A value can be emitted without quotes only when it lexes to exactly one
/// identifier token; anything else (`a b`, `123.com:60`, the empty string) has
/// to be quoted to survive a round trip.
fn is_bare_literal(value: &str) -> bool {
    let mut lexer = Lexer::new(value);
    match lexer.next_token() {
        Ok(Some(token)) if matches!(token.kind, TokenKind::Id | TokenKind::NonId) => {
            token.end == value.len() && lexer.next_token().is_ok_and(|next| next.is_none())
        }
        _ => false,
    }
}

fn write_quoted(f: &mut fmt::Formatter<'_>, value: &str) -> fmt::Result {
    use fmt::Write as _;

    let quote = if value.contains('\'') && !value.contains('"') {
        '"'
    } else {
        '\''
    };
    f.write_char(quote)?;
    for ch in value.chars() {
        if ch == quote {
            f.write_char('\\')?;
        }
        f.write_char(ch)?;
    }
    f.write_char(quote)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_rules_back_into_parseable_text() {
        let rule = RoutingRule {
            and_functions: vec![Function::with_params(
                "domain",
                vec![Param::literal("geosite", "cn")],
            )],
            outbound: Function::new("direct"),
        };
        assert_eq!(rule.to_string(), "domain(geosite: cn) -> direct");
    }

    #[test]
    fn quotes_values_that_would_not_lex_as_one_literal() {
        assert_eq!(Param::literal("key", "a b").to_string(), "key: 'a b'");
        assert_eq!(
            Param::literal("key", "123.com:60").to_string(),
            "key: '123.com:60'"
        );
        assert_eq!(Param::bare("").to_string(), "''");
        assert_eq!(Param::literal("key", "-1").to_string(), "key: -1");
        assert_eq!(Param::literal("key", "it's").to_string(), "key: \"it's\"");
    }
}
