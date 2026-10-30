// SPDX-License-Identifier: AGPL-3.0-only

//! The rule expression language.
//!
//! daer's configuration is TOML. Three things in it are *expressions* rather than
//! data, and they share one grammar:
//!
//! | Where | Shape | Example |
//! | --- | --- | --- |
//! | `routing.rules` | `predicate && … -> outbound` | `domain(suffix: a.com) && port(443) -> proxy` |
//! | `group.filters` | `predicate && …` | `subtag(sub) && !name(keyword: 'ExpireAt:')` |
//! | `group.policy`, `dns.*.fallback` | name or call | `fixed(0)`, `min-moving-avg` |
//!
//! They stay expressions because a boolean combination over arbitrary predicates
//! has no faithful tabular encoding, and because the parsed form — a
//! [`RoutingRule`] / [`Function`] tree — is exactly what the routing engine
//! consumes. Everything else in the configuration is data.
//!
//! ```text
//! rule                := predicate ('&&' predicate)* '->' outbound
//! predicate           := '!'? name '(' (parameter (',' parameter)*)? ')'
//! outbound            := literal | predicate
//! parameter           := name ':' literal | literal
//! value               := literal (',' literal)* | predicate ('&&' predicate)*
//! literal             := NAME | OTHER | QUOTED
//! name                := [A-Za-z0-9_./+-]+
//! ```
//!
//! Two properties matter for error quality:
//!
//! * a comment starts only at a token boundary, so `a#b` is one identifier and not
//!   "identifier, comment";
//! * `->` wins over a bare `-` at token start, so `f(a)->direct` parses and
//!   `a->b` is a syntax error rather than a subtraction.

mod ast;
mod lexer;
mod parser;

pub use ast::{Function, Param, ParamValue, RoutingRule};
pub use lexer::{Lexer, Token, TokenKind};
pub use parser::Parser;

use crate::error::ParseError;

/// Parses one routing rule.
///
/// # Errors
///
/// Returns a positioned [`ParseError`] when the text is not a rule, including
/// when it holds more than one.
pub fn parse_rule(src: &str) -> Result<RoutingRule, ParseError> {
    Parser::new(src)?.parse_rule()
}

/// Parses one value: a bare name (`min-moving-avg`) or a call (`fixed(0)`).
///
/// # Errors
///
/// Returns a positioned [`ParseError`] when the text is neither.
pub fn parse_value(src: &str) -> Result<ParamValue, ParseError> {
    Parser::new(src)?.parse_value()
}

/// Parses a filter line: one or more predicates joined by `&&`.
///
/// # Errors
///
/// Returns a message rendered for a fragment, not for a whole file.
pub fn parse_filter(src: &str) -> Result<Vec<Function>, String> {
    match parse_value(src).map_err(|error| render_fragment_error(src, &error))? {
        ParamValue::Functions(functions) => Ok(functions),
        ParamValue::Literal(name) => Err(format!(
            "invalid filter {src:?}: expected a predicate such as `pname(curl)`, got the bare name `{name}`"
        )),
    }
}

/// Renders an expression error against the expression text instead of against a
/// file line, which is what a caller that embedded the expression wants to show.
#[must_use]
pub fn render_fragment_error(src: &str, error: &ParseError) -> String {
    let prefix = format!("line {}:{} ", error.line, error.column);
    let padding = " ".repeat(prefix.chars().count() + error.column as usize);
    format!(
        "invalid expression {src:?}\n{prefix}{src}\n{padding}{}: {}",
        "^".repeat(error.highlight as usize),
        error.message
    )
}

/// Renders a predicate conjunction back into expression text.
#[must_use]
pub fn render_functions(functions: &[Function]) -> String {
    functions
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(" && ")
}
