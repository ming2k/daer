// SPDX-License-Identifier: AGPL-3.0-only

//! Recursive-descent parser for the rule expression language.

use super::ast::{DnsRule, Function, MatchExpr, Param, ParamValue};
use super::lexer::{Lexer, Token, TokenKind};
use crate::error::ParseError;

#[derive(Debug)]
pub struct Parser<'a> {
    src: &'a str,
    tokens: Vec<Token<'a>>,
    pos: usize,
}

impl<'a> Parser<'a> {
    pub fn new(src: &'a str) -> Result<Self, ParseError> {
        Ok(Self {
            src,
            tokens: Lexer::new(src).tokenize()?,
            pos: 0,
        })
    }

    /// Parses one routing match (`predicate && …`). The action is a typed field,
    /// not part of the expression.
    pub fn parse_match(&mut self) -> Result<MatchExpr, ParseError> {
        let and_functions = self.parse_function_expression()?;
        self.expect_end("after the match expression")?;
        Ok(MatchExpr::new(and_functions))
    }

    /// Parses one DNS rule (`predicate && … -> upstream`).
    pub fn parse_dns_rule(&mut self) -> Result<DnsRule, ParseError> {
        let and_functions = self.parse_function_expression()?;
        self.expect(TokenKind::Arrow, "'->' in the DNS rule")?;
        let upstream = match self.peek() {
            Some(token)
                if token.kind == TokenKind::Id
                    && self.peek_at(1).map(|next| next.kind) == Some(TokenKind::LParen) =>
            {
                self.parse_function()?
            }
            Some(token) if token.kind.is_literal() => {
                self.pos += 1;
                Function::new(token.literal_value())
            }
            Some(token) => {
                return Err(self.error_at(
                    token,
                    format!(
                        "expected an upstream name or function, found {}",
                        token.kind.describe()
                    ),
                ));
            }
            None => return Err(self.error_eof("expected an upstream after '->'")),
        };
        self.expect_end("after the DNS rule")?;
        Ok(DnsRule {
            and_functions,
            upstream,
        })
    }

    /// Parses a standalone value expression: `min`, `fixed(0)`, `min(10%)`.
    pub fn parse_value(&mut self) -> Result<ParamValue, ParseError> {
        let value = if self.starts_function_expression() {
            ParamValue::Functions(self.parse_function_expression()?)
        } else {
            ParamValue::Literal(self.parse_literal_expression()?)
        };
        self.expect_end("after the value")?;
        Ok(value)
    }

    fn expect_end(&mut self, context: &str) -> Result<(), ParseError> {
        match self.peek() {
            None => Ok(()),
            Some(token) => Err(self.error_at(
                token,
                format!("unexpected {} {context}", token.kind.describe()),
            )),
        }
    }

    fn peek(&self) -> Option<Token<'a>> {
        self.tokens.get(self.pos).copied()
    }

    fn peek_at(&self, offset: usize) -> Option<Token<'a>> {
        self.tokens.get(self.pos + offset).copied()
    }

    fn peek_kind(&self) -> Option<TokenKind> {
        self.peek().map(|token| token.kind)
    }

    fn error_at(&self, token: Token<'a>, message: impl Into<String>) -> ParseError {
        ParseError::new(self.src, token.start, token.end - token.start, message)
    }

    fn error_eof(&self, message: impl Into<String>) -> ParseError {
        ParseError::new(self.src, self.src.len(), 1, message)
    }

    fn expect(&mut self, kind: TokenKind, what: &str) -> Result<Token<'a>, ParseError> {
        match self.peek() {
            Some(token) if token.kind == kind => {
                self.pos += 1;
                Ok(token)
            }
            Some(token) => Err(self.error_at(
                token,
                format!("expected {what}, found {}", token.kind.describe()),
            )),
            None => Err(self.error_eof(format!("expected {what}, found end of input"))),
        }
    }

    fn parse_literal(&mut self) -> Result<String, ParseError> {
        let token = self
            .peek()
            .ok_or_else(|| self.error_eof("expected a literal, found end of input"))?;
        if !token.kind.is_literal() {
            return Err(self.error_at(
                token,
                format!("expected a literal, found {}", token.kind.describe()),
            ));
        }
        self.pos += 1;
        Ok(token.literal_value().to_owned())
    }

    /// `literal (',' literal)*`, joined with commas the way the Go walker does.
    fn parse_literal_expression(&mut self) -> Result<String, ParseError> {
        let mut parts = vec![self.parse_literal()?];
        while self.peek_kind() == Some(TokenKind::Comma) {
            self.pos += 1;
            parts.push(self.parse_literal()?);
        }
        Ok(parts.join(","))
    }

    fn starts_function_expression(&self) -> bool {
        match self.peek_kind() {
            Some(TokenKind::Bang) => true,
            Some(TokenKind::Id) => {
                self.peek_at(1).map(|token| token.kind) == Some(TokenKind::LParen)
            }
            _ => false,
        }
    }

    fn parse_parameters(&mut self) -> Result<Vec<Param>, ParseError> {
        let mut params = vec![self.parse_parameter()?];
        while self.peek_kind() == Some(TokenKind::Comma) {
            self.pos += 1;
            params.push(self.parse_parameter()?);
        }
        Ok(params)
    }

    fn parse_parameter(&mut self) -> Result<Param, ParseError> {
        let has_key = self.peek_kind() == Some(TokenKind::Id)
            && self.peek_at(1).map(|token| token.kind) == Some(TokenKind::Colon);
        if !has_key {
            return Ok(Param::bare(self.parse_literal()?));
        }
        let key = self.expect(TokenKind::Id, "a parameter key")?;
        self.expect(TokenKind::Colon, "':' after the parameter key")?;
        let value = self.parse_literal()?;
        Ok(Param::literal(key.text, value))
    }

    fn parse_function_expression(&mut self) -> Result<Vec<Function>, ParseError> {
        let mut functions = vec![self.parse_function()?];
        while self.peek_kind() == Some(TokenKind::AndAnd) {
            self.pos += 1;
            functions.push(self.parse_function()?);
        }
        Ok(functions)
    }

    fn parse_function(&mut self) -> Result<Function, ParseError> {
        let negated = if self.peek_kind() == Some(TokenKind::Bang) {
            self.pos += 1;
            true
        } else {
            false
        };
        let name = self.expect(TokenKind::Id, "a function name")?;
        self.expect(TokenKind::LParen, "'(' after the function name")?;
        let params = if self.peek_kind() == Some(TokenKind::RParen) {
            Vec::new()
        } else {
            self.parse_parameters()?
        };
        self.expect(TokenKind::RParen, "')' to close the parameter list")?;
        Ok(Function {
            name: name.text.to_owned(),
            negated,
            params,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matches(src: &str) -> MatchExpr {
        Parser::new(src)
            .and_then(|mut parser| parser.parse_match())
            .expect("parses")
    }

    fn error(src: &str) -> ParseError {
        Parser::new(src)
            .and_then(|mut parser| parser.parse_match())
            .expect_err("must fail")
    }

    #[test]
    fn parses_matches_with_negation_and_lists() {
        let parsed = matches("pname(curl) && !dip(1.1.1.1, 'ff00::/8')");
        assert_eq!(parsed.and_functions.len(), 2);
        assert_eq!(parsed.and_functions[0].name, "pname");
        assert!(parsed.and_functions[1].negated);
        assert_eq!(parsed.and_functions[1].params.len(), 2);
    }

    #[test]
    fn parses_keyed_parameters() {
        let parsed = matches("domain(provider:cn)");
        assert_eq!(parsed.and_functions[0].params[0].key, "provider");
        assert_eq!(parsed.and_functions[0].params[0].value.to_string(), "cn");
    }

    #[test]
    fn parses_values() {
        let mut parser = Parser::new("min-moving-avg").expect("lexes");
        assert_eq!(
            parser.parse_value().expect("parses"),
            ParamValue::Literal("min-moving-avg".to_owned())
        );

        let mut parser = Parser::new("fixed(0)").expect("lexes");
        let ParamValue::Functions(functions) = parser.parse_value().expect("parses") else {
            panic!("expected a call");
        };
        assert_eq!(functions[0].name, "fixed");
        assert_eq!(functions[0].params[0].as_literal(), Some("0"));
    }

    #[test]
    fn rejects_trailing_input() {
        let err = error("domain(a), domain(b)");
        assert!(err.message.contains("unexpected"), "{}", err.message);
    }

    #[test]
    fn an_arrow_is_not_part_of_a_match() {
        let err = error("domain(a.com) -> direct");
        assert!(err.message.contains("unexpected"), "{}", err.message);
        assert_eq!(err.line, 1);
    }

    #[test]
    fn reports_unexpected_characters() {
        let err = error("domain(a) >");
        assert!(err.message.contains("'>'"), "{}", err.message);
    }
}
