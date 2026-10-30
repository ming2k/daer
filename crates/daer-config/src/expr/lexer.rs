// SPDX-License-Identifier: AGPL-3.0-only

//! Tokenizer for the rule expression language.
//!
//! Two consequences of the character classes are deliberate and load-bearing:
//!
//! * `#` and `/*` are valid *continuation* characters of an identifier, so
//!   `value#note` is a single identifier and `a/*x*/b` is one identifier too.
//!   Comments only start at a token boundary.
//! * `->` is only recognised when it starts a token, so `f(a)->direct` parses
//!   while `a->b` lexes as `ID("a-")` and then fails: the arrow is never a
//!   subtraction.

use std::fmt;

use crate::error::ParseError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TokenKind {
    Comma,
    LBrace,
    RBrace,
    Colon,
    LBracket,
    RBracket,
    Bang,
    LParen,
    RParen,
    Arrow,
    AndAnd,
    Id,
    NonId,
    QuoteString,
}

impl TokenKind {
    pub fn describe(self) -> &'static str {
        match self {
            Self::Comma => "','",
            Self::LBrace => "'{'",
            Self::RBrace => "'}'",
            Self::Colon => "':'",
            Self::LBracket => "'['",
            Self::RBracket => "']'",
            Self::Bang => "'!'",
            Self::LParen => "'('",
            Self::RParen => "')'",
            Self::Arrow => "'->'",
            Self::AndAnd => "'&&'",
            Self::Id => "identifier",
            Self::NonId => "literal",
            Self::QuoteString => "quoted string",
        }
    }

    pub fn is_literal(self) -> bool {
        matches!(self, Self::Id | Self::NonId | Self::QuoteString)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Token<'a> {
    pub kind: TokenKind,
    /// Raw source slice, including quotes for [`TokenKind::QuoteString`].
    pub text: &'a str,
    pub start: usize,
    pub end: usize,
    /// 1-based.
    pub line: u32,
    /// 0-based, counted in characters.
    pub column: u32,
}

impl Token<'_> {
    /// The literal's value: quoted strings lose their delimiters and keep their
    /// escape sequences verbatim, matching `getValueFromLiteral` in Go.
    pub fn literal_value(&self) -> &str {
        if self.kind == TokenKind::QuoteString {
            &self.text[1..self.text.len() - 1]
        } else {
            self.text
        }
    }
}

fn is_id_head(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_'
}

fn is_non_id_head(b: u8) -> bool {
    b.is_ascii_digit() || matches!(b, b'.' | b'*' | b'+' | b'-' | b'\\' | b'^')
}

fn is_safe_char(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'_' | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'/'
                | b'\\'
                | b'^'
                | b'!'
                | b'#'
                | b'$'
                | b'%'
                | b'='
                | b'@'
        )
}

/// Is `b` a hex digit, as an IPv6 group or a MAC octet is spelled?
fn is_hex(b: u8) -> bool {
    b.is_ascii_hexdigit()
}

/// True when `src[..end]` followed by `:` starts an **address literal**, not a parameter key.
///
/// The grammar has a genuine ambiguity: `domain(suffix:example.com)` is a key and a value, while
/// `mac(aa:bb:cc:dd:ee:ff)` and `dip(2001:db8::1)` are single addresses whose colons are part of
/// the value. A lexer that treated every colon as a separator made those two rules **unwritable**
/// (the parser reported "expected ')' to close the parameter list"), which is how this was found.
///
/// The disambiguation is decidable without knowing the grammar, because the two shapes cannot
/// overlap: an address literal's colon-separated segments are **all hex digits** (possibly
/// empty, for `::`), and every parameter key in the language is a word that is not
/// (`suffix`, `keyword`, `regex`, `full`, `prefix`, …). `suffix:abc.example` is therefore a key,
/// `aa:bb` is an address, and the rule is a property of the bytes rather than of a keyword list
/// that would rot.
fn starts_address_literal(bytes: &[u8], start: usize) -> bool {
    let mut index = start;
    let mut segments = 0usize;
    loop {
        let segment_start = index;
        while index < bytes.len() && is_hex(bytes[index]) {
            index += 1;
        }
        // An IPv6 group is at most four hex digits; a longer run is not a group.
        if index - segment_start > 4 {
            return false;
        }
        segments += 1;
        if bytes.get(index) != Some(&b':') {
            break;
        }
        index += 1;
    }
    // At least two segments, and the first must be non-empty or the whole thing is not an
    // address (`:foo` is not valid anywhere in the language).
    segments >= 2 && index > start && bytes[start] != b':'
}

fn is_whitespace(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\r' | b'\n')
}

pub struct Lexer<'a> {
    src: &'a str,
    bytes: &'a [u8],
    pos: usize,
    line: u32,
    line_start: usize,
}

impl<'a> Lexer<'a> {
    pub fn new(src: &'a str) -> Self {
        Self {
            src,
            bytes: src.as_bytes(),
            pos: 0,
            line: 1,
            line_start: 0,
        }
    }

    /// Returns the next token, or `None` at end of input.
    pub fn next_token(&mut self) -> Result<Option<Token<'a>>, ParseError> {
        self.skip_trivia()?;
        let start = self.pos;
        if start >= self.bytes.len() {
            return Ok(None);
        }

        let line = self.line;
        let column = self.column(start);
        let b = self.bytes[start];

        let (kind, end) = match b {
            b',' => (TokenKind::Comma, start + 1),
            b'{' => (TokenKind::LBrace, start + 1),
            b'}' => (TokenKind::RBrace, start + 1),
            // `::1` / `::/0` — the `::`-leading addresses. This has to be tested *before* the
            // single-colon arm below, or the separator wins and the address never lexes as one
            // value (see `starts_address_literal` for the disambiguation).
            b':' if self.bytes.get(start + 1) == Some(&b':') => {
                (TokenKind::NonId, self.scan_address(start))
            }
            b':' => (TokenKind::Colon, start + 1),
            b'[' => (TokenKind::LBracket, start + 1),
            b']' => (TokenKind::RBracket, start + 1),
            b'(' => (TokenKind::LParen, start + 1),
            b')' => (TokenKind::RParen, start + 1),
            b'!' => (TokenKind::Bang, start + 1),
            b'-' if self.bytes.get(start + 1) == Some(&b'>') => (TokenKind::Arrow, start + 2),
            b'&' if self.bytes.get(start + 1) == Some(&b'&') => (TokenKind::AndAnd, start + 2),
            b'"' | b'\'' => (TokenKind::QuoteString, self.scan_quoted(start)?),
            _ if is_id_head(b) => (TokenKind::Id, self.scan_identifier(start)),
            _ if is_non_id_head(b) => (TokenKind::NonId, self.scan_identifier(start)),
            _ => {
                let ch = self.src[start..].chars().next().unwrap_or('\0');
                return Err(ParseError::new(
                    self.src,
                    start,
                    ch.len_utf8(),
                    format!("unexpected character {ch:?}"),
                ));
            }
        };

        self.advance(end);
        Ok(Some(Token {
            kind,
            text: &self.src[start..end],
            start,
            end,
            line,
            column,
        }))
    }

    /// Tokenizes the whole input.
    pub fn tokenize(mut self) -> Result<Vec<Token<'a>>, ParseError> {
        let mut tokens = Vec::new();
        while let Some(token) = self.next_token()? {
            tokens.push(token);
        }
        Ok(tokens)
    }

    fn column(&self, offset: usize) -> u32 {
        self.src[self.line_start..offset].chars().count() as u32
    }

    /// Moves to `to`, updating line bookkeeping for any newlines crossed.
    fn advance(&mut self, to: usize) {
        debug_assert!((self.pos..=self.bytes.len()).contains(&to));
        for offset in self.pos..to {
            if self.bytes[offset] == b'\n' {
                self.line += 1;
                self.line_start = offset + 1;
            }
        }
        self.pos = to;
    }

    /// Scans a whole address literal, including its colons.
    ///
    /// Used for the `::`-leading forms, which the generic identifier scan cannot reach because
    /// `:` is a separator token there.
    fn scan_address(&self, start: usize) -> usize {
        let mut end = start;
        while end < self.bytes.len() && (is_safe_char(self.bytes[end]) || self.bytes[end] == b':') {
            end += 1;
        }
        end
    }

    fn scan_identifier(&self, start: usize) -> usize {
        let mut end = start;
        while end < self.bytes.len() && is_safe_char(self.bytes[end]) {
            end += 1;
        }
        // Extend over an address literal's colons, so `aa:bb:cc:dd:ee:ff` and
        // `2001:db8::1` survive as one value. See `starts_address_literal` for why this is
        // decidable and why it cannot swallow a parameter key.
        if end > start && starts_address_literal(self.bytes, start) {
            while end < self.bytes.len()
                && (is_safe_char(self.bytes[end]) || self.bytes[end] == b':')
            {
                end += 1;
            }
        }
        end
    }

    fn scan_quoted(&self, start: usize) -> Result<usize, ParseError> {
        let quote = self.bytes[start];
        let mut offset = start + 1;
        while offset < self.bytes.len() {
            if self.bytes[offset] == quote {
                return Ok(offset + 1);
            }
            if self.bytes[offset] == b'\\' && self.bytes.get(offset + 1) == Some(&quote) {
                offset += 2;
            } else {
                offset += 1;
            }
        }
        Err(ParseError::new(
            self.src,
            start,
            1,
            "unterminated quoted string",
        ))
    }

    fn skip_trivia(&mut self) -> Result<(), ParseError> {
        loop {
            let Some(&b) = self.bytes.get(self.pos) else {
                return Ok(());
            };
            if is_whitespace(b) {
                self.advance(self.pos + 1);
            } else if b == b'#' {
                let end = self.bytes[self.pos..]
                    .iter()
                    .position(|&c| c == b'\n')
                    .map_or(self.bytes.len(), |i| self.pos + i + 1);
                self.advance(end);
            } else if self.bytes[self.pos..].starts_with(b"/*") {
                let rest = &self.bytes[self.pos + 2..];
                let Some(close) = rest.windows(2).position(|w| w == b"*/") else {
                    return Err(ParseError::new(
                        self.src,
                        self.pos,
                        2,
                        "unterminated block comment",
                    ));
                };
                self.advance(self.pos + 2 + close + 2);
            } else {
                return Ok(());
            }
        }
    }
}

impl fmt::Debug for Lexer<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Lexer")
            .field("pos", &self.pos)
            .field("line", &self.line)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(src: &str) -> Vec<(TokenKind, &str)> {
        Lexer::new(src)
            .tokenize()
            .expect("tokenizes")
            .into_iter()
            .map(|t| (t.kind, t.text))
            .collect()
    }

    #[test]
    fn an_address_literal_keeps_its_colons() {
        // Both of these were **unwritable** before `starts_address_literal` existed: the lexer
        // stopped at the first colon, the parser then reported "expected ')' to close the
        // parameter list", and `daer` could not express a MAC or IPv6 rule at all. Asserting the
        // token shape (not just "it parses") is what keeps the separator from coming back.
        assert_eq!(
            kinds("mac(aa:bb:cc:dd:ee:ff)"),
            vec![
                (TokenKind::Id, "mac"),
                (TokenKind::LParen, "("),
                (TokenKind::Id, "aa:bb:cc:dd:ee:ff"),
                (TokenKind::RParen, ")"),
            ]
        );
        assert_eq!(
            kinds("dip(2001:db8::/32)"),
            vec![
                (TokenKind::Id, "dip"),
                (TokenKind::LParen, "("),
                (TokenKind::NonId, "2001:db8::/32"),
                (TokenKind::RParen, ")"),
            ]
        );
        assert_eq!(
            kinds("dip(::1)"),
            vec![
                (TokenKind::Id, "dip"),
                (TokenKind::LParen, "("),
                (TokenKind::NonId, "::1"),
                (TokenKind::RParen, ")"),
            ]
        );
    }

    #[test]
    fn a_named_parameter_key_is_still_a_key() {
        // The other half of the ambiguity: every key in the language is a word whose colon
        // follows a non-hex run, so the address rule must not swallow it.
        for (src, key, value, kind) in [
            ("suffix:example.com", "suffix", "example.com", TokenKind::Id),
            ("keyword:example", "keyword", "example", TokenKind::Id),
            // A regex starts with `^`, which is a non-identifier literal head.
            ("regex:^a.*b$", "regex", "^a.*b$", TokenKind::NonId),
            (
                "full:www.example.com",
                "full",
                "www.example.com",
                TokenKind::Id,
            ),
        ] {
            assert_eq!(
                kinds(src),
                vec![(TokenKind::Id, key), (TokenKind::Colon, ":"), (kind, value)],
                "{src}"
            );
        }
    }

    #[test]
    fn a_parameter_key_is_not_confused_with_a_short_address() {
        // `ab:cd` *is* shaped like an address (two hex segments) and is also shaped like a key
        // with a hex value. It resolves as an address, which is the correct precedence: no
        // routing function has a parameter key spelled with hex digits, while `mac(...)` must
        // accept exactly this form.
        assert_eq!(
            kinds("ab:cd"),
            vec![(TokenKind::Id, "ab:cd")],
            "a hex pair joined by a colon is one value, not a key and a separator"
        );
    }

    #[test]
    fn arrow_wins_over_non_id_at_token_start() {
        assert_eq!(
            kinds("domain(a)->direct"),
            vec![
                (TokenKind::Id, "domain"),
                (TokenKind::LParen, "("),
                (TokenKind::Id, "a"),
                (TokenKind::RParen, ")"),
                (TokenKind::Arrow, "->"),
                (TokenKind::Id, "direct"),
            ]
        );
    }

    #[test]
    fn identifier_absorbs_arrow_without_parens() {
        let error = Lexer::new("a->b").tokenize().unwrap_err();
        assert_eq!(error.line, 1);
        assert_eq!(error.column, 2);
    }

    #[test]
    fn comments_only_start_at_token_boundaries() {
        assert_eq!(
            kinds("key: abc#comment"),
            vec![
                (TokenKind::Id, "key"),
                (TokenKind::Colon, ":"),
                (TokenKind::Id, "abc#comment")
            ]
        );
        assert_eq!(kinds("a/*x*/b"), vec![(TokenKind::Id, "a/*x*/b")]);
        assert_eq!(
            kinds("key: 'a#b' # trailing"),
            vec![
                (TokenKind::Id, "key"),
                (TokenKind::Colon, ":"),
                (TokenKind::QuoteString, "'a#b'"),
            ]
        );
    }

    #[test]
    fn bare_literals_and_ip_addresses() {
        assert_eq!(kinds("1.2.3.4")[0], (TokenKind::NonId, "1.2.3.4"));
        assert_eq!(kinds("-1")[0], (TokenKind::NonId, "-1"));
        assert_eq!(kinds("foo-bar")[0], (TokenKind::Id, "foo-bar"));
        assert_eq!(kinds("a@b=c%d$e")[0], (TokenKind::Id, "a@b=c%d$e"));
    }

    #[test]
    fn quoted_strings_keep_escapes_verbatim() {
        assert_eq!(
            kinds(r#"key:"x\"y""#)[2],
            (TokenKind::QuoteString, r#""x\"y""#)
        );
        assert_eq!(
            kinds(r#"key:"x\"y""#)[2].1[1..4].to_owned(),
            r#"x\""#.to_owned()
        );
    }

    #[test]
    fn tracks_lines_and_columns_in_characters() {
        let tokens = Lexer::new("a\n  b").tokenize().unwrap();
        assert_eq!((tokens[1].line, tokens[1].column), (2, 2));
        let tokens = Lexer::new("\"é\"\n\"é\"").tokenize().unwrap();
        assert_eq!((tokens[1].line, tokens[1].column), (2, 0));
    }
}
