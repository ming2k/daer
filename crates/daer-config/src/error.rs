// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt;

/// A syntax or lexical error, positioned in the source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub message: String,
    /// 1-based line number.
    pub line: u32,
    /// 0-based column, counted in characters.
    pub column: u32,
    /// Text of the offending line, without its terminator.
    pub line_text: String,
    /// Number of characters to underline, at least 1.
    pub highlight: u32,
}

impl ParseError {
    pub(crate) fn new(
        src: &str,
        offset: usize,
        len_bytes: usize,
        message: impl Into<String>,
    ) -> Self {
        let offset = offset.min(src.len());
        let line_start = src[..offset].rfind('\n').map_or(0, |i| i + 1);
        let line_end = src[offset..].find('\n').map_or(src.len(), |i| offset + i);

        let mut line = src[..offset].matches('\n').count() as u32 + 1;
        let mut column = src[line_start..offset].chars().count() as u32;
        let mut line_text = src[line_start..line_end].trim_end_matches('\r').to_owned();
        let mut highlight = src[offset..(offset + len_bytes).min(line_end)]
            .chars()
            .count()
            .max(1) as u32;

        // A file that ends with a newline puts end-of-input on an empty line.
        // Underlining nothing there is unhelpful, so point at the end of the
        // last line that has content instead.
        if offset == src.len() && line_text.trim().is_empty() && line_start > 0 {
            let previous_end = line_start - 1;
            let previous_start = src[..previous_end].rfind('\n').map_or(0, |i| i + 1);
            let previous = src[previous_start..previous_end].trim_end_matches('\r');
            line -= 1;
            column = previous.chars().count() as u32;
            line_text = previous.to_owned();
            highlight = 1;
        }

        Self {
            message: message.into(),
            line,
            column,
            line_text,
            highlight,
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let prefix = format!("line {}:{} ", self.line, self.column);
        let padding = prefix.chars().count() + self.column as usize;
        writeln!(f, "{prefix}{}", self.line_text)?;
        write!(
            f,
            "{}{}: {}",
            " ".repeat(padding),
            "^".repeat(self.highlight as usize),
            self.message
        )
    }
}

impl std::error::Error for ParseError {}
