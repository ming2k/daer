// SPDX-License-Identifier: AGPL-3.0-only

//! Credential redaction by type.
//!
//! A proxy link can carry a password, a UUID, a Trojan secret or a REALITY key in its
//! userinfo, query string or fragment. A diagnostic that prints the link turns a bug report
//! into a credential disclosure. The rule is structural: the only way to carry a link into a
//! log, event or incident bundle is [`RedactedLink`], and the only thing it preserves is the
//! scheme — the one part that cannot be a secret and the part an operator needs to know why the
//! link was rejected.

use std::fmt;

/// A link reduced to its scheme and an explicit redaction marker.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RedactedLink {
    scheme: String,
}

impl RedactedLink {
    /// Redacts a URI, keeping only a syntactically plausible scheme.
    ///
    /// If the input has no `://`, the whole value is redacted. A scheme longer than 32 bytes or
    /// containing anything other than ASCII letters, digits, `+`, `-` or `.` is not a scheme;
    /// returning it would risk echoing arbitrary attacker-controlled text.
    #[must_use]
    pub fn new(link: &str) -> Self {
        let scheme = link
            .split_once("://")
            .map(|(scheme, _)| scheme)
            .filter(|scheme| {
                !scheme.is_empty()
                    && scheme.len() <= 32
                    && scheme
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
            })
            .unwrap_or("unknown");
        Self {
            scheme: scheme.to_owned(),
        }
    }

    /// The scheme, for a field that needs to distinguish `ss` from `tuic`.
    #[must_use]
    pub fn scheme(&self) -> &str {
        &self.scheme
    }
}

impl fmt::Display for RedactedLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}://<redacted>", self.scheme)
    }
}

/// Redacts any URI-shaped token in free-form text.
///
/// Panic messages and transport errors are not typed; a user-supplied URL can still reach
/// them. This is the last line of defence for an incident manifest: it is not a substitute
/// for `RedactedLink` at a log call site, and it cannot recognise every possible secret.
#[must_use]
pub fn redact_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for token in text.split_inclusive(char::is_whitespace) {
        let trimmed = token.trim_end_matches(char::is_whitespace);
        let suffix = &token[trimmed.len()..];
        if trimmed.contains("://") {
            out.push_str(&RedactedLink::new(trimmed).to_string());
        } else {
            out.push_str(trimmed);
        }
        out.push_str(suffix);
    }
    out
}

/// A value that must never be printed, serialized or formatted.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret<T>(T);

impl<T> Secret<T> {
    /// Wraps a secret.
    pub const fn new(value: T) -> Self {
        Self(value)
    }

    /// Exposes the value to the one caller that actually needs it.
    ///
    /// The method name is deliberate: every call site reads as a privilege escalation and is
    /// easy to review.
    pub fn expose(&self) -> &T {
        &self.0
    }
}

impl<T> fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

impl<T> fmt::Display for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_link_with_userinfo_is_reduced_to_its_scheme() {
        let link = RedactedLink::new("tuic://user:hunter2@192.0.2.1:443#node");
        assert_eq!(link.to_string(), "tuic://<redacted>");
        assert!(!link.to_string().contains("hunter2"));
        assert_eq!(link.scheme(), "tuic");
    }

    #[test]
    fn a_link_with_a_password_in_the_query_is_reduced_to_its_scheme() {
        let link = RedactedLink::new("ss://aes-256-gcm:hunter2@host:443?plugin=obfs#tag");
        let rendered = link.to_string();
        assert_eq!(rendered, "ss://<redacted>");
        assert!(!rendered.contains("hunter2"));
    }

    #[test]
    fn a_non_uri_is_fully_redacted() {
        let link = RedactedLink::new("hunter2");
        assert_eq!(link.to_string(), "unknown://<redacted>");
        assert!(!link.to_string().contains("hunter2"));
    }

    #[test]
    fn a_hostile_scheme_is_not_echoed() {
        let link = RedactedLink::new("bad scheme\nwith newline://host");
        assert_eq!(link.to_string(), "unknown://<redacted>");
    }

    #[test]
    fn a_uri_inside_free_form_text_is_redacted() {
        let text = "failed to parse ss://aes-256-gcm:hunter2@host:443 while loading";
        let redacted = redact_text(text);
        assert!(!redacted.contains("hunter2"), "{redacted}");
        assert!(redacted.contains("ss://<redacted>"), "{redacted}");
    }

    #[test]
    fn a_secret_is_redacted_in_both_debug_and_display() {
        let secret = Secret::new("hunter2");
        assert!(!format!("{secret:?}").contains("hunter2"));
        assert!(!format!("{secret}").contains("hunter2"));
        assert_eq!(*secret.expose(), "hunter2");
    }
}
