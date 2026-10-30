// SPDX-License-Identifier: AGPL-3.0-only

//! Go-compatible duration and scalar parsing.
//!
//! The Go implementation decodes configuration values with
//! `strconv.ParseInt(val, 0, …)` and `time.ParseDuration`, and accepts a loose
//! set of boolean spellings. Configs in the wild rely on that leniency, so the
//! same rules are reproduced here rather than using `str::parse`.

use std::fmt;
use std::time::Duration;

/// A signed duration, mirroring Go's `time.Duration`.
///
/// Some options legitimately take a negative value (`check_tolerance` shifts the
/// switch threshold), so `std::time::Duration` is not sufficient.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct TimeSpan {
    nanos: i64,
}

impl TimeSpan {
    pub const ZERO: Self = Self { nanos: 0 };

    pub const fn from_nanos(nanos: i64) -> Self {
        Self { nanos }
    }

    pub const fn from_millis(millis: i64) -> Self {
        Self {
            nanos: millis.saturating_mul(1_000_000),
        }
    }

    pub const fn from_secs(secs: i64) -> Self {
        Self {
            nanos: secs.saturating_mul(1_000_000_000),
        }
    }

    pub const fn as_nanos(self) -> i64 {
        self.nanos
    }

    pub const fn is_negative(self) -> bool {
        self.nanos < 0
    }

    pub const fn is_zero(self) -> bool {
        self.nanos == 0
    }

    /// The value as a std duration, when it is not negative.
    pub fn as_std(self) -> Option<Duration> {
        u64::try_from(self.nanos).ok().map(Duration::from_nanos)
    }
}

impl std::ops::Add for TimeSpan {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self::from_nanos(self.nanos + rhs.nanos)
    }
}

impl std::ops::Sub for TimeSpan {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        Self::from_nanos(self.nanos - rhs.nanos)
    }
}

impl std::ops::AddAssign for TimeSpan {
    fn add_assign(&mut self, rhs: Self) {
        self.nanos += rhs.nanos;
    }
}

impl std::fmt::Display for TimeSpan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let nanos = self.nanos;
        let sign = if nanos < 0 { "-" } else { "" };
        let mut rest = nanos.unsigned_abs();
        if rest == 0 {
            return write!(f, "0s");
        }
        let units = [
            ("h", 3_600_000_000_000u64),
            ("m", 60_000_000_000),
            ("s", 1_000_000_000),
            ("ms", 1_000_000),
            ("µs", 1_000),
            ("ns", 1),
        ];
        let mut out = String::new();
        out.push_str(sign);
        for (suffix, scale) in units {
            if rest >= scale {
                let whole = rest / scale;
                let remainder = rest % scale;
                if remainder == 0 {
                    out.push_str(&format!("{whole}{suffix}"));
                    return f.write_str(&out);
                }
                if suffix == "ns" {
                    out.push_str(&format!("{whole}{suffix}"));
                    return f.write_str(&out);
                }
                out.push_str(&format!("{whole}{suffix}"));
                rest = remainder;
            }
        }
        f.write_str(&out)
    }
}

/// Parses a Go duration literal: `30s`, `50ms`, `1h30m`, `0`, `-500ms`.
pub fn parse_duration(value: &str) -> Option<TimeSpan> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    let (negative, rest) = match value.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, value.strip_prefix('+').unwrap_or(value)),
    };
    if rest == "0" {
        return Some(TimeSpan::ZERO);
    }
    if rest.is_empty() {
        return None;
    }

    let mut total = 0f64;
    let mut remaining = rest;
    while !remaining.is_empty() {
        let number_end = remaining
            .find(|c: char| !(c.is_ascii_digit() || c == '.'))
            .unwrap_or(remaining.len());
        if number_end == 0 {
            return None;
        }
        let number: f64 = remaining[..number_end].parse().ok()?;
        let unit_end = remaining[number_end..]
            .find(|c: char| c.is_ascii_digit() || c == '.')
            .map_or(remaining.len(), |index| number_end + index);
        let factor = match &remaining[number_end..unit_end] {
            "ns" => 1.0,
            "us" | "µs" | "μs" => 1e3,
            "ms" => 1e6,
            "s" => 1e9,
            "m" => 60e9,
            "h" => 3600e9,
            _ => return None,
        };
        total += number * factor;
        remaining = &remaining[unit_end..];
    }

    let nanos = total.round();
    if !nanos.is_finite() || nanos > i64::MAX as f64 {
        return None;
    }
    let nanos = nanos as i64;
    Some(TimeSpan::from_nanos(if negative { -nanos } else { nanos }))
}

/// A bandwidth cap, stored as bits per second.
///
/// `0` means "no cap". The parser accepts the spellings operators actually
/// write: `0`, `1048576` (bytes per second), `512kbps`, `200 mbps`, `1.5Gbps`,
/// `10mb` (bytes per second), `8mib`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Bandwidth {
    bits_per_second: u64,
}

impl Bandwidth {
    pub const UNLIMITED: Self = Self { bits_per_second: 0 };

    #[must_use]
    pub const fn from_bits_per_second(bits_per_second: u64) -> Self {
        Self { bits_per_second }
    }

    #[must_use]
    pub const fn bits_per_second(self) -> u64 {
        self.bits_per_second
    }

    /// The cap in bytes per second, rounded down.
    #[must_use]
    pub const fn bytes_per_second(self) -> u64 {
        self.bits_per_second / 8
    }

    #[must_use]
    pub const fn is_unlimited(self) -> bool {
        self.bits_per_second == 0
    }
}

impl std::str::FromStr for Bandwidth {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        parse_bandwidth(value).ok_or(())
    }
}

impl fmt::Display for Bandwidth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bits = self.bits_per_second;
        if bits == 0 {
            return f.write_str("0");
        }
        const UNITS: [(u64, &str); 3] = [
            (1_000_000_000, "Gbps"),
            (1_000_000, "Mbps"),
            (1_000, "Kbps"),
        ];
        for (scale, suffix) in UNITS {
            if bits.is_multiple_of(scale) {
                return write!(f, "{}{suffix}", bits / scale);
            }
        }
        write!(f, "{bits}bps")
    }
}

/// Parses a bandwidth cap into bits per second.
pub fn parse_bandwidth(value: &str) -> Option<Bandwidth> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    let split = value
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(value.len());
    if split == 0 {
        return None;
    }
    let number: f64 = value[..split].parse().ok()?;
    if !number.is_finite() || number < 0.0 {
        return None;
    }
    // Bits per second per unit; `None` for an unknown suffix.
    let factor = match value[split..].trim().to_ascii_lowercase().as_str() {
        // A bare number is bytes per second.
        "" => 8.0,
        "bps" => 1.0,
        "kbps" | "kbit" | "kbit/s" => 1e3,
        "mbps" | "mbit" | "mbit/s" => 1e6,
        "gbps" | "gbit" | "gbit/s" => 1e9,
        "b" => 8.0,
        "kb" => 8e3,
        "mb" => 8e6,
        "gb" => 8e9,
        "kib" => 8.0 * 1024.0,
        "mib" => 8.0 * 1024.0 * 1024.0,
        "gib" => 8.0 * 1024.0 * 1024.0 * 1024.0,
        _ => return None,
    };
    let bits = (number * factor).round();
    if bits > u64::MAX as f64 {
        return None;
    }
    Some(Bandwidth::from_bits_per_second(bits as u64))
}

/// Parses an integer the way `strconv.ParseInt(s, 0, bits)` does: optional sign,
/// `0x`/`0b`/`0o` prefixes, a leading `0` meaning octal, and `_` separators.
pub fn parse_integer(value: &str) -> Option<i128> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    let (negative, rest) = match value.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, value.strip_prefix('+').unwrap_or(value)),
    };
    let rest = rest.replace('_', "");

    let (radix, digits) = if let Some(digits) = strip_prefix_ci(&rest, "0x") {
        (16, digits)
    } else if let Some(digits) = strip_prefix_ci(&rest, "0b") {
        (2, digits)
    } else if let Some(digits) = strip_prefix_ci(&rest, "0o") {
        (8, digits)
    } else if rest.len() > 1 && rest.starts_with('0') {
        (8, &rest[1..])
    } else {
        (10, rest.as_str())
    };
    if digits.is_empty() {
        return None;
    }
    let magnitude = i128::from_str_radix(digits, radix).ok()?;
    Some(if negative { -magnitude } else { magnitude })
}

fn strip_prefix_ci<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
    let head = value.get(..prefix.len())?;
    if head.eq_ignore_ascii_case(prefix) {
        Some(&value[prefix.len()..])
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_go_durations() {
        assert_eq!(parse_duration("0"), Some(TimeSpan::ZERO));
        assert_eq!(parse_duration("30s"), Some(TimeSpan::from_secs(30)));
        assert_eq!(parse_duration("50ms"), Some(TimeSpan::from_millis(50)));
        assert_eq!(
            parse_duration("1h30m"),
            Some(TimeSpan::from_nanos(5_400_000_000_000))
        );
        assert_eq!(parse_duration("-500ms"), Some(TimeSpan::from_millis(-500)));
        assert_eq!(parse_duration("1.5s"), Some(TimeSpan::from_millis(1500)));
        assert_eq!(parse_duration("30"), None);
        assert_eq!(parse_duration("s"), None);
        assert_eq!(parse_duration(""), None);
    }

    #[test]
    fn formats_durations_like_go() {
        assert_eq!(TimeSpan::ZERO.to_string(), "0s");
        assert_eq!(TimeSpan::from_secs(30).to_string(), "30s");
        assert_eq!(TimeSpan::from_millis(50).to_string(), "50ms");
        assert_eq!(TimeSpan::from_nanos(5_400_000_000_000).to_string(), "1h30m");
        assert_eq!(TimeSpan::from_millis(-500).to_string(), "-500ms");
    }

    #[test]
    fn parses_integers_with_go_base_detection() {
        assert_eq!(parse_integer("12345"), Some(12345));
        assert_eq!(parse_integer("0x10"), Some(16));
        assert_eq!(parse_integer("0b101"), Some(5));
        assert_eq!(parse_integer("0o17"), Some(15));
        assert_eq!(parse_integer("017"), Some(15));
        assert_eq!(parse_integer("0"), Some(0));
        assert_eq!(parse_integer("-1"), Some(-1));
        assert_eq!(parse_integer("1_000"), Some(1000));
        assert_eq!(parse_integer("12a"), None);
    }
}
