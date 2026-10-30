// SPDX-License-Identifier: AGPL-3.0-only

//! Operand types and parsers for routing functions.
//!
//! Mirrors the parser factories in `component/routing/function_parser.go`.

use std::fmt;

use daer_common::{MacAddr, PortRange};
use ipnet::IpNet;

use crate::error::RoutingError;

/// `TASK_COMM_LEN` on Linux: process names are compared as fixed 16-byte arrays.
pub const TASK_COMM_LEN: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct L4ProtoMask(pub u8);

impl L4ProtoMask {
    pub const NONE: Self = Self(0);
    pub const TCP: Self = Self(1);
    pub const UDP: Self = Self(2);

    pub const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl fmt::Display for L4ProtoMask {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            1 => f.write_str("tcp"),
            2 => f.write_str("udp"),
            3 => f.write_str("tcp+udp"),
            _ => write!(f, "l4proto({})", self.0),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct IpVersionMask(pub u8);

impl IpVersionMask {
    pub const NONE: Self = Self(0);
    pub const V4: Self = Self(1);
    pub const V6: Self = Self(2);

    pub const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The version of an address, as a single-bit mask.
    pub fn of(addr: std::net::IpAddr) -> Self {
        if addr.is_ipv4() { Self::V4 } else { Self::V6 }
    }
}

/// A process name truncated and NUL-padded to [`TASK_COMM_LEN`].
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct ProcessName(pub [u8; TASK_COMM_LEN]);

impl ProcessName {
    pub fn is_unspecified(self) -> bool {
        self.0[0] == 0
    }

    /// Copies at most `TASK_COMM_LEN` bytes, exactly like `toProcessName`.
    pub fn from_bytes_truncated(bytes: &[u8]) -> Self {
        let mut name = [0u8; TASK_COMM_LEN];
        let length = bytes.len().min(TASK_COMM_LEN);
        name[..length].copy_from_slice(&bytes[..length]);
        Self(name)
    }
}

impl fmt::Display for ProcessName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let end = self
            .0
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(TASK_COMM_LEN);
        f.write_str(&String::from_utf8_lossy(&self.0[..end]))
    }
}

impl fmt::Debug for ProcessName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ProcessName({self})")
    }
}

/// Parses CIDRs, appending `/32` or `/128` when no prefix length is given.
pub fn parse_prefixes(values: &[&str]) -> Result<Vec<IpNet>, RoutingError> {
    let mut prefixes = Vec::with_capacity(values.len());
    for value in values {
        let to_parse = if !value.contains('/') {
            if value.contains(':') {
                format!("{value}/128")
            } else {
                format!("{value}/32")
            }
        } else {
            (*value).to_owned()
        };
        let prefix: IpNet = to_parse
            .parse()
            .map_err(|err| RoutingError::new(format!("cannot parse {value}: {err}")))?;
        prefixes.push(prefix);
    }
    Ok(prefixes)
}

pub fn parse_mac_addresses(values: &[&str]) -> Result<Vec<MacAddr>, RoutingError> {
    values
        .iter()
        .map(|value| value.parse::<MacAddr>().map_err(RoutingError::new))
        .collect()
}

pub fn parse_port_ranges(values: &[&str]) -> Result<Vec<PortRange>, RoutingError> {
    values
        .iter()
        .map(|value| value.parse::<PortRange>().map_err(RoutingError::new))
        .collect()
}

pub fn parse_l4_proto(values: &[&str]) -> Result<L4ProtoMask, RoutingError> {
    let mut mask = L4ProtoMask::NONE;
    for value in values {
        match *value {
            "tcp" => mask.0 |= L4ProtoMask::TCP.0,
            "udp" => mask.0 |= L4ProtoMask::UDP.0,
            other => {
                return Err(RoutingError::new(format!(
                    "l4proto: unknown value {other:?}; supported values are tcp and udp"
                )));
            }
        }
    }
    if mask.is_empty() {
        return Err(RoutingError::new(
            "l4proto: at least one of tcp and udp is required",
        ));
    }
    Ok(mask)
}

pub fn parse_ip_version(values: &[&str]) -> Result<IpVersionMask, RoutingError> {
    let mut mask = IpVersionMask::NONE;
    for value in values {
        match *value {
            "4" => mask.0 |= IpVersionMask::V4.0,
            "6" => mask.0 |= IpVersionMask::V6.0,
            other => {
                return Err(RoutingError::new(format!(
                    "ipversion: unknown value {other:?}; supported values are 4 and 6"
                )));
            }
        }
    }
    if mask.is_empty() {
        return Err(RoutingError::new(
            "ipversion: at least one of 4 and 6 is required",
        ));
    }
    Ok(mask)
}

/// Truncates process names to [`TASK_COMM_LEN`] and records a warning, matching
/// the `log.Infof` in the Go parser.
pub fn parse_process_names(values: &[&str], warnings: &mut Vec<String>) -> Vec<ProcessName> {
    values
        .iter()
        .map(|value| {
            let bytes = value.as_bytes();
            if bytes.len() > TASK_COMM_LEN {
                warnings.push(format!(
                    "pname routing: trim \"{value}\" to \"{}\" because it is too long.",
                    String::from_utf8_lossy(&bytes[..TASK_COMM_LEN])
                ));
            }
            ProcessName::from_bytes_truncated(bytes)
        })
        .collect()
}

pub fn parse_dscp(values: &[&str]) -> Result<Vec<u8>, RoutingError> {
    values
        .iter()
        .map(|value| {
            daer_config::parse_integer(value)
                .and_then(|number| u8::try_from(number).ok())
                .ok_or_else(|| RoutingError::new(format!("cannot parse {value}: invalid uint8")))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefixes_get_a_default_length() {
        let prefixes = parse_prefixes(&["1.1.1.1", "2606:4700:4700::1111", "10.0.0.0/8"]).unwrap();
        assert_eq!(prefixes[0].to_string(), "1.1.1.1/32");
        assert_eq!(prefixes[1].to_string(), "2606:4700:4700::1111/128");
        assert_eq!(prefixes[2].to_string(), "10.0.0.0/8");
        assert!(parse_prefixes(&["not-an-ip"]).is_err());
    }

    #[test]
    fn l4proto_requires_a_value() {
        assert!(
            parse_l4_proto(&["tcp"])
                .unwrap()
                .intersects(L4ProtoMask::TCP)
        );
        assert_eq!(parse_l4_proto(&["tcp", "udp"]).unwrap().0, 3);
        assert!(parse_l4_proto(&[]).is_err());
        let error = parse_l4_proto(&["icmp"]).unwrap_err();
        assert!(error.message.contains("unknown value \"icmp\""), "{error}");
    }

    #[test]
    fn ip_version_requires_a_value() {
        assert_eq!(parse_ip_version(&["4"]).unwrap(), IpVersionMask::V4);
        assert!(parse_ip_version(&[]).is_err());
        let error = parse_ip_version(&["5"]).unwrap_err();
        assert!(error.message.contains("unknown value \"5\""), "{error}");
    }

    #[test]
    fn process_names_truncate_with_a_warning() {
        let mut warnings = Vec::new();
        let names = parse_process_names(&["firefox", "a-very-long-process-name"], &mut warnings);
        assert_eq!(&names[0].0[..7], b"firefox");
        assert_eq!(&names[1].0, b"a-very-long-proc");
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("trim"), "{}", warnings[0]);
    }

    #[test]
    fn dscp_is_parsed_as_uint8() {
        assert_eq!(parse_dscp(&["0", "0x2e", "46"]).unwrap(), [0, 46, 46]);
        assert!(parse_dscp(&["300"]).is_err());
    }
}
