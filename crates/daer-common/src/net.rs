// SPDX-License-Identifier: AGPL-3.0-only

//! Network value types shared by routing, the data path and the eBPF ABI.
//!
//! Parsing follows `common/utils.go` (`ParsePortRange`, `ParseMac`) so that
//! configuration errors stay identical to the Go implementation.

use std::fmt;
use std::str::FromStr;

/// An inclusive port range. `start == end` means a single port.
///
/// The layout is also the eBPF ABI for `struct port_range`, hence `repr(C)`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl PortRange {
    pub const fn new(start: u16, end: u16) -> Self {
        Self { start, end }
    }

    pub const fn single(port: u16) -> Self {
        Self {
            start: port,
            end: port,
        }
    }

    pub const fn contains(self, port: u16) -> bool {
        port >= self.start && port <= self.end
    }
}

impl FromStr for PortRange {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let mut fields = value.splitn(2, '-');
        let start_text = fields.next().unwrap_or_default();
        if start_text.is_empty() {
            return Err(format!("bad port range: {value}"));
        }
        let start: u16 = start_text
            .parse()
            .map_err(|_| format!("cannot parse {start_text}: invalid port"))?;

        let Some(end_text) = fields.next() else {
            return Ok(Self::single(start));
        };
        if end_text.is_empty() {
            return Err(format!("bad port range: {value}"));
        }
        let end: u16 = end_text
            .parse()
            .map_err(|_| format!("cannot parse {end_text}: invalid port"))?;
        Ok(Self::new(start, end))
    }
}

impl fmt::Display for PortRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.start == self.end {
            write!(f, "{}", self.start)
        } else {
            write!(f, "{}-{}", self.start, self.end)
        }
    }
}

/// A 48-bit MAC address.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    pub const UNSPECIFIED: Self = Self([0; 6]);

    pub fn is_unspecified(self) -> bool {
        self.0 == [0; 6]
    }
}

impl FromStr for MacAddr {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        // `strings.SplitN(mac, ":", 6)` accepts short groups like `1:2:3:4:5:6`
        // because `hex.DecodeString` is applied per field.
        let fields: Vec<&str> = value.splitn(6, ':').collect();
        if fields.len() != 6 {
            return Err(format!("invalid mac: {value}"));
        }
        let mut addr = [0u8; 6];
        for (index, field) in fields.iter().enumerate() {
            let bytes = decode_hex(field).ok_or_else(|| format!("invalid mac: {value}"))?;
            if bytes.len() != 1 {
                return Err(format!("invalid mac: {value}"));
            }
            addr[index] = bytes[0];
        }
        Ok(Self(addr))
    }
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return None;
    }
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks(2) {
        let high = (pair[0] as char).to_digit(16)?;
        let low = (pair[1] as char).to_digit(16)?;
        out.push(((high << 4) | low) as u8);
    }
    Some(out)
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

impl fmt::Debug for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_single_ports_and_ranges() {
        assert_eq!("443".parse::<PortRange>(), Ok(PortRange::single(443)));
        assert_eq!(
            "8000-9000".parse::<PortRange>(),
            Ok(PortRange::new(8000, 9000))
        );
        assert!("".parse::<PortRange>().is_err());
        assert!("-1".parse::<PortRange>().is_err());
        assert!("70000".parse::<PortRange>().is_err());
        assert!("8000-".parse::<PortRange>().is_err());
    }

    #[test]
    fn formats_port_ranges() {
        assert_eq!(PortRange::single(443).to_string(), "443");
        assert_eq!(PortRange::new(8000, 9000).to_string(), "8000-9000");
    }

    #[test]
    fn parses_macs() {
        assert_eq!(
            "aa:bb:cc:dd:ee:ff".parse::<MacAddr>().unwrap().0,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
        );
        // `hex.DecodeString` rejects odd-length groups, so the Go parser does
        // too; short groups like "1" are not valid.
        assert!("1:2:3:4:5:6".parse::<MacAddr>().is_err());
        assert!("aa:bb:cc:dd:ee".parse::<MacAddr>().is_err());
        assert!("aa:bb:cc:dd:ee:ff:00".parse::<MacAddr>().is_err());
        assert!("zz:bb:cc:dd:ee:ff".parse::<MacAddr>().is_err());
        assert!("aab:bb:cc:dd:ee:ff".parse::<MacAddr>().is_err());
    }

    #[test]
    fn round_trips_mac_display() {
        let mac: MacAddr = "aa:bb:cc:dd:ee:ff".parse().unwrap();
        assert_eq!(mac.to_string(), "aa:bb:cc:dd:ee:ff");
    }
}
