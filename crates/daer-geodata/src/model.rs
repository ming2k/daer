// SPDX-License-Identifier: AGPL-3.0-only

//! The subset of the v2ray geodata schema daer reads.
//!
//! Field numbers come from `pkg/geodata/common.pb.go`
//! (`v2ray.core.app.router.routercommon`).

use crate::error::GeoDataError;
use crate::wire::{FieldValue, Fields, string_field};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainType {
    /// `Plain` (0): the value is a substring/keyword.
    Plain,
    /// `Regex` (1).
    Regex,
    /// `RootDomain` (2): the value matches the domain and its subdomains.
    RootDomain,
    /// `Full` (3): exact match.
    Full,
    /// A type this build does not know; the entry is ignored.
    Unknown(u32),
}

impl DomainType {
    fn from_wire(value: u64) -> Self {
        match value {
            0 => Self::Plain,
            1 => Self::Regex,
            2 => Self::RootDomain,
            3 => Self::Full,
            other => Self::Unknown(other as u32),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainAttribute {
    pub key: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Domain {
    pub domain_type: DomainType,
    pub value: String,
    pub attributes: Vec<DomainAttribute>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cidr {
    /// 4 bytes for IPv4, 16 for IPv6.
    pub ip: Vec<u8>,
    pub prefix: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GeoIp {
    pub country_code: String,
    pub cidrs: Vec<Cidr>,
    pub inverse_match: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GeoSite {
    pub country_code: String,
    pub domains: Vec<Domain>,
}

pub(crate) fn parse_geoip(bytes: &[u8]) -> Result<GeoIp, GeoDataError> {
    let mut geoip = GeoIp::default();
    for field in Fields::new(bytes) {
        let field = field?;
        match (field.number, field.value) {
            (1, FieldValue::Bytes(value)) => geoip.country_code = string_field(value)?,
            (2, FieldValue::Bytes(value)) => geoip.cidrs.push(parse_cidr(value)?),
            (3, FieldValue::Varint(value)) => geoip.inverse_match = value != 0,
            _ => {}
        }
    }
    Ok(geoip)
}

pub(crate) fn parse_geosite(bytes: &[u8]) -> Result<GeoSite, GeoDataError> {
    let mut geosite = GeoSite::default();
    for field in Fields::new(bytes) {
        let field = field?;
        match (field.number, field.value) {
            (1, FieldValue::Bytes(value)) => geosite.country_code = string_field(value)?,
            (2, FieldValue::Bytes(value)) => geosite.domains.push(parse_domain(value)?),
            _ => {}
        }
    }
    Ok(geosite)
}

fn parse_cidr(bytes: &[u8]) -> Result<Cidr, GeoDataError> {
    let mut cidr = Cidr {
        ip: Vec::new(),
        prefix: 0,
    };
    for field in Fields::new(bytes) {
        let field = field?;
        match (field.number, field.value) {
            (1, FieldValue::Bytes(value)) => cidr.ip = value.to_vec(),
            (2, FieldValue::Varint(value)) => {
                cidr.prefix = u32::try_from(value)
                    .map_err(|_| GeoDataError::invalid("cidr prefix does not fit u32"))?;
            }
            _ => {}
        }
    }
    Ok(cidr)
}

fn parse_domain(bytes: &[u8]) -> Result<Domain, GeoDataError> {
    let mut domain = Domain {
        domain_type: DomainType::Plain,
        value: String::new(),
        attributes: Vec::new(),
    };
    for field in Fields::new(bytes) {
        let field = field?;
        match (field.number, field.value) {
            (1, FieldValue::Varint(value)) => domain.domain_type = DomainType::from_wire(value),
            (2, FieldValue::Bytes(value)) => domain.value = string_field(value)?,
            (3, FieldValue::Bytes(value)) => domain.attributes.push(parse_attribute(value)?),
            _ => {}
        }
    }
    Ok(domain)
}

fn parse_attribute(bytes: &[u8]) -> Result<DomainAttribute, GeoDataError> {
    let mut attribute = DomainAttribute { key: String::new() };
    for field in Fields::new(bytes) {
        let field = field?;
        if let (1, FieldValue::Bytes(value)) = (field.number, field.value) {
            attribute.key = string_field(value)?;
        }
    }
    Ok(attribute)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_geoip_entry() {
        // country_code: "CN", cidr { ip: 1.2.3.0, prefix: 24 }
        let mut cidr = vec![0x0a, 0x02, b'C', b'N', 0x12, 0x08];
        cidr.extend_from_slice(&[0x0a, 0x04, 1, 2, 3, 0]);
        cidr.extend_from_slice(&[0x10, 24]);
        let geoip = parse_geoip(&cidr).expect("parses");
        assert_eq!(geoip.country_code, "CN");
        assert_eq!(geoip.cidrs.len(), 1);
        assert_eq!(geoip.cidrs[0].ip, vec![1, 2, 3, 0]);
        assert_eq!(geoip.cidrs[0].prefix, 24);
    }

    #[test]
    fn parses_domain_types_and_attributes() {
        let mut domain = vec![0x08, 0x03]; // type = Full
        domain.extend_from_slice(&[0x12, 0x0b]);
        domain.extend_from_slice(b"example.com");
        domain.extend_from_slice(&[0x1a, 0x05, 0x0a, 0x03, b'c', b'n', b'@']);
        let geosite = parse_geosite(&{
            let mut entry = vec![0x12, domain.len() as u8];
            entry.extend_from_slice(&domain);
            entry
        })
        .expect("parses");
        assert_eq!(geosite.domains.len(), 1);
        assert_eq!(geosite.domains[0].domain_type, DomainType::Full);
        assert_eq!(geosite.domains[0].value, "example.com");
        assert_eq!(geosite.domains[0].attributes[0].key, "cn@");
    }
}
