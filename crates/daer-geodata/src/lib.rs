// SPDX-License-Identifier: AGPL-3.0-only

//! geosite / geoip loading for daer.
//!
//! Replaces `pkg/geodata`. The `.dat` files are protobuf lists
//! (`GeoIPList` / `GeoSiteList`); only the entry whose country code matches is
//! decoded, so a large file does not cost the memory of every code in it. This
//! is the behaviour v2ray calls "memconservative" and the reason
//! `pkg/geodata/decode.go` streams the file byte by byte.
//!
//! ```no_run
//! use std::path::Path;
//!
//! let geoip = daer_geodata::unmarshal_geoip(Path::new("/usr/share/daer/geoip.dat"), "cn")?;
//! for cidr in &geoip.cidrs {
//!     let _ = cidr.prefix;
//! }
//! # Ok::<(), daer_geodata::GeoDataError>(())
//! ```

mod assets;
mod error;
mod model;
mod wire;

use std::path::Path;

pub use assets::LocationFinder;
pub use error::GeoDataError;
pub use model::{Cidr, Domain, DomainAttribute, DomainType, GeoIp, GeoSite};

use wire::{FieldValue, Fields};

/// Reads the `GeoIP` entry for `code` from a geoip file.
pub fn unmarshal_geoip(path: &Path, code: &str) -> Result<GeoIp, GeoDataError> {
    let bytes = error::read_file(path)?;
    let entry = find_entry(&bytes, code)?.ok_or_else(|| GeoDataError::CodeNotFound {
        label: "country code",
        code: code.to_owned(),
        path: path.to_path_buf(),
    })?;
    model::parse_geoip(entry)
}

/// Reads the `GeoSite` entry for `code` from a geosite file.
pub fn unmarshal_geosite(path: &Path, code: &str) -> Result<GeoSite, GeoDataError> {
    let bytes = error::read_file(path)?;
    let entry = find_entry(&bytes, code)?.ok_or_else(|| GeoDataError::CodeNotFound {
        label: "code",
        code: code.to_owned(),
        path: path.to_path_buf(),
    })?;
    model::parse_geosite(entry)
}

/// Returns the raw bytes of the list entry whose `country_code` matches `code`,
/// without decoding the entries that do not match.
fn find_entry<'a>(bytes: &'a [u8], code: &str) -> Result<Option<&'a [u8]>, GeoDataError> {
    for field in Fields::new(bytes) {
        let field = field?;
        if let (1, FieldValue::Bytes(entry)) = (field.number, field.value)
            && entry_matches(entry, code)
        {
            return Ok(Some(entry));
        }
    }
    Ok(None)
}

fn entry_matches(entry: &[u8], code: &str) -> bool {
    for field in Fields::new(entry) {
        let Ok(field) = field else {
            return false;
        };
        if let (1, FieldValue::Bytes(value)) = (field.number, field.value) {
            return value.eq_ignore_ascii_case(code.as_bytes());
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn length_delimited(number: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![(number << 3) | 2, payload.len() as u8];
        out.extend_from_slice(payload);
        out
    }

    fn geoip_entry(code: &str, cidr: &[u8], prefix: u8) -> Vec<u8> {
        let mut entry = length_delimited(1, code.as_bytes());
        let mut cidr_message = length_delimited(1, cidr);
        cidr_message.extend_from_slice(&[0x10, prefix]);
        entry.extend_from_slice(&length_delimited(2, &cidr_message));
        entry
    }

    #[test]
    fn finds_the_matching_entry_case_insensitively() {
        let mut file = length_delimited(1, &geoip_entry("US", &[8, 8, 8, 0], 24));
        file.extend_from_slice(&length_delimited(1, &geoip_entry("CN", &[1, 2, 3, 0], 24)));

        let entry = find_entry(&file, "cn").expect("decodes").expect("found");
        let geoip = model::parse_geoip(entry).expect("parses");
        assert_eq!(geoip.country_code, "CN");
        assert_eq!(geoip.cidrs.len(), 1);
    }

    #[test]
    fn reports_a_missing_code() {
        let file = length_delimited(1, &geoip_entry("US", &[8, 8, 8, 0], 24));
        assert!(find_entry(&file, "cn").expect("decodes").is_none());
    }

    #[test]
    fn rejects_truncated_files() {
        let file = [0x0a, 0x08, 0x0a];
        assert!(find_entry(&file, "cn").is_err());
    }
}
