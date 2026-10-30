// SPDX-License-Identifier: AGPL-3.0-only

//! Expands `geosite:` / `geoip:` / `ext:` parameters into concrete operands.
//!
//! Port of `DatReaderOptimizer` in `component/routing/optimizer.go`. The Go
//! implementation expands the rules in parallel; this one is sequential, which
//! only affects how long a large rule set takes to load.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};

use daer_config::{Param, RoutingRule};
use daer_geodata::{Cidr, DomainType, GeoDataError, LocationFinder};
use ipnet::IpNet;

use crate::error::RoutingError;
use crate::optimizer::RulesOptimizer;

#[derive(Debug)]
pub struct DatReaderOptimizer {
    finder: LocationFinder,
    caches: Mutex<Caches>,
}

#[derive(Debug, Default)]
struct Caches {
    geosite: HashMap<String, Vec<Param>>,
    geoip: HashMap<String, Vec<Param>>,
}

impl DatReaderOptimizer {
    /// Searches `extern_dirs` (for daer, the config file's directory) plus the
    /// standard asset locations.
    pub fn new(extern_dirs: Vec<PathBuf>) -> Self {
        Self::with_finder(LocationFinder::new(extern_dirs))
    }

    pub fn with_finder(finder: LocationFinder) -> Self {
        Self {
            finder,
            caches: Mutex::new(Caches::default()),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Caches> {
        self.caches
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn load_geosite(&self, filename: &str, code: &str) -> Result<Vec<Param>, RoutingError> {
        let filename = with_dat_suffix(filename);
        let cache_key = format!("{}:{}", filename.to_lowercase(), code.to_lowercase());
        if let Some(cached) = self.lock().geosite.get(&cache_key).cloned() {
            return Ok(cached);
        }

        let path = self.finder.find(&filename).map_err(geodata_error)?;
        let (code, attribute) = match code.split_once('@') {
            Some((code, attribute)) => (code, attribute),
            None => (code, ""),
        };
        let site = daer_geodata::unmarshal_geosite(&path, code).map_err(geodata_error)?;

        let mut params = Vec::with_capacity(site.domains.len());
        for domain in site.domains {
            if !attribute.is_empty()
                && !domain
                    .attributes
                    .iter()
                    .any(|item| item.key.eq_ignore_ascii_case(attribute))
            {
                continue;
            }
            let key = match domain.domain_type {
                DomainType::Full => "full",
                DomainType::RootDomain => "suffix",
                DomainType::Plain => "keyword",
                DomainType::Regex => "regex",
                DomainType::Unknown(_) => continue,
            };
            params.push(Param::literal(key, domain.value));
        }

        self.lock().geosite.insert(cache_key, params.clone());
        Ok(params)
    }

    fn load_geoip(&self, filename: &str, code: &str) -> Result<Vec<Param>, RoutingError> {
        let filename = with_dat_suffix(filename);
        let cache_key = format!("{}:{}", filename.to_lowercase(), code.to_lowercase());
        if let Some(cached) = self.lock().geoip.get(&cache_key).cloned() {
            return Ok(cached);
        }

        let path = self.finder.find(&filename).map_err(geodata_error)?;
        let geoip = daer_geodata::unmarshal_geoip(&path, code).map_err(geodata_error)?;
        if geoip.inverse_match {
            return Err(RoutingError::new(GeoDataError::InverseMatch.to_string()));
        }

        let mut params = Vec::with_capacity(geoip.cidrs.len());
        for cidr in &geoip.cidrs {
            params.push(Param::bare(cidr_to_prefix(cidr, &filename)?));
        }

        self.lock().geoip.insert(cache_key, params.clone());
        Ok(params)
    }

    fn load_ext(&self, function_name: &str, param: &Param) -> Result<Vec<Param>, RoutingError> {
        let value = literal(param)?;
        let (filename, code) = value.split_once(':').ok_or_else(|| {
            RoutingError::new(format!("ext: expected \"file:code\" but got {value:?}"))
        })?;
        match function_name {
            "domain" | "qname" => self.load_geosite(filename, code),
            "ip" => self.load_geoip(filename, code),
            other => Err(RoutingError::new(format!(
                "unsupported extension file extraction in function {other}"
            ))),
        }
    }
}

impl RulesOptimizer for DatReaderOptimizer {
    fn optimize(&self, mut rules: Vec<RoutingRule>) -> Result<Vec<RoutingRule>, RoutingError> {
        for rule in &mut rules {
            for function in &mut rule.and_functions {
                let mut expanded = Vec::with_capacity(function.params.len());
                for param in &function.params {
                    match param.key.as_str() {
                        "geosite" => {
                            expanded.extend(self.load_geosite("geosite", literal(param)?)?);
                        }
                        "geoip" => {
                            expanded.extend(self.load_geoip("geoip", literal(param)?)?);
                        }
                        "ext" => expanded.extend(self.load_ext(&function.name, param)?),
                        _ => expanded.push(param.clone()),
                    }
                }
                function.params = expanded;
            }
        }
        Ok(rules)
    }
}

fn literal(param: &Param) -> Result<&str, RoutingError> {
    param.as_literal().ok_or_else(|| {
        RoutingError::new(format!(
            "{}: expected a literal value, e.g. {}(geoip:cn)",
            param.key, param.key
        ))
    })
}

fn with_dat_suffix(filename: &str) -> String {
    if filename.ends_with(".dat") {
        filename.to_owned()
    } else {
        format!("{filename}.dat")
    }
}

fn cidr_to_prefix(cidr: &Cidr, filename: &str) -> Result<String, RoutingError> {
    let address = match cidr.ip.len() {
        4 => IpAddr::V4(Ipv4Addr::new(
            cidr.ip[0], cidr.ip[1], cidr.ip[2], cidr.ip[3],
        )),
        16 => {
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(&cidr.ip);
            IpAddr::V6(Ipv6Addr::from(bytes))
        }
        _ => return Err(RoutingError::new(format!("bad geoip file: {filename}"))),
    };
    let prefix = u8::try_from(cidr.prefix)
        .map_err(|_| RoutingError::new(format!("bad geoip file: {filename}")))?;
    let net = IpNet::new(address, prefix).map_err(|_| {
        RoutingError::new(format!(
            "bad geoip file: {filename}: prefix {prefix} is too long for {address}"
        ))
    })?;
    Ok(net.to_string())
}

fn geodata_error(err: GeoDataError) -> RoutingError {
    RoutingError::new(err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::Path;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let mut path = std::env::temp_dir();
            path.push(format!(
                "daer-datreader-{name}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).expect("creates dir");
            Self(path)
        }

        fn write(&self, name: &str, bytes: &[u8]) {
            let path = self.0.join(name);
            std::fs::File::create(&path)
                .expect("creates file")
                .write_all(bytes)
                .expect("writes");
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn varint(mut value: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let byte = (value & 0x7f) as u8;
            value >>= 7;
            if value == 0 {
                out.push(byte);
                return out;
            }
            out.push(byte | 0x80);
        }
    }

    fn length_delimited(number: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = varint(u64::from((number << 3) | 2));
        out.extend_from_slice(&varint(payload.len() as u64));
        out.extend_from_slice(payload);
        out
    }

    type GeoIpEntry<'a> = (&'a str, &'a [(u8, &'a [u8])]);
    type GeoSiteEntry<'a> = (&'a str, &'a [(u8, &'a str, &'a [&'a str])]);

    fn geoip_list(entries: &[GeoIpEntry<'_>]) -> Vec<u8> {
        let mut file = Vec::new();
        for (code, cidrs) in entries {
            let mut entry = length_delimited(1, code.as_bytes());
            for (prefix, ip) in *cidrs {
                let mut cidr = length_delimited(1, ip);
                cidr.extend_from_slice(&varint(0x10));
                cidr.extend_from_slice(&varint(u64::from(*prefix)));
                entry.extend_from_slice(&length_delimited(2, &cidr));
            }
            file.extend_from_slice(&length_delimited(1, &entry));
        }
        file
    }

    fn geosite_list(entries: &[GeoSiteEntry<'_>]) -> Vec<u8> {
        let mut file = Vec::new();
        for (code, domains) in entries {
            let mut entry = length_delimited(1, code.as_bytes());
            for (domain_type, value, attributes) in *domains {
                let mut domain = vec![0x08, *domain_type];
                domain.extend_from_slice(&length_delimited(2, value.as_bytes()));
                for attribute in *attributes {
                    let attribute_message = length_delimited(1, attribute.as_bytes());
                    domain.extend_from_slice(&length_delimited(3, &attribute_message));
                }
                entry.extend_from_slice(&length_delimited(2, &domain));
            }
            file.extend_from_slice(&length_delimited(1, &entry));
        }
        file
    }

    /// Fixtures are written as config used to read: a `routing { … }` wrapper
    /// around one rule per line. Only the lines matter.
    fn rules(src: &str) -> Vec<RoutingRule> {
        let body = src.trim();
        let body = body.strip_prefix("routing {").unwrap_or(body);
        let body = body.strip_suffix('}').unwrap_or(body);
        body.lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(|line| daer_config::parse_rule_expr(line).expect("parses"))
            .collect()
    }

    fn optimized(finder_dir: &Path, src: &str) -> Vec<RoutingRule> {
        let optimizer = DatReaderOptimizer::new(vec![finder_dir.to_path_buf()]);
        optimizer.optimize(rules(src)).expect("optimizes")
    }

    #[test]
    fn expands_geosite_with_types_and_attribute_filters() {
        let dir = TempDir::new("geosite");
        dir.write(
            "geosite.dat",
            &geosite_list(&[
                (
                    "TEST",
                    &[
                        (3, "full.example", &[]),
                        (2, "suffix.example", &[]),
                        (0, "keyword", &[]),
                        (1, "^regex\\.example$", &[]),
                        (3, "only-cn", &["cn"]),
                    ],
                ),
                ("OTHER", &[(3, "other.example", &[])]),
            ]),
        );

        let rules = optimized(&dir.0, "routing { domain(geosite:test) -> direct }");
        let params = &rules[0].and_functions[0].params;
        assert_eq!(params.len(), 5);
        assert_eq!(params[0], Param::literal("full", "full.example"));
        assert_eq!(params[1], Param::literal("suffix", "suffix.example"));
        assert_eq!(params[2], Param::literal("keyword", "keyword"));
        assert_eq!(params[3], Param::literal("regex", "^regex\\.example$"));

        let filtered = optimized(&dir.0, "routing { domain(geosite:test@cn) -> direct }");
        let params = &filtered[0].and_functions[0].params;
        assert_eq!(params, &[Param::literal("full", "only-cn")]);
    }

    #[test]
    fn expands_geoip_into_prefixes() {
        let dir = TempDir::new("geoip");
        dir.write(
            "geoip.dat",
            &geoip_list(&[
                (
                    "TEST",
                    &[
                        (24, &[1, 2, 3, 0]),
                        (
                            128,
                            &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                        ),
                    ],
                ),
                ("OTHER", &[(8, &[8, 0, 0, 0])]),
            ]),
        );

        let rules = optimized(&dir.0, "routing { dip(geoip:test) -> direct }");
        let params = &rules[0].and_functions[0].params;
        assert_eq!(params.len(), 2);
        assert_eq!(params[0], Param::bare("1.2.3.0/24"));
        assert_eq!(params[1], Param::bare("2001:db8::1/128"));
    }

    #[test]
    fn expands_ext_with_an_explicit_file() {
        let dir = TempDir::new("ext");
        dir.write(
            "mylist.dat",
            &geosite_list(&[("cn", &[(3, "a.example", &[])])]),
        );

        let rules = optimized(&dir.0, "routing { domain(ext:'mylist:cn') -> direct }");
        assert_eq!(
            rules[0].and_functions[0].params,
            [Param::literal("full", "a.example")]
        );
    }

    #[test]
    fn reports_missing_geodata_files() {
        let dir = TempDir::new("missing");
        let optimizer = DatReaderOptimizer::new(vec![dir.0.clone()]);
        let error = optimizer
            .optimize(rules("routing { dip(geoip:cn) -> direct }"))
            .expect_err("must fail");
        assert!(error.message.contains("geoip.dat: not found"), "{error}");
    }

    #[test]
    fn reports_missing_codes() {
        let dir = TempDir::new("nocode");
        dir.write("geoip.dat", &geoip_list(&[("US", &[(8, &[8, 0, 0, 0])])]));
        let optimizer = DatReaderOptimizer::new(vec![dir.0.clone()]);
        let error = optimizer
            .optimize(rules("routing { dip(geoip:cn) -> direct }"))
            .expect_err("must fail");
        assert!(
            error.message.contains("country code cn not found"),
            "{error}"
        );
    }

    #[test]
    fn caches_loaded_codes() {
        let dir = TempDir::new("cache");
        dir.write("geoip.dat", &geoip_list(&[("CN", &[(24, &[1, 2, 3, 0])])]));
        let optimizer = DatReaderOptimizer::new(vec![dir.0.clone()]);
        let first = optimizer
            .optimize(rules("routing { dip(geoip:cn) -> direct }"))
            .expect("expands");
        std::fs::remove_file(dir.0.join("geoip.dat")).expect("removes");
        let second = optimizer
            .optimize(rules("routing { dip(geoip:cn) -> direct }"))
            .expect("uses cache");
        assert_eq!(first, second);
    }

    #[test]
    fn leaves_non_geodata_params_alone() {
        let dir = TempDir::new("plain");
        let rules = optimized(&dir.0, "routing { dip(1.0.0.0/8) && dport(443) -> direct }");
        assert_eq!(rules[0].and_functions[0].params, [Param::bare("1.0.0.0/8")]);
    }
}
