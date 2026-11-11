// SPDX-License-Identifier: AGPL-3.0-only

//! Synthetic Fake-IP allocation pool (ADR-0012) and DNS Snooping cache (ADR-0011).

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::exclusions::Exclusions;
use daer_config::FakeIpConfig;
use ipnet::{Ipv4Net, Ipv6Net};

/// The bi-directional Fake-IP pool (ADR-0012).
#[derive(Debug)]
pub struct FakeIpPool {
    enabled: bool,
    net: Ipv4Net,
    /// The optional IPv6 pool. `None` preserves the IPv4-only behaviour.
    net6: Option<Ipv6Net>,
    pool_size: usize,
    /// The compiled exclusion list.
    ///
    /// Compiled rather than compared as strings: ADR-0012 documents
    /// `exclude = ["domain(suffix: local)"]`, and the previous `ends_with` comparison would
    /// have looked for a domain literally ending in `.domain(suffix: local)` — matching
    /// nothing, so the exclusion the operator wrote was silently inert and every matching
    /// domain got a synthetic address.
    exclude: Exclusions,
    state: Mutex<PoolState>,
}

#[derive(Debug, Default)]
struct PoolState {
    v4: FamilyState<Ipv4Addr>,
    v6: FamilyState<Ipv6Addr>,
}

#[derive(Debug)]
struct FamilyState<A> {
    domain_to_ip: HashMap<Arc<str>, A>,
    ip_to_domain: HashMap<A, Arc<str>>,
    order: VecDeque<A>,
    cursor: u128,
}

impl<A> Default for FamilyState<A> {
    fn default() -> Self {
        Self {
            domain_to_ip: HashMap::new(),
            ip_to_domain: HashMap::new(),
            order: VecDeque::new(),
            cursor: 0,
        }
    }
}

impl<A> FamilyState<A>
where
    A: Copy + Eq + Hash,
{
    fn evict_if_full(&mut self, pool_size: usize) {
        while self.domain_to_ip.len() >= pool_size {
            if let Some(old_ip) = self.order.pop_front() {
                if let Some(old_domain) = self.ip_to_domain.remove(&old_ip) {
                    self.domain_to_ip.remove(&old_domain);
                }
            } else {
                break;
            }
        }
    }

    fn remember(&mut self, domain: &str, ip: A) {
        let domain_arc: Arc<str> = Arc::from(domain);
        if let Some(evicted_domain) = self.ip_to_domain.insert(ip, Arc::clone(&domain_arc)) {
            self.domain_to_ip.remove(&evicted_domain);
        }
        self.domain_to_ip.insert(domain_arc, ip);
        self.order.push_back(ip);
    }
}

impl FakeIpPool {
    /// Builds a pool from configuration.
    ///
    /// # Errors
    ///
    /// Returns an error message if either configured subnet is not a valid CIDR. The IPv4
    /// prefix is required; the IPv6 prefix is optional and enables dual-stack synthesis.
    pub fn from_config(config: &FakeIpConfig) -> Result<Self, String> {
        let net = Ipv4Net::from_str(&config.inet)
            .map_err(|e| format!("invalid fake-ip inet {:?}: {e}", config.inet))?;
        let net6 = config
            .inet6
            .as_deref()
            .map(|inet6| {
                Ipv6Net::from_str(inet6)
                    .map_err(|e| format!("invalid fake-ip inet6 {:?}: {e}", inet6))
            })
            .transpose()?;
        Ok(Self {
            enabled: config.enabled,
            net,
            net6,
            pool_size: config.pool_size.max(1),
            exclude: Exclusions::compile(&config.exclude)?,
            state: Mutex::new(PoolState::default()),
        })
    }

    /// Whether Fake-IP synthesis is active.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// The configured IPv4 subnet.
    #[must_use]
    pub fn net(&self) -> Ipv4Net {
        self.net
    }

    /// The configured IPv6 subnet, when dual-stack Fake-IP is enabled.
    #[must_use]
    pub fn net6(&self) -> Option<Ipv6Net> {
        self.net6
    }

    /// Whether a configured IPv6 subnet exists.
    #[must_use]
    pub fn has_ipv6(&self) -> bool {
        self.net6.is_some()
    }

    /// The configured pool size bound, applied per address family.
    #[must_use]
    pub fn pool_size(&self) -> usize {
        self.pool_size
    }

    /// Whether the exclusion list is empty.
    #[must_use]
    pub fn has_exclusions(&self) -> bool {
        !self.exclude.is_empty()
    }

    /// Whether an address falls within a configured Fake-IP subnet.
    #[must_use]
    pub fn contains_ip(&self, ip: IpAddr) -> bool {
        if !self.enabled {
            return false;
        }
        match ip {
            IpAddr::V4(v4) => self.net.contains(&v4),
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => self.net.contains(&v4),
                None => self.net6.is_some_and(|net| net.contains(&v6)),
            },
        }
    }

    /// Whether a domain is excluded from Fake-IP synthesis.
    ///
    /// The pattern syntax is one language (ADR-0036): a bare name (suffix), `.name`
    /// (subdomains only), `=name` (exact), plus the DNS-only `keyword:`/`regex:` (ADR-0033 §3).
    /// The matcher itself is [`crate::routing::NameMatch`], shared with the DNS router, so these
    /// mean here exactly what they mean in a `qname(...)` selector.
    #[must_use]
    pub fn is_excluded(&self, domain: &str) -> bool {
        if self.exclude.is_empty() {
            return false;
        }
        self.exclude.matches(domain.trim_end_matches('.'))
    }

    /// Allocates or returns the synthetic IPv4 address associated with `domain`.
    pub fn allocate(&self, domain: &str) -> Ipv4Addr {
        let normalized = domain.trim_end_matches('.').to_ascii_lowercase();
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());

        if let Some(&ip) = state.v4.domain_to_ip.get(normalized.as_str()) {
            return ip;
        }

        state.v4.evict_if_full(self.pool_size);

        // Next address in the subnet, skipping the network and broadcast addresses. The
        // u128 cursor is shared by both families so a pool configured near the end of a
        // prefix cannot wrap a smaller counter into an address it already handed out.
        let network = u32::from(self.net.network());
        let broadcast = u32::from(self.net.broadcast());
        let first = network.saturating_add(1).min(broadcast);
        let last = broadcast.saturating_sub(1).max(first);
        let capacity = u128::from(last - first) + 1;
        let offset = (state.v4.cursor % capacity) as u32;
        state.v4.cursor = state.v4.cursor.wrapping_add(1);

        let ip = Ipv4Addr::from(first.saturating_add(offset));
        state.v4.remember(&normalized, ip);
        ip
    }

    /// Allocates or returns the synthetic IPv6 address associated with `domain`.
    ///
    /// Returns `None` when Fake-IP is disabled or no `inet6` prefix was configured. That is
    /// the compatibility path: an IPv4-only Fake-IP configuration keeps answering `AAAA`
    /// with an empty NOERROR, so a dual-stack client falls back to the synthetic `A` record
    /// instead of bypassing the pool over real IPv6.
    pub fn allocate_v6(&self, domain: &str) -> Option<Ipv6Addr> {
        if !self.enabled {
            return None;
        }
        let net = self.net6?;
        let normalized = domain.trim_end_matches('.').to_ascii_lowercase();
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());

        if let Some(&ip) = state.v6.domain_to_ip.get(normalized.as_str()) {
            return Some(ip);
        }

        state.v6.evict_if_full(self.pool_size);

        let network = u128::from(net.network());
        let broadcast = u128::from(net.broadcast());
        let first = network.saturating_add(1);
        let last = broadcast.saturating_sub(1).max(first);
        let capacity = last.saturating_sub(first).saturating_add(1);
        let offset = state.v6.cursor % capacity;
        state.v6.cursor = state.v6.cursor.wrapping_add(1);

        let ip = Ipv6Addr::from(first.saturating_add(offset));
        state.v6.remember(&normalized, ip);
        Some(ip)
    }

    /// Reverse-lookups the original domain for a synthetic IPv4 address.
    #[must_use]
    pub fn reverse_lookup(&self, ip: Ipv4Addr) -> Option<Arc<str>> {
        if !self.enabled || !self.net.contains(&ip) {
            return None;
        }
        let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        state.v4.ip_to_domain.get(&ip).cloned()
    }

    /// Reverse-lookups the original domain for a synthetic IPv6 address.
    #[must_use]
    pub fn reverse_lookup_v6(&self, ip: Ipv6Addr) -> Option<Arc<str>> {
        // A v4-mapped address is an IPv4 flow in an IPv6 envelope; it belongs to the IPv4
        // pool, not to a configured `inet6` prefix.
        if let Some(v4) = ip.to_ipv4_mapped() {
            return self.reverse_lookup(v4);
        }
        if !self.enabled || !self.net6.is_some_and(|net| net.contains(&ip)) {
            return None;
        }
        let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        state.v6.ip_to_domain.get(&ip).cloned()
    }

    /// Reverse-lookup for either address family.
    #[must_use]
    pub fn reverse_lookup_ip(&self, ip: IpAddr) -> Option<Arc<str>> {
        match ip {
            IpAddr::V4(v4) => self.reverse_lookup(v4),
            IpAddr::V6(v6) => self.reverse_lookup_v6(v6),
        }
    }
}

/// The observational DNS Snooping cache for Real-IP mode (ADR-0011).
#[derive(Debug)]
pub struct DnsSnooper {
    max_entries: usize,
    state: Mutex<SnooperState>,
}

#[derive(Debug, Default)]
struct SnooperState {
    entries: HashMap<IpAddr, (Arc<str>, Instant)>,
    order: VecDeque<(IpAddr, Instant)>,
}

impl Default for DnsSnooper {
    fn default() -> Self {
        Self::new(32_768)
    }
}

impl DnsSnooper {
    #[must_use]
    pub fn new(max_entries: usize) -> Self {
        Self {
            max_entries: max_entries.max(1),
            state: Mutex::new(SnooperState::default()),
        }
    }

    /// Records an observed DNS resolution for an IP address.
    pub fn record(&self, ip: IpAddr, domain: &str, ttl_secs: u64) {
        let normalized = domain.trim_end_matches('.').to_ascii_lowercase();
        let expires_at = Instant::now() + Duration::from_secs(ttl_secs.clamp(5, 86_400));
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());

        while state.entries.len() >= self.max_entries {
            if let Some((old_ip, _)) = state.order.pop_front() {
                state.entries.remove(&old_ip);
            } else {
                break;
            }
        }

        let domain_arc: Arc<str> = Arc::from(normalized.as_str());
        state.entries.insert(ip, (domain_arc, expires_at));
        state.order.push_back((ip, expires_at));
    }

    /// Recovers the domain associated with `ip`, if known and unexpired.
    #[must_use]
    pub fn lookup(&self, ip: IpAddr) -> Option<Arc<str>> {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if let Some((domain, expires_at)) = state.entries.get(&ip) {
            if Instant::now() < *expires_at {
                return Some(domain.clone());
            }
            state.entries.remove(&ip);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_ip_allocation_and_reverse_lookup() {
        let config = FakeIpConfig {
            enabled: true,
            inet: "198.18.0.0/15".to_owned(),
            inet6: None,
            pool_size: 100,
            exclude: vec!["local".to_owned(), "corp.internal".to_owned()],
        };
        let pool = FakeIpPool::from_config(&config).expect("pool builds");

        assert!(pool.is_enabled());
        assert_eq!(pool.pool_size(), 100);
        assert!(pool.has_exclusions());

        // Exclusion check
        assert!(pool.is_excluded("gateway.local"));
        assert!(pool.is_excluded("srv.corp.internal"));
        assert!(!pool.is_excluded("example.com"));

        // Allocation
        let ip1 = pool.allocate("example.com");
        let ip2 = pool.allocate("example.com");
        assert_eq!(ip1, ip2, "idempotent allocation");
        assert!(pool.contains_ip(IpAddr::V4(ip1)));

        // Reverse lookup
        let resolved = pool.reverse_lookup(ip1).expect("reverse lookup");
        assert_eq!(&*resolved, "example.com");

        // Disabled isolation (INV-FAKEIP-01)
        let disabled_config = FakeIpConfig {
            enabled: false,
            inet: "198.18.0.0/15".to_owned(),
            inet6: None,
            pool_size: 100,
            exclude: vec![],
        };
        let disabled_pool = FakeIpPool::from_config(&disabled_config).expect("builds");
        assert!(!disabled_pool.is_enabled());
        assert!(!disabled_pool.contains_ip(IpAddr::V4(ip1)));
        assert_eq!(disabled_pool.reverse_lookup(ip1), None);
    }

    #[test]
    fn dual_stack_allocation_keeps_the_families_independent() {
        let config = FakeIpConfig {
            enabled: true,
            inet: "198.18.0.0/15".to_owned(),
            inet6: Some("fdfe:dcba:9876::/64".to_owned()),
            pool_size: 100,
            exclude: vec![],
        };
        let pool = FakeIpPool::from_config(&config).expect("pool builds");

        assert!(pool.has_ipv6());
        assert_eq!(
            pool.net6().map(|net| net.to_string()),
            Some("fdfe:dcba:9876::/64".to_owned())
        );

        let v4 = pool.allocate("example.com");
        let v6 = pool.allocate_v6("example.com").expect("v6 allocation");
        assert!(pool.contains_ip(IpAddr::V4(v4)));
        assert!(pool.contains_ip(IpAddr::V6(v6)));

        // Allocating one family must not disturb the other's reverse mapping.
        assert_eq!(pool.reverse_lookup(v4).as_deref(), Some("example.com"));
        assert_eq!(pool.reverse_lookup_v6(v6).as_deref(), Some("example.com"));
        assert_eq!(
            pool.reverse_lookup_ip(IpAddr::V6(v6)).as_deref(),
            Some("example.com")
        );
        // A v4-mapped v6 address is the IPv4 flow in an IPv6 envelope, not a member of the
        // IPv6 pool; the reverse lookup must not lose the name by choosing the wrong map.
        let mapped = IpAddr::V6(v4.to_ipv6_mapped());
        assert!(pool.contains_ip(mapped));
        assert_eq!(
            pool.reverse_lookup_ip(mapped).as_deref(),
            Some("example.com")
        );
    }

    #[test]
    fn an_ipv4_only_pool_never_allocates_an_ipv6_address() {
        let config = FakeIpConfig {
            enabled: true,
            inet: "198.18.0.0/15".to_owned(),
            inet6: None,
            pool_size: 100,
            exclude: vec![],
        };
        let pool = FakeIpPool::from_config(&config).expect("pool builds");
        assert!(!pool.has_ipv6());
        assert!(pool.allocate_v6("example.com").is_none());
        assert_eq!(pool.net6(), None);
    }

    #[test]
    fn an_invalid_ipv6_prefix_names_the_field() {
        let config = FakeIpConfig {
            enabled: true,
            inet: "198.18.0.0/15".to_owned(),
            inet6: Some("not-a-prefix".to_owned()),
            pool_size: 100,
            exclude: vec![],
        };
        let error = FakeIpPool::from_config(&config).expect_err("must refuse");
        assert!(error.contains("inet6"), "{error}");
    }

    #[test]
    fn the_exclusion_list_understands_the_documented_pattern_syntax() {
        // The old matcher compared strings with `ends_with`, so a pattern the operator wrote was
        // inert and every excluded name got a synthetic address. This is the falsifier: each
        // accepted form (bare suffix, subdomains-only, exact, keyword, regex) must match the
        // names it is supposed to.
        let config = FakeIpConfig {
            enabled: true,
            inet: "198.18.0.0/15".to_owned(),
            inet6: None,
            pool_size: 100,
            exclude: vec![
                "local".to_owned(),
                ".corp.internal".to_owned(),
                "=only.example".to_owned(),
                "keyword:ads".to_owned(),
                "regex:^track[0-9]+\\.".to_owned(),
            ],
        };
        let pool = FakeIpPool::from_config(&config).expect("pool builds");

        for excluded in [
            "gateway.local",
            "srv.corp.internal",
            "only.example",
            "ads.example.net",
            "track7.example.org",
        ] {
            assert!(pool.is_excluded(excluded), "{excluded} must be excluded");
        }
        for included in [
            "example.com",
            "notonly.example",
            "example.org",
            "corp.internal",
        ] {
            assert!(
                !pool.is_excluded(included),
                "{included} must not be excluded"
            );
        }
    }

    #[test]
    fn a_dat_category_is_refused_by_name_rather_than_ignored() {
        // `geosite:cn` is a Protobuf `.dat` reference, retired by ADR-0014. Accepting the
        // pattern and matching nothing would silently disable an exclusion the operator
        // believes is active, so it is refused and the message says what to write instead.
        let config = FakeIpConfig {
            enabled: true,
            inet: "198.18.0.0/15".to_owned(),
            inet6: None,
            pool_size: 100,
            exclude: vec!["geosite:cn".to_owned()],
        };
        let error = FakeIpPool::from_config(&config).expect_err("must refuse");
        assert!(error.contains("geosite"), "{error}");
        assert!(
            error.contains("ADR-0031"),
            "the error must say why the category is gone: {error}"
        );
    }

    #[test]
    fn an_unknown_matcher_key_is_refused_by_name() {
        let config = FakeIpConfig {
            enabled: true,
            inet: "198.18.0.0/15".to_owned(),
            inet6: None,
            pool_size: 100,
            exclude: vec!["sufix:local".to_owned()],
        };
        let error = FakeIpPool::from_config(&config).expect_err("must refuse");
        assert!(error.contains("sufix"), "{error}");
    }

    #[test]
    fn snooper_records_and_retrieves() {
        let snooper = DnsSnooper::new(10);
        let ip: IpAddr = "93.184.216.34".parse().unwrap();
        snooper.record(ip, "example.com", 60);

        let domain = snooper.lookup(ip).expect("lookup hit");
        assert_eq!(&*domain, "example.com");

        let unknown: IpAddr = "1.2.3.4".parse().unwrap();
        assert_eq!(snooper.lookup(unknown), None);
    }
}
