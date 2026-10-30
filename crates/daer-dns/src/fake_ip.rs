// SPDX-License-Identifier: AGPL-3.0-only

//! Synthetic Fake-IP allocation pool (ADR-0012) and DNS Snooping cache (ADR-0011).

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use daer_config::FakeIpConfig;
use ipnet::Ipv4Net;

/// The bi-directional Fake-IP pool (ADR-0012).
#[derive(Debug)]
pub struct FakeIpPool {
    enabled: bool,
    net: Ipv4Net,
    pool_size: usize,
    exclude: Vec<String>,
    state: Mutex<PoolState>,
}

#[derive(Debug, Default)]
struct PoolState {
    domain_to_ip: HashMap<Arc<str>, Ipv4Addr>,
    ip_to_domain: HashMap<Ipv4Addr, Arc<str>>,
    order: VecDeque<Ipv4Addr>,
    cursor: u32,
}

impl FakeIpPool {
    /// Builds a pool from configuration.
    ///
    /// # Errors
    ///
    /// Returns an error message if the configured `inet` subnet is not a valid IPv4 CIDR.
    pub fn from_config(config: &FakeIpConfig) -> Result<Self, String> {
        let net = Ipv4Net::from_str(&config.inet)
            .map_err(|e| format!("invalid fake-ip inet {:?}: {e}", config.inet))?;
        Ok(Self {
            enabled: config.enabled,
            net,
            pool_size: config.pool_size.max(1),
            exclude: config.exclude.clone(),
            state: Mutex::new(PoolState::default()),
        })
    }

    /// Whether Fake-IP synthesis is active.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// The configured subnet.
    #[must_use]
    pub fn net(&self) -> Ipv4Net {
        self.net
    }

    /// The configured pool size bound.
    #[must_use]
    pub fn pool_size(&self) -> usize {
        self.pool_size
    }

    /// The exclusion list.
    #[must_use]
    pub fn exclude(&self) -> &[String] {
        &self.exclude
    }

    /// Whether an address falls within the configured Fake-IP subnet.
    #[must_use]
    pub fn contains_ip(&self, ip: IpAddr) -> bool {
        if !self.enabled {
            return false;
        }
        match ip {
            IpAddr::V4(v4) => self.net.contains(&v4),
            IpAddr::V6(_) => false,
        }
    }

    /// Whether a domain is excluded from Fake-IP synthesis.
    #[must_use]
    pub fn is_excluded(&self, domain: &str) -> bool {
        let normalized = domain.trim_end_matches('.').to_ascii_lowercase();
        for pattern in &self.exclude {
            let pat = pattern.trim_end_matches('.').to_ascii_lowercase();
            if pat.is_empty() {
                continue;
            }
            if normalized == pat || normalized.ends_with(&format!(".{pat}")) {
                return true;
            }
        }
        false
    }

    /// Allocates or returns the synthetic IP associated with `domain`.
    pub fn allocate(&self, domain: &str) -> Ipv4Addr {
        let normalized = domain.trim_end_matches('.').to_ascii_lowercase();
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());

        if let Some(&ip) = state.domain_to_ip.get(normalized.as_str()) {
            return ip;
        }

        // Evict oldest if pool is full.
        while state.domain_to_ip.len() >= self.pool_size {
            if let Some(old_ip) = state.order.pop_front() {
                if let Some(old_domain) = state.ip_to_domain.remove(&old_ip) {
                    state.domain_to_ip.remove(&old_domain);
                }
            } else {
                break;
            }
        }

        // Next IP in subnet (skipping network and broadcast addresses).
        let start_u32 = u32::from(self.net.network()) + 1;
        let host_capacity = (1u32 << (32 - self.net.prefix_len()))
            .saturating_sub(2)
            .max(1);
        let offset = state.cursor % host_capacity;
        state.cursor = state.cursor.wrapping_add(1);

        let ip = Ipv4Addr::from(start_u32 + offset);
        let domain_arc: Arc<str> = Arc::from(normalized.as_str());

        if let Some(evicted_domain) = state.ip_to_domain.insert(ip, domain_arc.clone()) {
            state.domain_to_ip.remove(&evicted_domain);
        }
        state.domain_to_ip.insert(domain_arc, ip);
        state.order.push_back(ip);

        ip
    }

    /// Reverse-lookups the original domain for a synthetic IP.
    #[must_use]
    pub fn reverse_lookup(&self, ip: Ipv4Addr) -> Option<Arc<str>> {
        if !self.enabled || !self.net.contains(&ip) {
            return None;
        }
        let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        state.ip_to_domain.get(&ip).cloned()
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
            pool_size: 100,
            exclude: vec!["local".to_owned(), "corp.internal".to_owned()],
        };
        let pool = FakeIpPool::from_config(&config).expect("pool builds");

        assert!(pool.is_enabled());
        assert_eq!(pool.pool_size(), 100);
        assert_eq!(pool.exclude().len(), 2);

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
            pool_size: 100,
            exclude: vec![],
        };
        let disabled_pool = FakeIpPool::from_config(&disabled_config).expect("builds");
        assert!(!disabled_pool.is_enabled());
        assert!(!disabled_pool.contains_ip(IpAddr::V4(ip1)));
        assert_eq!(disabled_pool.reverse_lookup(ip1), None);
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
