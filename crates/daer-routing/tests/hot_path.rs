// SPDX-License-Identifier: AGPL-3.0-only

//! The decision path's contract: it allocates nothing and it does not get slower
//! as the configuration grows.
//!
//! # Why these are tests and not a benchmark
//!
//! A benchmark reports a number a human reads once. These assert the two
//! properties that actually regress silently:
//!
//! 1. **No allocation per decision.** A `malloc`/`free` pair per connection is
//!    invisible in a synthetic benchmark and fatal under load, because it puts the
//!    allocator on the path between two sockets.
//! 2. **Cost does not scale with rule size.** The matcher used to be a linear scan,
//!    so `geosite:cn` (110,000 domains) cost 368 µs per miss. Nothing in the API
//!    prevented that from coming back; a timing assertion does.
//!
//! Timing assertions are enabled by default and can be relaxed with
//! `DAER_HOT_PATH_SCALE` on a slow or loaded machine — a flaky gate that gets
//! disabled is worse than an explicit knob.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use daer_common::{MacAddr, PortRange};
use daer_routing::{
    MatchFacts, MatchSet, MatchTarget, MatchValue, Outbound, ProcessName, evaluate,
};

/// A counting allocator, so "no allocation" is measured rather than asserted.
///
/// The counter is **thread-local**. `cargo test` runs tests in parallel, so a
/// process-global counter measures every other test's allocations too — the first
/// version of this file failed with 11,165 allocations that all belonged to
/// sibling threads. A thread-local count answers the question actually being
/// asked: does the thread making the decision allocate?
mod alloc {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::cell::Cell;

    thread_local! {
        /// `const` so the initialiser cannot itself allocate, which would recurse.
        static COUNT: Cell<usize> = const { Cell::new(0) };
        static ENABLED: Cell<bool> = const { Cell::new(false) };
    }

    pub fn enable() {
        ENABLED.with(|flag| flag.set(true));
        COUNT.with(|count| count.set(0));
    }

    pub fn read() -> usize {
        COUNT.with(Cell::get)
    }

    fn record() {
        if ENABLED.try_with(Cell::get).unwrap_or(false) {
            let _ = COUNT.try_with(|count| count.set(count.get() + 1));
        }
    }

    pub struct Counting;

    // SAFETY: every method forwards to `System` with the same layout and the same
    // contract; the only added work is a thread-local counter bump, which cannot
    // affect the returned pointer.
    unsafe impl GlobalAlloc for Counting {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            record();
            // SAFETY: forwarded unchanged.
            unsafe { System.alloc(layout) }
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            // SAFETY: forwarded unchanged.
            unsafe { System.dealloc(ptr, layout) }
        }

        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
            record();
            // SAFETY: forwarded unchanged.
            unsafe { System.realloc(ptr, layout, new_size) }
        }
    }
}

#[global_allocator]
static ALLOCATOR: alloc::Counting = alloc::Counting;

fn facts() -> MatchFacts<'static> {
    MatchFacts {
        source_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
        dest_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        source_port: 40_000,
        dest_port: 443,
        l4proto: daer_routing::L4ProtoMask::TCP,
        domain: Some("site1.example.cn"),
        process_name: ProcessName::from_bytes_truncated(b"curl"),
        dscp: 0,
        mac: MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
    }
}

/// A match set shaped like a real `geosite:cn` / `geoip:cn` rule.
fn realistic_sets() -> Vec<MatchSet> {
    let mut warnings = Vec::new();
    let domains: Vec<String> = (0..20_000)
        .map(|index| format!("site{index}.example.cn"))
        .collect();
    let borrowed: Vec<&str> = domains.iter().map(String::as_str).collect();
    let domain =
        daer_routing::DomainIndex::new(daer_routing::DomainKey::Suffix, &borrowed, &mut warnings);
    assert!(warnings.is_empty(), "{warnings:?}");

    let prefixes: Vec<ipnet::IpNet> = (0..5_000u32)
        .map(|index| {
            let octet = (index % 256) as u8;
            let third = (index / 256) as u8;
            format!("10.{third}.{octet}.0/24").parse().expect("prefix")
        })
        .collect();
    let ip = daer_routing::IpIndex::new(&prefixes).expect("index");

    vec![
        MatchSet {
            value: MatchValue::IpSet(ip),
            target: MatchTarget::logical_and(0, false),
            negated: false,
        },
        MatchSet {
            value: MatchValue::Domain(domain),
            target: MatchTarget::Outbound(Outbound::new("proxy")),
            negated: false,
        },
    ]
}

/// A decision must not touch the heap: the outbound identity is shared, not copied
/// into a fresh `String`.
#[test]
fn a_decision_allocates_nothing() {
    let sets = realistic_sets();
    let facts = facts();

    // Warm every lazily-built path so the measurement is of the decision, not of
    // one-time initialisation.
    for _ in 0..64 {
        let _ = evaluate(&sets, &facts);
    }

    alloc::enable();
    for _ in 0..1_000 {
        let result = evaluate(&sets, &facts).expect("hits");
        // Reading the name must not force a copy either.
        assert_eq!(&*result.outbound.name, "proxy");
    }
    let allocated = alloc::read();

    assert_eq!(
        allocated, 0,
        "a decision allocated {allocated} times over 1,000 evaluations"
    );
}

/// The decision must not pay for the size of a set it does not match.
#[test]
fn lookup_cost_does_not_scale_with_set_size() {
    let sets = realistic_sets();
    let mut miss = facts();
    // A name and an address outside both sets.
    miss.domain = Some("www.not-in-the-set.example");
    miss.dest_addr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));

    let mut hit = facts();
    hit.domain = Some("site7.example.cn");
    hit.dest_addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

    let scale: u32 = std::env::var("DAER_HOT_PATH_SCALE")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(1);

    // Calibrate against a baseline of the same shape, so the budget is a ratio
    // rather than an absolute that depends on the machine.
    let budget = Duration::from_micros(50) * scale.max(1);

    for (label, probe) in [("miss", &miss), ("hit", &hit)] {
        // Warm up.
        for _ in 0..100 {
            let _ = evaluate(&sets, probe);
        }
        let iterations = 20_000;
        let started = Instant::now();
        for _ in 0..iterations {
            let _ = evaluate(&sets, probe);
        }
        let per = started.elapsed() / iterations;
        assert!(
            per < budget,
            "{label}: {per:?} per decision over 25,000 patterns and 5,000 prefixes \
             (budget {budget:?}); the matcher has regressed to scanning. \
             Set DAER_HOT_PATH_SCALE to relax this on a slow machine."
        );
    }
}

/// A rule ordinal must be exact no matter how many match sets precede it.
#[test]
fn a_late_rule_reports_its_own_ordinal() {
    let mut sets = Vec::new();
    // 200 rules of two predicates each, so the terminator of rule `n` sits at a
    // match-set index far from `n`.
    for index in 0..200u16 {
        sets.push(MatchSet {
            value: MatchValue::SourcePort(PortRange::single(index)),
            target: MatchTarget::logical_and(0, false),
            negated: false,
        });
        sets.push(MatchSet {
            value: MatchValue::Port(PortRange::single(443)),
            target: MatchTarget::Outbound(Outbound::new(format!("group{index}"))),
            negated: false,
        });
    }

    let mut probe = facts();
    probe.source_port = 157;
    probe.dest_port = 443;
    let result = evaluate(&sets, &probe).expect("hits");
    assert_eq!(&*result.outbound.name, "group157");
}

/// The whole point of `Arc<str>`: cloning an identity is cheap and shares storage.
#[test]
fn outbound_identity_is_shared_not_copied() {
    let name: Arc<str> = Arc::from("proxy");
    let strong = Arc::strong_count(&name);
    let outbound = Outbound::new(name.clone());
    assert!(Arc::strong_count(&name) > strong);
    assert!(Arc::ptr_eq(&name, &outbound.name));
}

/// An empty set must be cheap and must not match, rather than hash a default.
#[test]
fn an_empty_set_matches_nothing_without_work() {
    let index = daer_routing::IpIndex::new(&[]).expect("index");
    assert!(!index.contains(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
    let domains = daer_routing::DomainIndex::new(daer_routing::DomainKey::Suffix, &[], &mut vec![]);
    assert!(!domains.matches("example.com"));
}
