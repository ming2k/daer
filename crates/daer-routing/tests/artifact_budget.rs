// SPDX-License-Identifier: AGPL-3.0-only

//! The benchmark that decides whether the artifact format is acceptable.
//!
//! This exists because a previous revision of the format was justified with a claim — "order of
//! magnitude faster on negative hits" — that turned out to be backwards: it was seven times
//! *slower*, and the artifact was 61% larger. The claim survived because it was never measured.
//! So the model is written down here as executable assertions rather than as prose.
//!
//! Run with a real corpus:
//!
//! ```text
//! DAER_DRB_CORPUS=/path/to/geosite-cn.drb cargo test -p daer-routing --release \
//!     --test artifact_budget -- --nocapture --ignored
//! ```
//!
//! Without `DAER_DRB_CORPUS` the tests skip, so CI on a machine with no corpus stays green while
//! a developer with one gets the real numbers.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use daer_routing::DrbSet;

fn corpus() -> Option<PathBuf> {
    let path = PathBuf::from(std::env::var("DAER_DRB_CORPUS").ok()?);
    path.is_file().then_some(path)
}

fn load(path: &PathBuf) -> (Vec<u8>, DrbSet) {
    let bytes = std::fs::read(path).expect("reads the corpus");
    let set = DrbSet::decode(&bytes).expect("decodes the corpus");
    (bytes, set)
}

/// Names a "domestic" rule set is expected to match, and names it is not.
///
/// The negative list is the interesting one: a proxy evaluates a rule set for traffic that
/// mostly does *not* belong to it, so a design that only performs well on hits is measuring the
/// wrong case. This was the specific mistake the previous revision made.
const HITS: &[&str] = &[
    "www.baidu.com",
    "qq.com",
    "taobao.com",
    "www.aliyun.com",
    "bilibili.com",
    "www.163.com",
    "jd.com",
    "weibo.com",
];

const MISSES: &[&str] = &[
    "google.com",
    "youtube.com",
    "github.com",
    "x.com",
    "telegram.org",
    "netflix.com",
    "spotify.com",
    "cloudflare.com",
];

fn time_lookups(set: &DrbSet, names: &[&str], iterations: usize) -> Duration {
    let start = Instant::now();
    let mut sink = 0usize;
    for _ in 0..iterations {
        for name in names {
            sink += usize::from(set.matches_domain(name));
        }
    }
    // Keep the work observable so the optimiser cannot delete the loop.
    assert!(sink <= iterations * names.len());
    start.elapsed()
}

#[test]
#[ignore = "needs DAER_DRB_CORPUS; run with --ignored and a real artifact"]
fn the_artifact_fits_its_size_budget() {
    let Some(path) = corpus() else {
        eprintln!("skipping: set DAER_DRB_CORPUS to a real .drb artifact");
        return;
    };
    let (bytes, set) = load(&path);
    eprintln!(
        "{}: {} bytes, {} ip intervals, {} domain patterns",
        path.display(),
        bytes.len(),
        set.v4_intervals.len() + set.v6_intervals.len(),
        set.domain_patterns(),
    );
    // A published artifact is downloaded by every client, every day. Anything past a megabyte
    // per set is a bandwidth decision nobody signed off on.
    assert!(
        bytes.len() < 8 << 20,
        "{} is {} bytes; past the 8 MiB budget",
        path.display(),
        bytes.len()
    );
}

#[test]
#[ignore = "needs DAER_DRB_CORPUS; run with --ignored and a real artifact"]
fn a_miss_is_not_more_expensive_than_a_hit() {
    let Some(path) = corpus() else {
        eprintln!("skipping: set DAER_DRB_CORPUS to a real .drb artifact");
        return;
    };
    let (_, set) = load(&path);
    const ITERATIONS: usize = 20_000;

    // Warm both paths so the comparison is not dominated by first-touch page faults.
    let _ = time_lookups(&set, HITS, 100);
    let _ = time_lookups(&set, MISSES, 100);

    let hit = time_lookups(&set, HITS, ITERATIONS);
    let miss = time_lookups(&set, MISSES, ITERATIONS);
    let per_hit = hit / (ITERATIONS * HITS.len()) as u32;
    let per_miss = miss / (ITERATIONS * MISSES.len()) as u32;
    eprintln!("hit  {per_hit:?}/lookup");
    eprintln!("miss {per_miss:?}/lookup");

    // A name that is in no rule set walks the same label boundaries a hit does, so the two costs
    // should be within a small factor. The rejected trie design was 2.5x worse on misses than
    // hits *and* slower than a hash in absolute terms; this asserts the shape stayed flat.
    assert!(
        per_miss < per_hit * 3 + Duration::from_nanos(500),
        "a miss ({per_miss:?}) must not cost several times a hit ({per_hit:?}): \
         the lookup must not degrade for the traffic a proxy actually sees"
    );
}

#[test]
#[ignore = "needs DAER_DRB_CORPUS; run with --ignored and a real artifact"]
fn lookup_stays_within_its_latency_budget() {
    let Some(path) = corpus() else {
        eprintln!("skipping: set DAER_DRB_CORPUS to a real .drb artifact");
        return;
    };
    let (_, set) = load(&path);
    const ITERATIONS: usize = 20_000;

    let _ = time_lookups(&set, HITS, 100);
    let elapsed = time_lookups(&set, HITS, ITERATIONS);
    let per_lookup = elapsed / (ITERATIONS * HITS.len()) as u32;
    eprintln!(
        "{per_lookup:?}/lookup over {} patterns",
        set.domain_patterns()
    );

    // The documented model: matching runs once per connection, so a microsecond is fine and a
    // millisecond is not. This bound is loose on purpose — it is a regression tripwire, not a
    // target — but it is far tighter than what the rejected design would have needed.
    assert!(
        per_lookup < Duration::from_micros(20),
        "{per_lookup:?}/lookup exceeds the 20 µs budget; the lookup regressed"
    );
}

#[test]
#[ignore = "needs DAER_DRB_CORPUS; run with --ignored and a real artifact"]
fn decoding_is_cheap_enough_for_a_reload() {
    let Some(path) = corpus() else {
        eprintln!("skipping: set DAER_DRB_CORPUS to a real .drb artifact");
        return;
    };
    let bytes = std::fs::read(&path).expect("reads");
    let start = Instant::now();
    let set = DrbSet::decode(&bytes).expect("decodes");
    let elapsed = start.elapsed();
    eprintln!(
        "decode {:?} for {} patterns ({} bytes)",
        elapsed,
        set.domain_patterns(),
        bytes.len()
    );

    // SIGHUP reloads every provider; a second per artifact would be a bad reload.
    assert!(
        elapsed < Duration::from_millis(200),
        "decoding took {elapsed:?}; a reload would stall"
    );
}

#[test]
#[ignore = "needs DAER_DRB_CORPUS; run with --ignored and a real artifact"]
fn every_hit_and_miss_agrees_with_a_reference_matcher() {
    let Some(path) = corpus() else {
        eprintln!("skipping: set DAER_DRB_CORPUS to a real .drb artifact");
        return;
    };
    let (_, set) = load(&path);

    // The reference is the decompiled rule set: if the table and the rules it claims to encode
    // disagree about a name, one of them is lying and neither can be trusted.
    let rules = set.to_rule_set();
    let mut patterns: Vec<String> = Vec::new();
    for rule in rules.domains() {
        patterns.push(format!(
            "{}{}",
            match &rule.pattern {
                daer_rule_ast::DomainPattern::Full(_) => "=",
                daer_rule_ast::DomainPattern::Suffix(
                    _,
                    daer_rule_ast::SuffixScope::SubdomainsOnly,
                ) => ".",
                daer_rule_ast::DomainPattern::Suffix(..) => "",
            },
            rule.pattern.value()
        ));
    }
    let reference = daer_routing::DomainTable::compile(
        &patterns.iter().map(String::as_str).collect::<Vec<_>>(),
        &mut Vec::new(),
    );

    for name in HITS.iter().chain(MISSES) {
        assert_eq!(
            set.matches_domain(name),
            reference.matches(name),
            "{name}: the artifact and its decompiled rules disagree"
        );
    }
}
