# ADR-0032 — The domain table is flat and front-coded, not a trie

- Status: accepted
- Date: 2026-11-06
- Related: [ADR-0014](0014-drb-rule-binary-and-providers.md), [ADR-0019](0019-rule-asset-topology-and-lookup-mechanics.md), [ADR-0031](0031-drb-v2-and-canonical-rules.md)
- Supersedes: the Compact Reverse Label Radix of ADR-0031 §3
- Amends: [ADR-0031](0031-drb-v2-and-canonical-rules.md) — the IP half stands; the domain encoding does not.

---

## Context

ADR-0031 replaced four domain engines (exact set, suffix map, Aho-Corasick, regex set) with a
**Compact Reverse Label Radix**: a flat BFS array of 16-byte nodes, one node per label. The
reasoning was that a single tree walk answers `full` and `suffix` together and terminates a
negative lookup at the first missing label, eliminating what that ADR called the *negative
lookup fallacy*.

Two measurements falsified it on the published corpus.

### 1. There was no node sharing

The premise of a trie is that prefixes are shared, so `N` names cost fewer than `N` nodes. On
`geosite.dat`:

| set | rules | nodes | nodes / rule |
| --- | --- | --- | --- |
| `geosite:cn` | 110,189 | 110,448 | **1.002** |
| `geosite:category-ads-all` | ~317k | 317,353 | **1.000** |

Reverse-label order groups names by TLD, but the *labels themselves are essentially unique*, so
almost no node is shared. The tree paid 16 bytes per label to represent what is really a flat
list, and `www.baidu.com` cost 48 bytes against ~13 for the string it was derived from.

### 2. The artifact grew, and that is the cost that matters

| artifact | DRB v1 (flat) | ADR-0031 radix |
| --- | --- | --- |
| `geosite-cn.drb` | 1,616,630 | 2,604,880 (**+61%**) |
| `geosite-category-ads-all.drb` | 4,528,351 | 7,778,414 (**+71%**) |

ADR-0031 justified the design with "order-of-magnitude reduction in domain lookup latency on
negative hits". Two things were wrong with that justification:

- **The measurement did not support it.** For a miss-heavy sample (10 foreign names × 10,000
  iterations, the true common case for a proxy) the radix took **27.5 ms** against the old
  `DomainIndex`'s **3.9 ms** — seven times *slower*. Each level did a `binary_search_by` over
  up to 25,951 sibling labels (the `com` node had exactly that many), comparing bytes; the
  `HashMap` it replaced was O(1).
- **The cost was modelled against the wrong frequency.** Any rule containing a `domain(...)`
  predicate sets `DeferReason::Domain`, so the datapath never evaluates names — domain matching
  runs **once per connection in the userspace evaluator**, not once per packet. The binding
  constraint is therefore **artifact size**, because every client re-downloads these files
  daily, and secondarily generation-build time. Nanoseconds per lookup are irrelevant next to
  +61% outbound bytes and a 36 ms per-generation rebuild that expands the tree back into a map.

## Decision

The domain section is a **flat, front-coded, reversed-label-sorted table**.

### 1. One record per pattern, stored once

Records are sorted by **reversed-label key** (`www.example.com` → `com.example.www`). Because the
list is sorted, each record shares a prefix with its immediate predecessor, so the shared bytes
are stored once as `shared_len` and only the differing tail is written:

```text
record := flags:u8  shared_len:u16  suffix_len:u16  suffix[suffix_len]
```

### 2. Reverse-label sorting is what makes the lookup cheap

With that order, every pattern a name descends from is a **label-boundary prefix of the name's
reversed key**. `www.example.com` → key `com.example.www`, whose label-boundary prefixes are
`com`, `com.example`, `com.example.www`. Those are exactly the suffixes that could cover it.

The lookup rewrites the name once, then binary-searches each boundary prefix in the sorted
table: `O(depth · log n)`, allocation-free, contiguous memory. A miss costs the same as a hit,
which is the property ADR-0031 wanted — reached by sorting rather than by adding nodes.

### 3. Records covered by a broader suffix are dropped at compile time

If `suffix: example.com` exists, every `full:`/`suffix:` beneath `example.com` is dead weight:
the broader rule already answers it. The compiler removes them. Subdomains-only rules are kept
when they are not covered, because `.example.com` does *not* answer `example.com`.

### 4. Keys live in one arena

Records hold `(offset, len, flags)` into a single byte arena, not a `String` each. Measured on
`geosite:cn`: the record table is 1.3 MB plus ~0.6 MB of keys, against an estimated ~6.9 MB for
the `HashSet` + `HashMap` it replaced — **roughly 3.6× less resident memory** and one allocation
per section rather than 110,045.

## The trade that is actually being made

This ADR buys size and memory with lookup latency. The measurements are stated plainly because
the earlier revision of this decision got them wrong in the optimistic direction:

| metric | `DomainIndex` (hash) | this flat table | verdict |
| --- | --- | --- | --- |
| `geosite-cn.drb` on disk | 1,616,630 (v1) | **1,002,600** | **−37%** |
| resident domain state | ~6.9 MB (est.) | **~1.9 MB** | **≈3.6× less** |
| hit lookup, 50k iterations | 1.8 ms | 28.2 ms | ~15× slower |
| miss lookup, 50k iterations | 1.9 ms | 14.1 ms | ~7× slower |
| per-generation rebuild | 0 | 38 ms | +38 ms |

**Why this direction is still correct:** domain matching runs once per connection in the
userspace evaluator — the datapath defers every rule containing `domain(...)`, so eBPF never
matches names. The absolute difference is ~350 ns per connection. Against that, every client
re-downloads these artifacts daily, so −37% of a 1.6 MB file is ~600 KB saved per client per day,
and 5 MB less resident memory on a low-power gateway is a real budget item.

A hash map is O(1); a sorted array is O(depth · log n). At 110k entries the hash wins per
lookup, and no amount of implementation tuning changes that — the arena change above made the
lookup no faster, which is itself the evidence. The choice is between the two, and the frequency
of the operation decides it.

**If domain matching ever moves onto a per-packet path**, this decision must be revisited: at
that point the lookup cost dominates and the table should go back to hashing.

## Consequences

### Positive

Every published artifact is smaller than the format it replaced:

| artifact | DRB v1 | radix (rejected) | **flat + front-coded** |
| --- | --- | --- | --- |
| `geosite-cn.drb` | 1,616,630 | 2,604,880 | **1,002,600 (−37%)** |
| `geosite-category-ads-all.drb` | 4,528,351 | 7,778,414 | **3,199,060 (−29%)** |
| `geosite-apple.drb` | 37,197 | — | **22,712 (−38%)** |
| `geoip-cn.drb` | 207,008 | 107,330 | **107,330 (−48%)** |

- 250 real domains sampled from the upstream `.dat`, cross-checked against an independent
  decoder: **0 mismatches**.
- All 24 artifacts round-trip `compile(decompile(drb))` to **identical bytes**.

### Negative and accepted costs

- The record form is variable-length, so a record cannot be random-accessed by index. Nothing
  needs that: matching is a binary search over keys, not positional access.
- Front-coding couples records: a corrupted byte shifts every later record. The payload SHA-256
  catches that at the gate, which is the same guarantee every other section has.
- `to_domain_index` still materialises a `DomainIndex` for the evaluator's `MatchValue`. That is
  a deliberate, documented per-generation bridge, not the data path; replacing it means changing
  `MatchValue`, which this ADR does not attempt.

## Enforcement

| Claim | Falsifier |
| --- | --- |
| Coverage pruning works | `an_enclosing_suffix_absorbs_the_names_it_covers` |
| Subdomains-only semantics preserved | `a_subdomains_only_suffix_does_not_cover_the_bare_name` |
| Front-coding survives prefix-shaped keys | `front_coding_survives_a_key_that_is_a_prefix_of_the_next` |
| Lookups agree with the source rules | `lookups_agree_with_the_rules_that_produced_them` |
| Artifacts are re-compilable byte-for-byte | `drb-sets` CI `cmp` over all published artifacts |
| The format never regrows a v1 header | `decoding_rejects_a_v1_artifact` |
