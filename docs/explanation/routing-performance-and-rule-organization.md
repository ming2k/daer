# Routing Performance, Kernel Datapath Bounds, and Rule Asset Topology

This article explains the mechanical reality of `daer`'s routing policy evaluation: why binary search and hash lookups behave with logarithmic and constant scale, why splitting rules across fragmented files degrades performance rather than improving it, why monolithic multi-tag archives fail in production, and how kernel eBPF limits shape the rule asset topology.

---

## 1. The Two-Tiered Performance Model

When packet facts arrive at the routing engine (either in the eBPF kernel datapath or the userspace relay evaluator), routing decisions follow a **two-tiered evaluation hierarchy**:

```text
Incoming Flow Facts (IPs, Ports, SNI / Domain, Protocol, Process)
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│ Tier 1: Outer Predicate Walk (Sequential Loop)              │
│                                                             │
│ for set in match_sets {                                     │
│     if matches_value(set.value, facts) {                    │
│         // Check logical operators (AND / OR) & Outbounds   │
│     }                                                       │
│ }                                                           │
└──────────────────────────┬──────────────────────────────────┘
                           │
             ┌─────────────┴─────────────┐
             ▼                           ▼
┌───────────────────────────┐ ┌───────────────────────────┐
│ Tier 2A: IpIndex          │ │ Tier 2B: DomainIndex      │
│ Single Binary Search      │ │ Reverse Label Hash Walk   │
│ O(log M) — ~13 comparisons│ │ O(1) — <= 5 probes        │
└───────────────────────────┘ └───────────────────────────┘
```

The fundamental distinction to grasp is between **Tier 1 (Outer Predicate Walk)** and **Tier 2 (Inner Algorithmic Index)**.

### Tier 2A: IP Prefix Matching (`IpIndex`)

Routing never asks *which* prefix matched an address; it asks a boolean predicate: *is this address inside this set?*

1. **Interval Coalescence at Build Time**:
   During compilation, all IPv4 and IPv6 prefixes (whether ten or ten thousand) are expanded into inclusive numerical intervals `[start, end]`. Overlapping, nested, and adjacent intervals are merged:
   - Consecutive `/24` subnets collapse into a single `/16` or `/15` numerical range.
   - For `geoip:cn` (~8,000 distinct CIDR allocations), coalescence collapses the set into ~3,000 to ~4,000 non-overlapping integer intervals.
2. **Deterministic, Cache-Line Friendly Binary Search**:
   The merged intervals are stored in a contiguous, flat `Vec<(u32, u32)>` (or `Vec<(u128, u128)>`). Lookup is a standard binary search:
   - For 1,000 intervals: $\log_2(1,000) \approx 10$ integer comparisons.
   - For 10,000 intervals: $\log_2(10,000) \approx 13\sim 14$ integer comparisons.
   - For 100,000 intervals: $\log_2(100,000) \approx 17$ integer comparisons.

**Scaling 10× in data volume costs only 3 to 4 additional CPU register comparisons.** Because the array is flat and contiguous, probing touches approximately 13 `u32` integers in memory—fitting entirely within one or two L1/L2 CPU cache lines.

### Tier 2B: Domain Pattern Matching (`DomainIndex`)

`geosite:cn` contains ~110,000 domain rules. A linear string search or regular expression scan over 110,000 patterns per packet would destroy gateway throughput.

`daer` compiles domain rules into exact sets, suffix hash sets, and substring automata:

| Pattern Key | In-Memory Structure | Query Cost Per Flow |
| :--- | :--- | :--- |
| `full` | `HashSet<String>` | Exactly 1 hash lookup |
| `suffix` | Pattern hash set + label walk | At most $(K + 1)$ hash lookups ($K \le 5$) |
| `keyword` | Aho–Corasick automaton | Single pass, 0 allocation |
| `regex` | Combined `RegexSet` | Single pass DFA traversal |

For the dominant suffix matching, the query splits the candidate hostname by label boundaries in reverse:
`music.163.com` $\to$ probe `music.163.com`, probe `163.com`, probe `com`.

**The lookup time is strictly proportional to the label depth of the incoming hostname ($K \le 5$), and completely independent of whether the rule set contains 50 domains or 500,000 domains ($O(1)$ scaling relative to rule set size).**

---

## 2. Why Rule Fragmentation Is an Anti-Pattern

A common operator misconception is: *"If I split my routing rules into 100 separate files or 100 small provider tags, search will be faster because the engine searches smaller chunks."*

In reality, **fragmentation has the exact opposite effect**:

### 1. Outer Loop Amplification & Cache Thrashing
When rules are split into 100 separate statements (`provider(siteA) -> proxy`, `provider(siteB) -> proxy`...):
- Tier 1 must execute **100 linear iterations** for unmatched traffic.
- Each iteration performs a function dispatch, evaluates negation, checks target flags, and dereferences separate heap pointers for each index.
- Instead of a single binary search touching 13 contiguous `u32` elements in one cache line, the CPU is forced to jump across 100 disparate memory locations, causing catastrophic CPU cache misses and pipeline stalls.

### 2. The 1024-Match-Set Kernel Barrier (`[INV-KERNEL-BOUND-01]`)

Under ADR-0003, ADR-0005, and ADR-0011, `daer` compiles routing policies directly into the Linux kernel eBPF datapath via a fixed-size `BPF_MAP_TYPE_ARRAY` routing table:

$$\text{MAX\_MATCH\_SET\_LEN} = 1024$$

```text
User Program Lowering:
  Rules (TOML) ──> Optimizer ──> RulesBuilder ──> MatchSets (Vec<MatchSet>)
                                                         │
                        ┌────────────────────────────────┴────────────────────────────────┐
                        ▼                                                                 ▼
               MatchSets <= 1024                                                 MatchSets > 1024
                        │                                                                 │
                        ▼                                                                 ▼
            Kernel Policy Compiled!                                          DeferReason::TooManySets
      eBPF TC Line-Rate Hardware Offload                                    Kernel Line-Rate Offload ABORTED
  (Packets redirected/passed at wire speed)                                (100% of flows deferred to userspace)
```

- Each non-merged rule lowers to one or more `MatchSet` entries.
- If an operator fragments rules across dozens of files or granular statements, the generated match set count rapidly exceeds `1024`.
- **The Failure Mode**: The compiler immediately marks the policy as non-equivalent (`Policy::defer`). The kernel datapath drops hardware line-rate switching and sends **every single connection to userspace relay**. Forwarding latency and CPU overhead increase by an order of magnitude.

**By aggregating rules into coarse-grained providers, tens of thousands of domains and subnets collapse into a handful of `MatchSet` entries, maintaining 100% kernel offload eligibility.**

---

## 3. The Myth of the Monolithic Multi-Tag Database

Another intuitive suggestion is: *"Why not pack all global rules into a single large database file (like SQLite or MMDB) where each entry has a tag, and query by tag?"*

While aesthetically neat on disk, this monolithic model fails in distributed production environments:

### 1. The Update Blast Radius
Rules in modern routing belong to fundamentally different update authorities and lifecycles:
- **Anti-Ad lists** (e.g. AdGuard, anti-AD): Update hourly or daily as ad delivery domains rotate.
- **GeoIP allocations** (e.g. MaxMind, APNIC): Update monthly as BGP ASNs and CIDRs change.
- **Regional Site Whitelists** (e.g. `geosite:cn`): Update weekly.

In a monolithic archive, adding a single ad-tracking domain changes the SHA-256 hash of the entire 50 MB database. Every client, router, and cloud gateway must re-download the entire 50 MB artifact. With independent providers, updating the ad list consumes a 200 KB differential HTTP transfer, while the 30 MB GeoIP archive remains untouched via HTTP `304 Not Modified`.

### 2. Hot-Path `mmap` Page Fault Latency
Relying on virtual memory `mmap` to dynamically fault in tag slices from a single database on demand creates jitter:
- When a flow encounters a cold tag for the first time, a hardware page fault is triggered to read the block from non-volatile flash storage.
- Connection setup latency spikes from $\approx 5\ \mu\text{s}$ to $10\sim 50\ \text{ms}$.
- Transparent proxying requires bounded, deterministic microseconds. Pre-indexing discrete providers at startup eliminates all hot-path I/O.

---

## 4. Why DRB Is a Unified Container (`.drb`), Not Split Formats

IP prefix intervals and domain label trees are completely distinct mathematical structures. Why does `daer` use a single `.drb` (daer Rule Binary) extension rather than splitting into `.dib` (IP) and `.ddp` (Domain)?

### 1. Container vs. Payload Separation
`DRB` is an **envelope and wire protocol** (ADR-0014). It specifies:
- Magic bytes (`DAER_DRB`) and version tags.
- Cryptographic SHA-256 payload integrity check.
- Standardized binary serialization framing.

The algorithmic divergence belongs in memory (`IpIndex` vs. `DomainIndex`), not in the file extension. Renaming extensions based on payload contents would be equivalent to renaming `.zip` to `.pzip` if it holds photos, or `.mzip` if it holds music.

### 2. Atomic Composite Rules
Real-world infrastructure frequently requires rules tied to a single organizational boundary containing **both** IP subnets and internal domain suffixes.

In a unified DRB container, operators write a single plain text rule:
```text
# corporate.rules
ip: 10.0.0.0/8
ip: 172.16.0.0/12
suffix: corp.internal
full: vpn.company.com
```

Compiled via `geodrb compile corporate.rules -o corporate.drb`, this artifact loads into `daer` under one provider:
```toml
[routing]
rules = [
    "provider(corporate) -> direct",
]
```
`daer-routing` automatically lowers this into:
$$\text{IpSet(10.0.0.0/8, ...)} \lor \text{Domain(corp.internal, ...)} \to \text{direct}$$
Splitting formats by type would force maintaining two files (`corporate.dib` and `corporate.ddp`), two provider declarations, and two routing rules for every business asset.

---

## 5. Summary: Golden Rules of Rule Organization

| Dimension | Anti-Pattern | Recommended Architecture |
| :--- | :--- | :--- |
| **Rule Topology** | Hundreds of fine-grained files or per-site rules | **3 to 6 coarse-grained providers** grouped by outbound action |
| **Index Scaling** | Relying on outer rule order to separate domains | Let **`DomainIndex` ($O(1)$)** and **`IpIndex` ($O(\log M)$)** do the heavy lifting inside sets |
| **Kernel Datapath** | Generating $> 1024$ match sets (triggers user-space fallback) | Keep match sets $< 1024$ to preserve **eBPF line-rate hardware offload** |
| **Asset Formats** | Creating custom file formats per data type | Use **`.drb`** for precompiled production assets and plain text (`format = "text"`) for local scripts |
