---
id: ADR-0019
title: "Rule asset topology: coarse-grained provider envelopes over monolithic archives and fragmented rule sets"
status: accepted
date: 2026-10-31
scope: [routing/lookup, config/rule-providers, architecture/data-path, ebpf/kernel-policy]
supersedes: []
---

# 0019. Rule asset topology: coarse-grained provider envelopes over monolithic archives and fragmented rule sets

- Status: Accepted
- Date: 2026-10-31
- Deciders: Ming Li
- Related: [ADR-0003](0003-datapath-abi.md), [ADR-0005](0005-kernel-policy-encoding.md), [ADR-0011](0011-partitioned-kernel-routing.md), [ADR-0014](0014-drb-rule-binary-and-providers.md)

---

## Context and Problem Statement

Routing rules in transparent proxy appliances are evaluated on the nanosecond-to-microsecond hot path for every connection. Two recurring structural temptations emerge in community discussions and user configurations:

1. **The Fragmentation Illusion ("More files / smaller rules = faster lookup")**:
   Operators sometimes assume splitting rules into dozens or hundreds of granular files (e.g. per-application or per-site `.toml` files or granular rule sets) improves search efficiency by "dividing and conquering" the search space.
2. **The Monolithic Multi-Tag Archive Illusion ("A single SQLite/archive database with tag offsets")**:
   Conversely, operators request packing all global rules (thousands of categories, country codes, and services) into a single monolithic database file where all entries carry tags, and daer selects tags at runtime.
3. **Format Proliferation ("Split IP into `.dib` and Domain into `.ddp`")**:
   Because IP prefix matching and domain pattern matching rely on fundamentally distinct mathematical algorithms and data structures, operators wonder whether DRB should be split into distinct file formats by payload type.

These temptations overlook the physics of CPU caches, the memory layout of modern eBPF datapaths, the operational realities of decentralized rule distribution, and the architectural distinction between container envelopes and in-memory indexes.

We must record an authoritative architectural decision governing rule asset topology, lookup mechanics, containerization boundaries, and kernel offload invariants.

---

## Decision

### 1. The Two-Tiered Lookup Hierarchy (`[INV-LOOKUP-01]`)

The routing evaluator evaluates traffic in two strictly decoupled tiers:

```text
[ Incoming Flow Facts ]
         │
         ▼
[ Outer Tier: Linear Predicate Walk O(N) ]  <─── High-cost when fragmented!
         │
         ├── Rule 1: MatchSet (IpIndex / DomainIndex)
         ├── Rule 2: MatchSet (IpIndex / DomainIndex)
         └── ...
                 │
                 ▼
[ Inner Tier: Indexed Algorithmic Evaluation ] <── Zero-cost scale!
         │
         ├── IpIndex: Contiguous merged intervals -> 1 binary search O(log M)
         └── DomainIndex: Reverse label-walking -> <= 5 hash probes O(1)
```

- **Invariant `[INV-LOOKUP-01]` (Logarithmic and Constant Scale Within Sets)**:
  - **IP Matching (`IpIndex`)**: Prefixes are compiled into sorted, non-overlapping `[start, end]` intervals. A union of 100,000 IP prefixes reduces to contiguous integer intervals. A lookup takes exactly one binary search ($\approx 13\sim 17$ integer comparisons), touching $\le 13$ contiguous `u32` elements fitting in a handful of CPU L1/L2 cache lines.
  - **Domain Matching (`DomainIndex`)**: Suffix patterns are queried via reverse label-walking. A name with $K$ labels performs at most $K$ hash set lookups ($\le 5$), independent of whether the set contains 100 or 100,000 domains.
  - **The Outer Rule Loop**: Unlike the inner index, the outer walk across `MatchSet` elements is an $O(N)$ linear loop. Splitting 10,000 domains into 500 individual rules forces 500 outer iterations, 500 branch mispredictions, and non-contiguous heap traversals. Merging them into a single provider forces exactly 1 outer iteration and 1 inner index probe.

### 2. The 1024 Match-Set Kernel Bound (`[INV-KERNEL-BOUND-01]`)

Under ADR-0003, ADR-0005, and ADR-0011, the eBPF datapath maintains a fixed-size `BPF_MAP_TYPE_ARRAY` routing table bounded by `MAX_MATCH_SET_LEN = 1024`.

- Fragmenting rules into fine-grained per-site or per-service statements rapidly exhausts the 1024-set ceiling.
- **Invariant `[INV-KERNEL-BOUND-01]` (Fail-Safe User-Space Deferral)**:
  When lowered rules exceed 1024 match sets, the compiler produces `DeferReason::TooManySets` and defers all traffic to userspace relay. **Rule fragmentation directly destroys kernel line-rate offload.**
- Consolidating rules into coarse-grained provider predicates keeps the total lowered `MatchSet` count in the low dozens, guaranteeing 100% kernel offload eligibility.

### 3. Rejection of the Monolithic Archive Model

We explicitly reject packing all global tags into a single monolithic database (e.g. SQLite, MMDB, or multi-tag tar/zip-like container) for the runtime daemon:

1. **Update Blast Radius**: Third-party rule sources operate on mismatched lifecycles (anti-ad updates hourly/daily; GeoIP updates monthly; regional whitelists update weekly). A monolithic database requires downloading and rewriting a 40–80 MB artifact on every upstream modification, destroying edge device flash endurance and consuming massive subscription bandwidth.
2. **Decentralized Ecosystem Ownership**: No single authority maintains all routing rules. A monolithic archive creates a single point of failure (SPOF) requiring central curation and continuous upstream repackaging.
3. **Hot-Path Page-Fault Latency**: Relying on runtime `mmap` lazy faulting for un-indexed archive blocks introduces millisecond-level disk I/O pauses into first-packet connection handshakes.

### 4. DRB as a Unified Container Envelope (`[INV-DRB-ENVELOPE-01]`)

We reject splitting DRB into payload-specific file extensions (such as `.dib` for IP or `.ddp` for domain):

- **Envelope vs. Payload Separation**:
  `.drb` is a transport and storage envelope. It standardizes framing, magic bytes (`DAER_DRB`), version negotiation, section counts, and SHA-256 cryptographic verification.
- **Algorithmic Orthogonality Lives in Memory**:
  The algorithmic divergence between numerical intervals and string trees belongs in `IpIndex` vs. `DomainIndex` in memory. The storage envelope remains unified.
- **Composite Business Rules**:
  A single organizational unit (e.g. an enterprise asset or media service) naturally contains both private IP subnets and internal domains. A unified `.drb` container allows writing:
  ```text
  # company.rules -> compiled to company.drb
  ip: 10.0.0.0/8
  suffix: corp.internal
  ```
  Lowering automatically connects the resulting `IpIndex` and `DomainIndex` via `LogicalOr` into a single `provider(company) -> direct` rule. Splitting extensions would destroy atomic composite rule deployment.

### 5. Standard Topology: 3 to 6 Coarse-Grained Providers

The recommended and supported rule topology aggregates traffic by **outbound action** and **independent update authority**:

```text
/etc/daer/
├── daer.toml                      # Root daemon configuration
└── providers/
    ├── block-ads.drb              # Outbound: block (high frequency, external)
    ├── geosite-cn.drb             # Outbound: direct (medium frequency, external)
    ├── geoip-cn.drb               # Outbound: direct (low frequency, external)
    ├── proxy-special.drb          # Outbound: designated proxy group (medium frequency)
    └── internal.drb               # Outbound: direct (composite IP + domain, local)
```

---

## Consequences

### Positive
- **Guaranteed Kernel Offload**: Restricting configuration rules to coarse-grained providers guarantees lowered match sets remain well below `MAX_MATCH_SET_LEN` (1024), maintaining line-rate eBPF forwarding.
- **Zero Cache-Miss Amplification**: Consolidating thousands of patterns into single providers maximizes CPU cache locality in `IpIndex` and `DomainIndex`.
- **Minimal Update Bandwidth**: Independent providers update via HTTP 304 (ETag) without cross-provider re-download cascades.
- **Composite Simplicity**: Enterprises and operators package hybrid IP/domain assets as single atomic `.drb` files.

### Negative & Operational Costs
- Operators migrating from legacy configurations with hundreds of individual rule lines must consolidate them into `.rules` source files and compile them via `geodrb`.
- Subscribing to multiple fine-grained categories requires declaring individual `[[rule-provider]]` blocks, though this is bounded by design to 3–6 entries.