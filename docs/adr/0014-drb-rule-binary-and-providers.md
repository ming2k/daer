---
id: ADR-0014
title: "DRB (daer Rule Binary) compiled artifacts and declarative Rule Providers"
status: accepted
date: 2026-02-15
scope: [routing/drb, config/rule-providers, cli/rules, control-plane/loader]
supersedes: []
---

# 0014. DRB (daer Rule Binary) compiled artifacts and declarative Rule Providers

- Status: Accepted
- Date: 2026-02-15
- Deciders: Ming Li
- Related: [ADR-0001](0001-config-format.md), [ADR-0004](0004-routing-epochs.md), [ADR-0006](0006-wiring-ownership.md), [ADR-0011](0011-partitioned-kernel-routing.md)

---

## Context and Problem Statement

`daer` routing performance on the hot path achieves line-rate forwarding via eBPF kernel offload (`[INV-PARTITION-01]`), contiguous-memory interval binary search (`IpIndex`), and reverse label-walking hash set matching (`DomainIndex`).

However, the **cold path and distribution pipeline** suffered from historical legacy baggage:

1. **The Protobuf `.dat` Cold-Start Penalty**:
   Legacy geodata files (`geoip.dat` and `geosite.dat`, originally designed by V2Ray) are serialized Protobuf byte streams. Loading `geosite:cn` (~110,000 domains) and `geoip:cn` (~8,000 prefixes) requires streaming protobuf varints, allocating intermediate strings, and executing runtime sorting and interval merging. On low-power edge gateways and container environments, this produces significant startup CPU bursts (100–400ms) and transient memory amplification.
2. **Operational Friction & Privileged Maintenance**:
   Operators had to manually download `.dat` files and copy them into privileged system asset directories (e.g. `/usr/share/daer` or `/usr/local/share/daer`) with `sudo`. There was no declarative mechanism for remote URL subscription, periodic background updates, or user-owned rule lists.
3. **No Direct User-Defined Rule Set Format**:
   Users who wanted to maintain custom rule sets (e.g. enterprise internal subnets, custom domain whitelists) had either to paste hundreds of lines directly into `routing.rules` in TOML, or reverse-engineer the Protobuf compilation pipeline.

We require a zero-compromise, modern binary rule artifact format combined with an automated, non-privileged rule provider subsystem.

---

## Decision

### 1. The DRB (daer Rule Binary) Specification (`[INV-DRB-01]`)

We introduce **DRB** (`.drb`), an optimized binary format for routing rule sets:

```text
+-------------------------------------------------------------------------+
| Magic: b"DAER_DRB" (8B)  | Version: u32 (4B) | Section Count: u32 (4B)  |
+-------------------------------------------------------------------------+
| Created At: u64 (8B)     | Checksum: SHA-256 of payload (32B)           |
+-------------------------------------------------------------------------+
| Payload:                                                                |
|  - Name (u16 length + UTF-8 string)                                     |
|  - IPv4 Intervals: [start: u32, end: u32] × count (pre-sorted, merged)  |
|  - IPv6 Intervals: [start: u128, end: u128] × count (pre-sorted, merged)|
|  - IP Prefixes: [kind, prefix_len, addr_bytes] × count (for kernel LPM) |
|  - Domain Full: [len: u16, string] × count                              |
|  - Domain Suffix: [scope: u8, len: u16, string] × count                 |
|  - Domain Keyword: [len: u16, string] × count                           |
|  - Domain Regex: [len: u16, string] × count                             |
+-------------------------------------------------------------------------+
```

- **Invariant `[INV-DRB-01]` (Precompiled Determinism)**:
  A DRB file encodes pre-merged intervals and pre-sorted patterns. Loading it performs zero interval merging and zero pattern normalization. Truncation or bit flips are rejected at the gate via fixed magic, version verification, and cryptographic SHA-256 checksum checks.
- **Microsecond Cold-Start**: Loading a DRB takes microseconds (`< 0.01ms`), bypassing all protobuf streaming and interval coalescence loops.

### 2. Declarative `[[rule-provider]]` Subsystem (`[INV-PROVIDER-01]`)

Rule sets are declared as first-class citizens in configuration:

```toml
[[rule-provider]]
tag = "china-rules"
type = "http"
url = "https://cdn.example.com/rules/china.drb"
format = "drb"
interval = "24h"

[[rule-provider]]
tag = "custom-lan"
type = "file"
path = "rules/custom-lan.rules"
format = "text"

[routing]
rules = [
    "provider(custom-lan) -> direct",
    "provider(china-rules) -> direct",
]
fallback = "proxy"
```

- **Non-Root & XDG Compliance**:
  Downloaded artifacts are stored in `$XDG_CACHE_HOME/daer/rules` or `$HOME/.cache/daer/rules` (with `/tmp` fallback). No root or `sudo` privilege is required.
- **Invariant `[INV-PROVIDER-01]` (Rule Provider SSOT)**:
  Rule providers are resolved in `daer_control::load_resolved` prior to generation creation, ensuring diagnostic commands (`daer route`, `daer check --nodes`) never diverge from the running daemon.
- **Offline Resilience**:
  If an HTTP provider is temporarily unreachable, the loader uses the cached DRB and emits a warning rather than failing the proxy.

### 3. Producer Tooling in `geodrb`

The DRB producer is `geodrb`, a separate binary (ADR-0015), so the daemon links no geodata
reader:
- `geodrb compile <input.rules> -o <output.drb>`: compiles plain-text rules into a DRB artifact.
- `geodrb inspect <input.drb>`: verifies checksum and displays section counts and binary metadata.
- `geodrb convert <input.dat> --code <code> -o <output.drb>`: converts legacy `geoip.dat` or `geosite.dat` files into DRB.

---

## Consequences

### Positive
- **Instantaneous Cold-Start**: Eliminates protobuf decoding bursts at startup; DRB files are ingested immediately into `IpIndex` and `DomainIndex`.
- **Zero-Privilege Management**: Operators manage rule subscriptions and custom lists without touching `/usr/share` or needing root permissions.
- **Unified Rule Semantics**: `provider(name)` seamlessly supports both IP intervals and domain patterns within the same predicate, with automatic kernel LPM lowering for the IP partition.

### Negative & Operational Costs
- Added binary encoding/decoding logic in `daer-routing::drb`.
- Added provider fetching and caching lifecycle in `daer-control::rule_provider`.
