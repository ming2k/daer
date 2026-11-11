# ADR-0031 — DRB v2 Binary ABI and Canonical Rule Source (CRS)

- Status: accepted (amended by [ADR-0032](0032-flat-front-coded-domain-table.md): the IP half stands; the domain encoding is replaced by a flat front-coded table)
- Date: 2026-11-06
- Related: [ADR-0014](0014-drb-rule-binary-and-providers.md), [ADR-0015](0015-cli-is-four-verbs.md), [ADR-0019](0019-rule-asset-topology-and-lookup-mechanics.md), [ADR-0023](0023-constants-have-one-definition.md)
- Supersedes: ADR-0014, ADR-0019, ADR-0027

---

## Context and Problem Statement

`daer` routing performance on the hot path evaluates packets on line-rate forwarding via eBPF and userspace fast paths. However, the rule compilation and representation layers suffered from persistent architectural baggage:

1. **Storage & Representation Redundancy**:
   DRB v1 stored both pre-merged interval arrays *and* raw IP CIDR prefixes in the same binary file. This increased artifact sizes by ~40% and created a dual-source-of-truth hazard where intervals and prefixes could theoretically diverge.
2. **Negative Lookup Fallacy in Domain Matching**:
   The runtime evaluated domains across four heterogeneous engines in series (`exact` HashSet, `suffix` HashMap with linear label splitting, `keyword` Aho-Corasick automaton, and `regex` RegexSet). For non-matching domains (the dominant case for traffic bypassed to proxies), every flow had to execute all four engines, incurring severe cache misses and CPU cycle waste.
3. **Format Creep and Toolchain Blurring**:
   `daer` continued to house `crates/daer-geodata` (a legacy Protobuf parser for V2Ray `.dat` files). This violated the architectural boundary: the runtime must never speak `.dat`, and `daer-drb` should not be a universal format converter.

## Decision

We execute a **Clean Break** across the rule specification, compiler, binary format, and runtime engine:

### 1. Canonical Rule Source (CRS v1) is the Sole Compiler Input

> **Amended by [ADR-0036](0036-canonical-rule-source-v2-and-symbolic-syntax.md):** the domain
> spellings below (`suffix:`/`full:`) were replaced by the symbolic CRS v2 forms `name`,
> `.name` and `=name`. Everything else — the single text format, the single binary format —
> stands.

`daer-drb` accepts exactly one text format (`.rules`) and outputs exactly one binary format (`.drb`):
- `name: <set-name>`
- `ip: <cidr | address | start - end>`
- `<domain>` (suffix: the name and every subdomain)
- `.<domain>` (subdomains only)
- `=<domain>` (exact match)

All legacy Protobuf `.dat` decoding is **completely removed** from the `daer` repository. `crates/daer-geodata` is deleted. External data sources must be converted to CRS prior to invoking `daer-drb compile`.

### 2. Disjoint Closed Intervals as the Single IP Truth

In DRB v2:
- The binary file **only stores sorted, non-overlapping, non-adjacent closed intervals**:
  - IPv4: `[u32 start, u32 end]` (8 bytes per interval).
  - IPv6: `[u128 start, u128 end]` (32 bytes per interval).
- **Userspace**: Mapped directly from memory (`mmap`), evaluated via `binary_search`. Zero allocations, $< 15\,\text{ns}$ lookup.
- **Kernel eBPF**: When compiling kernel policy for `BPF_MAP_TYPE_LPM_TRIE`, intervals are mathematically decomposed into standard power-of-two CIDRs on the fly via the `intervals_to_cidrs` operator during low-frequency policy generation.

### 3. Domain matching is hierarchical only (encoding superseded by ADR-0032)

`keyword:` and `regex:` domain matching are removed from the architecture. A domain rule is
either exact (`=name`) or hierarchical (`name`, with a leading dot for subdomains only), and
the two are evaluated over one table.

> The original encoding here was a Compact Reverse Label Radix. It was measured to produce no
> node sharing and a 61% larger artifact, and is replaced by the flat front-coded table of
> [ADR-0032](0032-flat-front-coded-domain-table.md). The structural decision — two pattern kinds,
> one structure, no engine per kind — stands.

### 4. Deterministic DRB v2 Binary ABI

- **Magic**: `b"DAERDRB2"` (8 bytes).
- **Version**: `2` (u32).
- **Header**: Fixed 128 bytes (two 64-byte cache lines; SHA-256 checksum at `[0x40..0x60]`, fields padded to 128 bytes).
- **Payload-Only Checksum**: SHA-256 is computed strictly over `[0x80..EOF]`. Dynamic timestamps (`created_at`) are deleted from the file format, guaranteeing byte-for-byte deterministic, reproducible builds across machines and dates.

### 5. Two-Way Reversible Toolchain

`daer-drb` exposes four verbs:
```text
daer-drb compile <input.rules> -o <output.drb>
daer-drb decompile <input.drb> -o <output.rules>
daer-drb inspect <input.drb>
daer-drb test <input.drb> <target>
```
Invariant: `compile(decompile(drb)) == drb` (identity preservation).

---

## Consequences

### Positive
- Zero Protobuf dependencies across the entire `daer` workspace.
- 40% reduction in `.drb` artifact size.
- Zero heap allocation during rule loading (`mmap`) and evaluation.
- Order-of-magnitude reduction in domain lookup latency, especially on negative hits.
- Deterministic byte-for-byte builds enable verifiable CI and efficient HTTP caching.

### Negative and Breaking Changes
- DRB v1 files (`b"DAER_DRB"`, version 1) are rejected. Upstream providers must publish DRB v2.
- `daer-geodata` is removed; scripts relying on `daer-drb convert --type geosite` must convert to `.rules` first.
