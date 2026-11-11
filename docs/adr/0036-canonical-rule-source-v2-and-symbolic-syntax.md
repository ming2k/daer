---
id: ADR-0036
title: "Canonical Rule Source (CRS v2) symbolic syntax and topology discipline"
status: accepted
date: 2026-11-07
scope: [routing/drb, rule-ast, daer-drb, config/rules, docs]
supersedes: []
superseded_by: []
---

# 0036. Canonical Rule Source (CRS v2) symbolic syntax and topology discipline

- Status: Accepted
- Date: 2026-11-07
- Deciders: Ming Li
- Related: [ADR-0014](0014-drb-rule-binary-and-providers.md), [ADR-0019](0019-rule-asset-topology-and-lookup-mechanics.md), [ADR-0031](0031-drb-v2-and-canonical-rules.md), [ADR-0032](0032-flat-front-coded-domain-table.md), [ADR-0033](0033-one-domain-table-two-vocabularies.md)
- Amends: [ADR-0031](0031-drb-v2-and-canonical-rules.md) §1, [ADR-0033](0033-one-domain-table-two-vocabularies.md) §2

---

## Context

ADR-0031 and ADR-0033 eliminated the legacy Protobuf converter, removed `keyword:` and `regex:` domain matching engines, and consolidated routing into two hierarchical domain kinds (`full:` and `suffix:`).

However, real-world deployment and rule-authoring surfaced two remaining architectural flaws:

1. **Syntax Clutter and Visual Fragmentation in CRS Text**:
   While bare names were accepted as suffixes, exact domain matching still required the wordy `full: <domain>` prefix. In large rule sets containing tens of thousands of lines, mixing key-value prefixes (`full:`) with bare names breaks the visual and structural stream of rules.

2. **The Danger of Mixed Rule Topologies on eBPF Kernel Line-Rate Forwarding**:
   Because `.drb` is a unified container envelope that mathematically supports storing both IP intervals and domain tables, operators are tempted to interleave IP and domain rules within the same file. In transparent proxying (Real-IP mode), the first packet (TCP SYN) carries only IP and port metadata without application-layer domain SNI. Consequently, any rule containing a `domain(...)` predicate forces the compiler to emit `DeferReason::Domain` and triggers the **Kernel Partition Boundary (ADR-0011)**:
   > **All rules after the first domain predicate are ejected from kernel eBPF and deferred to userspace.**
   Placing high-bandwidth LAN/direct IP subnets in a composite rule containing domains completely destroys eBPF line-rate bypass, saturating userspace relay.

3. **Ambiguity in Shorthand Syntax Proposals**:
   Community proposals frequently suggest using `^` or arbitrary glob wildcards (`*`):
   - In POSIX/PCRE regex, `^` represents a "starts-with" anchor (allowing trailing extensions), directly contradicting the exact equality semantics of "full match". Furthermore, `^` represents negation (`NOT`) in character classes, acts as a delimiter in adblock lists, and triggers command history expansion or glob errors in Unix shells (`bash`/`zsh`).
   - Infix/arbitrary wildcards (`*google*`, `api.*.com`) destroy $O(\log N)$ reverse-label binary search, forcing an $O(N)$ linear scan of hundreds of thousands of rules per connection.

We require a definitive clean-break standard for Canonical Rule Source syntax and rule topology discipline.

---

## Decision

### 1. Canonical Rule Source v2 (CRS v2) Symbolic Grammar

CRS v2 adopts a pure, prefix-free, symbolic domain syntax across `daer-rule-ast`, `daer-drb`, and `daer-routing`:

| Pattern Syntax | Semantic Meaning | Example | Behavior |
| :--- | :--- | :--- | :--- |
| **`domain.com`** | Self and Subdomains Suffix | `bilibili.com` | Matches `bilibili.com` and all subdomains (`*.bilibili.com`). |
| **`.domain.com`** | Subdomains-Only Suffix | `.corp.internal` | Matches `*.corp.internal`, strictly excluding `corp.internal`. |
| **`=domain.com`** | Exact / Full Match | `=auth.company.com` | Strictly matches `auth.company.com` only; no subdomains. |

- **Decommissioning `full:`**:
  The legacy `full:` keyword is retired in favor of `=`. In `RuleSet::render()` and `daer-drb decompile`, exact matches are canonically emitted with the `=` prefix (`=example.com`).
- **Network Directives**:
  IP rules continue to accept CIDRs (`192.168.0.0/16`), ranges (`172.16.1.10-172.16.1.50`), and host IPs (`1.1.1.1`). The optional `ip:` prefix is preserved for explicit clarity.
- **Bi-directional Round-Trip Invariant (`[INV-DRB-02]`)**:
  `compile(decompile(drb)) == drb` holds strictly under the new symbolic syntax.

### 2. Disjoint Rule Topology Invariant (`[INV-RULE-TOPOLOGY-01]`)

To preserve eBPF line-rate kernel forwarding:

1. **High-Throughput Bypass Subnets Must Be Pure IP**:
   Internal subnets (`10.0.0.0/8`, `192.168.0.0/16`, local interfaces) must reside in dedicated pure-IP rule files (e.g. `direct-lan.rules` $\to$ `direct-lan.drb`).
2. **Top-of-Table Placement**:
   In `daer.toml`, pure-IP direct rules must be declared **before** any rule referencing domains or providers containing domains. This guarantees they are lowered into the eBPF Prefix Partition, terminating in-kernel with zero userspace context switching.
3. **Composite Rules Restricted to Atomic Units**:
   Mixed IP-and-domain `.drb` artifacts are reserved exclusively for isolated enterprise entities requiring atomic updates where userspace deferral is accepted.

---

## Negative Knowledge & Discarded Alternatives

### 1. Rejection of `^` for Exact Matching
- In regex, `^foo` matches strings *starting with* `foo` (not exact equality).
- In regex character sets and boolean logic, `^` denotes `NOT` (negation), leading operators to interpret `^domain` as an exclusion rule.
- In `zsh` with `extended_glob`, unescaped `^` causes `zsh: no matches found`.
- **Verdict**: `=` (equality) is universally understood across mathematics, C/Rust, and Nginx (`location = /uri`), carrying zero ambiguity and zero shell-escape hazards.

### 2. Rejection of Arbitrary Wildcards (`*google*`, `api.*.com`)
- A reverse-label sorted table achieves $O(\text{labels} \cdot \log N)$ contiguous binary search.
- Middle wildcards or arbitrary substrings cannot be indexed by label-boundary prefixes, forcing an $O(N)$ linear scan of all patterns on every flow.
- Scanning 100,000 patterns per connection drops routing throughput by $>99\%$.
- **Verdict**: Wildcard normalization belongs upstream in data-cleaning pipelines, never on the packet-forwarding hot path.

---

## Consequences

### Positive
- **Visual Purity**: Rules files are clean streams of domains and IPs without repetitive key-value syntax noise.
- **Zero Ambiguity**: `=` and `.` completely eliminate confusion between full matches, bare suffixes, and subdomains.
- **Architectural Clarity**: Operators understand the direct correlation between rule ordering, IP/domain separation, and eBPF kernel offload.
- **100% Deterministic**: Decompiled output is cleaner, shorter, and remains byte-for-byte reproducible upon recompilation.

### Breaking Changes
- `RuleSet::render()` and `daer-drb decompile` emit `=example.com` instead of `full: example.com`.
- Third-party tools relying on parsing text output with `full:` prefix must accept `=`.
