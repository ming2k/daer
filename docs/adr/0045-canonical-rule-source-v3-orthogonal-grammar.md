---
id: ADR-0045
title: "Canonical Rule Source (CRS v3) orthogonal grammar and deterministic lexing"
status: accepted
date: 2026-11-12
scope: [routing/drb, rule-ast, daer-drb, config/rules, docs]
supersedes: []
superseded_by: []
---

# 0045. Canonical Rule Source (CRS v3) orthogonal grammar and deterministic lexing

- Status: Accepted
- Date: 2026-11-12
- Deciders: daer maintainers
- Related: [ADR-0031](0031-drb-v2-and-canonical-rules.md), [ADR-0036](0036-canonical-rule-source-v2-and-symbolic-syntax.md), [ADR-0039](0039-remove-rule-attributes.md)
- Amends: [ADR-0031](0031-drb-v2-and-canonical-rules.md) §1, [ADR-0036](0036-canonical-rule-source-v2-and-symbolic-syntax.md) §1

---

## Context and Problem Statement

Canonical Rule Source v2 ([ADR-0036](0036-canonical-rule-source-v2-and-symbolic-syntax.md)) eliminated `full:` in favor of `=domain`, made bare domains default suffixes, and mandated topology separation to safeguard eBPF kernel offload (`[INV-RULE-TOPOLOGY-01]`).

However, real-world deployment and rule authoring surfaced three architectural and linguistic flaws in CRS v2:

1. **Semantic Hierarchy Mismatch between Metadata and Content**:
   The rule set identifier (`name: <set-name>`) was parsed as a line directive interchangeable with matching rules. In CRS text, declaring a global rule set attribute with the same syntax as a rule entry created scope ambiguity (operators mistaking `name:` for an item-level label or tag). Furthermore, multiple `name:` lines anywhere in the file silently overwrote the global name without error.

2. **Asymmetry and Directive Clutter in IP Rendering**:
   While domains became prefix-free symbolic streams (`example.com`, `=auth.corp`), IP rules in `RuleSet::render()` and `daer-drb decompile` still emitted the legacy `ip:` prefix (`ip: 192.168.1.0/24`). This broke visual parity and contradicted the symbolic, prefix-free design philosophy of CRS.

3. **Silent Type Drift and Kernel Topology Pollution via Fallback Parsing**:
   Because `daer-rule-ast` relied on trial-and-error parsing ("try IP, fallback to Domain"), and domain character validation permitted digits and dots, an invalid IP address (such as `192.168.1.256` or `10.0.0.1-10.0.0.256`) failed IP parsing and silently degraded into a domain suffix rule (`*.192.168.1.256`).
   Under `[INV-RULE-TOPOLOGY-01]` and ADR-0011, a single domain predicate triggers `DeferReason::Domain`, ejecting the rule set from eBPF kernel line-rate offload. A simple typo in a pure-IP rule set thus silently destroyed line-rate forwarding with zero diagnostic errors.

4. **Range Notation Lexical Collision**:
   The legacy range syntax `start - end` uses the hyphen `-`, which is a legal character in domain names (e.g. `corp-vpn.com`). Disambiguating ranges required multi-step trial parsing and fragile whitespace handling.

We require a definitive clean-break standard that establishes an orthogonal, prefix-free grammar with deterministic, fallback-free lexing.

---

## Decision

We execute a **Clean Break** across the rule specification, AST parser, decompiler, and producer tooling:

### 1. Frontmatter Metadata Isolation
Metadata is decoupled from the rule stream. A rule set's name is declared exclusively in a standard YAML-style frontmatter header at the beginning of the file:

```text
---
name: my-rules
---
```

- Any `name:` directive outside frontmatter is a compile-time syntax error.
- Within frontmatter, unrecognised keys are rejected with compile-time errors (Zero Unwired Keys).
- When frontmatter is omitted, `name` defaults to the CLI `--name` option or the input file stem.

### 2. Prefix-Free Orthogonal Network Grammar (CRS v3)

All rule directives are prefix-free. The `ip:` prefix is completely retired and rejected:

| Network Category | CRS v3 Syntax | Defining Lexical Feature | Disambiguation Guarantee |
| :--- | :--- | :--- | :--- |
| **Single Host IP** | `1.1.1.1`<br>`2001:db8::1` | 4 decimal octets (IPv4) or `:` (IPv6) | RFC 1123/3696 forbids all-numeric TLDs; colons are illegal in domain names |
| **Subnet (CIDR)** | `192.168.1.0/24`<br>`2001:db8::/32` | `/` followed by prefix length | Forward slash `/` is strictly illegal in domain names |
| **IP Range** | `10.0.0.1..10.0.0.50`<br>`2001:db8::1..2001:db8::ff` | `..` (Double dot) | Double dots `..` (empty DNS label) are strictly illegal in domain names |

- The legacy hyphen range syntax (`start - end`) is retired in favor of the double-dot range operator (`start..end`), eliminating hyphen collisions with domain names.
- Singe host IPs are written bare (`1.1.1.1`, `::1`) without requiring artificial `/32` or `/128` CIDR masks.

### 3. Deterministic Lexing (Zero-Fallback Rule)

`RuleSet::parse` dispatches strictly on explicit lexical discriminators:
1. Lines with `..` $\to$ **Assert IP Range**. Validate both endpoints as IP addresses of the same family (`start <= end`).
2. Lines with `/` $\to$ **Assert CIDR**. Validate via `IpNet`.
3. Lines with `:` $\to$ **Assert IPv6 Host**. Validate via `Ipv6Addr`.
4. Lines matching 4 numeric octets (`^\d+\.\d+\.\d+\.\d+$`) $\to$ **Assert IPv4 Host**. Validate octets in `0..=255`.
5. Lines starting with `=` $\to$ **Assert Exact Domain** (`DomainPattern::Full`).
6. Lines starting with `.` $\to$ **Assert Subdomain-only** (`DomainPattern::Suffix(SubdomainsOnly)`).
7. Remaining lines $\to$ **Assert Domain Suffix** (`DomainPattern::Suffix(SelfAndSubdomains)`).

> **The Zero-Fallback Invariant**:
> If a line matches discriminators 1–4, any validation failure (e.g. `192.168.1.256` or `/33`) **immediately terminates compilation with a fatal error**. It is mathematically impossible for a malformed network rule to degrade into a domain rule.

### 4. Domain RFC Compliance Assertion
In `fold_domain`:
- Domain patterns must not be all-numeric.
- Domain patterns must not end with an all-numeric top-level domain (TLD), enforcing RFC 1123 §2.1 and RFC 3696 §2.

### 5. Canonical Decompiler Output
In `RuleSet::render()` and `daer-drb decompile`:
- The rule set name is emitted as frontmatter (`--- \n name: <set-name> \n ---`).
- Single IP addresses are emitted as bare host addresses (`1.1.1.1`, `::1`).
- Subnets are emitted as standard CIDRs (`192.168.1.0/24`).
- All `ip:` prefixes are eradicated from decompiled text.
- Bi-directional identity `compile(decompile(drb)) == drb` ([INV-DRB-02]) holds strictly.

---

## Consequences

### Positive
- **Complete Orthogonality**: Metadata, network addresses, CIDRs, ranges, and domain patterns have mutually exclusive lexical signatures.
- **Fail-Fast Safety**: IP typos can never silently corrupt domain tables or break eBPF kernel line-rate offload.
- **Compiler Performance**: Lexer eliminates 300,000+ failed trial IP parsing allocations when compiling large domain datasets (e.g. `geosite.rules`).
- **Visual Purity**: Eliminates `ip: ` clutter across all rule artifacts.

### Breaking Changes
- `ip: <address>` is a compile-time error. Migration: remove `ip:`.
- `name: <name>` outside frontmatter is an error. Migration: place inside `--- \n name: <name> \n ---` or use `--name`.
- `start - end` range syntax is an error. Migration: change `-` to `..`.
