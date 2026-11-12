# Invariant & Constraint Governance

This document defines repository-agnostic policy for system invariants: what qualifies, how it is classified, and how it is recorded. It does not list any repository's invariants.

---

## 1. Core Principle: Mechanisms Over Exhortations

In software engineering, an invariant is a condition that must unconditionally hold across all valid states of a system.

**The Golden Rule**:

> **If a rule has neither a compiler-level proof nor an automated test assertion, it is NOT an invariant — it is merely an aspiration.**

---

## 2. Constraint Admissibility Matrix

Every architectural and operational rule maps deterministically into one of four categories:

| Category | Definition & Scope | Identifier Policy | Mandatory Enforcement Mechanism |
| :--- | :--- | :--- | :--- |
| **System Invariant** | Non-negotiable structural red-lines with cross-boundary blast radius (e.g. loop evasion, fast-path parity, atomic state switching). Max ~15 per repository. | Formally ratified in ADRs (`[INV-<DOMAIN>-NN]`) with one authoritative definition site. | 1. Package dependency firewalls<br>2. Dedicated regression test suite<br>3. Configuration-key consumption test |
| **Domain Contract** | State-machine transitions and behavioral rules within a single crate or subsystem (e.g. selection policy, cache expiry). | **NO global `INV-` tag**.<br>Expressed as named types. | 1. Typed `enum` variants and private field encapsulation<br>2. RAII guard patterns<br>3. Unit tests |
| **Design Specification** | File defaults, timeout constants, port presets, layout tokens. | **NO `INV-` tag**.<br>Expressed as design constants. | 1. Constant definitions<br>2. Schema or snapshot validation tests |
| **Implementation Note** | Workarounds for platform quirks, version branches, localized edge-case guards. | **NO `INV-` tag**.<br>Standard code comments. | Direct regression unit test |

---

## 3. The 3-Condition Gate for System Invariants

A rule may be elevated to a **System Invariant** if and only if it satisfies all three criteria:

1. **High Blast Radius**: Violation results in infinite loops, data corruption, silent bypass, crash-level failure, or generation corruption.
2. **Durable Architecture**: It represents a foundational pillar that will not become obsolete due to routine feature iterations.
3. **Mechanically Enforced**: It specifies an automated enforcement mechanism (compiler type check, dependency firewall, or deterministic automated test).

---

## 4. Recording and Lifecycle

This suite defines invariant policy, not any repository's invariant registry.

1. **Project Registry**: A repository records its ratified invariants in a project-level registry (for example `docs/dev/invariants.md`) and in the ratifying ADRs. Those documents are product-specific and are intentionally not part of this neutral suite.
2. **Single Definition Site**: Every `[INV-*]` tag has exactly one authoritative definition. Citations are not definitions; a citation may appear many times without creating another rule.
3. **No Renumbering**: Once assigned, an invariant identifier is permanent. Retired invariants are marked superseded or deprecated in place; remaining identifiers are never renumbered.
4. **In-Place Retirement**: When an invariant is replaced, link the successor ADR and preserve the discarded rule and its failure mode as negative knowledge. Do not delete the historical record merely because the rule no longer binds.
5. **Neutral Boundary**: Project-specific invariants must not be added to this document. If a rule names a product, crate, command, or deployment, it belongs in that project's registry.
