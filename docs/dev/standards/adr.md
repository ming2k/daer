# Architectural Decision Records (ADR) Standards

This document establishes the qualification criteria, lifecycle management, and authoring standards for Architectural Decision Records in `daer`.

---

## 1. The 3-Question Test for ADR Qualification

Not every design decision requires an ADR. To prevent document fatigue while capturing load-bearing architecture, a decision must pass the **3-Question Test**:

1. **High Reversal Cost**: Would reverting this decision in six months require rewriting substantial code or breaking cross-crate APIs?
2. **Structural Boundary or Invariant**: Does this decision set a boundary between subsystems (e.g. kernel vs userspace, `daer` vs `netune`), or establish a System Invariant?
3. **Negative Knowledge**: Does the decision document discarded alternatives, verifier failure modes, or architectural traps that future maintainers must not re-attempt?

If the answer to all three is yes, an ADR is mandatory.

---

## 2. In-Place Lifecycle

ADRs follow an in-place lifecycle. When an architecture evolves, existing records are not deleted:

```text
  ┌───────┐      ┌──────────┐      ┌────────────┐
  │ Draft │ ───> │ Accepted │ ───> │ Superseded │
  └───────┘      └──────────┘      └────────────┘
      │
      v
  ┌──────────┐
  │ Rejected │
  └──────────┘
```

- **`draft`**: Under review and experimentation.
- **`accepted`**: Ratified and actively binding in current releases.
- **`superseded`**: Replaced by a successor ADR (must explicitly link `superseded_by: ADR-NNNN`).
- **`rejected`**: Deliberated but rejected, preserving negative knowledge.

---

## 3. ADR Frontmatter Schema & Template

New ADRs must be numbered sequentially with a four-digit zero-padded index (e.g. `0011-topic.md`) in `docs/adr/`, registered in `docs/adr/index.md`, and formatted as follows:

```markdown
---
id: ADR-NNNN
title: "Imperative statement of the architectural decision"
status: accepted # draft | accepted | superseded | rejected
date: YYYY-MM-DD
scope: [subsystem/topic, boundary/category]
supersedes: [] # e.g. [ADR-0001]
superseded_by: [] # e.g. [ADR-0005]
---

# NNNN. Imperative statement of the decision

- Status: Accepted
- Date: YYYY-MM-DD
- Deciders: [Author / Team]
- Related: [ADR-XXXX](XXXX-topic.md)

## Context

What problem are we solving? What are the physical or kernel constraints?

## Decision

The clear, unambiguous decision made, stated as rules and boundaries.

## Negative Knowledge & Discarded Alternatives

What alternatives were considered and why were they rejected? What failure modes were observed?

## Consequences

What becomes easier, what becomes harder, and what follow-ups are created?
```
