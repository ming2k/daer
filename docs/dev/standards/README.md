# Engineering Standards

This directory defines neutral, project-independent engineering standards. It covers workspace architecture, invariant classification, decision records, documentation taxonomy, and writing style.

The suite deliberately contains no product names, crate names, commands, workflow gates, or project-specific invariant registry. Those belong in each repository's project documentation and ADR registry; keeping them out of this directory lets the same standards apply unchanged across repositories.

---

## Standards Directory Structure

All neutral standards reside flatly in `docs/dev/standards/`:

| Document | Purpose & Authority |
| :--- | :--- |
| **[`architecture.md`](architecture.md)** | **System Architecture Governance**: Layered dependency rules, boundary ownership, atomic handover, data-path stability, and workspace integrity. |
| **[`invariants.md`](invariants.md)** | **Invariant Standards & Admissibility**: Definition, classification matrix, the three-condition gate, and where project-specific invariants are recorded. |
| **[`adr.md`](adr.md)** | **Architectural Decision Records**: The 3-Question Test for ADR qualification, in-place lifecycle, and authoring template. |
| **[`taxonomy.md`](taxonomy.md)** | **Documentation Taxonomy & Information Architecture**: Four-quadrant Diátaxis layout, audience boundaries, and directory rules. |
| **[`style.md`](style.md)** | **Documentation & Markdown Style**: Canonical hyperlink conventions, relative routing, formatting consistency, and prose guidelines. |

---

## Core Governance Philosophy

1. **Mechanisms Over Exhortations**:
   Rules and system boundaries must be enforced by concrete mechanisms: compiler typestates, private encapsulation, configuration-key consumption tests, dependency firewalls, or deterministic test assertions. Natural-language "swearing" in comments is forbidden.

2. **Falsifiable Verification**:
   A test that cannot fail is a liability. Every test asserting a behavioral claim must name its falsifier and include a negative control that fails if the mechanism is bypassed.

3. **Anti-Inflation**:
   A sharp line separates **System Invariants** (non-negotiable structural red-lines with cross-boundary blast radius), **Domain Contracts** (internal state machines), **Design Specifications** (constants and defaults), and **Implementation Notes**.

4. **Neutral Boundary**:
   Repository-specific architecture, invariants, commands, and operational procedures are recorded in that repository's project documentation and ADR registry, never in this suite. A standards document that names a product has stopped being reusable.

5. **Self-Contained Epistemic Lineage**:
   Every decision citation resolves within the citing repository's ADR registry. Ghost references to external or non-existent lineages are strictly prohibited.
