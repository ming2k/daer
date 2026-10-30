# daer Engineering Standards

This directory defines the authoritative engineering, architectural, and quality standards for the `daer` project.

Following the design principles established in high-discipline Rust workspaces, `daer` maintains a **flat, high-cohesion, practical, and code-aligned standards suite directly inside `docs/dev/standards/`**.

---

## Standards Directory Structure

All engineering standards reside flatly in `docs/dev/standards/`:

| Document | Purpose & Authority |
| :--- | :--- |
| **[`architecture.md`](architecture.md)** | **Workspace Topology & System Boundaries**: Defines the concentric 4-layer runtime, kernel-userspace division, socket mark evasion, and Netune boundary. |
| **[`invariants.md`](invariants.md)** | **Invariant Standards & Admissibility**: Codifies true system invariants (mechanisms over exhortations), establishes the classification matrix, and defines `daer` core invariants (`INV-*`). |
| **[`workflow.md`](workflow.md)** | **Engineering Workflow & PR Gates**: The 5 PR verification gates (`make ci`), atomic commits, code-to-doc synchronization, and pre-release hygiene checklist. |
| **[`testing.md`](testing.md)** | **Automated Verification & Testing Strategy**: The 4-tier test pyramid (Unit, Integration, Differential, Kernel Verification) and falsifiable testing principles (ADR-0007). |
| **[`taxonomy.md`](taxonomy.md)** | **Documentation Taxonomy & Diátaxis Layout**: Four-quadrant Diátaxis information architecture, audience boundaries (Public vs Contributor), and root directory rules. |
| **[`style.md`](style.md)** | **Documentation & Markdown Style**: Canonical hyperlink conventions, relative routing, formatting consistency, and prose guidelines. |
| **[`adr.md`](adr.md)** | **Architectural Decision Records**: The 3-Question Test for ADR qualification, in-place lifecycle (`draft`, `accepted`, `superseded`, `rejected`), and authoring template. |

---

## Core Governance Philosophy

1. **Mechanisms Over Exhortations**:
   Rules and system boundaries must be enforced by concrete mechanisms: Rust compiler typestates, private encapsulation, native key consumption tests (`daer-config::tests::config_keys`), or deterministic test assertions. Natural-language "swearing" in comments is forbidden.

2. **Falsifiable Verification (ADR-0007)**:
   A test that cannot fail is a liability. Every test asserting datapath correctness must name its falsifier, employ dynamic per-run nonces, and include negative controls that fail if traffic ever bypasses the proxy.

3. **Anti-Inflation**:
   A sharp line separates **System Invariants** (non-negotiable structural red-lines with cross-boundary blast radius), **Domain Contracts** (internal state machines), and **Implementation Notes**.

4. **Self-Contained Epistemic Lineage**:
   All architectural decisions must resolve directly within [`docs/adr/`](../../adr/index.md) (ADR-0001 through current). Ghost references to external or non-existent lineages are strictly prohibited.
