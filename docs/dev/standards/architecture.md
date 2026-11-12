# System Architecture Governance

This document defines repository-agnostic rules for workspace topology, subsystem boundaries, and architectural red-lines. It states the rule; each repository records its concrete implementation, identifiers, and enforcement tests in its own ADRs and project documentation.

---

## 1. Layered Workspace Topology

A workspace is organized into concentric layers. Dependencies flow from outer layers toward inner foundation layers; backward, sideways-across-boundary, or circular dependencies are prohibited:

```text
┌─────────────────────────────────────────────────────────────┐
│ Layer 4: Host Interface                                     │
│   Executables, CLI/API surface, service entry points        │
├─────────────────────────────────────────────────────────────┤
│ Layer 3: Control Plane & Data Path                          │
│   Orchestration, ingress, sessions, lifecycle, handover     │
├─────────────────────────────────────────────────────────────┤
│ Layer 2: Domain Engines & Capabilities                      │
│   Policy, protocol, provider, and media logic               │
├─────────────────────────────────────────────────────────────┤
│ Layer 1: Foundation & Platform Primitives                   │
│   ABI, configuration, shared types, loaders, constants      │
└─────────────────────────────────────────────────────────────┘
```

Rules:

1. An outer layer may depend on an inner layer. An inner layer must not depend on an outer layer.
2. A layer may consume another layer only through its public contract. Reaching into private modules, or re-exporting an inner capability as if the outer layer owned it, is prohibited.
3. Layer names and counts are repository decisions; the dependency-direction rule is normative.
4. Enforcement is a dependency-graph check (workspace metadata, a dependency-policy linter, or equivalent), not review discipline.

---

## 2. Architectural Red-Lines

### 2.1 Egress Identity and Loop Evasion

- **Red-Line**: Every socket the process creates for its own egress, listeners, or health probes must carry a durable identity that the interception path recognizes before traffic leaves.
- **Why**: Without that identity, the process's own traffic is recaptured by its redirect rules, producing an infinite loop that hangs connections without a useful error.
- **Enforcement**: One constructor stamps the identity; a test asserts every egress path carries it; a negative control proves intercepted traffic is distinguished from bypassed traffic.

### 2.2 Single Resolver and Loader

- **Red-Line**: Runtime and inspection/diagnostic paths must resolve configuration and policy through one loader. There is no second parser, resolver, or compilation path.
- **Why**: Two loaders drift. A diagnostic command that disagrees with the running process is worse than no diagnostic at all.
- **Enforcement**: One shared entry point; tests assert inspection output equals the runtime representation; a dependency check forbids an alternative loader.

### 2.3 Fast-Path Parity or Explicit Deferral

- **Red-Line**: Policy compiled into a fast path must either be provably equivalent to the reference evaluator or explicitly defer to the reference path with a logged reason. Silent truncation or a partial policy is prohibited.
- **Why**: A fast path that quietly matches a subset of the reference rules is a correctness hole that looks like a performance win.
- **Enforcement**: Equivalence tests over the encodable subset; an explicit defer-reason type; a counter or log entry for every deferral.

### 2.4 Capability Ownership

- **Red-Line**: Generic capabilities live in the shared capability layer; product-specific behavior lives in the product layer. Governance or selection layers must not re-export capability types as their own.
- **Why**: A type reachable through a layer that does not own it announces a boundary that does not exist and lets future features reach the capability without naming its owner.
- **Enforcement**: Dependency-closure audit, forbidden-dependency list, and a public-surface test.

### 2.5 Atomic State Handover

- **Red-Line**: Live state replacement must never mutate active state in place. Build the replacement fully in an inactive slot, then switch atomically.
- **Why**: In-place mutation exposes readers to a partially published policy and creates transient gaps that are hard to reproduce.
- **Enforcement**: Dual-slot or generation-based design; a concurrency test that exercises traffic during the switch; no code path that publishes partial state.

### 2.6 Stable Data Path

- **Red-Line**: The component that forwards bytes decides nothing. It must not depend on configuration, selection, or domain-policy types; decisions arrive through a narrow typed seam.
- **Liveness**: Ingress and accept loops must not await a decision or a dial. Independent flows must not share a blocking task.
- **Enforcement**: Dependency firewall; test doubles at the seam; a slow-decision test that proves unrelated flows continue.

### 2.7 Isolation Boundary

- **Red-Line**: Privileged listeners and state that can loop live behind a dedicated process or namespace boundary. The host retains only the minimal forwarding and redirect state. There is no same-namespace fallback.
- **Why**: The boundary makes ownership and lifetime explicit; removing the fallback prevents a silent degraded mode that behaves differently from the tested path.
- **Enforcement**: One component creates and owns the boundary; a teardown test proves no state survives process exit; no identity-keyed rule may loop replies.

### 2.8 Protocol Ownership

- **Red-Line**: Protocol implementations are not re-exported through governance or selection crates. Consumers depend on the protocol crate directly; a governance crate may carry only inert values.
- **Why**: Re-exporting a handshake couples selection policy to wire implementation and makes the dependency direction ambiguous.
- **Enforcement**: Dependency-closure and public-API tests fail if a protocol type is reachable through the governance crate.

---

## 3. Workspace Integrity

1. **One Primary Public Surface**: A workspace exposes one public binary or entry point unless a recorded product decision says otherwise.
2. **Physical Tiering**: Source packages live under their canonical workspace directory. No package resides directly at the repository root.
3. **Zero Unconsumed Configuration**: Every accepted configuration key is consumed by the runtime or rejected by schema validation. An accepted key that neither changes behavior nor is rejected is a defect.
4. **Repository-Specific Red-Lines**: Concrete names, identifiers, commands, and enforcement tests belong in the repository's ADRs and project documentation. This document defines only the neutral rule.
