# Invariant & Constraint Governance

This document codifies the definition, categorization, and lifecycle of system invariants in `daer`. It establishes a strict policy against pseudo-invariant tag proliferation, ensuring that invariants remain high-value architectural anchors rather than ceremonial comments.

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
| **System Invariant** | Non-negotiable structural red-lines with cross-boundary blast radius (e.g. routing loop evasion, kernel/userspace policy parity, atomic epoch switching). Max ~15 across the repo. | Formally ratified in ADRs (`[INV-*]`) | 1. Package dependency firewalls<br>2. Dedicated regression test suite<br>3. Automated verification test (`daer-config::tests::config_keys`) |
| **Domain Contract** | State-machine transitions and behavioral rules within a single crate or subsystem (e.g. dialer selection policies, DNS cache TTL expiration). | **NO global `INV-` tag**.<br>Expressed as named types. | 1. Typed `enum` variants & private field encapsulation<br>2. RAII Guard patterns<br>3. Unit tests |
| **Design Specification** | Configuration file defaults, timeout constants, port presets. | **NO `INV-` tag**.<br>Expressed as design constants. | 1. Constant definitions<br>2. Schema validation tests |
| **Implementation Note** | Workarounds for platform quirks, kernel version branches, localized edge-case guards. | **NO `INV-` tag**.<br>Standard code comments. | Direct regression unit test |

---

## 3. The 3-Condition Gate for System Invariants

A rule may be elevated to a **System Invariant** if and only if it satisfies all three criteria:

1. **High Blast Radius**: Violation results in infinite packet loops, kernel panic/rejection, silent proxy bypass, or generation corruption.
2. **Durable Architecture**: It represents a foundational pillar that will not become obsolete due to routine feature iterations.
3. **Mechanically Enforced**: It specifies an automated enforcement mechanism (compiler type check, dependency firewall, or deterministic automated test).

---

## 4. Ratified System Invariants for daer

| Invariant ID | Title & Red-Line | Ratified ADR | Enforcement Mechanism |
| :--- | :--- | :--- | :--- |
| **`[INV-MARK-01]`** | **Socket Mark Loop Evasion**: Egress sockets dialed by `daer` must carry `SO_MARK` to prevent proxy loops. | [ADR-0002](../../adr/0002-netune-boundary.md) | Enforced via `RouterOptions::with_socket_mark`, unit tests in `daer-control` and `daer-cli`. |
| **`[INV-LOADER-01]`** | **Single Config Loader SSOT**: Diagnostics and daemon must resolve and lower configuration identically. | [ADR-0006](../../adr/0006-wiring-ownership.md) | Single shared function `daer_control::load_resolved`; tested in `crates/daer-control/tests/router.rs`. |
| **`[INV-KERNEL-01]`** | **Kernel Policy Fidelity**: Kernel eBPF routing policy is provably equivalent to userspace or explicitly defers. | [ADR-0005](../../adr/0005-kernel-policy-encoding.md) | `KernelPolicy::verify_equivalence`, tests in `crates/daer-routing/tests/kernel_policy.rs`. |
| **`[INV-EPOCH-01]`** | **Dual-Slot Epoch Handover**: Datapath reload writes the inactive slot fully before atomic integer switch. | [ADR-0004](../../adr/0004-routing-epochs.md) | Dual-slot map layout in `daer-ebpf`, verified in `crates/daer-control/tests/handover.rs`. |
| **`[INV-NETUNE-01]`** | **Netune Capability Boundary**: Outbound client stack lives in `netune`; transparent proxy appliance lives in `daer`. | [ADR-0002](../../adr/0002-netune-boundary.md), [ADR-0010](../../adr/0010-reality-client-ownership.md) | Cargo dependency pinning, crate isolation audits. |
| **`[INV-VERIFY-01]`** | **Falsifiable Verification**: Every datapath claim must name its falsifier and include negative controls. | [ADR-0007](../../adr/0007-verification.md) | Dynamic per-run nonces and negative bypass control in `tests/transparent.rs`. |
| **`[INV-WIRING-01]`** | **Zero Unconsumed Configuration**: Every accepted config key must be read by daemon or rejected by schema. | [ADR-0006](../../adr/0006-wiring-ownership.md) | `daer-config::tests::config_keys` in test suite. |
| **`[INV-PARTITION-01]`** | **Partitioned Policy Invariance**: Prefix L4/IP rules compiled into eBPF before the deferral gate are provably equivalent to userspace evaluation. | [ADR-0011](../../adr/0011-partitioned-kernel-routing.md) | Verified in `daer-routing::kernel::compile` and `tests/kernel_partition.rs`. |
| **`[INV-FAKEIP-01]`** | **Fake-IP Isolation Guarantee**: When `[dns.fake-ip]` is disabled, synthetic addresses are never allocated and `198.18.0.0/15` produces zero reverse mappings. | [ADR-0012](../../adr/0012-optional-fake-ip-ebpf.md) | Enforced via `FakeIpPool` typestate and `tests/fake_ip_isolation.rs`. |
