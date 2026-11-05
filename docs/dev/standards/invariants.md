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
| **`[INV-PARTITION-01]`** | **Partitioned Policy Invariance**: Prefix L4/IP rules compiled into eBPF before the deferral gate are provably equivalent to userspace evaluation. | [ADR-0011](../../adr/0011-partitioned-kernel-routing.md) | Verified in `daer-routing::kernel::compile` and `daer-routing/tests/kernel_policy.rs`. |
| **`[INV-FAKEIP-01]`** | **Fake-IP Isolation Guarantee**: When `[dns.fake-ip]` is disabled, synthetic addresses are never allocated and `198.18.0.0/15` produces zero reverse mappings. | [ADR-0012](../../adr/0012-optional-fake-ip-ebpf.md) | Enforced via `FakeIpPool`'s typestate and its unit tests in `daer-dns/src/fake_ip.rs`; the end-to-end behaviour is `daer-dns/tests/end_to_end.rs::fake_ip_*`. |
| **`[INV-DATAPATH-01]`** | **Datapath State Ownership**: Attaching the datapath installs every piece of box-global state it needs (the `fwmark` rule and `local default` route for v4 and v6, `rp_filter`, forwarding, the link-layer variant chosen from `ARPHRD`, and all three `listen_socket_map` slots) and removes it on drop. No required state is documentation-only, and no interface gets both the `_l2` and `_l3` variant of a hook. | [ADR-0013](../../adr/0013-datapath-state-ownership.md) | `daer-control::datapath::{attach, RouteTable, Sysctl, LinkKind}`, `daer-ebpf::listeners`; the kernel side is gated in `daer-ebpf/tests/kernel.rs`. |
| **`[INV-KERNEL-FACTS-01]`** | **Observed-Fact Honesty**: A `mac(...)`, `dscp(...)`, or `pname(...)` rule matches only when the datapath observed that fact. With no observer the fact is `KernelFacts::default()` and the rule does not match; a `pid` of `0` reports the process name as unknown rather than empty. | [ADR-0013](../../adr/0013-datapath-state-ownership.md) | `daer-control::decide::{KernelObserver, KernelFacts::from_handoff, verdict_for_flow}`; `decide::tests::a_mac_rule_*`, `a_pname_rule_*`, `a_pid_of_zero_*`. |
| **`[INV-DRB-01]`** | **Precompiled Rule Determinism**: A DRB file encodes pre-merged intervals and pre-sorted patterns; loading it performs zero prefix merging and zero string validation allocations, and corruption is detected by header magic, version bounds, and SHA-256 cryptographic verification. | [ADR-0014](../../adr/0014-drb-rule-binary-and-providers.md) | `daer-routing::drb::{DrbSet, DrbError}`, unit tests in `crates/daer-routing/src/drb.rs`. |
| **`[INV-PROVIDER-01]`** | **Rule Provider SSOT**: All rule providers (`file` and `http`) are resolved before generation building in `load_resolved` with cached fallback, ensuring offline stability and strict parity between diagnostic commands and daemon data path. | [ADR-0014](../../adr/0014-drb-rule-binary-and-providers.md) | `daer_control::rule_provider::resolve_rule_providers`, tests in `crates/daer-cli/src/main.rs`. |
| **`[INV-CLI-01]`** | **Runtime CLI Surface**: The binary exposes exactly `run`, `check`, `route`, `probe`, `schema`, `version`. No build-time producer (DRB compilation, `.dat` conversion, URI rewriting) and no second service (standalone DNS) is linked into the daemon; `daer check` is the single pre-bind gate whose exit status is the deployment contract, and `route` is offline policy evaluation while `probe` is the only verb that performs network I/O on demand. | [ADR-0015](../../adr/0015-cli-is-four-verbs.md), [ADR-0016](../../adr/0016-cli-route-and-probe.md) | `crates/daer-cli/src/main.rs` command enum; `crates/daer-cli/tests/surface.rs` asserts the dependency closure links no producer; `crates/daer-cli/tests/route.rs`. |
