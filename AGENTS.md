# Agent Directives

## 1. Operational Guardrails (Hard Constraints)
- **Prohibited Git Commands**: NEVER execute `git stash`, `git branch`, or `git reset`.
- **Command Termination**: All commands MUST be finite and self-terminating. Never start background servers or unbounded loops without a strict timeout.
- **Root-Cause Engineering**: Prioritize root-cause architectural fixes over superficial patches, silent fallbacks, or suppressions.

## 2. Core Mental Model & Subsystem Boundaries
- **Concentric Layering**: `daer` is an eBPF transparent proxy organized into four strict concentric layers:
  - **Layer 4 (Host CLI)**: `crates/daer-cli` (single public binary, commands, signals, service entry point).
  - **Layer 3 (Control Plane & Ingress)**: `crates/daer-control` (transparent ingress, relay, flow supervisor, handover), `crates/daer-dns` (DNS server, cache, upstreams).
  - **Layer 2 (Domain Capabilities)**: `crates/daer-routing` (rule lowering, indexed matching), `crates/daer-outbound` (dialers, group policies, health check, REALITY), `crates/daer-sniff` (TLS SNI, HTTP Host, QUIC), `crates/daer-rule-ast` (canonical rule source), `crates/daer-drb` (DRB producer).
  - **Layer 1 (Kernel Datapath & Primitives)**: `crates/daer-ebpf` (map/program ABI, loader), `crates/daer-primitives` (network primitives, constants), `crates/daer-config` (TOML schema, AST, parser), `ebpf/kern` (C eBPF datapath).
- **Socket Mark Loop Evasion ([INV-MARK-01])**: Outbound dials from `daer` must carry `so-mark` before `connect(2)` to prevent the proxy from capturing and redirecting its own egress traffic.
- **Single Configuration Loader SSOT ([INV-LOADER-01])**: `daer_control::load_resolved` is the single source of truth for both runtime (`run`) and inspection (`daer route`, `daer check --nodes`). Diagnostic commands must never diverge from daemon state.
- **Kernel Policy Parity or Deferral ([INV-KERNEL-01])**: The kernel policy table is either provably equivalent to userspace evaluation or explicitly defers to the userspace control plane with logged reasons (ADR-0005).
- **Netune Boundary ([INV-NETUNE-01])**: Generic network capabilities (TLS profiles, HTTP/1.1 framing, socket options, TCP_INFO) belong to `netune`. Product-specific proxy protocols (Shadowsocks, Trojan, REALITY) and transparent ingress belong to `daer` (ADR-0002, ADR-0010).

## 3. Engineering Discipline
- **Mechanisms Over Exhortations**: Rely on Rust compiler typestates, private encapsulation, and automated tests to guarantee invariants. Never rely on natural-language comments alone.
- **Falsifiable Verification ([INV-VERIFY-01])**: Every test asserting datapath correctness must name its falsifier and carry negative controls (ADR-0007). A test that cannot fail is a liability.
- **Zero Unwired Keys**: Every accepted configuration key must be consumed by the daemon or rejected by schema validation (ADR-0006). Enforced by native Rust test `daer-config::tests::config_keys`.
- **Atomic Verification**: Always verify code changes with `cargo fmt`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo build --bins`, `cargo nextest run --workspace` and `cargo test --workspace --doc` before declaring tasks complete. External tests live in the root `tests/` harness; see `docs/dev/testing.md`.

## 4. On-Demand Standards Routing
Do not guess repository rules or rely on unverified assumptions. Consult authoritative specifications as needed:
- Documentation Standards & Taxonomy: `docs/dev/standards/taxonomy.md`
- Engineering Standards Suite: `docs/dev/standards/README.md`
  - Workspace Architecture & Boundaries: `docs/dev/standards/architecture.md`
  - Invariant & Constraint Policy: `docs/dev/standards/invariants.md`
  - Project Invariant Registry: `docs/dev/invariants.md`
  - Test Architecture & Layered Runner: `docs/dev/testing.md`
  - Testing & Verification Policy: `docs/adr/0007-verification.md`
  - Markdown & Hyperlink Style: `docs/dev/standards/style.md`
  - Architectural Decision Records: `docs/dev/standards/adr.md`
- Architecture Decision Records Index: `docs/adr/index.md`
- Build, Run & Verification: `docs/dev/build-and-run.md`
- Operator Guides & Deployment: `docs/how-to/deployment.md`
- Reference & Configuration: `docs/reference/configuration.md`
- Architecture Explanation: `docs/explanation/architecture-overview.md`
