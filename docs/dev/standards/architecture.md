# System Architecture Governance

This document codifies the workspace topology, subsystem boundaries, and non-negotiable architectural red-lines of `daer`.

---

## 1. Concentric Workspace Topology

`daer` organizes its Cargo workspace into four concentric layers. Dependencies flow strictly from outer layers inward; backward or circular dependencies across layer boundaries are prohibited:

```text
┌────────────────────────────────────────────────────────────────────────┐
│  Layer 4: Host Binary & CLI (`crates/daer-cli`)                        │
│  - Unified single public executable (`daer`)                           │
│  - Service runtime (`run`, `dns serve`)                                │
│  - Inspection & diagnostics (`config`, `route explain`, `dns check`)   │
├────────────────────────────────────────────────────────────────────────┤
│  Layer 3: Control Plane & Ingress Relay                                │
│  - Transparent ingress & flow supervisor: `crates/daer-control`        │
│  - Integrated DNS pipeline & cache: `crates/daer-dns`                  │
│  - Generation management & zero-downtime hot reload                    │
├────────────────────────────────────────────────────────────────────────┤
│  Layer 2: Domain Engines & Capabilities                                │
│  - Rule lowering & indexed matching: `crates/daer-routing`             │
│  - Outbound dialers, groups & REALITY client: `crates/daer-outbound`   │
│  - Prefix protocol sniffing (TLS SNI, HTTP Host, QUIC): `daer-sniff`  │
│  - Streaming geo database reader: `crates/daer-geodata`                │
├────────────────────────────────────────────────────────────────────────┤
│  Layer 1: Kernel Datapath & Core Foundation                            │
│  - eBPF object loader & map ABI: `crates/daer-ebpf`                    │
│  - C eBPF datapath program: `ebpf/kern/`                               │
│  - TOML configuration schema & expression AST: `crates/daer-config`    │
│  - Shared constants & network primitives: `crates/daer-common`         │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Architectural Red-Lines

### 2.1 Socket Mark Loop Evasion ([INV-MARK-01])
- **Red-Line**: All outbound egress dials originating from `daer` must carry `SO_MARK` (`so-mark = 0x0dae`) before the socket connects to origin servers.
- **Enforcement**: Without the socket mark, traffic dialed by the proxy itself would be recaptured by the redirect firewall rule and forced back into the transparent port, causing an infinite loop that hangs connections without error logs. Enforced via `RouterOptions::with_socket_mark` and netune's `SocketConfig::mark`.

### 2.2 Single Configuration Loader SSOT ([INV-LOADER-01])
- **Red-Line**: Diagnostic commands (`daer route explain`, `daer route nodes`, `daer config validate`) and the runtime daemon (`daer run`) MUST load and compile configuration through the exact same loader (`daer_control::load_resolved`).
- **Enforcement**: Diagnostics and runtime share identical generation lowering, alias optimization, and subscription caching. A node or rule that appears in `daer route explain` is guaranteed to exist identically in the running daemon (ADR-0006).

### 2.3 Kernel Policy Fidelity or Explicit Deferral ([INV-KERNEL-01])
- **Red-Line**: The eBPF kernel policy table must either be provably equivalent to userspace rule evaluation, or explicitly defer the decision to the userspace control plane with logged reasons (ADR-0005).
- **Enforcement**: Predicates supported directly by the kernel fast path (`dip`, `sip`, `port`, `sport`, `l4proto`, `ipversion`, `mac`, `dscp`) execute in-kernel at the tc hook. If a configuration uses predicates requiring userspace state (`domain(...)`, `pname(...)`), the datapath policy is published as a deferral, logging a warning and safely relaying through userspace rather than fabricating an incomplete kernel decision.

### 2.4 Netune Boundary Purity ([INV-NETUNE-01])
- **Red-Line**: Generic network capabilities belong to `netune`; proxy appliance data path, eBPF maps, transparent accept, and proxy protocols stay in `daer` (ADR-0002).
- **Enforcement**: `daer` consumes `netune` as a pinned dependency. `daer` does not implement generic TLS, HTTP codecs, or raw SOCKS5/CONNECT framing. The only exception is REALITY (ADR-0010), where custom unauthenticated TLS 1.3 client mechanics are owned directly by `daer-outbound`.

### 2.5 Dual-Slot Epoch Atomic Handover ([INV-EPOCH-01])
- **Red-Line**: Kernel policy updates during reload must NEVER mutate live active routing tables in-place.
- **Enforcement**: The datapath maintains two alternating policy slots (`slot 0` and `slot 1`). The userspace daemon fully compiles and populates the inactive slot before flipping the atomic `active_slot` integer, guaranteeing zero-downtime hot reload without transient policy gaps (ADR-0004).

---

## 3. Crate Addition and Workspace Integrity

1. **Single Public Binary**: `daer` is the sole public executable binary produced by the workspace.
2. **Strict Physical Tiering**: Crates reside exclusively under `crates/*`. No crates reside directly at the root.
3. **Zero Unconsumed Configuration**: Every configuration key defined in `daer-config` must be consumed by the daemon or rejected by strict validation (enforced by `daer-config::tests::config_keys`).
