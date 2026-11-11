# System Architecture Governance

This document codifies the workspace topology, subsystem boundaries, and non-negotiable architectural red-lines of `daer`.

---

## 1. Concentric Workspace Topology

`daer` organizes its Cargo workspace into four concentric layers. Dependencies flow strictly from outer layers inward; backward or circular dependencies across layer boundaries are prohibited:

```text
┌────────────────────────────────────────────────────────────────────────┐
│  Layer 4: Host Binary & CLI (`crates/daer-cli`)                        │
│  - Unified single public executable (`daer`)                           │
│  - Service runtime (`run`, which also serves DNS)                      │
│  - Inspection & diagnostics (`check`, `route`, `probe`, `schema`)      │
├────────────────────────────────────────────────────────────────────────┤
│  Layer 3: Decision Plane & Userspace Data Path                         │
│  - Routing decisions, node selection, health scheduling:               │
│    `crates/daer-control`                                               │
│  - Transparent ingress, splice, UDP sessions, flow supervision:        │
│    `crates/daer-relay` (ADR-0018)                                      │
│  - Integrated DNS pipeline & cache: `crates/daer-dns`                  │
│  - Generation management & zero-downtime hot reload                    │
├────────────────────────────────────────────────────────────────────────┤
│  Layer 2: Domain Engines & Capabilities                                │
│  - Rule lowering & indexed matching: `crates/daer-routing`             │
│  - Outbound groups, alive sets, probes: `crates/daer-outbound`         │
│  - Proxy protocol implementations: `crates/daer-proxy-protocols`       │
│  - Prefix protocol sniffing (TLS SNI, HTTP Host, QUIC): `daer-sniff`   │
│  - Canonical rule source & DRB producer: `crates/daer-rule-ast`, `crates/daer-drb` │
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
- **Red-Line**: Diagnostic commands (`daer route`, `daer probe node`, `daer check --nodes`, `daer check`) and the runtime daemon (`daer run`) MUST load and compile configuration through the exact same loader (`daer_control::load_resolved`).
- **Enforcement**: Diagnostics and runtime share identical generation lowering, alias optimization, subscription and rule-provider caching. A node or rule that appears in `daer route` is guaranteed to exist identically in the running daemon (ADR-0006). `daer probe` adds network I/O to that same generation; it never re-resolves a node from the file on its own.

### 2.3 Kernel Policy Fidelity or Explicit Deferral ([INV-KERNEL-01])
- **Red-Line**: The eBPF kernel policy table must either be provably equivalent to userspace rule evaluation, or explicitly defer the decision to the userspace control plane with logged reasons (ADR-0005).
- **Enforcement**: Predicates supported directly by the kernel fast path (`dip`, `sip`, `port`, `sport`, `l4proto`, `ipversion`, `mac`, `dscp`) execute in-kernel at the tc hook. If a configuration uses predicates requiring userspace state (`domain(...)`, `pname(...)`), the datapath policy is published as a deferral, logging a warning and safely relaying through userspace rather than fabricating an incomplete kernel decision.

### 2.4 Netune Boundary Purity ([INV-NETUNE-01])
- **Red-Line**: Generic network capabilities belong to `netune`; proxy appliance data path, eBPF maps, transparent accept, and proxy protocols stay in `daer` (ADR-0002).
- **Enforcement**: `daer` consumes `netune` as a pinned dependency. `daer` does not implement generic TLS, HTTP codecs, or raw SOCKS5/CONNECT framing. The only exception is REALITY (ADR-0010), where custom unauthenticated TLS 1.3 client mechanics are owned directly by `daer-proxy-protocols`.

### 2.5 Dual-Slot Epoch Atomic Handover ([INV-EPOCH-01])
- **Red-Line**: Kernel policy updates during reload must NEVER mutate live active routing tables in-place.
- **Enforcement**: The datapath maintains two alternating policy slots (`slot 0` and `slot 1`). The userspace daemon fully compiles and populates the inactive slot before flipping the atomic `active_slot` integer, guaranteeing zero-downtime hot reload without transient policy gaps (ADR-0004).

### 2.6 Data Path Stays Stable ([INV-RELAY-01])
- **Red-Line**: `daer-relay` decides nothing. It must not depend on `daer-config`, `daer-outbound`, `daer-routing` or `daer-proxy-protocols`, and its public seam must not name a routing concept (ADR-0018).
- **Enforcement**: The seam is `daer_relay::Decide` (a stream per accepted flow) and `daer_relay::DatagramRouter` (a `DatagramLeg` per datagram flow). A `Verdict`, a group or a policy appearing in either signature is a red-line breach: it would make every new selection concept a change to the code that forwards bytes, and it would put the accept loop's failure modes behind a routing configuration instead of a test double.

### 2.7 The Transparent Ingress Has One Namespace Boundary ([INV-DATAPATH-01])
- **Red-Line**: `daer0peer`, the transparent listeners, and table 2023 live in the private `daer0ns` namespace (ADR-0038). The host keeps `daer0`, the forwarding path, and the redirect source. There is no same-namespace fallback.
- **Enforcement**: `daer-control::netns::PreparedIngress` creates the namespace before `Daemon::bind_in`; `IngressNamespace::with` binds and attaches on a thread that has entered it; `RouteTable` installs `iif daer0peer`, never a mark-keyed rule, which would loop the listener's marked replies.

### 2.8 Proxy Protocols Are Not Re-Exported ([INV-PROTO-01])
- **Red-Line**: `daer-outbound` owns outbound governance, not protocol implementations, and does not re-export the latter's types (ADR-0017). The only exception is `daer_outbound::fragment`, which `DialerOptions` carries as a value.
- **Enforcement**: `cargo tree -p daer-outbound --depth 1` must show no `quinn`, `h3`, `rustls`, `x25519-dalek`, `ml-kem` or AEAD crate. A protocol type reachable through the governance crate's root would announce a boundary it does not own, and would let a future selection feature reach a handshake without naming `daer-proxy-protocols`.


---

## 3. Crate Addition and Workspace Integrity

1. **Single Public Binary**: `daer` is the sole public executable binary produced by the workspace.
2. **Strict Physical Tiering**: Crates reside exclusively under `crates/*`. No crates reside directly at the root.
3. **Zero Unconsumed Configuration**: Every configuration key defined in `daer-config` must be consumed by the daemon or rejected by strict validation (enforced by `daer-config::tests::config_keys`).
