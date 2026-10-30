---
id: ADR-0011
title: "Partitioned kernel routing and DNS snooping for Real-IP datapaths"
status: accepted
date: 2026-01-08
scope: [datapath/policy, routing/lowering, control-plane, dns]
supersedes: []
---

# 0011. Partitioned kernel routing and DNS snooping for Real-IP datapaths

- Status: Accepted
- Date: 2026-01-08
- Deciders: Ming Li
- Related: [ADR-0005](0005-kernel-policy-encoding.md), [ADR-0004](0004-routing-epochs.md), [ADR-0012](0012-optional-fake-ip-ebpf.md)

---

## Context and Problem Statement

[ADR-0005](0005-kernel-policy-encoding.md) ratified the foundational invariant `[INV-KERNEL-01]`:
*The kernel policy table is written, and it is either provably equivalent to userspace or it defers.*

To enforce this, `daer-routing::kernel::compile` implemented an **all-or-nothing deferral gate**: if *any* lowered `MatchSet` in the entire program contains a predicate requiring state the kernel lacks (specifically `domain(...)` without pre-computed IP maps, or `pname(...)`), `compile` returns `Policy::defer(reasons)`. This publishes a single fallback entry:

```text
routing_map[slot*MAX + 0] = { type: Fallback, outbound: OUTBOUND_CONTROL_PLANE_ROUTING }
```

In production configurations, virtually **every real-world rule set** contains domain rules (such as `geosite:cn -> direct` or `domain(suffix: example.com) -> proxy`). Consequently:

1. **100% Kernel Fast-Path Invalidation**: Even if a configuration begins with dozens of deterministic L4/IP rules (e.g. `sip(192.168.0.0/16) -> direct`, `dip(10.0.0.0/8) -> direct`, `dport(22) -> direct`), the presence of a single downstream `domain(...)` rule causes the entire kernel policy to collapse into userspace deferral.
2. **Userspace Relay Saturation**: High-bandwidth LAN-to-LAN, direct domestic traffic, and infrastructure management flows are unnecessarily subjected to `tc` redirect, userspace TPROXY socket accept, userspace relay, and socket re-dialing.
3. **The Real-IP Sniffing Bottleneck**: When deferred traffic reaches `daer-control`, the proxy has only the 4-tuple (`src:sport -> dst:dport`). To match domain rules without Fake-IP, it must perform observational sniffing (`TcpStream::peek()`). This incurs a 1-RTT delay waiting for client payload (e.g., TLS `ClientHello`), and fails entirely for non-TLS/HTTP protocols or Encrypted Client Hello (ECH).

We require an architecture that preserves `[INV-KERNEL-01]` while allowing deterministic prefix rules to execute at wire speed in the kernel, complemented by an unpolluted Real-IP domain resolution bridge.

---

## Decision

### 1. Partitioned Kernel Policy Lowering (`[INV-PARTITION-01]`)

The rule lowering compiler (`daer-routing::kernel::compile`) is restructured into a **two-phase partitioned compiler**:

```text
Full Rule Set: [ R0 (IP) ] -> [ R1 (Port) ] -> [ R2 (GeoIP) ] -> [ R3 (Domain) ] -> [ R4 (IP) ]
                                                              ▲
                                                              │ Partition Boundary
                       ┌──────────────────────────────────────┴───────────────────────┐
                       ▼                                                              ▼
               [ Prefix Partition ]                                          [ Suffix Partition ]
        Encoded into kernel match_set table                            Deferred to Control Plane
        [ R0 ] -> [ R1 ] -> [ R2 ] -> [ GATE: DEFER ]
```

1. **Deterministic Prefix Extraction**:
   The compiler iterates through rules sequentially. Any contiguous prefix of rules containing solely kernel-encodable predicates (`dip`, `sip`, `port`, `sport`, `l4proto`, `ipversion`, `mac`, `dscp`) is lowered directly into `struct match_set` entries and their associated LPM tries.
2. **The Deferral Gate (`MATCH_FALLBACK -> OUTBOUND_CONTROL_PLANE_ROUTING`)**:
   At the exact boundary where the first unencodable predicate appears (or when `MAX_MATCH_SET_LEN` would be exceeded), the compiler appends a **Deferral Gate**.
3. **Provable Invariant (`[INV-PARTITION-01]`)**:
   Traffic matching any rule *before* the boundary is guaranteed to terminate with its definitive verdict in kernel space. Because rule evaluation is ordered and top-to-bottom, a match in the prefix partition is mathematically independent of all subsequent downstream rules.
4. **Outcome**:
   Direct LAN traffic, trusted subnets, management ports, and static IP bypasses execute entirely within eBPF (`TC_ACT_OK` or direct mark bypass), achieving line-rate forwarding with **zero userspace context switches**.

### 2. DNS Snooping State Engine (`(client_ip, resolved_ip) -> domain`)

To eliminate the 1-RTT stream peeking penalty in Real-IP mode:

1. **Resolver Event Emission**:
   `daer-dns` maintains an internal, bounded LRU snooping table:
   `SnoopKey { client: IpAddr, resolved: IpAddr } -> SnoopEntry { domain: Arc<str>, expires_at: Instant }`.
   Whenever `daer-dns` returns a resolved A/AAAA response to a client, it writes the mapping with a TTL aligned with the DNS record.
2. **Control-Plane Zero-RTT Domain Recovery**:
   When `daer-control` accepts a flow deferred by the kernel, it queries the snooping table with `(flow.source, flow.destination)`.
   - **Cache Hit**: `MatchFacts.domain` is populated immediately. The flow is evaluated by `daer_routing::first_hit()` before TCP handshake completion or payload arrival.
   - **Cache Miss / Collision**: If the IP is unmapped or shared across multiple active domains (e.g. multi-tenant CDNs), the system falls back to `stream.peek()` sniffing as an observational tie-breaker.

---

## Negative Knowledge & Discarded Alternatives

- **All-or-Nothing Deferral (ADR-0005 status quo)**:
  Discarded as an over-simplification. While safe, it renders the kernel datapath useless in practice, treating an eBPF router as a glorified TPROXY packet redirector.
- **Out-of-Order Rule Promotion (Reordering IP rules ahead of Domain rules)**:
  Rejected. Reordering rules violates the user's explicit configuration semantics. If Rule 1 is `domain(suffix: a.com) -> proxy` and Rule 2 is `ip(any) -> direct`, hoisting Rule 2 would cause traffic intended for `a.com` to bypass the proxy. Partitioning must strictly respect lexical order.
- **Hot-Path Synchronous Reverse DNS (PTR) Queries**:
  Rejected. Querying upstream DNS on intercepted TCP SYNs introduces high latency (50–300ms), creates recursive proxying deadlocks, and leaks traffic. DNS snooping is strictly observational and asynchronous.

---

## Consequences

### Positive
- **Dramatic Datapath Offload**: High-volume direct traffic (e.g., local backup, NAS, internal VPC, GeoIP direct) is processed entirely in `tc` eBPF without crossing the kernel-userspace boundary.
- **Zero-Latency Real-IP Domain Routing**: Eliminates `stream.peek()` delays for >95% of standard browser and application flows where DNS was resolved locally.
- **Pristine Real-IP Guarantee**: Fully satisfies developers and network engineers; no IP address mangling, ICMP ping works natively, Wireshark captures display authentic endpoints.

### Negative & Operational Costs
- **Increased Lowering Logic**: `daer-routing::kernel` must compute partition boundaries and maintain equivalence invariants across the split.
- **Memory Footprint for Snooping**: An LRU table of 32,768 snooped entries consumes ~2 MB of RAM in `daer-control`.

---

## Enforcement & Verification Plan

1. **Compiler Equivalence Test (`tests/kernel_partition.rs`)**:
   Verify that a program with 5 prefix IP rules followed by 1 domain rule compiles to 6 kernel entries (5 rules + 1 deferral gate). Assert flows matching rules 0..4 return verdicts directly in kernel simulation; assert flows passing rule 4 hit the deferral gate.
2. **Negative Bypass Control**:
   Assert that any packet whose destination matches a downstream rule placed *after* the boundary is never misrouted by the prefix partition.
