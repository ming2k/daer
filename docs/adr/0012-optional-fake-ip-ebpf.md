---
id: ADR-0012
title: "Pluggable Fake-IP subsystem and eBPF domain-bitmap synthesis"
status: accepted
date: 2026-01-08
scope: [dns/fake-ip, datapath/ebpf, control-plane/routing, config/schema]
supersedes: []
---

# 0012. Pluggable Fake-IP subsystem and eBPF domain-bitmap synthesis

- Status: Accepted
- Date: 2026-01-08
- Deciders: Ming Li
- Related: [ADR-0004](0004-routing-epochs.md), [ADR-0005](0005-kernel-policy-encoding.md), [ADR-0011](0011-partitioned-kernel-routing.md)

---

## Context and Problem Statement

[ADR-0011](0011-partitioned-kernel-routing.md) guarantees that Real-IP remains the default operational mode, preserving authentic IP diagnostics for developers and diagnostic tools.

However, in line-rate transparent proxy deployments (e.g. gateway appliances handling 10G+ throughput with high connection rates), domain-based routing encounters a fundamental physics problem:

1. **eBPF Kernel Verifier Constraints**: The kernel datapath (`tc` eBPF) operates per-packet on the softirq path. It cannot allocate dynamic memory, cannot iterate unbounded string loops, and cannot execute complex string matching (Aho–Corasick or Regex) over variable-length domain names.
2. **The Unpopulated Datapath Map**: In `ebpf/kern/tproxy.c`, the datapath provisions `domain_routing_map`:
   ```c
   struct routing_epoch_ip { __u32 slot; __be32 addr[4]; };
   struct domain_routing   { __u32 bitmap[MAX_MATCH_SET_LEN / 32]; };
   struct {
       __uint(type, BPF_MAP_TYPE_HASH);
       __type(key, struct routing_epoch_ip);
       __type(value, struct domain_routing);
       __uint(max_entries, ROUTING_EPOCH_SLOT_NUM * MAX_DOMAIN_ROUTING_NUM);
   } domain_routing_map SEC(".maps");
   ```
   In Real-IP mode, this map cannot be safely populated from DNS answers because arbitrary real IPs (notably multi-tenant CDN edges) exhibit a 1-to-many relationship with domains, creating hash collision and policy leakage risks.
3. **The Legacy Proxy Antipattern**: Legacy tools (early Clash/V2Ray) enforced Fake-IP as an all-or-nothing global default, permanently polluting local DNS caches, breaking raw-socket and ICMP ping tools, and making network debugging impossible.

We need a clean-break architecture where:
- Fake-IP is a **pluggable, strictly non-default capability**;
- When enabled, it establishes an unambiguous 1-to-1 bijection between an IP and a domain name;
- That bijection compiles domain routing decisions directly into the kernel's `domain_routing_map`, achieving **kernel line-rate domain steering**.

---

## Decision

### 1. Pluggable, Non-Default `[dns.fake-ip]` Specification (`[INV-FAKEIP-01]`)

Fake-IP is isolated behind an explicit configuration table in `[dns.fake-ip]`. It defaults to disabled (`enabled = false`), ensuring zero unexpected environment pollution.

```toml
[dns]
listen = "127.0.0.1:53"

[dns.fake-ip]
enabled = false
inet = "198.18.0.0/15"           # Reserved benchmark range (RFC 2544 / RFC 3596)
pool-size = 65535                 # Bound memory allocation
exclude = [
    "geosite:cn",
    "domain(suffix: local)",
    "domain(suffix: lan)",
]
```

- **Invariant `[INV-FAKEIP-01]` (Isolation Guarantee)**:
  When `enabled = false`, the Fake-IP subsystem is inert. The ingress datapath performs zero reverse lookups, treats `198.18.0.0/15` as standard unmapped IP addresses, and produces no DNS responses from synthetic pools.

### 2. High-Performance Bijective State Pool (`daer_dns::FakeIpPool`)

When enabled, `daer-dns` instantiates a concurrent, lock-free or read-optimized bidirectional mapping pool:

```text
       DNS Query ("api.example.com")
                   │
                   ▼
     [ Matches `exclude` filters? ]
        ├── YES ──▶ Forward to standard upstream resolver (Real-IP)
        └── NO  ──▶ Allocate or lookup in FakeIpPool:
                     BiMap: "api.example.com" <═══ 1:1 ═══> 198.18.0.42
```

- **Capacity & LRU Eviction**: Fixed capacity (`pool-size`). When full, the oldest unreferenced IP is recycled. Eviction emits an explicit removal event to the datapath to invalidate stale kernel map entries.
- **Exclusion Filters**: Domains matching `exclude` (e.g. corporate intranet, local mDNS, domestic services) bypass the pool and receive authentic upstream IP addresses.

### 3. eBPF Kernel Domain-Bitmap Synthesis

Because a synthetic Fake-IP uniquely identifies a single domain name, the control plane can pre-evaluate routing policy at the exact instant the DNS query is answered:

```text
 1. daer-dns allocates 198.18.0.42 for "example.com"
 2. daer-routing::evaluate_domain_bitmask("example.com") -> u32 bitmap
 3. daer-control writes directly to the active kernel slot:
    domain_routing_map[slot, 198.18.0.42] = { bitmap }
 4. Client receives 198.18.0.42 and issues TCP SYN to 198.18.0.42:443
 5. Kernel tc eBPF evaluates route_eval_domain_bitmap():
    - Finds 198.18.0.42 in domain_routing_map
    - Bitwise test matches rule -> Outbound: Proxy (or Direct bypass)
    - Verdict applied immediately in kernel datapath!
```

- **Zero Sniffing**: No TCP stream peeking, no waiting for TLS ClientHello, no inspection of application bytes.
- **Protocol Agnostic**: Works identically for TLS, QUIC, SSH, raw TCP, and custom UDP datagrams.

### 4. Zero-Copy Inbound Unwrapping (`daer-control`)

When a flow deferred for outbound proxy relay reaches `daer-control`:
1. The ingress handler inspects `flow.destination`.
2. If `flow.destination.ip() ∈ fake_ip_net`, it performs an $O(1)$ reverse lookup in `FakeIpPool`.
3. The original domain string (`"example.com"`) is restored and placed into `FlowFacts.domain` before dialing the upstream proxy node.
4. Upstream protocols (Shadowsocks, Trojan, REALITY, VLESS) receive the authentic domain name in their connection headers without the remote server ever seeing synthetic addresses.

---

## Negative Knowledge & Discarded Alternatives

- **Mandatory Fake-IP (Legacy Clash/V2Ray Model)**:
  Discarded as hostile to developers. Forcing synthetic IPs breaks `ping`, `traceroute`, ICMP latency probes, direct socket binding, and local microservice discovery.
- **Userspace-Only Fake-IP**:
  Rejected. Using Fake-IP only to bypass userspace sniffing while leaving eBPF kernel maps unpopulated throws away the primary performance benefit. Fake-IP's true power is transforming string routing into kernel-level integer/bitmap lookups.
- **In-Kernel Domain String Parsing**:
  Rejected as an architectural impossibility. Linux BPF verifier constraints (512-byte stack limit, instructions ceiling, lack of dynamic allocators) make robust, secure domain parsing and regex in kernel space unviable.
- **Global In-Memory Maps without LRU Bound**:
  Rejected. An unbounded hash map exposed to arbitrary DNS queries is a denial-of-service vector (memory exhaustion). `pool-size` is hard-enforced.

---

## Consequences

### Positive
- **Maximum Line-Rate Throughput**: Enables eBPF kernel datapath to evaluate domain rules at line rate, eliminating all userspace packet relay for kernel-handled flows.
- **Zero First-Packet Delay (0-RTT)**: Connections establish immediately; no waiting for client TLS payload or DNS snooping heuristics.
- **Clean Developer Hygiene**: Off by default; zero side effects on developer workflows unless explicitly opted in.

### Negative & Operational Costs
- **Datapath Map Synchronisation**: `daer-dns` must synchronize map entries with `daer-ebpf` across configuration reloads and routing epoch flips (ADR-0004).

---

## Enforcement & Verification Plan

1. **Isolation Test (`tests/fake_ip_isolation.rs`)**:
   Verify that with `[dns.fake-ip]` disabled, queries to `198.18.0.0/15` are treated as normal IP addresses and no reverse translation occurs.
2. **Kernel Parity Test (`tests/kernel_fake_ip.rs`)**:
   Verify that when a Fake-IP is written to `domain_routing_map`, kernel evaluation produces the exact same verdict as userspace evaluation for the originating domain name.
3. **Capacity & Recirculation Test (`tests/fake_ip_pool.rs`)**:
   Verify that allocating $N > \text{pool-size}$ distinct domains does not panic, leaks zero memory, and correctly purges stale map entries.
