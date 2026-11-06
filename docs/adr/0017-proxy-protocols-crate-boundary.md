---
id: ADR-0017
title: "Proxy protocols and crypto engines belong to daer-proxy-protocols"
status: accepted
date: 2026-10-31
scope: [architecture/boundary, outbound/protocols, crypto, crate-topology]
supersedes: []
---

# 0017. Proxy protocols and crypto engines belong to daer-proxy-protocols

- Status: Accepted (Amended by [ADR-0028](0028-protocol-layering.md): the crate now holds
  orthogonal *layers* rather than one module per product protocol, so `reality` is a security
  layer, `vless`/`vmess` are protocol layers, and `transport` is a layer of its own)
- Date: 2026-10-31
- Related: [ADR-0002](0002-netune-boundary.md), [ADR-0010](0010-reality-client-ownership.md)

---

## Context and Problem Statement

`daer-outbound` was originally designed as a thin dispatch layer (ADR-0002):
> *"daer-outbound is thin: latency statistics, alive-set selection, group assembly, policy, and the mapping from a node link to a netune connector."*

As proxy protocol support expanded (Shadowsocks AEAD, Trojan, AnyTLS, Hysteria 2, and REALITY per ADR-0010), `daer-outbound` absorbed full protocol implementations, custom wire framing, handshake state machines, and a minimal unauthenticated TLS 1.3 client engine.

This resulted in significant architectural strain:
1. **Single Responsibility Principle (SRP) Violation**: `daer-outbound` bundled two disparate concerns:
   - High-level outbound governance: node groups, health checks, moving latency averages, alive sets, filters, and subscriptions.
   - Low-level tunnel protocol implementations: cryptographic primitives, QUIC/H3 framing, TLS record manipulation, and vision padding.
2. **Heavy Dependency Pollution**: Heavy crypto libraries (`x25519-dalek`, `ml-kem`, `aes-gcm`, `chacha20poly1305`, `hkdf`, `hmac`, `sha1`, `sha2`, `zeroize`) and QUIC stacks (`quinn`, `h3`, `rustls`) leaked into any consumer of `daer-outbound`.
3. **Compilation Overhead & Test Blast Radius**: A change in protocol framing required re-compiling the outbound orchestrator, and running unit tests in outbound pulled in 9 heavyweight integration interop test suites.

## Decision

**1. Create `crates/daer-proxy-protocols` to house all proxy product protocol implementations.**

All client tunnel implementations, wire framing, and bespoke crypto/TLS engines belong strictly to `daer-proxy-protocols`:
- `shadowsocks`: SIP004 AEAD crypto, salt replay filter, framing.
- `trojan`: Authentication headers, link parsing.
- `anytls`: Multiplexed session management, framing, datagrams.
- `hysteria2`: QUIC and HTTP/3 client transports, UDP encapsulation, varint codecs.
- `reality`: Minimal TLS 1.3 client (record, schedule, stream), VLESS framing, Vision obfuscation, probe and verification.
- `fragment`: Handshake segmenting I/O for TLS ClientHello fragmentation.

**2. `daer-outbound` remains the exclusive owner of outbound governance and orchestration.**

`daer-outbound` retains:
- Group selection policies (`min`, `priority`, `round_robin`, `random`, `fallback`).
- Latency tracking and moving averages (`LatenciesN`, `MovingAverage`).
- Alive dialer sets and failure tolerance (`AliveDialerSet`).
- Probes and health checks (`HttpChecker`, `TcpChecker`, `UdpDnsChecker`).
- Node filtering and annotations (`FilterSet`, `Annotation`).
- Subscription downloading, decoding, and caching.
- Direct dialer and socket options (`SO_MARK` loop evasion).
- `NodeDialer` factory: lowers configured nodes into dialers by invoking `daer-proxy-protocols` or `netune`.

**3. Clear unidirectional dependency flow.**

```text
daer-control / daer-cli
          │
          ▼
    daer-outbound   (Governance, Groups, Health Checks, Routing Dispatch)
          │
          ▼
daer-proxy-protocols (Proxy Protocols: Shadowsocks, Trojan, REALITY, Hysteria 2, AnyTLS)
          │
          ▼
       netune       (Network Capabilities: TCP, TLS, CONNECT/Socks5, Datagrams)
```

No cyclic dependencies are permitted. `daer-proxy-protocols` does not depend on `daer-outbound`.

**4. Error boundary separation.**

`daer-proxy-protocols` defines `ProxyProtocolError` covering connection failures, deadlines, and link syntax issues. `daer-outbound` maps these into `OutboundError` at the boundary.

## Consequences

- `daer-outbound` returns to its thin governance role as envisaged in ADR-0002.
- Protocol implementations and their tests are isolated into `crates/daer-proxy-protocols`.
- Downstream crates only linking against outbound utilities are shielded from transitive cryptographic and QUIC dependencies.
- Adding future proxy protocols (e.g. TUIC, VMess) touches `daer-proxy-protocols` without destabilizing group or health-check logic.
