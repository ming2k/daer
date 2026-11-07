---
id: ADR-0035
title: "QUIC and HTTP/3 client transports migrate to netune; daer drops quinn and ring"
status: accepted
date: 2026-11-07
scope: [outbound/protocols, hysteria2, quic, http3, architecture/boundary, crypto]
supersedes: []
---

# 0035. QUIC and HTTP/3 client transports migrate to netune; daer drops quinn and ring

- Status: Accepted
- Date: 2026-11-07
- Deciders: Ming Li
- Amends: [ADR-0002](0002-netune-boundary.md),
  [ADR-0017](0017-proxy-protocols-crate-boundary.md),
  [ADR-0029](0029-hysteria2-socket-stack.md)
- Related: [netune ADR-0016](../../../netune/docs/adr/0016-quic-and-http3-transport.md)

---

## Context and Problem Statement

When Hysteria 2 support was implemented ([ADR-0029](0029-hysteria2-socket-stack.md)), `netune` had deferred QUIC and HTTP/3 client transport ([netune ADR-0010](../../../netune/docs/adr/0010-quic-ownership-and-trace-sink.md)). Consequently, `daer-proxy-protocols` directly imported `quinn`, `quinn-proto`, `h3`, `h3-quinn`, and a secondary `rustls` engine compiled with `ring` (while `netune` uses `aws-lc-rs`).

This resulted in significant architectural strain:
1. **Dual Crypto Engines and Binary Bloat**: `daer` linked both `aws-lc-rs` and `ring`, producing two distinct compilations of `rustls 0.23` in one binary. This bloated the text segment by ~18 MB and incurred heavy linking overhead.
2. **Boundary Inversion (`[INV-NETUNE-01]`)**: QUIC (RFC 9000), QUIC Datagrams (RFC 9221), and HTTP/3 (RFC 9114) are generic IETF transport standards. Implementing raw QUIC endpoints, flow control, and HTTP/3 state machines in `daer` violated the foundational principle that *network capabilities belong to netune; the proxy data path belongs to daer*.
3. **Observability Loss**: QUIC dials and HTTP/3 streams operated outside `netune-trace`, preventing unified latency derivations (`[INV-TRACE-01]`).

With `netune ADR-0016` ratifying first-class QUIC and HTTP/3 client capabilities unified under `aws-lc-rs`, this temporary concession is no longer justified.

---

## Decision

### 1. `daer` Drops All Direct QUIC, HTTP/3, and `ring` Dependencies
`crates/daer-proxy-protocols` deletes direct dependencies on:
* `quinn`
* `quinn-proto`
* `h3`
* `h3-quinn`
* `rustls` (compiled with `ring`)
* `tokio-rustls`

All QUIC and HTTP/3 transport facilities are consumed exclusively from `netune::quic` (`netune-quic`) and `netune::http3` (`netune-http3`).

### 2. Hysteria 2 Retains Only Product-Specific Semantics
Hysteria 2 in `daer-proxy-protocols` is refactored to focus strictly on its proxy protocol responsibilities:
* Authentication handshake headers (`auth.rs`).
* Salamander and Gecko obfuscation layers (`obfs.rs`), which now implement `netune_quic::QuicUdpSocket`.
* Port-hopping socket rotation (`hop.rs`), also implemented via `netune_quic::QuicUdpSocket`.
* Brutal congestion control (`brutal.rs`), mapped to `netune_quic::quinn_proto::congestion::ControllerFactory`.
* Ingress/egress stream and UDP datagram framing.

### 3. Unified Cryptographic Backend
`daer` now compiles against a single cryptographic provider (`aws-lc-rs`) across its entire dependency graph. `ring` is completely eliminated from the build graph.

---

## Consequences

- Restores strict adherence to `[INV-NETUNE-01]`: generic QUIC and HTTP/3 transport live in `netune`.
- `daer` binary size drops by ~18 MB, with significantly reduced link times.
- QUIC dials and HTTP/3 client exchanges are fully visible to `netune-trace`.
