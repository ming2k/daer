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
- Related: [netune ADR-0016](../../../netune/docs/adr/0016-quic-and-http3-transport.md),
  [netune ADR-0027](../../../netune/docs/adr/0027-owned-h3-qpack.md),
  [netune ADR-0028](../../../netune/docs/adr/0028-owned-quic.md)

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

### 1. `daer` Drops Direct QUIC/HTTP-3 Runtimes and `ring`
`crates/daer-proxy-protocols` deletes direct dependencies on:
* `quinn`
* `quinn-proto`
* `h3`
* `h3-quinn`
* any `rustls` compiled with `ring`

All QUIC and HTTP/3 transport facilities are consumed exclusively from `netune::quic` (`netune-quic`) and `netune::http3` (`netune-http3`).

`rustls` remains a direct dependency for the REALITY TLS 1.3 client (ADR-0010), the
product-specific TLS configuration Hysteria 2 hands to `netune-quic`, and the
`AcceptAny` verifier the standard-TLS security layer supplies for
`netune::TlsConnector`. The standard TLS handshake itself is netune's: the security
layer passes a preconnected stream and a netune-built profile to `TlsConnector`, so
the DNS/TCP/TLS phases share one trace and one handshake implementation.
`tokio-rustls` is no longer a normal dependency of `daer`; it survives only in
dev-dependencies that stand up local TLS test servers. Both crypto paths use
`aws-lc-rs`; the point of this decision is one crypto provider and no second QUIC
runtime, not the removal of a TLS type daer still needs.

### 2. Hysteria 2 Retains Only Product-Specific Semantics
Hysteria 2 in `daer-proxy-protocols` is refactored to focus strictly on its proxy protocol
responsibilities:
* Authentication handshake headers (`auth.rs`), sent through `netune_http3::H3Client`.
* Salamander and Gecko obfuscation layers (`obfs.rs`), which implement `netune_quic::QuicUdpSocket`.
* Port-hopping socket rotation (`hop.rs`), also implemented via `netune_quic::QuicUdpSocket`.
* Brutal congestion control (`brutal.rs`), mapped to
  `netune_quic::CongestionControllerFactory`.
* Ingress/egress stream and UDP datagram framing.

### 3. The Transport Seams Are netune's, Not daer's
netune 0.0.28 owns QUIC and HTTP/3; `quinn`, `quinn-proto`, `h3` and `h3-quinn` are absent from
the production graph. Three capabilities that a proxy needs are exposed as generic seams rather
than product code in daer:

* `QuicUdpSocket` / `QuicUdpSocketFactory`: an abstract datagram socket built once per
  connection by `QuicConnector::with_socket_factory`. Hysteria 2's obfs and source-port rotation
  wrap this trait, and the factory applies netune's `QuicSocketConfig` to the base socket.
* `CongestionControllerFactory`: a per-connection controller passed to
  `QuicConnector::with_congestion_factory`. Brutal implements it.
* `QuicProfile.keep_alive` and `Connection::peer_certificates`: the NAT keep-alive and the
  post-handshake `pin-sha256` check.

### 4. Unified Cryptographic Backend
`daer` now compiles against a single cryptographic provider (`aws-lc-rs`) across its entire dependency graph. `ring` is completely eliminated from the build graph.

---

## Consequences

- Restores strict adherence to `[INV-NETUNE-01]`: generic QUIC and HTTP/3 transport live in `netune`.
- `daer` binary size drops by ~18 MB, with significantly reduced link times.
- QUIC dials and HTTP/3 client exchanges are fully visible to `netune-trace`.
- Port hopping rotates the local socket selected by `HopSocket` and keeps the previous one for
  one interval; the connection id space is untouched. Destination-port rotation remains the
  recorded gap it was in ADR-0029.
- The owned engine performs DPLPMTUD by default. `disable-path-mtu-discovery` maps to
  `QuicProfile.path_mtu_discovery = false`, which advertises the 1200-byte QUIC floor so the
  validated path cannot grow. The engine still has no GSO, so `disable-segmentation-offload` is
  accepted because the requested state is already true; it is a documented engine property, not
  a runtime switch.
- `daer` does not depend on `netune-server`; HTTP/3 ingress remains an upstream-only capability.
