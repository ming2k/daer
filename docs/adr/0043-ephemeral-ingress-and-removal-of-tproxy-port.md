---
id: ADR-0043
title: "Ephemeral ingress binding and complete elimination of tproxy-port"
status: accepted
date: 2026-11-12
scope: [architecture/boundary, datapath, transparent-ingress, config, cli]
supersedes: []
superseded_by: []
amends: [ADR-0006, ADR-0021, ADR-0023, ADR-0038]
---

# 0043. Ephemeral ingress binding and complete elimination of tproxy-port

- Status: Accepted
- Date: 2026-11-12
- Deciders: daer maintainers
- Related: [ADR-0006](0006-wiring-ownership.md),
  [ADR-0021](0021-kernel-abi-single-source.md),
  [ADR-0023](0023-constants-have-one-definition.md),
  [ADR-0038](0038-private-ingress-network-namespace.md)

---

## Context

In traditional transparent proxies relying on `iptables` or `nftables` `TPROXY`, the firewall rule rewrites destination lookup to an explicit port (e.g., `tproxy to :12345`). The proxy must bind that exact port on the host, requiring explicit configuration, port management, and collision mitigation.

`daer` uses an eBPF datapath with `bpf_sk_assign` (ADR-0020, ADR-0038). When traffic matches a routing rule, the datapath redirects packets onto `daer0` into the private `daer0ns` network namespace. On `daer0peer` ingress, `assign_listener` looks up the socket directly in `listen_socket_map` (`SOCKMAP`) by protocol and family, and calls `bpf_sk_assign(skb, sk, 0)`.

This creates several decisive architectural contradictions:
1. **The eBPF kernel datapath never reads the port.** `daer_param.tproxy_port` was declared in ABI, but no line of C in `ebpf/kern/` ever accessed it. The socket is looked up by map index, not port.
2. **The listeners live in a private network namespace (`daer0ns`, ADR-0038).** There are no competing host services, no port collisions, and no direct external routes into `daer0ns`.
3. **The `is_self_connect` port heuristic actively breaks legitimate traffic.** Because `is_self_connect` dropped traffic whose `destination.port == transparent_port`, any legitimate client connection directed to a public internet service on that port (default 12345) was silently dropped.
4. **Configuration abstraction leak.** Demanding a port number in `[global]` forces users to understand and configure internal implementation plumbing that has no bearing on routing.

## Decision

1. **Complete clean break: eliminate `tproxy-port` and `tproxy-port-protect` from configuration.**
   Delete `tproxy_port` and `tproxy_port_protect` from [`daer_config::Global`]. Configuration files specifying `tproxy-port` or `tproxy-port-protect` are rejected by `deny_unknown_fields`. Validation rules requiring non-zero ports are removed.
2. **Ephemeral ingress binding (`port = 0`).**
   Transparent listeners (`TransparentListener` and `TransparentDatagramListener`) always bind to port `0` inside `daer0ns`. The operating system dynamically assigns an available ephemeral port. The bound port is retained purely as a read-only fact on `Daemon` for diagnostics (`daer status`).
3. **Delete `is_self_connect` and port-based self-connection rejection.**
   Since ingress traffic in `daer0ns` arrives exclusively via kernel redirect on `daer0peer`, external direct connections cannot hit the listener. Port comparison against client destinations is deleted, eliminating silent drops of external traffic on the default port.
4. **Purge `tproxy_port` from kernel ABI and common constants.**
   Remove `tproxy_port` from `ebpf/abi.toml`, regenerating `daer_abi.h` and Rust layout assertions. Delete `TPROXY_PORT_DEFAULT` from `daer-common::consts`.

## Consequences

- **Zero configuration overhead**: Users configure interfaces and routing rules; transparent socket plumbing is fully managed by `daer`.
- **Elimination of false-positive connection drops**: External services on port 12345 (or any previously configured port) are proxied normally.
- **Smaller kernel ABI**: `struct daer_param` shrinks by 4 bytes; unused parameters are completely purged.
- **Breaking change**: Existing configuration files containing `tproxy-port` must remove the field.
