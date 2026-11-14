---
id: ADR-0055
title: "Direct outbound unwraps synthetic Fake-IPs through internal real DNS"
status: accepted
date: 2026-11-14
scope: [control-plane/routing, dns/resolver, architecture/boundary]
supersedes: []
superseded_by: []
---

# 0055. Direct outbound unwraps synthetic Fake-IPs through internal real DNS

- Status: Accepted
- Date: 2026-11-14
- Deciders: daer maintainers
- Related: [ADR-0012](0012-optional-fake-ip-ebpf.md), [ADR-0051](0051-datagram-relay-is-transport-only.md), [ADR-0054](0054-transparent-dns-interception.md)

## Context

[ADR-0051](0051-datagram-relay-is-transport-only.md) stated that the `direct` outbound always dials the literal destination address because a `direct` flow's destination is authoritative. That assumption is false whenever `[dns.fake-ip]` is enabled:

1. A client queries DNS for a domestic domain (for example `www.baidu.com`), and `daer-dns` synthesizes an address from `198.18.0.0/15`.
2. The client connects to `198.18.0.28:443`.
3. `daer-control` reverse-maps `198.18.0.28` to `www.baidu.com`, evaluates routing rules (such as `rule-set(cn-sites) -> direct`), and selects `OutboundKind::Direct`.
4. `Router::dial_with_authority` (TCP) and `Router::dial_target` (UDP) ignored the unwrapped domain for `Direct` and dialed `198.18.0.28:443` directly, failing every domestic/direct flow with `dial_connect` or `dial_timeout`.

Calling system `getaddrinfo` from `DirectDialer` is not acceptable either: under transparent DNS interception ([ADR-0054](0054-transparent-dns-interception.md)) or loopback DNS binding, system resolution would loop back into `daer-dns` and synthesize another Fake-IP, and would bypass `so-mark` (`[INV-MARK-01]`) and `[dns.request]` rules.

## Decision

This decision ratifies **`[INV-DIRECT-FAKEIP-01]`** and amends [ADR-0051](0051-datagram-relay-is-transport-only.md):

1. **`daer-dns::Resolver::resolve_real_ips`** resolves a domain through the configured `[dns]` request router, cache, and `so-mark`ed upstreams while bypassing Fake-IP synthesis.
2. **`Router::resolve_direct_destination`** (shared by both TCP `dial_with_authority` and UDP `open_datagram_with_source`) distinguishes synthetic Fake-IPs (`DomainSource::FakeIp` or `DomainResolver::is_fake_ip`) from authoritative real IPs (`DnsSnooper`, `Sniff`, or raw IP):
   - Authoritative real IPs are dialed literally with zero re-resolution.
   - Synthetic Fake-IPs are unwrapped to their domain and resolved via `Resolver::resolve_real_ips` to a real `SocketAddr` before dialing `DirectDialer` or `UdpConnector`.
   - A Fake-IP with no domain mapping or no active resolver fails fast rather than dialing `198.18.0.0/15`.
3. The legacy synchronous `Router::dial_target` helper is removed.

## Consequences

- Domestic and other `direct`-routed flows work identically whether `[dns.fake-ip]` is enabled or disabled.
- `Direct` flows with real IPs (DNS snooping, payload sniffing, raw IPs) continue to dial the original IP without extra DNS queries.
- No backward-compatibility shim is kept for dialing synthetic `198.18.0.0/15` addresses.
