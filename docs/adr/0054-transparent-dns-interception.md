---
id: ADR-0054
title: "Transparent DNS interception in the control plane"
status: accepted
date: 2026-11-14
scope: [dns/interception, control-plane/routing, config/schema, datapath/dns, architecture/boundary]
supersedes: []
superseded_by: []
---

# 0054. Transparent DNS interception in the control plane

- Status: Accepted
- Date: 2026-11-14
- Deciders: daer maintainers
- Related: [ADR-0012](0012-optional-fake-ip-ebpf.md), [ADR-0050](0050-domain-acquisition-is-explicit.md), [ADR-0051](0051-datagram-relay-is-transport-only.md)

## Context

Previously, [ADR-0050](0050-domain-acquisition-is-explicit.md) treated `[dns].bind` as the
only switch for the built-in DNS service and required `dns.bind` whenever Fake-IP was
enabled. Client queries to external resolvers (`8.8.8.8:53`) were treated as ordinary
flows and never entered `daer-dns`.

That design forced operators to mutate `/etc/resolv.conf` or `systemd-resolved` on the
host (and rely on DHCP/client compliance on a LAN) for Fake-IP, `DnsSnooper`, or
anti-poisoning DNS routing to work:

1. Mutating host resolver files is invasive and fragile across NetworkManager,
   `systemd-resolved`, and container runtimes.
2. Pointing `/etc/resolv.conf` at `127.0.0.1` creates a hard availability dependency: if
   `daer` stops or crashes, the host loses DNS resolution completely.
3. LAN clients with hardcoded DNS servers (`8.8.8.8:53`) bypass `dns.bind` entirely.

Meanwhile, the eBPF datapath (`policy.h`) already steers non-`must` `:53` UDP/TCP traffic
to `OUTBOUND_CONTROL_PLANE_ROUTING`, and `daer-dns` upstream sockets carry `so-mark`
(`[INV-MARK-01]`) so they are never recaptured.

## Decision

This decision ratifies **`[INV-DNS-INTERCEPT-01]`**: when transparent DNS interception
is active, `:53` UDP and TCP flows arriving at the transparent ingress are answered
in-process by `daer-dns::Resolver`, without requiring `[dns].bind` or host resolver
changes.

1. **`[dns].intercept` (`Option<bool>`)**:
   - `None` (default): active (`true`) whenever `[dns].upstream` is non-empty or
     `[dns.fake-ip] enabled = true`; inactive (`false`) when `[dns]` is unconfigured.
   - `Some(true)`: explicitly enabled; requires at least one `[dns].upstream`.
   - `Some(false)`: explicitly disabled; `:53` flows are routed as ordinary TCP/UDP flows.
2. **`[dns].bind` becomes an optional explicit listener**:
   - `[dns.fake-ip] enabled = true` and `[routing.sniff] enabled = false` require an
     active DNS service (`dns.is_active() == dns.effective_intercept() || dns.bind.is_some()`),
     not `[dns].bind`.
   - `[dns].bind` remains available for deployments that also want an explicit listening
     socket (e.g., for local loopback clients or non-proxied LAN hosts).
3. **In-process interception seam (`daer-control`)**:
   - `Router` receives `Option<Arc<daer_dns::Resolver>>` when `effective_intercept()` is
     `true`.
   - Routing `block` verdicts on `:53` flows are still enforced before interception, and
     `must` rules in `[routing]` bypass `OUTBOUND_CONTROL_PLANE_ROUTING` in eBPF.
   - For UDP `:53`, `Router::open_datagram_with_payload` inspects the first DNS query:
     if `[dns.request]` evaluates to `AsIs`, it falls through to normal `[routing]` and
     dials the client's original destination resolver; otherwise it returns an in-process
     `DnsDatagramConnector` backed by `daer_dns::Resolver`.
   - For TCP `:53`, `Router::resolve` peeks the first length-prefixed DNS query without
     consuming bytes: if `[dns.request]` evaluates to `AsIs`, it falls through to normal
     `[routing]`; otherwise it bridges an in-process `tokio::io::duplex` stream to
     `daer_dns::serve_tcp_stream`.
4. **Loop freedom**:
   - `daer-dns` upstream transports use `netune` sockets configured with `so-mark`
     (`[INV-MARK-01]`), so eBPF passes upstream queries directly without re-entering
     the transparent ingress.
5. **Clean break from ADR-0050's `dns.bind` coupling**:
   - Amends [ADR-0050](0050-domain-acquisition-is-explicit.md) and
     [ADR-0012](0012-optional-fake-ip-ebpf.md): Fake-IP and DNS-based domain acquisition
     no longer require `[dns].bind`.

## Negative Knowledge & Discarded Alternatives

- **Unconditionally binding `0.0.0.0:53` and rewriting `/etc/resolv.conf`**: rejected.
  Conflicts with `systemd-resolved` (`EADDRINUSE`) and leaves the host without DNS if the
  daemon exits unexpectedly.
- **Hijacking `:53` inside `daer-relay`**: rejected by [ADR-0018](0018-userspace-data-path-is-daer-relay.md)
  and [ADR-0051](0051-datagram-relay-is-transport-only.md). `daer-relay` is transport-only
  and must not depend on `daer-dns`.
- **Consuming TCP bytes before checking `AsIs`**: rejected. Consuming the first query
  from `TcpStream` would corrupt the stream if `AsIs` later fell through to an outbound
  dial; `TcpStream::peek` keeps the stream intact on `AsIs`.

## Consequences

- A working transparent proxy with Fake-IP and DNS-first domain routing requires only
  `[dns].upstream` (and optionally `[dns.fake-ip] enabled = true`), with zero changes to
  `/etc/resolv.conf` or `systemd-resolved`.
- Stopping `daer` detaches eBPF and restores normal host DNS resolution immediately.
- `[dns.request]` `asis` now genuinely delegates to the client's original destination
  resolver on intercepted flows instead of dropping the query silently.
