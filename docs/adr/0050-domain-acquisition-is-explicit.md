---
id: ADR-0050
title: "Domain acquisition is an explicit routing policy, not a global sniff knob"
status: accepted
date: 2026-11-13
scope: [config/schema, routing/name-acquisition, dns/fake-ip, control-plane/routing, cli/diagnostics]
supersedes: []
superseded_by: []
---

# 0050. Domain acquisition is an explicit routing policy, not a global sniff knob

- Status: Accepted
- Date: 2026-11-13
- Deciders: daer maintainers
- Related: [ADR-0011](0011-partitioned-kernel-routing.md), [ADR-0012](0012-optional-fake-ip-ebpf.md), [ADR-0051](0051-datagram-relay-is-transport-only.md)

## Context

`domain(...)` is a routing predicate, but a transparent proxy first sees an IP and a
4-tuple. The name can come from three places: a Fake-IP mapping, the DNS snooper, or a
bounded inspection of the first bytes (TLS SNI, HTTP `Host`, QUIC Initial SNI). The first
two require the built-in DNS service; the third does not.

The previous surface exposed the mechanism instead of the decision:

```toml
[global]
sniffing-timeout = "30ms"
auto-sniff-punt = true
```

`auto-sniff-punt = false` and `sniffing-timeout = "0ms"` were two ways to disable the same
thing. The names did not say that payload inspection was happening, which protocol it
covered, or that DNS/Fake-IP always won. A `domain(...)` rule silently enabled the
behavior, so the operator could not tell whether a flow would be held for a peek. Fake-IP
also started an implicit `0.0.0.0:53` listener, making an answer mode look like a
listener switch.

The DNS snooper stored one domain per IP. On a shared CDN address the last answer won,
and the router could not distinguish a unique mapping from an ambiguous one.

## Decision

This decision ratifies **[INV-DOMAIN-01]**: domain acquisition is explicit, DNS-first,
and never inspects payload without an opt-in.

Domain acquisition is an explicit policy with a fixed source order:

```text
Fake-IP
  > a unique DNS-snooper candidate for (client, resolved)
  > payload inspection, only when [routing.sniff] enabled = true
  > address
```

The configuration is split by owner:

```toml
[dns]
bind = "0.0.0.0"
upstream = ["alidns:udp://223.5.5.5:53"]

[dns.fake-ip]
enabled = true

[routing.sniff]
enabled = true
timeout = "30ms"
```

Rules:

1. `[dns]` owns the DNS service. `bind` is the only listener switch; it requires at least
   one upstream. `[dns.fake-ip] enabled = true` requires an explicit `bind` and never
   starts a listener by itself.
2. `[routing.sniff] enabled` is required whenever the lowered policy contains a domain
   predicate, including a domain set contributed by a rule provider. `true` allows a
   bounded payload inspection; `false` forbids it.
3. `timeout` is required with `enabled = true` and forbidden with `enabled = false`. It is
   the total TCP wait budget. UDP inspects only the first datagram and never waits.
4. A DNS mapping that is unique is used without payload inspection. An ambiguous DNS
   candidate set is not guessed: with `enabled = true` it is a reason to sniff; with
   `enabled = false` it is an unnamed flow.
5. `DomainPlan` is built once per generation from the configuration and the lowered match
   sets. TCP, UDP, `daer check` and the reload report read the same plan. A plan that has a
   domain rule and no name source is a load error.
6. The snooper stores a candidate set keyed by `(client_ip, resolved_ip)`, with per-domain
   expiry and a bounded LRU. It records both upstream answers and cache hits, because a
   cached answer is still an observation the client receives.
7. Schema 4 is a clean break. The old keys are not aliases and are not accepted; a
   configuration that uses them fails with a migration hint.

## Negative Knowledge & Discarded Alternatives

- **`[routing.domain-fallback]` + `when-unknown = "sniff" | "address"`**: rejected. The
  section name still promised a domain table without containing DNS, and the second enum
  invited confusion between a policy (`sniff`/`address`) and a runtime result (`None`).
- **`auto-sniff-punt` plus `sniffing-timeout = 0`**: rejected as two ways to express one
  decision. The final model has exactly one disable: `enabled = false`.
- **Implicit Fake-IP listener**: rejected. Binding port 53 is a host-wide side effect and
  must be the operator's explicit decision.
- **Per-rule `sniff = true`**: rejected. Sniffing happens before rule evaluation; without a
  name it is impossible to know which domain rule would match, and a per-rule flag would
  break first-match semantics.
- **Configurable source order**: rejected. Fake-IP is exact and DNS is cheaper than a
  peek; a user-configured order would only make the common case slower or less correct.
- **PTR, Whois or reverse DNS**: rejected for the same reasons as ADR-0011: latency,
  recursion, leakage and no local authority.
- **Keeping the old keys as aliases**: rejected. Permanent aliases preserve the exact
  ambiguity schema 4 removes.

## Consequences

- A configuration with a domain rule must answer one question explicitly, and `daer check`
  prints the effective plan.
- `enabled = false` with no DNS service is a load error instead of a silently dead domain
  rule.
- DNS + Fake-IP remains the preferred deployment; payload inspection is a visible
  fallback, not an invisible default.
- `daer-dns` carries more state per mapping (a candidate set), and the router no longer
  reads DNS state directly.
- The schema break is intentional. The old keys fail by name; there is no second accepted
  spelling and no permanent alias.
