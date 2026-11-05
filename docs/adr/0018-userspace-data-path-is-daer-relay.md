---
id: ADR-0018
title: "The userspace data path is a crate of its own, called daer-relay"
status: accepted
date: 2026-10-31
scope: [architecture/boundary, data-path, relay, crate-topology]
supersedes: []
---

# 0018. The userspace data path is a crate of its own, called daer-relay

- Status: Accepted
- Date: 2026-10-31
- Related: [ADR-0002](0002-netune-boundary.md), [ADR-0017](0017-proxy-protocols-crate-boundary.md)

---

## Context and Problem Statement

After ADR-0017 moved the proxy protocols out of `daer-outbound` and back into their own
crate, `daer-outbound` was left holding nothing but outbound governance: groups, alive
selection, measured latency, probes, filters, subscriptions. That raised the next question,
and it was the right one: **where does that governance live, and what happens to the crate
that used to hold it next to the data path?**

`daer-control` was carrying two responsibilities that change for unrelated reasons:

| Responsibility | Changes when… | Typical failure |
| --- | --- | --- |
| Transparent accept, splice, UDP session table, flow supervision | a socket option or a session invariant is wrong | a proxy that hangs after half-close, a reply delivered to the wrong peer |
| Routing decisions, node selection, health scheduling, reload | a routing concept, a policy or a config key is added | a flow routed by stale rules, a group that never selects |

The name made the ambiguity worse. "Control plane" is a term of art for the *non-forwarding*
half of a system, yet this crate also owned the userspace forwarding: `IP_TRANSPARENT`
accept, `copy_bidirectional`, the UDP session table. Meanwhile it spelled the ingress half
`inbound` in one file and `ingress_udp` in another, mixing the packet-direction vocabulary
(`ingress`/`egress`) with the proxy vocabulary (`inbound`/`outbound`) inside a single crate.

## Decision

**1. The userspace data path becomes `crates/daer-relay`.**

It owns exactly what changes only when the data path itself is wrong:

- `inbound::tcp` — the transparent listener, the original-destination recovery, the
  self-connect rule, `Accepted`/`FlowFacts`.
- `inbound::udp` — the transparent datagram socket, per-datagram original destination via
  `IP_RECVORIGDSTADDR`.
- `relay::stream` — `splice`, half-close and byte accounting.
- `relay::datagram` — the session table, the reply direction, idle reaping, the ceiling.
- `serve` — the accept loop, `Ingress`/`Decide`, resource-exhaustion backoff, `Metrics`.
- `supervise` — flow ownership, so a reload cannot drop a connection.

**2. `daer-control` keeps the decision, and only the decision.**

Routing program compilation, node groups and their measured state, health scheduling,
subscription and rule-provider resolution, sniffing, generations and reload. It implements
`daer_relay::Decide` and `daer_relay::DatagramRouter`; it does not accept, splice or reap.

**3. The seam is two traits, and they name no routing vocabulary.**

`Decide::decide(&Accepted) -> Upstream` and
`DatagramRouter::open_datagram(FlowFacts, Option<&str>) -> DatagramLeg`. Neither mentions a
`Verdict`, a `Router`, a group or a policy: the relay needs a name, a dial target and a
connector, and a `Verdict` parameter would drag the control plane's rule vocabulary into
the stable data path, making every new selection concept a change there.

The datagram trait returns the dial target **together with** the connector for the same
reason one level down: asking the decider twice (`dial_target` then `open_datagram`) let a
reload land between the two calls, so a flow could be dialed to a target the rule that
opened its leg had never chosen.

**4. One vocabulary, everywhere.**

The ingress half is `inbound`, in both files and in the public names (`inbound::tcp`,
`inbound::udp`, `TransparentListener`, `TransparentDatagramListener`). `ingress` survives
only where it names the *act* of accepting (`Ingress`, `serve_ingress`), never as a module
name competing with `inbound`.

**5. The error types separate, and only one crosses the boundary.**

`daer_relay::RelayError` and `Reject` describe the data path (a socket, an accept, a
rejected flow, a failed relay). A dial failure crossing *into* the data path is a `String`
(`DialFailure`): the control plane owns the reason, and copying its enum here would make
every new selection error a change to the stable half.

## Consequences

- The dependency graph is one-directional and each crate's reason to change is distinct:

  ```text
  daer-cli
      │
      ▼
  daer-control  (decides: routing, groups, health, reload)
      │
      ├──────────────▶ daer-relay  (carries: accept, splice, sessions)
      │                     │
      ▼                     ▼
  daer-outbound         netune, daer-sniff
      │
      ▼
  daer-proxy-protocols
      │
      ▼
  netune
  ```

- `daer-relay` does not depend on `daer-config`, `daer-outbound`, `daer-routing` or
  `daer-proxy-protocols`. Its tests need neither a configuration nor a protocol: the
  doubles live in a `#[cfg(test)]` module, so the accept loop's failure modes are asserted
  without inventing a routing file.
- A protocol or policy change no longer recompiles the accept loop, and a data-path change
  no longer re-runs the routing suite.
- `daer-outbound` keeps its name. "Outbound" is the domain's word for the pool of egress
  nodes and the policy over it — `dae`, `sing-box`, `Clash` and `Xray` all use it that way —
  and the reason the name felt wrong was that it had also absorbed the protocols, which
  ADR-0017 fixed. Renaming it as well would have been churn without a boundary to show for
  it.
