---
id: ADR-0051
title: "The datagram relay is transport-only; domain inspection belongs to the control plane"
status: accepted
date: 2026-11-13
scope: [architecture/boundary, data-path/relay, control-plane/routing, dns, sniff]
supersedes: []
superseded_by: []
---

# 0051. The datagram relay is transport-only; domain inspection belongs to the control plane

- Status: Accepted
- Date: 2026-11-13
- Deciders: daer maintainers
- Related: [ADR-0018](0018-userspace-data-path-is-daer-relay.md), [ADR-0050](0050-domain-acquisition-is-explicit.md), [ADR-0011](0011-partitioned-kernel-routing.md)

## Context

ADR-0018 made `daer-relay` the userspace data path and `daer-control` the decision plane.
The TCP path already followed that boundary: the relay accepted a stream and handed the
flow to the router, which acquired the domain.

The UDP path did not. `peer_for` called `router.known_domain(...)`, then imported
`daer-sniff` directly and parsed the first payload before calling `open_datagram(facts,
domain)`. That produced three problems:

1. the transport knew about name acquisition and linked `daer-sniff`;
2. TCP and UDP could drift in their source order or ambiguity handling;
3. the `DatagramRouter` seam carried a `domain: Option<&str>`, so a routing concept leaked
   into the component that forwards bytes.

The datagram relay must remain unable to decide anything ([INV-RELAY-01]).

## Decision

The datagram seam is the flow facts plus the first payload:

```rust
pub trait DatagramRouter: Send + Sync + std::fmt::Debug {
    fn open_datagram<'a>(
        &'a self,
        facts: FlowFacts,
        initial_payload: &'a [u8],
    ) -> OpenDatagram<'a>;
}
```

- `known_domain` is removed from the trait.
- `daer-relay` does not depend on `daer-sniff`; the dependency firewall names it as
  forbidden.
- `daer-control::domain::DomainResolver` owns Fake-IP, DNS snooping, ambiguity and the
  bounded first-datagram parse.
- `Router::open_datagram_with_payload` resolves the domain, logs its source, evaluates the
  routing program, selects the outbound and returns one `DatagramLeg`.
- The relay never learns where the name came from. It forwards bytes and keeps its session
  table.

## Negative Knowledge & Discarded Alternatives

- **Keeping `known_domain` on the relay trait**: rejected. It is a second name-acquisition
  path, and it makes UDP policy depend on which crate happens to import the parser.
- **Passing `domain: Option<&str>` into the relay**: rejected. The transport would still
  participate in the decision and could disagree with the TCP path.
- **Letting the relay sniff but not route**: rejected. Sniffing is policy: it decides
  whether a flow may be held and which source wins. Splitting the parse from the policy is
  how the two paths drift.
- **A separate UDP-only timeout**: rejected. A UDP datagram has already arrived; waiting
  would change datagram semantics. The first payload is parsed immediately or not at all.

## Consequences

- `daer-relay` becomes smaller and links no domain parser.
- The architecture test `the_userspace_data_path_links_no_decider` now also rejects
  `daer-sniff` transitively.
- A slow or failing DNS lookup or sniff cannot be implemented inside the relay's session
  table without changing this boundary explicitly.
- The TCP and UDP paths share one `DomainPlan`, one source order and one ambiguity policy.
