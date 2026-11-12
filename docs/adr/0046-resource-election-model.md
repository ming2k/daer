---
id: ADR-0046
title: "Node and group are resources; election is the routing target"
status: accepted
date: 2026-11-12
scope: [config/model, control-plane/routing, outbound/selection, cli/surface, architecture/boundary]
supersedes: []
superseded_by: []
amends: [ADR-0006, ADR-0015]
---

# 0046. Node and group are resources; election is the routing target

- Status: Accepted
- Date: 2026-11-12
- Deciders: daer maintainers
- Related: [ADR-0006](0006-wiring-ownership.md), [ADR-0015](0015-cli-is-four-verbs.md),
  [ADR-0041](0041-runtime-status-verb.md), [ADR-0047](0047-runtime-election-control.md)

## Context

The schema carried one object that did three jobs. A `[[group]]` was a candidate set
(`filters`), a selection rule (`policy`), and a health/probe owner (`health-check`). Routing
rules pointed at the group. A single node that should be an explicit egress therefore had to
be expressed as a one-member group, and the group name became both a resource-pool name and a
routing target.

That conflation produced real failures:

- `fixed(n)` mixed "candidate membership" with "selection" and made an index into the filtered
  list a routing decision.
- a probe URL lived on the group, so changing the selection rule changed the meaning of the
  measurement; a URL test could not be said to belong to the strategy that used it.
- a rule could name a group that was empty or whose only node was unselectable, and the
  diagnostic had to explain a resource pool as if it were an outbound.
- there was no first-class place to put "manual node", "health-tested best" and "fallback
  order": they were all group policies, not election strategies.

## Decision

Separate resources from election. The configuration schema becomes **version 2**; version 1
is rejected, with no compatibility shim.

```text
Node    = atomic resource (server, protocol, credentials, detour)
Group   = candidate set; membership only
Election = routing target + selection rule + optional probe
Route   = flow -> election
```

### 1. `[[node]]` is unchanged as a resource

A node may be declared, working or not. A node outside every group is still a resource; it is
simply not reachable by an election that names a group. A node can be an election input
directly, as a singleton candidate set.

### 2. `[[group]]` is pure membership

```toml
[[group]]
name = "proxy-pool"
filters = ["sub(my-sub) && !name(keyword: 'Expire')"]
```

A group has no `policy` and no `health-check`. It owns no routing target and no probe. A
group whose filters match no node is still a valid resource pool; an election that consumes it
is reported with a warning and elects no node, so `daer check` and the daemon agree that the
configuration loads but the affected flows will fail.

### 3. `[[election]]` is the only named routing target

```toml
[[election]]
name = "proxy"
group = "proxy-pool"           # or node = "hk-01"
type = "min-moving-avg"        # manual | random | min | min-avg10 | min-moving-avg
mode = "url"                   # or "server"
url = "https://www.gstatic.com/generate_204"
```

- Exactly one of `group` or `node` is the input.
- The output is `Option<Node>`: at most one elected node.
- `manual` requires a node input; a manual choice over a group is a **runtime** election
  override, not a configuration policy.
- Probe settings belong to the election. `[global.probe]` supplies defaults; an election may
  override `mode`, `url`, `method`, `udp-dns`, `interval`, `timeout`, and `tolerance`.
- `mode = "url"` establishes the proxy session and requests the URL **through the node**.
  `mode = "server"` is a cheaper server-port liveness probe. The mode is explicit; a list's
  first entry no longer silently changes the probe's meaning.
- Election names are unique, cannot shadow a built-in outbound, and cannot collide with a
  group name. Group and election are different namespaces by design; keeping the names
  distinct is what prevents a reader from mistaking a resource pool for an outbound.

### 4. Routing targets elections

Rules and `fallback` name elections, never groups. A rule that names a group fails at
generation build with a message that names the missing election. The kernel datapath is
unchanged: it still maps an outbound name to an id; the userspace router resolves that name to
an election and elects one node.

### 5. Runtime override is not configuration

`daer elect <election> <node>` pins an election to one of its candidates;
`daer elect <election> --reset` removes the pin. The override is persistent runtime state
(`/var/lib/daer/elections.json`), not a second configuration and not a rewritten policy
definition. ADR-0047 defines its transport and authorization.

## Consequences

- `schema = 2` is a clean break. `group.policy`, `group.health-check`, `[global.health-check]`,
  `tcp-url`, `tcp-method`, `fixed(n)`, and rules targeting groups are rejected by the schema.
- A group and an election cannot share a name; configurations must use a pool name such as
  `proxy-pool` and an election name such as `proxy`.
- A single node is expressed as `node = "…"` on an election, not as a dynamic group. Runtime
  code never creates a group.
- `daer check`, `daer route`, the daemon, and the health scheduler all compile the same
  election model through `daer_control::load_resolved` and `Router::new`; there is no second
  selection path.
- A URL test is measured through the node, so the test proves the proxy session works. A
  server-mode probe remains available for cheap liveness and does not pretend to be a URL
  test.
- The health scheduler probes each election's candidates with that election's probe settings.
  A manual election is not probed by the scheduler; `daer probe node` remains the on-demand
  path.

## Negative Knowledge

- **Group as routing target.** Rejected. It makes a resource pool carry policy, and it makes
  a rule that should be explainable as "which election?" answer "which pool?" instead.
- **URL on the group.** Rejected. Measurement belongs to the strategy that consumes it; a
  group has no strategy.
- **Dynamic singleton groups for `pin`.** Rejected. A runtime group is not in
  `daer check`, not explainable by `daer route`, and not a routing target. A runtime
  election override reaches the same goal without hidden network objects.
- **`fixed(index)`.** Rejected. An index into a filtered list is not a stable node identity;
  a manual election names a node.
- **A compatibility shim for schema 1.** Rejected. The old keys have different meanings; a
  shim would preserve the conflation this ADR removes.
