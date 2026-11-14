---
id: ADR-0053
title: "The process scope is the top level; an election owns its probe"
status: accepted
date: 2026-11-14
scope: [config/model, config/schema, control-plane/routing, control-plane/health, cli/surface, docs]
supersedes: []
superseded_by: []
amends: [ADR-0001, ADR-0046]
---

# 0053. The process scope is the top level; an election owns its probe

- Status: Accepted
- Date: 2026-11-14
- Deciders: daer maintainers
- Related: [ADR-0001](0001-config-format.md), [ADR-0046](0046-resource-election-model.md), [ADR-0006](0006-wiring-ownership.md)

## Context

Schema 4 still carried a `[global]` table. It was a container with no invariant of its
own: socket mark, logging, ingress/egress interfaces, network waiting and TLS defaults do
not interact, and none of them is a property of a node, a group or an election. The table
did not create a boundary; the top level already is the process scope.

It also carried `[global.probe]`. ADR-0046 moved measurement ownership to the election,
but the implementation renamed the old `[global.health-check]` defaults to
`[global.probe]` and left them under `global`. The result was a second source of truth:

- `Election` fields were optional and `resolved_probe(&global.probe)` merged them;
- the scheduler probed each election with the merged result, but a manual election was
  skipped entirely;
- `ProbeSettings` still contained `tolerance`, which is a moving-average selection
  threshold, not a probe parameter;
- a manual election could carry a URL probe that never ran. `daer.66-la.toml` did exactly
  that, with a comment claiming it made `daer status` useful.

The schema was therefore teaching a false mental model: "global probe" sounded like a
daemon-wide health check, when it was only an inheritance table for a strategy.

## Decision

Schema 5 is a clean break.

### 1. The top level is the process scope

`[global]` is removed. Host and daemon keys are written directly:

```toml
schema = 5
log-level = "info"
lan-interface = ["eth1"]
wan-interface = "auto"
disable-waiting-network = false

[tls]
profile = "chrome-current"
fragment = false
```

`[global.tls]` becomes `[tls]`: a coherent default for every outbound TLS leg, with
node-level overrides. There is no second wrapper to rename.

The socket mark is not exposed either. It is daer's internal loop-evasion identity:
`0x64616572` (ASCII `daer`) is applied by a privileged run and compared by the datapath
through `PARAM.socket_mark`. A configured `0` would mean "no mark" to the kernel and break
the loop evasion; any other site value would have to stay in sync with the datapath. The
process option (`--no-datapath`, tests) remains the only override.

### 2. An election owns its probe

`[global.probe]` is removed. Each `[[election]]` declares the probe it needs; absent
fields use `ProbeSettings::default()` (server mode, `HEAD`, the built-in UDP DNS
endpoints, `30s` interval, `5s` timeout). There is no inheritance from a distant table.

`tolerance` moves out of `ProbeSettings` and stays on the election. It is only valid for
`type = "min-moving-avg"`; another type that sets it is rejected.

A manual election is never scheduled for probing. It rejects all probe keys; `daer probe
node` remains the on-demand measurement path. This makes "manual" and "scheduled health
check" impossible to confuse.

### 3. Probe execution stays separate from selection

The health scheduler still runs in the background and records results into the router;
`select()` never performs network I/O. The split is required by the data path, not an
optional abstraction. What schema 5 removes is only the configuration inheritance layer.

## Consequences

- `schema = 5` refuses `[global]`, `[global.tls]`, `[global.probe]` and `so-mark` by name.
- `Config` owns the host/daemon fields directly; the `Global` struct is deleted.
- The socket mark is `DEFAULT_SOCKET_MARK`, not a configuration key; `RouterOptions`
  remains the process-level override for `--no-datapath` and tests.
- `Election::resolved_probe()` takes no defaults argument. `ProbeSettings` no longer has
  `tolerance`.
- `Generation::probe()` and `Daemon::probe()` are deleted; status reads each election's
  resolved probe from the router.
- `daer check` reports `wan-interface`, `tls.profile` and `log-level` instead of
  `global.*`.
- Top-level scalar keys must precede the first table header. A key placed after a table
  is rejected by `deny_unknown_fields`; it is never silently assigned to that table.

## Negative Knowledge

- **Keep `[global]` as a namespace.** Rejected. It has no invariant and no behaviour of
  its own; the top level is already the process scope. Keeping the wrapper only makes it
  easy to put another non-global default under it.
- **Keep `[global.probe]` for DRY.** Rejected. Repeating one URL is cheaper than making an
  election's meaning depend on a table it does not own. A shared probe profile, if ever
  needed, must be an explicit named reference, not an ambient default.
- **Probe inside `select()`.** Rejected. Network I/O on the decision path would let one
  dead candidate stall every new flow.
- **Probe manual elections for status.** Rejected. A manual election has no failover, and
  the daemon must not spend traffic on a measurement that cannot change a decision. Use
  `daer probe node`.
- **A configurable `so-mark`.** Rejected. The datapath and the daemon must agree on one
  nonzero value; the default is self-describing and collision-avoidance is not a documented
  requirement. Exposing it invited `0`, which is the self-capture case.
- **A compatibility shim for schema 4.** Rejected. The old keys have a different scope;
  the whole point is that `[global]` no longer means anything.
