---
id: ADR-0006
title: "A running daemon owns its whole data path: adapters that are not wired are deleted, not documented"
status: accepted
date: 2026-10-30
scope: [control-plane, outbound/selection, config, cli, verification]
supersedes: []
---

# 0006. A running daemon owns its whole data path: adapters that are not wired are deleted, not documented

- Status: Accepted
- Date: 2026-10-30
- Deciders: Ming Li
- Related: [ADR-0002](0002-netune-boundary.md), [ADR-0005](0005-kernel-policy-encoding.md)

---

## Context and Problem Statement

The tree contains complete, tested, unwired subsystems. Each one was built to a high
standard and then never called by `daer run`:

| Subsystem | Where it works | Where it is called from in production |
| --- | --- | --- |
| node health scheduling (`health::Scheduler`, `Scheduler::run`) | `health.rs` unit tests | **nowhere** — `spawn_health_scheduler` is re-exported and never used |
| datagram relay (`serve_datagrams`, `DatagramService`) | `datagram.rs` tests, `serve_with_datagrams` tests | **nowhere** — `Daemon::serve` only runs the TCP accept loop |
| subscription resolution (`resolve_subscriptions`) | `config validate`, `route nodes`, `config validate` CLI paths | **nowhere in `run`** — startup and reload both call `toml_config::load` directly |
| `group.filters` subscription tag | filter compiler | **nowhere** — `decide.rs` passes `""` as the subscription tag |
| kernel policy (ADR-0005) | — | **nowhere** (that ADR fixes it) |

The consequence is not "a feature is missing". It is that the default configuration
in `daer.example.toml` — nodes plus `policy = "min-moving-avg"` — produces a group
with **no selectable node**, because a latency policy's alive set is empty until a
probe records something, and no probe ever runs:

```text
$ daer route explain 10.0.0.2:1234 1.1.1.1:443 -c config.toml
  verdict    : undeliverable, group "proxy" has no selectable node
```

Meanwhile `daer route nodes` happily lists the node, so the two diagnostics
disagree. A test suite that is green about each part while the composition does
nothing is the failure mode this ADR is about.

## Decision

### 1. Wiring is part of the feature

A subsystem is "done" only when a path from `daer run` reaches it. The test for a
feature is not its unit tests but an end-to-end test that fails when the wiring is
removed. Concretely, `daer run` gains, before it serves:

- **health scheduling**, started with the generation's own interval, shut down with
  the daemon, and restarted on reload (the scheduler holds the *current* router, so
  a reload must hand it the new one, not leave it probing the old one);
- **the datagram relay**, bound on the same transparent port, serving UDP flows
  through the same `Router`;
- **subscription resolution**, in both startup and reload, through one function so
  the two cannot drift.

### 2. One configuration loader for the data path

`daer run` and `daer config validate` must load the same configuration, or the
diagnostic answers about a node pool that does not exist. Both go through
`load_resolved` (parse → resolve subscriptions → report warnings), which moves out
of `daer-cli/src/main.rs` into `daer-control` so `run.rs` and `main.rs` share one
implementation rather than two.

### 3. A dead configuration key is an error, not a no-op

Every key the schema accepts must either take effect or **not exist**. The audit
found eighteen keys that are parsed, documented, and silently ignored —
`tproxy-port-protect`, `dial-mode`, `bpf-conn-state-map-size`, `mptcp`,
`bandwidth-max-tx/rx`, `pprof-port`, `disable-thp`, `disable-waiting-network`,
`auto-sniff-punt`, `auto-config-kernel-parameter`, `udp-hop-interval`,
`fallback-resolver`, `allow-insecure`, `global.tls.profile`, `health-check.udp-dns`,
`group.health-check.tcp-url`, `group.health-check.udp-dns`.

This ADR resolves them in three ways, and every key gets exactly one:

1. **Implemented**, when the daemon can honour it without a new subsystem;
2. **Removed from the schema**, when it describes a feature this build does not
   have. A key that cannot be honoured must fail to parse: an operator who sets
   `mptcp = true` and gets no MPTCP has been lied to, and the load-time error is
   the only honest answer.
3. **Kept and documented as a gap**, only where removing it would break existing
   configurations *and* the behavioural difference is reported at startup.

Nothing stays in the "accepted and ignored" state.

The same rule applies to defaults: `daer.example.toml`'s header claims "the defaults
below are the ones daer actually uses". Every default is asserted against
`Config::default()` by a test, so a doc default that drifts fails CI.

### 4. The node pool is a set of identities, and a node without one is inert

`Property::from_link` derives a node's identity from its URL. Two consequences:

- the **subscription tag** is a property of where a node came from, so it is
  passed down from the resolver, not hardcoded to `""`;
- a node whose protocol this build cannot speak is **listed but not selectable**,
  which is already true, and `route nodes` says so by name.

## Consequences

- `min-moving-avg` and `random` start working, because probes exist. Until the first
  probe completes, a latency policy group must be **selectable anyway**: refusing
  every flow for the first interval would make the default configuration broken for
  thirty seconds after every start. The alive set therefore admits every member
  before its first measurement (`STARTING_SORTING_LATENCY` already models this) and
  only excludes a node once a probe has proved it dead.
- Subscription nodes become selectable, so a configuration whose only nodes come
  from a subscription stops being silently empty.
- The configuration surface shrinks. That is a breaking change for anyone who set a
  removed key; `daer config validate` names it, which is the point.
- `docs/deployment.md` stops promising a `tier` the daemon does not implement, and
  gains a section on which tier the current configuration is in.
- The datagram relay being wired means UDP flows are *proxied* only over nodes that
  have a datagram transport. A REALITY node has none, so a UDP flow to it must be
  **blocked with a diagnostic**, never silently sent direct. Silence here is a
  leak: the client believes UDP is tunnelled when it is not.
