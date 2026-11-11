---
id: ADR-0041
title: "The CLI gains a read-only runtime inspector: daer status"
status: accepted
date: 2026-11-11
scope: [cli/surface, architecture/diagnostics, observability]
supersedes: []
superseded_by: []
amends: [ADR-0015, ADR-0016]
---

# 0041. The CLI gains a read-only runtime inspector: `daer status`

- Status: Accepted
- Date: 2026-11-11
- Deciders: daer maintainers
- Related: [ADR-0015](0015-cli-is-four-verbs.md), [ADR-0016](0016-cli-route-and-probe.md),
  [ADR-0040](0040-typed-diagnostic-plane.md)

## Context

ADR-0015 and ADR-0016 define the CLI as a runtime and diagnostic suite with six verbs:
`run`, `check`, `route`, `probe`, `schema`, `version`. Each answers a question an operator
has **before** the daemon is running, or by actively probing the network.

None of them answers the first question during an incident:

> What does the running daemon believe right now?

Today the answer requires `journalctl`, `ip netns` through `/proc/<pid>/root/run/netns`,
`bpftool`, `ss`, and knowledge of which counter lives in which subsystem. `Daemon::stats()`,
`DatagramSnapshot`, DNS `StatsSnapshot`, `Generation::policy_hash()` and
`Supervisor::in_flight()` exist but are in-process only. `Daemon.datapath` is never
populated, so even the daemon's own status field cannot answer whether the datapath is
attached.

Adding the answer as another flag on `check` would conflate two questions with different
contracts. `check` is the **pre-bind gate**: it loads and validates, binds nothing, mutates
nothing, and exits 0/non-zero as a deployment contract. A live query is the opposite: it
requires a running daemon, reads process state, and must not be mistaken for a validation
gate.

## Decision

Add exactly one verb:

```text
daer status [--json] [--flow <ID>] [--bundle <DIR>]
```

1. **`status` is read-only.** It never writes configuration, kernel state, sysctls, routes or
   sockets other than its own client connection. It cannot start, stop or reload the daemon.
2. **The daemon owns the snapshot.** A `SnapshotSource` aggregate in `daer-control` collects
   build/version, `run_id`, current and previous generation, policy hash, datapath tier and
   deferral reasons, listener/topology facts, `ServeStats`, in-flight flows, datagram
   counters, DNS counters and cache occupancy, health state, provider schedule, and the
   userspace mirror of the datapath counters.
3. **Transport is a Unix socket, with a file fallback.**
   - `/run/daer/control.sock` is a read-only, root-owned (`0600`) Unix stream socket serving
     the `snapshot` request. `--flow` reads the JSONL event stream and `--bundle` writes the
     bundle from the client side, so neither needs a second daemon endpoint.
   - `/run/daer/state.json` is the last snapshot, written atomically. It exists so a
     post-crash bundle and a `daer status` invocation can still answer when the socket is
     gone.
   No TCP listener, no HTTP server, no authentication layer: a network endpoint would be a
   second service and a new attack surface.
4. **`--json` is the automation contract.** The human output is a rendering of the same
   snapshot; every field in the human output exists in JSON. An external collector consumes
   `daer status --json`; the daemon embeds no exporter.
5. **`--flow <ID>` reads one record from the flight recorder** and prints every observed
   event for that flow/session, in order. The bundle does not copy the configuration, so the
   command does not invent a replay invocation; if the same generation is still serving, the
   operator can run `daer route` against the live config. If it is not, the output says the
   record is historical rather than pretending the current policy made the decision.
6. **`--bundle <DIR>` writes an incident bundle from the client** (ADR-0040): the last
   snapshot, the event-stream tail when readable, and an explicit manifest naming its source.
   The daemon's own panic/`SIGUSR1` bundle is the richer artifact; the client bundle is the
   fallback when the daemon is already gone.

`[INV-CLI-01]` is amended from six verbs to seven. The boundary is unchanged: no
build-time producer, no second service, no standalone DNS server. `status` is an inspector,
not a producer.

## Negative Knowledge and Discarded Alternatives

- **`daer check --live`.** Rejected. `check` is the pre-bind gate with an exit-status
  contract; adding a live mode would make the same command mean "will this run" or "what is
  running" depending on a flag. The two have different failure modes and different callers.
- **An HTTP metrics endpoint.** Rejected. It adds a network listener, a bind configuration,
  an authentication question, and a dependency surface. A root-owned Unix socket is the
  smallest correct transport for a host-local daemon.
- **A separate `daer-status` binary.** Rejected. The CLI is the public surface; a second
  binary would be a second install target, a second version skew, and a second place to
  forget a field.
- **Read `/proc/<pid>` from outside.** Rejected. It cannot see in-process counters, the
  routing generation, the packet decision for a flow, or the DNS cache; parsing another
  process's memory is not an interface.
- **Only a state file, no socket.** Rejected as the primary path. A file is a snapshot of a
  past moment; `--flow` and `--bundle` need the live process. The file remains the fallback,
  not the contract.
- **Expose the raw `Debug` of internal structs.** Rejected. The snapshot is a typed,
  documented schema; an incident bundle is a compatibility promise.

## Consequences

- The CLI surface grows to seven verbs. `--help`, `docs/reference/cli.md`, and the removed-
  verb migration tests are updated in the same commit.
- `daer run` creates `/run/daer/control.sock` and a periodic `state.json`. The systemd unit
  already creates `RuntimeDirectory=daer`; no new privilege is required. The socket is
  `0600` and owned by the daemon user (root in the shipped unit).
- The snapshot schema is versioned (`schema = 1`) and checked by a test. A field may be
  added, but a field cannot silently change meaning; that is a schema-version change.
- `daer status` is a read-only client, so it can be run by an operator without the ability
  to mutate the daemon. A caller that only has the state file gets a clear "socket
  unavailable; state is from <time>" message rather than a fabricated live answer.
- The old diagnostic recipe in `docs/how-to/diagnostics.md` remains as the deep-dive path,
  but `daer status` is the first command in the incident runbook.
