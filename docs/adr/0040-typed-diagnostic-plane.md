---
id: ADR-0040
title: "Observability is a typed diagnostic plane: events, correlation IDs, and incident bundles"
status: accepted
date: 2026-11-11
scope: [architecture/observability, diagnostics, datapath, cli/surface, verification]
supersedes: []
superseded_by: []
amends: [ADR-0007, ADR-0021]
---

# 0040. Observability is a typed diagnostic plane: events, correlation IDs, and incident bundles

- Status: Accepted
- Date: 2026-11-11
- Deciders: daer maintainers
- Related: [ADR-0007](0007-verification.md), [ADR-0015](0015-cli-is-four-verbs.md),
  [ADR-0016](0016-cli-route-and-probe.md), [ADR-0021](0021-kernel-abi-single-source.md),
  [ADR-0041](0041-runtime-status-verb.md)

## Context

The project's diagnostic *discipline* is strong: ADR-0007 makes falsifiers mandatory,
`daer route --why` replays the routing engine on demand, counters have documented
meanings, and `docs/how-to/diagnostics.md` maps symptoms to causes. The runtime
*mechanism* is not.

An audit of the tree found:

1. **145 `tracing` call sites in `src/`** (59 `debug`, 36 `info`, 34 `warn`, 8 `error`,
   8 `trace`) with no event contract. The message string is the de facto schema; the
   documentation and e2e scripts grep for it.
2. **No correlation ID.** `Accepted`, `Datagram`, DNS queries and dials carry addresses or
   a node/authority pair, so `accepted redirected flow` cannot be proven to belong to a
   specific `flow decided` / `dial finished` / `flow closed` sequence.
3. **Client-visible failures are mostly `debug`.** A dial failure, relay failure, DNS
   upstream failure and UDP session failure produce no log at the shipped `info` default;
   the only evidence is a counter read at shutdown.
4. **The kernel event contract is dead.** `bpf_stats_map` has 17 counters and
   `event_ringbuf` has 10 event types, but no Rust code reads either. The record layout and
   discriminants are not in `ebpf/abi.toml`, so a reader would be a second hand-written ABI
   and violate ADR-0021.
5. **Crash forensics are absent.** The release profile uses `panic = "abort"` and
   `strip = "symbols"`; the `FlowGuard` panic counter requires unwinding and cannot observe
   a release panic; there is no panic hook, flight recorder or incident bundle.
6. **Live state is unreachable.** `ServeStats`, `DatagramSnapshot` and DNS `StatsSnapshot`
   are in-process only; `Daemon.datapath` is never populated; `ReloadReport.warnings` is
   always empty. An operator's only live view is `journalctl` plus manual `ip netns` and
   `bpftool` commands.
7. **A credential can reach the log.** `subscription.rs` logs a raw subscription link
   (`link = %url`) for an unsupported node, which can contain a password, UUID or REALITY
   key. `Node::default_name` already redacts this case, but the daemon path bypasses it.
8. **Post-bug review is manual.** The transparent-ingress incident record is excellent, but
   it is one bespoke document; there is no incident schema, no bundle, no link from an
   incident to a regression test, and no CI gate that says so.

Logging statements cannot fix these. A log line is a formatting decision at one call site;
what is needed is a diagnostic *plane* with types, a contract, a consumer for every
producer, and an artifact that survives the process.

## Decision

### 1. A Layer 1 foundation crate, `daer-observe`

Add `crates/daer-observe` to the Layer 1 core foundation. It depends on no other daer
crate. Every layer may depend on it. It owns:

- the event catalog and its generated Rust module;
- neutral correlation IDs (`RunId`, `FlowId`, `QueryId`, `ProbeId`, `RefreshId`);
- severity, remediation, rate-limit and counter metadata;
- the `Diagnostic` error trait and stable `ErrorCode`;
- neutral `DialFailure` / `DialStage` values;
- redaction primitives (`Secret`, `RedactedLink`);
- snapshot primitives.

Only `daer-observe` may depend on `tracing` directly. `daer-cli` may depend on
`tracing-subscriber`; no other crate may depend on either. This is a dependency firewall,
enforced by `cargo metadata` in a test, in the same spirit as ADR-0017's protocol firewall.
A library that wants to log imports `daer_observe` and calls a code-requiring macro.

### 2. The event contract is generated from one declaration

`crates/daer-observe/events.toml` is the single source for the event catalog. It declares,
for every event:

```toml
[[events]]
name = "FlowDialFailed"
code = "flow.dial_failed"
level = "warn"
message = "flow dial failed"
fields = ["flow_id", "generation", "destination", "group", "node", "stage", "error_code", "elapsed_ms"]
counter = "flows.dial_failed"
rate = "flow.dial_failed"
remediation = "Check the selected node and the dial stage; run `daer probe node <node>`."
```

`cargo xtask events` generates `crates/daer-observe/src/generated.rs` and
`docs/reference/events.md`; `cargo xtask events --check` fails on drift, on a duplicate
code, on a missing remediation for a `warn`/`error` event, on a missing counter or rate
group, and on a raw `tracing` call outside the two permitted crates.

The code is the contract. Message text is presentation and may change. Every event emitted
from a library goes through `daer_observe::{trace,debug,info,warn,error}!` with an
`EventCode`; raw `tracing` macros are not permitted outside `daer-observe` and the CLI's
subscriber module.

### 3. Correlation is carried by types, not by log convention

- `Accepted` gains a `FlowId` and the generation it arrived under.
- `Datagram` gains a `FlowId` for its session and the generation.
- `Resolver::resolve` receives a `QueryContext` containing a `QueryId` and peer.
- `ObservedDialer` receives the flow context; `DialId` includes the `FlowId` and attempt.
- `ProbeResult` carries a `ProbeId`, sweep number and consecutive-failure count.
- Provider refreshes carry a `RefreshId`.

A flow's accepted, decided, dial-finished, dial-failed and closed events all carry the same
`flow_id` and `generation`. The rule is: **if two events about one flow cannot be joined by
an ID, the instrumentation is incomplete.** A test asserts the join for a real accept/relay
path and for a DNS query.

### 4. Severity is a contract, not a local choice

| Level | Meaning | Examples |
| --- | --- | --- |
| `error` | A promised contract is broken; the process cannot continue or a load-time invariant failed | startup configuration rejected, datapath attach failed, first-generation build failed |
| `warn` | A client-visible failure or a degraded capability while the service continues | `flow.dial_failed`, `dns.upstream_failed`, UDP unavailable, provider refresh failed, IPv6 ingress unavailable |
| `info` | Lifecycle and state transitions | ready, reload, policy tier, provider updated, shutdown |
| `debug` | Per-flow success and decision detail | accepted, decided, closed, cache hit, health probe |
| `trace` | Per-query/packet internals, opt-in | cache internals, `asis`, per-datagram detail |

No client-visible failure may be `debug`-only. Every `warn`/`error` event has a counter and
a rate-limit group; the counter is exact, the log is the sampled view. A `debug` event may be
sampled when the per-flow volume would otherwise flood the journal.

### 5. The daemon owns a flight recorder and incident artifacts

The CLI installs layered sinks: human text, a JSONL flight recorder (`/run/daer/events.jsonl`,
truncated per run) and an incident writer. The recorder keeps `info` and above always, and
`debug` when the operator enables it. A bundle copies the last 4 MiB of the stream, so a crash
keeps the run-up to the failure without a second per-packet buffer; the kernel ring remains
the bounded, rate-limited channel for datapath anomalies.

A trigger writes a self-contained, redacted bundle:

- panic hook (runs before `panic = "abort"`);
- `SIGUSR1`;
- explicit `daer status --bundle`.

An automatic error-burst trigger is deliberately not in this cut: a threshold that fires on a
transient upstream failure would create more bundles than evidence. The exact event counters
make a future trigger measurable rather than guessed.

The bundle contains `manifest.json`, `snapshot.json`, `events.jsonl` and `README.txt`. It
never contains a configuration file: a best-effort TOML redactor is not a typed policy, and a
heuristic that misses one key is worse than an operator attaching the config deliberately.
The manifest records the config path and a hash, not its content. Redaction is a typed policy
(`Secret`, `RedactedLink`), not a call-site convention. Canary tests inject a known
password/UUID/key and fail if any bundle file contains it.

> Amended by [ADR-0042](0042-tcx-only-linux-6-6.md): the daemon writes incident bundles
> directly to `/var/lib/daer/incidents`; the tmpfs fallback and the `daer-cleanup` copier are
> deleted. The paragraph below is retained as the history of the original decision.

`daer-cleanup` preserves the last bundle after a crash; `/run/daer` is tmpfs, so the bundle
must be copied to `StateDirectory=daer` before the process tree is reaped.

### 6. Kernel telemetry has a consumer, and its ABI has one source

Extend `ebpf/abi.toml` with the `daer_event` struct and the `bpf_stats_key` /
`daer_event_type` discriminants. `cargo xtask abi` generates both sides, as ADR-0021
requires. Add `daer-ebpf::telemetry`:

- read all 17 counters from `bpf_stats_map` on a timer and emit deltas;
- decode `event_ringbuf` records and emit typed events;
- pair the two: the ring is rate-limited per key, so volume comes from the counters, never
  from the event count.

Every counter key and event type must have a consumer; an unconsumed key fails a test. The
`docs/how-to/deployment.md` caveat "the event ring is not consumed" is deleted, not
softened.

### 7. Errors are diagnosable across layer boundaries

Add `Diagnostic` and stable `ErrorCode` to `daer-observe`. `RelayError::Dial` no longer
carries a `String`: it carries a neutral `DialFailure { stage, code, detail, elapsed,
timeout }`. `daer-control` maps `OutboundError` into that value; `daer-relay` still does not
depend on routing or outbound vocabulary (INV-RELAY-01). CLI errors print as
`error[<code>]: …` with a remediation line. Exit statuses remain the existing contract for
`route`; new diagnostics may distinguish load, runtime and policy-drop failures.

### 8. Post-bug review is a CI-enforced loop

Incident records move to `docs/dev/incidents/` with a schema:

- id, title, status, date, affected versions;
- a detection **signal** (event code and/or counter);
- the root cause and the discarded alternatives;
- at least one regression test and its falsifier;
- event codes/fields added by the fix.

`cargo xtask incident --check` validates the frontmatter, resolves every event code against
the catalog, verifies every named test exists and is not an unrun `#[ignore]`, and requires
a signal and a falsifier. The PR template asks for the event code, the falsifier and the
incident link. `cargo xtask ci` runs both `events --check` and `incident --check`.

### 9. New system invariants

- **[INV-EVENT-01] Typed event contract.** Every operational outcome is an event with a
  stable code, a severity, required fields, and a counter/rate policy where it can fail a
  client. Raw `tracing` outside `daer-observe`/`daer-cli` is a build failure.
- **[INV-FLOW-01] Causal correlation.** Every accepted flow/datagram and DNS query has an
  ID created at the boundary and carried through every decision, dial, relay and DNS event.
- **[INV-FORENSIC-01] Self-contained, redacted incident artifacts.** A panic, `SIGUSR1` or
  explicit `daer status --bundle` produces a bundle that survives the process and contains no
  credential; every incident record names a signal and a falsifier.

The existing `[INV-ABI-01]` is extended: it now covers the datapath event record and the
counter/event discriminants, not only map/program names and routing structs.

## Negative Knowledge and Discarded Alternatives

- **"Add more debug logs."** Rejected. The failure mode is not missing text; it is missing
  correlation, missing production capture, and dead kernel hooks. More `debug!` calls at the
  same level would remain invisible at the default configuration.
- **A generic metrics/OpenTelemetry stack.** Rejected. It adds a large dependency, a global
  exporter, and a network listener with an auth story the project does not need. The status
  snapshot and JSON event stream are sufficient operators' surfaces; an external collector
  can consume `daer status --json` if one is ever wanted.
- **Per-packet or per-flow logging by default.** Rejected. The kernel ring already rate-limits
  anomalies; userspace must not pay a formatting allocation per packet. Debug is opt-in, and
  the JSONL recorder tail is bounded when it is copied into a bundle.
- **A second logger in libraries.** Rejected. Only the host binary owns process-wide state;
  a library that installs a subscriber takes that decision away from the program that links
  it (the reason `init_logging` already lives in `daer-cli`).
- **Stringly event codes or optional codes.** Rejected. A code that is not in the catalog
  cannot be documented, filtered, counted or linked to a regression test.
- **A hand-written decoder for `daer_event`.** Rejected. It would be a second copy of the
  kernel layout and violate ADR-0021. The layout goes into `abi.toml`.
- **Copying the configuration into a bundle with a best-effort redactor.** Rejected. A key
  named `token`, `secret`, or a subscription URL with an unrecognised scheme would leak. The
  bundle omits the config and records its path and hash; the operator attaches it deliberately.
- **Keeping per-flow failures at `debug` and telling operators to use `RUST_LOG=debug`.**
  Rejected. A production incident cannot require reproducing the failure under a changed
  configuration; the warn event and counter must exist at the default.
- **A wiki-only incident template.** Rejected. A template without a check is an aspiration;
  `xtask incident --check` is the mechanism.

## Consequences

- The migration touches every logging call site and several core types (`Accepted`,
  `Datagram`, DNS resolver context, `RelayError::Dial`). This is intentional; the event
  plane is not an add-on. The break is clean: there is no compatibility alias for
  `RelayError::Dial(String)` and no raw-`tracing` escape hatch.
- `tracing` becomes an implementation detail of `daer-observe`; crates that only logged
  lose a direct dependency. `tracing-subscriber` remains a CLI dependency.
- The daemon gains an always-on JSONL recorder and a periodic counter reader. The cost is
  bounded and measured; per-flow debug remains opt-in.
- The shipped binary stays stripped and `panic = "abort"`. A separate `forensic` Cargo profile
  keeps line tables and unwinding for reproducing a failure; a bundle from a release build
  still names the flow and event sequence, and the forensic build explains the frame. A crash
  bundle without either is not a root-cause artifact.
- Incident records become slightly more expensive to write and much cheaper to use. A record
  that cannot name a signal or a falsifier is rejected by CI.
- `docs/how-to/diagnostics.md` becomes an index into event codes and the incident process,
  not a list of message strings that can rot.
