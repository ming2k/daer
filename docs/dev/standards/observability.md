# Observability & Diagnostic Plane

This document defines how `daer` produces, correlates, captures, and reviews diagnostic
content. It is the engineering standard behind [ADR-0040](../../adr/0040-typed-diagnostic-plane.md)
and [ADR-0041](../../adr/0041-runtime-status-verb.md).

---

## 1. The Principle

Observability is a **typed interface**, not a collection of formatted strings.

A subsystem does not "log a message." It **emits an event** with:

- a stable code from the catalog;
- a severity declared by the contract;
- the fields a future investigator needs;
- a counter and, for failures, a rate-limit group;
- a remediation for `warn`/`error` events.

The catalog is the single source. The message is presentation. A code change that silently
removes a field or downgrades a severity is a diagnostic regression, not a cosmetic edit.

---

## 2. Layering

`crates/daer-observe` is a **Layer 1 foundation** crate. It depends on no other daer crate.
Every layer depends on it.

| Layer | Responsibility |
| --- | --- |
| `daer-observe` | Event catalog, IDs, severity, `Diagnostic`, redaction, snapshot primitives |
| Domain/control crates | Emit events with IDs and facts; never install a subscriber |
| `daer-cli` | Owns the process-wide subscriber, JSONL recorder, incident writer, panic hook, status socket |

Only `daer-observe` may depend on `tracing` directly. Only `daer-cli` may depend on
`tracing-subscriber`. `crates/daer-cli/tests/surface.rs` asserts the dependency firewall.
A library that calls `tracing::*` directly fails the build.

---

## 3. The Event Catalog

`crates/daer-observe/events.toml` declares every event:

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

Rules:

1. **Unique code.** Dotted lower-case namespace (`flow.*`, `dns.*`, `datapath.*`, `daemon.*`).
2. **Unique name.** The generated Rust variant.
3. **Level is declared, not chosen at the call site.** A `warn` event is emitted with
   `daer_observe::warn!`; `cargo xtask events --check` compares the macro level with the
   catalog.
4. **Required fields are listed.** A change to the list changes the event contract and must
   update `docs/reference/events.md` in the same commit.
5. **`warn`/`error` need a counter, a rate group, and a remediation.** An event that cannot
   say what to do is not a diagnosis.
6. **`info` is lifecycle; `debug` is per-flow success; `trace` is opt-in internals.**
   A client-visible failure may never be `debug`-only.

Generation:

```sh
cargo xtask events --write   # regenerate generated.rs and docs/reference/events.md
cargo xtask events --check   # fail on drift, duplicate, missing metadata, raw tracing
```

---

## 4. Severity Contract

| Level | Use | Must have |
| --- | --- | --- |
| `error` | A promised contract is broken; the process cannot continue, or first-generation build failed | counter, remediation, incident trigger |
| `warn` | A client-visible failure or degraded capability while serving | counter, rate group, remediation |
| `info` | Lifecycle/state transition | snapshot field or documented lifecycle |
| `debug` | Per-flow success/decision detail | flow/query ID; sampled or capture-only |
| `trace` | Per-query/per-packet internals | explicit opt-in; no per-packet allocation by default |

The exact severity table is in ADR-0040. The key rule: **the default `info` configuration
must record enough to know that a client was failed.**

---

## 5. Correlation IDs

| ID | Created at | Carried through |
| --- | --- | --- |
| `RunId` | process startup | every event; `daemon.build` and `daemon.ready` |
| `FlowId` | TCP accept / UDP session creation | accept, decide, dial, relay close, DNS snoop |
| `QueryId` | DNS server receive | request routed, cache, upstream, response routed |
| `ProbeId` | health sweep | probe start/finish, state transition |
| `RefreshId` | provider refresh | fetch, unchanged/changed, generation rebuild |

IDs are typed fields on the relevant structs (`Accepted`, `Datagram`, `DialId`,
`QueryContext`, `ProbeResult`, `RefreshedProvider`), not values reconstructed from log
fields. A test must prove a complete trace is joinable by ID.

---

## 6. Capture and Incident Artifacts

The daemon maintains:

- `/run/daer/events.jsonl` (the JSONL flight recorder: `info`+ always, `debug` when enabled;
  truncated per run, tail-copied into every bundle);
- `/run/daer/state.json` (last snapshot, atomic replace);
- `/run/daer/control.sock` (read-only snapshot/flow/bundle requests);
- `/var/lib/daer/incidents/<id>/` (persistent bundles, written by the daemon or
  `daer-cleanup`).

A bundle is self-contained:

```text
manifest.json  snapshot.json  events.jsonl  README.txt
```

The configuration is deliberately not copied. A heuristic redactor is not a typed policy; the
manifest names the config path and hash so an operator can attach the file deliberately.

Triggers: panic hook, `SIGUSR1`, `daer status --bundle`. An automatic error-burst threshold is
not enabled until the event counters have a measured baseline.

**Redaction is typed.** `Secret<T>` and `RedactedLink` are the only ways to carry a
credential into diagnostic code. Canary tests inject `hunter2`, a fake UUID and a fake
REALITY key into config and assert that no bundle file contains them.

---

## 7. Kernel Telemetry

`ebpf/abi.toml` declares the `daer_event` struct and the `bpf_stats_key` /
`daer_event_type` discriminants. `cargo xtask abi` generates both sides.

`daer-ebpf::telemetry` reads:

- all 17 `bpf_stats_map` counters, on a timer, emitting deltas;
- `event_ringbuf` records, decoded and emitted as typed events.

The ring is rate-limited per key. **Volume comes from counters, never from event count.**
Every counter key and event type must have a consumer; an unconsumed key fails a test.

---

## 8. Errors

Errors returned across a boundary carry a stable `ErrorCode` and a remediation where the
operator can act. `RelayError::Dial` carries a neutral `DialFailure { stage, code, detail,
elapsed, timeout }`, not a `String`; the relay still does not depend on routing or outbound
vocabulary.

CLI output:

```text
error[daer.config.invalid]: line 12:3: unknown outbound "nope"
  help: declare a [[group]] named "nope", or change the rule target
```

---

## 9. Post-Bug Review

Every production incident gets a record in `docs/dev/incidents/`:

- frontmatter: id, status, date, affected versions;
- detection signal (event code and/or counter);
- root cause chain and discarded alternatives;
- at least one regression test and its falsifier;
- event codes/fields added by the fix;
- residual risk and a follow-up owner.

`cargo xtask incident --check` enforces the schema and resolves event/test references.
`cargo xtask ci` runs it. A record without a signal or a falsifier is rejected.

---

## 10. Review Checklist

Before merging an observability change:

1. Is the event in `events.toml`, with a unique code and required fields?
2. Is the severity what the contract says, not what is convenient?
3. Does a `warn`/`error` have a counter, rate group and remediation?
4. Is the flow/query ID present and carried from the boundary?
5. Does the human message remain readable without adding a new grep target?
6. Is a credential impossible by type, not by review?
7. Does `cargo xtask events --check` pass?
8. If this fixes a production bug, is there an incident record and a falsifier?
