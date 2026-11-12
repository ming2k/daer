---
id: ADR-0015
title: "The CLI is four verbs: producers are not shipped inside the runtime"
status: accepted
amended-by: [ADR-0016, ADR-0041, ADR-0046, ADR-0047]
date: 2026-02-15
scope: [cli/surface, architecture/boundary, routing/drb, dns]
supersedes: []
---

# 0015. The CLI is four verbs: producers are not shipped inside the runtime

- Status: Accepted
- Date: 2026-02-15
- Amended by: [ADR-0016](0016-cli-route-and-probe.md) — the four verbs keep their boundary, but
  `explain` became `route <TARGET>` and `probe` was added, so the surface became six names.
- Amended by: [ADR-0041](0041-runtime-status-verb.md) — `status` was added as a read-only
  runtime inspector; it is not a producer and not a second service. The boundary is unchanged.
- Deciders: Ming Li
- Related: [ADR-0006](0006-wiring-ownership.md), [ADR-0014](0014-drb-rule-binary-and-providers.md)

---

## Context and Problem Statement

By the time DRB and rule providers landed, `daer --help` listed six top-level verbs and eleven
subcommands:

```text
daer run | config {validate,fmt,example,schema} | node convert
daer route {explain,nodes} | dns {serve,check} | rule {compile,inspect,convert} | version
```

Each of those existed for a defensible local reason, and together they were indefensible:

1. **The runtime carried a build toolchain.** `daer rule convert` linked `daer-geodata`, the
   Protobuf reader. Its whole purpose is the format ADR-0014 exists to retire, so the daemon
   binary could speak `.dat` while the *only* thing that must never speak `.dat` is the daemon.
   `node convert` did the same for URI links: a text transformer inside a networking binary.
2. **Two ways to ask one question.** `config validate` and `dns check` both answered "is this
   configuration runnable"; `route explain` and `route nodes` both answered "what would happen".
   An operator had to learn which of two near-synonyms applied to their problem before they
   could learn the answer.
3. **A second product in the binary.** `dns serve` ran a standalone resolver. Fake-IP is inert
   without the datapath that reads the synthetic addresses back, and `domain(...)` rules are
   inert without the resolver, so standalone DNS is a service this project does not actually
   offer — it was a development convenience that survived into the shipped surface.
4. **Every verb is a compatibility promise.** `config fmt` promised a canonical TOML form, so
   changing the writer became a breaking change; `config example` promised a bundled sample, so
   the sample could drift from the docs and nothing would say so.

The cost was not binary size. It was that a new operator had eleven things to learn before the
first packet moved, and the daemon's own dependency graph recorded responsibilities it did not
have.

## Decision

**The CLI is exactly four verbs, and each answers one question a runtime owner asks.**

```text
daer run                     run the daemon
daer check [--nodes]         will this configuration run, and what would it do
daer explain <SRC> <DST>     which rule decides this flow, and why
daer schema                  the JSON Schema, for an editor
daer version                 build information
```

> **Amended by ADR-0016.** The boundary this decision draws — a runtime, with no producer and
> no second service linked into it — is unchanged and is still enforced structurally by
> `crates/daer-cli/tests/surface.rs`. Two names did change on usability grounds: `explain` is
> now `route <TARGET>`, because routing lookup is the vocabulary operators already have, and
> `probe` was added for the active diagnostics that an offline evaluator cannot answer.

### 1. Producers are removed from the runtime

| removed | where it lives now |
| --- | --- |
| `rule compile` / `inspect` / `convert` | `daer-drb`, the DRB producer (ADR-0014). `daer` links no `daer-geodata`. |
| `node convert` | Third-party tooling. `[[subscription]]` already parses links at runtime, so hand-converting a link is no longer on any supported path. |
| `dns serve` | Deleted. `daer run` starts the resolver when `dns.bind` or Fake-IP asks for it; a standalone server is a different product. |
| `config fmt`, `config example` | Deleted. A configuration is hand-written TOML; the sample is a repository file the docs link to, and one test asserts it validates. |

### 2. Diagnostics are collapsed, not multiplied

- `config validate` and `dns check` become **`daer check`**. It runs the complete pre-bind
  sequence — subscriptions, rule providers, rule lowering, group construction, node usability,
  DNS upstream usability, DNS bind address — and exits non-zero on anything `daer run` would
  refuse. One command, one exit status, one thing for a deployment gate to call.
- `route nodes` becomes **`daer check --nodes`**: the node pool is a property of the
  configuration, not a separate question about it.
- `route explain` becomes **`daer explain`**, with the same non-zero exit when the flow would
  be dropped. The `route` verb existed only to group one command.

### 3. The removed verbs fail with a reason, not "unknown subcommand"

`daer` names the replacement in the error, so a script that breaks tells its operator what to
change rather than leaving them to diff help output.

## Consequences

### Positive

- **One dependency graph.** `daer-cli` no longer depends on `daer-geodata`; the daemon binary
  cannot regress into a format converter.
- **Four things to learn**, each mapping to a question an operator already has.
- **Fewer promises.** No canonical-TOML contract, no bundled example contract.

### Negative

- Existing scripts and documentation that call `daer config validate`, `daer route explain`,
  `daer node convert`, `daer dns check`, or `daer rule *` break. Per project policy there is no
  compatibility shim: the migration is a rename, and the error message names it.
- A user who wants to build a `.drb` now needs `daer-drb`. That is the intended boundary: the
  runtime consumes, the producer builds.
