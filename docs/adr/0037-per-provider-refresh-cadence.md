---
id: ADR-0037
title: "Per-provider refresh cadence, content-gated generation swaps"
status: accepted
date: 2026-11-07
scope: [control-plane/rule-provider, cli/run, routing/generation, observability]
supersedes: []
superseded_by: []
---

# 0037. Per-provider refresh cadence, content-gated generation swaps

- Status: Accepted
- Date: 2026-11-07
- Deciders: Ming Li
- Related: [ADR-0006](0006-wiring-ownership.md),
  [ADR-0014](0014-drb-rule-binary-and-providers.md),
  [ADR-0031](0031-drb-v2-and-canonical-rules.md)

---

## Context and Problem Statement

`[[rule-provider]]` has carried an `interval` key since ADR-0014, and the operator guide
promises that an HTTP provider declaring an interval is "periodically checked for updates in
the background". The daemon did not implement that promise:

- The refresh timer used the **minimum** of every provider's interval and then called the
  generic `reload()` path. A provider declared at `168h` was therefore re-fetched every hour
  beside a `24h` provider, and its own declaration was never consulted.
- `reload()` re-resolves the whole configuration, including node subscriptions, and
  unconditionally swaps the routing generation. A provider that answered `304 Not Modified`
  still caused a generation rebuild, which discards measured node latency and restarts health
  probes for no routing change.
- `resolve_rule_providers_with` read `interval` into `_interval` only to satisfy a lint. That is
  the exact "parsed but not wired" failure ADR-0006 forbids: the key looked consumed while the
  scheduler ignored it.

The configuration in `daer.example.toml` already declares different cadences (`24h` next to
`168h`), so a single global ticker cannot be correct even on the shipped example.

---

## Decision

### 1. Scheduling is per provider

`daer_control::rule_provider::ProviderSchedule` is the only place that reads
`RuleProvider::interval` for scheduling:

- only `http` providers with a non-zero interval enter the schedule;
- `min_interval()` is the supervisor wake-up, because waking less often would make a provider
  miss its own deadline;
- `due(last_seen)` returns the providers whose own interval has elapsed, or which have never
  been refreshed.

A `file` provider never enters the schedule. The validator rejects an `interval` on it instead
of accepting a key with no meaning.

### 2. Refresh is content-gated

`refresh_rule_provider` fetches one provider and compares the resulting `DrbSet` with the set
already in the pool. It returns `Changed`, `Unchanged`, or `Failed`:

- `Changed` inserts the new set and republishes a generation through the same load-then-swap
  shape as `reload()`, so a failed build leaves the running policy untouched;
- `Unchanged` (the normal `304 Not Modified` answer) keeps the current generation, measured
  latency and health state;
- `Failed` keeps the current rule set and logs the tag and error. A provider outage must not
  discard working rules.

A refresh never fetches node subscriptions: those remain owned by `SIGHUP` and the explicit
reload path.

### 3. `SIGHUP` rebuilds the cadence from the new configuration

A reload may change a provider's tag, URL or interval. The supervisor rebuilds
`ProviderSchedule` and resets the timer after every successful `SIGHUP`; retaining the startup
ticker would keep a changed cadence silently ignored for the daemon's lifetime.

---

## Invariants & Behavioral Boundaries

- **`[INV-PROVIDER-02]` Per-Provider Refresh Cadence**: an HTTP provider is fetched no more
  often than its own declared `interval`, while a provider that has never been refreshed is due
  immediately. *Enforced by*: `ProviderSchedule::due`, and
  `daer_control::rule_provider::tests::schedule_honours_each_provider_interval` (positive and
  negative control).
- **`[INV-PROVIDER-03]` No Swap Without Change**: an unchanged provider response does not
  rebuild the routing generation or restart health probes. *Enforced by*:
  `RefreshedProvider::requires_swap`, `unchanged_content_does_not_require_a_swap`, and the
  `Changed` branch in `refresh_due_providers`.
- **`[INV-PROVIDER-01]`** remains binding: the loader resolves every provider before the first
  generation is built, with cached fallback. The refresh path reuses that loader and its cache
  format.

---

## Consequences

- A `24h` provider and a `168h` provider are both checked on their own schedule; the daemon
  wakes on the shortest one and skips the others until due.
- An unchanged refresh is cheap and invisible to the data path: no policy swap, no latency
  reset, no health-probe churn.
- A refresh failure is a warning, not an outage: the previous generation keeps serving.
- The refresh path reads the configuration from disk to find declarations, but does not resolve
  subscriptions or rebuild unrelated state. `SIGHUP` remains the single full-reload verb.

---

## Evidence

- `crates/daer-control/src/rule_provider.rs`: `ProviderSchedule`, `RefreshOutcome`,
  `refresh_rule_provider`, and the schedule/content tests.
- `crates/daer-cli/src/run.rs`: `refresh_due_providers` and the `SIGHUP` cadence rebuild.
- `docs/how-to/rule-providers.md`: the operator contract this ADR makes true.
