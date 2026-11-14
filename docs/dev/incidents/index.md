# Incident Records

Every production incident gets a record here. The record is not a narrative for its own
sake: it names the **signal** that detected the failure, the root cause chain, and at least
one regression test whose failure would have caught it.

`cargo xtask incident --check` enforces the frontmatter and resolves every event code and
test reference. A record without a signal or a falsifier is rejected.

| ID | Title | Status | Affected | Signal | Regression |
| :--- | :--- | :--- | :--- | :--- | :--- |
| [INC-0001](0001-transparent-ingress.md) | Transparent ingress `NO_SOCKET`: five layers, one observable failure | resolved | 0.0.11 | `datapath.policy_deferred`, `bpf_stats.listener_assign_failed` | `tests/e2e/control_transparent.rs`, `tests/e2e/control_netns_lifecycle.rs` |

## Record template

```markdown
---
id: INC-NNNN
title: "One sentence naming the observable failure"
status: draft | investigating | resolved | superseded
date: YYYY-MM-DD
affected: ["0.0.x"]
signal:
  - event: flow.dial_failed
  - counter: bpf_stats.listener_assign_failed
regression:
  - tests/e2e/control_transparent.rs::the_test_that_fails_if_this_returns
events_added: [flow.dial_failed]
adr: [ADR-NNNN]
---

# NNNN. Title

## Observable failure

What the operator saw, with the exact event code or counter. No "it was broken".

## Timeline

The run id, generation and event sequence. A bundle path or a redacted excerpt.

## Root cause

The layer that was wrong, and the evidence that moved the investigation there.

## Why it was not caught

The test, doc or invariant that was absent or vacuous. This section is mandatory.

## Fix and falsifier

What changed, the negative control, and the test that fails if the fix is removed.

## Content hooks added

The event codes/fields or counters that make the next occurrence visible sooner.

## Residual limits

What remains true even after the fix.
```
