---
id: ADR-0052
title: "Tests are layered by the question they answer; nextest selects the layer and the root harness owns external tests"
status: accepted
date: 2026-11-14
scope: [verification, ci, documentation]
supersedes: []
---

# 0052. Tests are layered by the question they answer; nextest selects the layer and the root harness owns external tests

- Status: Accepted
- Date: 2026-11-14
- Deciders: Ming Li
- Related: [ADR-0007](0007-verification.md), [ADR-0025](0025-verification-at-the-privilege-boundary.md), [ADR-0042](0042-tcx-only-linux-6-6.md)

---

## Context and Problem Statement

The workspace had three kinds of test evidence and no single definition separated them:

1. **In-crate unit tests** — fast, unprivileged, one contract at a time.
2. **Integration tests** (`crates/*/tests/*.rs` before this ADR) — real components over
   loopback, with the ingress or remote peer replaced only where privilege or a foreign service
   would otherwise be required.
3. **Privileged end-to-end gates** — a real daemon, a real `nftables tproxy` rule, real network
   namespaces, a real kernel object, and real signals.

Three costs followed from the layout:

- **One link step per test file.** Each `crates/*/tests/*.rs` was a separate binary, so the
  workspace linked its entire dependency graph dozens of times.
- **Fixtures were copied per crate.** `TempDir`, nonce and free-port helpers existed in several
  files with slightly different uniqueness rules; one version could delete another test's
  directory because `process::id()` was the only key.
- **The layer was implicit.** `cargo test --workspace` mixed unit, integration and doctests, so
  a failure did not name the rung that broke. A custom `cargo xtask test` runner was written to
  recover that information, but it re-implemented Cargo's target selection and required its own
  `cargo metadata` parser.

The suite also drifted in the skip contract: `3-netns` was emitted by a script but not required
in CI, so the private-ingress lifecycle could skip while the job stayed green. An earlier
`DAER_REQUIRE` list named `7-tcp`, a key no script emitted, so the gate could never fail for the
reason it claimed.

## Decision

### 1. Four layers, one question each

| Layer | Question | Location | Selector |
| :--- | :--- | :--- | :--- |
| L1 unit | does this function obey its contract? | `crates/*/src` | `nextest -E 'kind(lib) + kind(bin)'` |
| L1 doc | do the documented examples compile? | rustdoc fences | `cargo test --workspace --doc` |
| L2 integration | do the real components compose? | `tests/integration/` | `nextest -E 'binary(integration)'` |
| L3 e2e | does the real process and kernel produce the result? | `tests/e2e/` | `nextest -E 'binary(e2e)'` |

`cargo-nextest` is the runner for every Rust test. It already owns target selection, per-test
process isolation, retries, timeouts and JUnit output; a project-specific runner must not
re-implement that. The one exception is doctests, which nextest does not support:
`cargo test --workspace --doc` is used for that layer and nothing else.

### 2. External tests are one package with two targets

The workspace root is also the `daer-tests` package. It has an empty library and exactly two
test targets:

```text
tests/integration/main.rs   -> target `integration`
tests/e2e/main.rs           -> target `e2e`
tests/common/               -> shared fixtures, included by both
```

This keeps the multi-crate architecture and gives the external layer two link steps instead of
one per file. `tests/common` is the shared fixture seam; `daer-test-support` is the
dev-dependency that the in-crate unit tests and `tests/common` both use.

A crate-local `tests/` directory is not allowed. `tests/integration/test_architecture.rs` fails
if one reappears.

### 3. Unit tests stay in the crate

- Small and medium modules use an inline `#[cfg(test)] mod tests`.
- A large module whose test module dominates the file moves the body to
  `src/<module>/tests.rs` and leaves `#[cfg(test)] mod tests;`. This is a test-volume decision,
  not a file-size rule.
- `daer-test-support` is a dev-dependency and is never in a production dependency closure. The
  architecture test asserts that against `cargo metadata`.

### 4. Skips are audited by a test, not by xtask

`tests/integration/test_architecture.rs` enforces:

- every `#[ignore]` names a prerequisite;
- every `DAER_REQUIRE` key is emitted by a script;
- every emitted key is required by CI or listed in `MANUAL_SKIP_KEYS` with a reason;
- every external test lives in the root harness;
- the root harness has exactly the `integration` and `e2e` targets;
- `daer-test-support` is dev-only.

Because this is a normal integration test, nextest runs it with the layer it audits. There is no
`cargo xtask test` entry point; xtask is limited to code generation, packaging and the
unprivileged preflight.

### 5. Privileged orchestration stays in shell scripts

`scripts/verify/kernel-check.sh` and `scripts/verify/e2e-check.sh` build the one `e2e` target,
find its binary under `target/debug/deps/e2e-*`, and select tests by module-qualified name.
They still own `DAER_REQUIRE`, sudo, nftables and network namespaces. The old
`cargo xtask kernel-check` / `cargo xtask e2e-check` aliases are deleted.

## Consequences

- CI has explicit layer jobs: unit/doc, integration, kernel, ingress, object. A failure names
  the layer, and the layer is selected by a nextest filterset rather than by project code.
- External tests link twice, not once per file. The root harness is a package, so `cargo
  metadata` shows it; the architecture test keeps it honest.
- Unit tests that used to be at the bottom of a 2,000-line file are now findable next to the
  module, and the production file reads as production code.
- `cargo test --workspace` still works for a contributor who wants everything; the layer
  commands are what CI uses and what the docs teach.
- nextest is a development dependency of the workflow, not of the product. `cargo test` remains
  sufficient to run the suite; nextest is how the layers are selected and reported.
- The known gaps (coverage, mutation testing, soak) remain explicit in
  `docs/dev/testing.md`; closing one is a test change with a falsifier, not a documentation
  claim.
