## What changed

<!-- One paragraph. Name the subsystem and the observable behavior, not the implementation. -->

## Verification

- [ ] `cargo xtask ci` passes locally.
- [ ] A falsifier/negative control proves the change (ADR-0007). Test names:
      <!-- e.g. `daer-relay::serve::tests::...` -->
- [ ] If this touches a data path, the test fails when the fix is removed.

## Diagnostics

- [ ] New/changed event codes are in `crates/daer-observe/events.toml`; `cargo xtask events --check` passes.
- [ ] A client-visible failure is a `warn` event with a counter and a remediation, not `debug`-only.
- [ ] New fields carry a `flow_id`/`query_id` where the event is about one flow or query.
- [ ] No credential can reach a log or bundle (`Secret`/`RedactedLink`), including error text.
- [ ] If this fixes a production bug, an incident record exists under `docs/dev/incidents/`
      and `cargo xtask incident --check` passes.

## Documentation

- [ ] Operator-facing behavior is updated in the same commit (`docs/reference/cli.md`,
      `docs/how-to/diagnostics.md`, `daer.example.toml`, `install/daer.service`).
- [ ] `CHANGELOG.md` has an `[Unreleased]` entry.
