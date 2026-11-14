# Test Architecture

This is the project's test strategy: what each layer is for, where a test belongs, how it is
run, and which gate makes it non-optional. It is the project-specific companion to the neutral
[ADR-0007](../adr/0007-verification.md) rule that a test which cannot fail is a liability, and
it is recorded as [ADR-0052](../adr/0052-layered-test-architecture.md).

The short version: **nextest selects the layer, the root harness owns external tests, the
crate owns its unit tests, and every skip has an owner.**

---

## 1. The pyramid

```text
                         ┌──────────────────────────────┐
  L3  E2E                │ real daemon, kernel, nftables│  privileged, serial
                         │ real redirect, real signal   │
                         ├──────────────────────────────┤
  L2  Integration        │ real components over loopback│  unprivileged, parallel
                         │ real router, relay, sockets  │
                         ├──────────────────────────────┤
  L1  Unit               │ one function or type, no I/O │  fast, exhaustive
                         │ parsers, state machines      │
                         └──────────────────────────────┘
```

| Layer | Question it answers | Lives in | Command | CI gate |
| :--- | :--- | :--- | :--- | :--- |
| **L1 unit** | Does this function obey its contract, including its error paths? | `crates/*/src/**` | `cargo nextest run --workspace -E 'kind(lib) + kind(bin)'` | `test` job |
| **L1 doc** | Do the examples an operator copies actually compile? | rustdoc fences | `cargo test --workspace --doc` | `test` job |
| **L2 integration** | Do the real components compose across their seam? | `tests/integration/` | `cargo nextest run --workspace -E 'binary(integration)'` | `integration` job |
| **L3 E2E** | Does a real process, a real redirect, and the real kernel produce the client-visible result? | `tests/e2e/` | `cargo nextest run --workspace -E 'binary(e2e)'` | `kernel-datapath`, `e2e-ingress`, `ebpf-object` jobs |
| **Soak / delivery** | Does it survive sustained traffic and a real node? | `scripts/ops/` + site config | `sudo scripts/ops/daer-delivery-check.sh` | release gate, not per-PR |

nextest has no doctest support. `cargo test --workspace --doc` is the one native Cargo command
in the test flow, and it exists because nextest cannot replace it.

---

## 2. Unit tests live with the code

### Small and medium modules

Inline, at the bottom of the module:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    // ...
}
```

The rule is not "small file"; it is **the test is about this module's private contract**. If
it needs a socket, a spawned process, or another crate's public setup, it is not a unit test.

### Large modules: sibling `tests.rs`

When a module's test module is larger than the production code and the growth is test volume
rather than a genuinely large domain, move the whole `mod tests` body to a sibling file:

```text
crates/daer-relay/src/server.rs
crates/daer-relay/src/server/tests.rs
```

and leave only:

```rust
#[cfg(test)]
mod tests;
```

The test file keeps `use super::*;`, so the move is mechanical. Do this when the test module is
roughly 500+ lines or dominates the file, not pre-emptively: a 200-line test module beside 300
lines of state machine is proportionate.

### `daer-test-support`

`crates/daer-test-support` is the shared infrastructure crate. It is a **dev-dependency** and
must never enter a production dependency closure; `tests/integration/test_architecture.rs`
fails if any crate declares it as a normal dependency.

It provides:

- `Scratch` — a unique, self-removing scratch directory. Use it instead of hand-rolled
  `TempDir` structs; the counter and timestamp prevent two tests in one process from deleting
  each other's directory.
- `Scratch::write_private` — writes a config fixture with mode `0600`.
- `nonce()` — a per-run value a hard-coded fixture cannot satisfy.
- `binary()`, `daer()`, `daer_drb()` — locate built binaries from the running test binary, for
  the root harness where `CARGO_BIN_EXE_*` is not defined.
- `workspace_root()`, `workspace_path()`, `read_workspace()`.
- `wait_until()`, `unused_port()`.

A fixture that needs a protocol or a runtime belongs in the test that owns it, not in
`test-support`.

---

## 3. External tests live in the root harness

The workspace root is also the `daer-tests` package. It has an empty library and exactly two
external test targets:

```text
tests/
  common/                 # shared fixtures, included by both entries
    mod.rs
    shadowsocks_server.rs
    shadowsocks_2022_server.rs
  integration/
    main.rs               # target `integration`
    cli_route.rs
    control_router.rs
    dns_end_to_end.rs
    ...
  e2e/
    main.rs               # target `e2e`
    control_transparent.rs
    control_transparent_udp4.rs
    control_transparent_udp6.rs
    protocols_reality_interop.rs
    ...
  fixtures/               # TLS material and reference configs
```

Why one entry per layer:

- **Two link steps instead of one per crate.** The previous layout linked the entire dependency
  graph once per `crates/*/tests/*.rs` file; the root harness has one `integration` binary and
  one `e2e` binary.
- **A real `common` module.** `TempDir`, nonce, process and binary helpers are defined once.
- **A visible layer boundary.** The test name in nextest output starts with
  `daer-tests::integration` or `daer-tests::e2e`, so a failure names the layer.
- **No crate-local `tests/` directory.** `test_architecture.rs` fails if one reappears; an
  external test that needs a crate-private interface is a sign the unit test belongs in the
  crate instead.

`tests/common` is included with `#[path = "../common/mod.rs"] mod common;` in both entries.
Helpers used only by one layer stay in that layer's directory.

---

## 4. Writing a test that can fail

Every test that claims a data path or a contract must name its **falsifier**:

1. **A value only the real path can produce.** A per-run nonce, not `hello`.
2. **A liveness assertion that proves the component was involved.** `Daemon::stats()` advanced,
   a generation was published, a counter moved.
3. **A negative control.** The same input with the mechanism removed must fail; if the control
   passes, the fixture is broken and the test reports that, not a green tick.

A test that starts a fixture and then asks the fixture for its own answer is not evidence. This
is the failure mode [ADR-0007](../adr/0007-verification.md) records: the old transparent test
started an origin that answered `hello` and asserted `hello`, so it passed with no daemon and no
redirect rule.

### Determinism

- Do not depend on wall-clock duration except through generous timeouts that only fail a hung
  test.
- Do not use a fixed port. Bind port 0 and read the assigned port; `unused_port()` is only for
  an external process that must be configured before it starts.
- Make every scratch directory unique across tests in one process. Use `Scratch`.
- A concurrency test must assert the difference, not only the success:
  `cli_runtime.rs` asserts a spawned task starves on a current-thread runtime **and** runs on a
  multi-threaded one.
- E2E tests are serialised by the nextest `e2e-serial` test group. Do not rely on that for
  correctness; it prevents fixture collisions, not product races.

---

## 5. Skips, ignored tests, and `DAER_REQUIRE`

An `#[ignore]` attribute is a debt with an owner. It must name the capability or fixture it
needs in the attribute itself:

```rust
#[ignore = "needs CAP_BPF and CAP_NET_ADMIN; scripts/verify/kernel-check.sh runs it privileged"]
#[test]
fn the_object_loads_and_verifies() { /* ... */ }
```

A bare `#[ignore]` fails `test_architecture::every_ignored_test_names_its_prerequisite`.

The privileged scripts print `skip` with a key instead of failing when a fixture is missing, and
`DAER_REQUIRE=<key,...>` turns that skip into a failure. The keys are part of the CI contract:

- every key in a workflow's `DAER_REQUIRE` must be emitted by a script;
- every key a script emits must either be required by CI or be listed in
  `tests/integration/test_architecture.rs`'s `MANUAL_SKIP_KEYS` with a reason.

Current keys:

| Key | Script | Check | CI |
| :--- | :--- | :--- | :--- |
| `kernel-binary` | `kernel-check.sh` | the datapath object exists and the loader binary is built | required |
| `7` | `kernel-check.sh` | in-kernel datapath cases (`BPF_PROG_TEST_RUN`) | required |
| `3-tcp` | `e2e-check.sh` | redirected IPv4 TCP flow reaches the daemon and returns the nonce | required |
| `3-tcp6` | `e2e-check.sh` | the same over IPv6 loopback | required |
| `3-udp` | `e2e-check.sh` | single-namespace IPv4 UDP; deliberately manual because that fixture is invalid | manual |
| `3-udp4` | `e2e-check.sh` | two-namespace IPv4 UDP `tproxy` topology | required |
| `3-udp6` | `e2e-check.sh` | two-namespace IPv6 UDP `tproxy` topology | required |
| `3-netns` | `e2e-check.sh` | private ingress namespace, peer move, return route, teardown | required |
| `4` | `e2e-check.sh` | a real `SIGHUP` does not abort the daemon | required |

A new skip key must be added to a `DAER_REQUIRE` list or to `MANUAL_SKIP_KEYS` with a reason;
`test_architecture::every_daer_require_key_is_emitted_by_a_script` is the gate.

---

## 6. Running the layers

```bash
# L1: unit tests in lib and bin targets
cargo nextest run --workspace -E 'kind(lib) + kind(bin)'

# L1: doctests (nextest does not run these)
cargo test --workspace --doc

# L2: the root `integration` binary
cargo build -p daer-cli -p daer-drb --bins
cargo nextest run --workspace -E 'binary(integration)'

# L3: the root `e2e` binary (most tests skip without privilege)
cargo nextest run --workspace -E 'binary(e2e)'

# One test while iterating
cargo nextest run -p daer-tests -E 'test(control_router::a_rule_sends_a_flow_direct)'
```

Use `cargo nextest list --workspace` to see the live test inventory. Do not copy counts into
prose; the tree is the source of truth.

The CLI tests need `target/debug/daer` and `target/debug/daer-drb`; build them first. The
integration CI job does this explicitly.

### Privileged gates

```bash
scripts/verify/kernel-check.sh    # object loads, TCX attaches, in-kernel cases
scripts/verify/e2e-check.sh       # real tproxy redirect, namespaces, SIGHUP
```

Both scripts build the root `e2e` target, find the one binary under `target/debug/deps/e2e-*`,
and select individual tests by their module-qualified names. A skip is reported with a key;
`DAER_REQUIRE` makes it fatal. Host preparation is
[Test Environment Requirements](test-environment.md); the manual kernel procedure is
[Testing the kernel datapath](kernel-test-plan.md).

---

## 7. CI mapping

| Job | Layer | What it proves |
| :--- | :--- | :--- |
| `test` | L1 + doc | unit tests and doctests pass |
| `integration` | L2 | real components compose over loopback; the test architecture audit runs here |
| `kernel-datapath` | L3 | object loads, TCX attaches, in-kernel datapath cases, REALITY/Vision interop |
| `e2e-ingress` | L3 | transparent TCP/IPv4/UDP4/UDP6, private ingress lifecycle, `SIGHUP` reload |
| `ebpf-object` | L3 | the built object satisfies the ABI and the unprivileged preflight |

A green `test` job alone is not a delivery claim. The release gate remains
[Production Readiness](production-readiness.md).

---

## 8. Known gaps

These are test gaps, not documentation caveats. A change that closes one should add the
falsifier, not just the assertion.

| Gap | Why it matters | Next step |
| :--- | :--- | :--- |
| Coverage measurement | Layer counts show activity, not which lines are unreached | Add a non-gating `cargo llvm-cov` report; gate only after a baseline is recorded |
| Mutation testing | A green suite does not prove the assertions are sensitive | Run `cargo-mutants` over `daer-routing` and `daer-sniff` on a schedule |
| Soak / capacity | A flow passing once is not sustained load | 24-hour run with fd/map/session leak checks (production readiness) |
| Cross-crate fixture crate | `tests/common` is compiled into both entries, which is the intended cost | Revisit only if a third test binary appears |

The omissions are deliberate: a suite that claims complete coverage while these are open would
be the softened claim ADR-0007 exists to prevent.

---

## 9. Adding a test

1. Decide the layer with the table in §1. If the property needs a socket or a process, it is not
   a unit test.
2. Put a unit test in the crate. If it is about a large module and bloats the file, use
   `src/<module>/tests.rs`. If it needs shared infrastructure, use `daer-test-support`.
3. Put an external test in `tests/integration/` or `tests/e2e/`, add its `mod` line to the
   corresponding `main.rs`, and state its falsifier in the module doc.
4. Run the narrow nextest filter first, then the layer.
5. Run `cargo nextest run --workspace -E 'binary(integration)'`; the architecture test checks the
   new ignore reason, harness location, and `DAER_REQUIRE` key.
6. If the test changes a system invariant, update `docs/dev/invariants.md` and the ADR that
   owns it.
