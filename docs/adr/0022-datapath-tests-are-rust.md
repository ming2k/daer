# ADR-0022 — In-kernel datapath tests are Rust, and they run in CI

- Status: accepted
- Date: 2026-11-06
- Extends: [ADR-0007](0007-verification.md)

## Context

`ebpf/kern/tests/` holds 4,828 lines of datapath verification: 3,755 lines of self-checking
BPF programs in `bpf_test.c` (a pktgen program builds a packet, a setup program primes the
maps, a check program asserts the datapath's verdict) and ~870 lines of Go that load those
programs through `cilium/ebpf` and drive them with `BPF_PROG_TEST_RUN`. It is the only
verification in the repository that exercises the *kernel* logic rather than a Rust model of
it.

It is dead weight in three ways at once:

1. **It is Go, in a Rust project.** Nothing else here is Go. The harness cannot be built by
   `cargo`, is not run by `cargo xtask ci`, and requires a `go` toolchain that no other part
   of the build mentions.
2. **It is gated behind a build tag nothing sets.** `ab_regression_test.go` carries
   `//go:build linux && dae_bpf_tests`, and `bpf_test.c` carries `//go:build exclude` — a Go
   directive in a C file, which clang ignores and which therefore documents nothing. The
   suite has not been part of any gate for as long as the tag has existed.
3. **It uses the `dae` vocabulary** (`dae_socket_mark`, `loadABRegressionObjectsWithMark`,
   `markAllOutboundsAlive`) and, after ADR-0020, would need editing anyway.

Deleting it would remove the only test that can falsify a datapath claim at the kernel
level, which ADR-0007 explicitly refuses: a claim without a falsifier is an aspiration. So
the choice is between porting it and keeping a Go island. Porting wins, and `aya` makes it
tractable — it exposes `TestRunOptions` / `TestRunAttrs` over `BPF_PROG_TEST_RUN`, which is
the same syscall `cilium/ebpf`'s `Program.Run` uses, plus the map operations the setup
programs need.

## Decision

1. **The harness is ported to Rust, in `crates/daer-ebpf/tests/datapath.rs`.** It loads the
   test object, resolves the `pktgen_<case>` / `setup_<case>` / `check_<case>` program triple
   for every case, and drives each triple through `BPF_PROG_TEST_RUN` in the same order the
   Go harness does. A `check` program returning non-zero is a failure, and the case name is
   the failure message.
2. **The test programs stay in C.** `bpf_test.c` is 3,755 lines of kernel-side assertions
   that can only be written as BPF; rewriting them in Rust would be a second ABI to maintain
   for no gain. It is compiled by `cargo xtask ebpf --tests` alongside the production object,
   into a separate `target/ebpf/datapath_test.bpf.o`.
3. **The case list is discovered, not enumerated.** The harness reads the compiled object's
   program names, groups them by suffix, and fails if a `check_<case>` has no matching
   `pktgen_<case>` or `setup_<case>`. Adding a case to `bpf_test.c` therefore adds it to the
   suite with no Rust change, and a half-added case is a red test rather than a silently
   skipped one.
4. **The suite is part of `cargo xtask ci`, and skips loudly without privileges.**
   `BPF_PROG_TEST_RUN` needs `CAP_BPF`. The harness detects that once, and either runs or
   prints the reason it skipped and a non-zero-exit instruction — the same contract
   `tests/kernel.rs` already has. `scripts/verify/kernel-check.sh` runs it with the privileges and
   promotes the skip to a failure, so a green CI run on a developer box never implies the
   kernel tests passed.
5. **`//go:build` directives are deleted with the Go files, and the C test file loses its
   meaningless tag.** `bpf_test.c` gains a real guard: it is only compiled when
   `cargo xtask ebpf --tests` asks for it, which is a build-system fact rather than a
   comment.
6. **The `dae` names in the test programs are renamed with the rest of the datapath**
   (ADR-0020), so the harness and the C it drives speak the same vocabulary as production.

## Consequences

- The repository contains no Go. One toolchain (`rustc` + `clang`) builds and tests
  everything, which is what `docs/dev/standards` claims.
- Datapath cases become reachable from `cargo test`, so a change to the routing logic has a
  falsifier that runs on a laptop with the right capability and in `kernel-check.sh` in CI.
- The port is mechanical but not small: the Go harness is ~870 lines, and the Rust harness
  has to reproduce its map priming (outbound liveness, `lpm_array_map`, the `PARAM` override
  per object) as well as the triple discovery. That work is the price of deleting the island,
  and it is paid once.
- `bpf_test.c` keeps its `#include "../datapath.bpf.c"`, so the tests continue to compile against
  the production datapath rather than a copy. That is the property that makes them worth
  porting.
