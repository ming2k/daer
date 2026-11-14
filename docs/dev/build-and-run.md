# Build & Run Guide

How to build `daer` from source and run it on a development machine. This is the contributor
view: it names the tasks that build and check the tree.

An operator setting up a real box wants [Getting Started](../tutorials/getting-started.md) and
[Deployment](../how-to/deployment.md) instead; they cover the redirect, the policy route and the
systemd unit, which this page deliberately does not repeat.

---

## 1. Prerequisites

| Thing | Why |
| :--- | :--- |
| Rust 1.95+ (edition 2024) | the workspace's MSRV, enforced by `rust-version` |
| Linux 6.6+ | TCX (`BPF_TCX_INGRESS`/`BPF_TCX_EGRESS`), `bpf_loop`, and the cgroup hooks the datapath uses |
| `clang` | compiles `ebpf/kern` — there is no prebuilt object in the repository |
| `bpftool` | dumps the per-kernel `vmlinux.h` the datapath includes |
| cgroup v2 | the six `pname` hooks attach to the unified hierarchy at daemon startup |
| `CAP_BPF` + `CAP_NET_ADMIN` + `CAP_PERFMON` + `CAP_SYS_ADMIN` | only for the privileged gates in §4; building and the unprivileged gates need nothing. The first three load/attach the datapath; `CAP_SYS_ADMIN` creates and enters the private ingress namespace (ADR-0038) |

---

## 2. Building

There are two products, and the second one does not come from `cargo build`:

```bash
cargo build --release                  # target/release/daer, target/release/daer-drb
cargo xtask ebpf                       # target/ebpf/datapath.bpf.o  (needs clang)
```

`daer` is the single public binary: `run`, `check`, `route`, `probe`, `status`, `elect`,
`schema`, `version` (ADR-0015/ADR-0041/ADR-0047, `[INV-CLI-01]`). `daer-drb` is the
rule-artifact producer and is
*not* linked into the daemon — `tests/integration/cli_surface.rs` asserts that closure stays
empty (ADR-0031).

For a failure that needs a real backtrace, build the forensic profile:

```bash
cargo build --profile forensic        # line tables + unwinding, not the shipped build
```

The release build is deliberately stripped and `panic = "abort"`. The forensic build keeps
line tables and unwinding so the panic hook and the RAII cleanup paths can produce evidence;
use it only to explain a failure, never as the artifact you deploy.

`cargo xtask ebpf` needs a `vmlinux.h` that matches the kernel it will be loaded on. It is
per-kernel and is not vendored:

```bash
mkdir -p ebpf/kern/headers
bpftool btf dump file /sys/kernel/btf/vmlinux format c > ebpf/kern/headers/vmlinux.h
cargo xtask ebpf
```

The ABI is generated, not hand-written (ADR-0021). `ebpf/abi.toml` is the only place a map name,
program name, discriminant or struct layout is declared, and `cargo xtask abi` writes both
`ebpf/kern/daer_abi.h` and `crates/daer-ebpf/src/generated.rs` from it. Both are tracked, so a
line that smells wrong is either a stale artifact — regenerate it — or a change that belongs in
`abi.toml`.

---

## 3. Running it locally

```bash
sudo ./target/release/daer check -c daer.example.toml     # unprivileged: does it compile?
sudo ./target/release/daer run   -c config.toml --object target/ebpf/datapath.bpf.o
```

`daer.example.toml` is the annotated reference and the fixture the schema tests read; it fetches
its rule providers, so a `check` against it needs network access. For an offline run, or for a
minimal config, use the shape in [Getting Started](../tutorials/getting-started.md#3-create-a-minimal-configuration).

To ask what the daemon *would* do without touching the box, add `--dry-run`:

```bash
daer run -c config.toml --dry-run --object target/ebpf/datapath.bpf.o
```

That is the unprivileged half of the verification split in ADR-0029: it builds the generation,
validates the object against the ABI, computes the runtime parameter and reports which
capabilities the next phase would need — and returns before the port is bound, the device pair is
created, the private ingress namespace exists, any sysctl or policy route is written, or `bpf()` is
called.

A real run creates `daer0ns` first, then creates the veth pair with `daer0peer` already inside
it, before binding the listeners. If the listener and the packet are in different namespaces,
`bpf_sk_assign` can report success and the transport stack still answers `NO_SOCKET`; the
namespace is a prerequisite, not an optimization.
The host must already have the forwarding and martian sysctls listed in
[`docs/how-to/deployment.md#host-sysctls`](../how-to/deployment.md#host-sysctls); the daemon
checks them and refuses to change them.
`nsenter --mount=/proc/$(systemctl show -p MainPID --value daer)/ns/mnt ip -n daer0ns link`
and `... route` are the topology checks; the mount is private to the daemon, so the host's
`ip netns list` does not show it.

---

## 4. Verifying

The per-layer commands, and the ones to run before pushing:

```bash
# L1: unit tests in library and binary targets
cargo nextest run --workspace -E 'kind(lib) + kind(bin)'
# L1: doctests (nextest does not run them)
cargo test --workspace --doc

# L2: the root integration harness
cargo build -p daer-cli -p daer-drb --bins
cargo nextest run --workspace -E 'binary(integration)'

# L3: the root e2e harness (most tests skip without privilege)
cargo nextest run --workspace -E 'binary(e2e)'
```

The checks that do not run Rust tests are the ABI drift check, the diagnostic event catalog
check (`cargo xtask events --check`), the incident-record check
(`cargo xtask incident --check`), `cargo fmt --check`, `clippy -D warnings`, and the
unprivileged preflight (`cargo xtask preflight`). `.github/workflows/ci.yml` runs the same
steps, with tests selected by nextest filtersets.

[Test Architecture](testing.md) defines what belongs in each layer, the unit-test placement
rules, the skip policy, and the `DAER_REQUIRE` key contract. The two privileged gates answer
different questions over different dependency closures, so neither substitutes for the other:

```bash
scripts/verify/kernel-check.sh   # does the eBPF object load and behave?
scripts/verify/e2e-check.sh      # does a redirected flow reach the daemon and come back?
```

Both re-exec themselves under `sudo` and both report `skip` with a reason when a fixture is
missing. A skip is a fact on a laptop and a hole in CI, so `DAER_REQUIRE=<key,...>` turns a named
skip into a failure; the keys are in [Test Architecture](testing.md#5-skips-ignored-tests-and-daer_require).
The full script layout, including the host-level `ops/` helpers, is documented in
[`scripts/README.md`](../../scripts/README.md).

## 5. Diagnosing a flow

The daemon's decisions are reachable without running it, and they come from the same loader the
daemon uses (`[INV-LOADER-01]`), so a diagnostic cannot disagree with the service:

```bash
daer route example.com --why -c config.toml
daer check -c config.toml --nodes
daer probe node <tag> -c config.toml
```
