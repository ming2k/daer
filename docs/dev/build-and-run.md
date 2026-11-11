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
| Linux 5.17+ | `bpf_loop`, and the cgroup hooks the datapath uses |
| `clang` | compiles `ebpf/kern` — there is no prebuilt object in the repository |
| `bpftool` | dumps the per-kernel `vmlinux.h` the datapath includes |
| `CAP_BPF` + `CAP_NET_ADMIN` + `CAP_PERFMON` + `CAP_SYS_ADMIN` | only for the privileged gates in §4; building and the unprivileged gates need nothing. The first three load/attach the datapath; `CAP_SYS_ADMIN` creates and enters the private ingress namespace (ADR-0038) |

---

## 2. Building

There are two products, and the second one does not come from `cargo build`:

```bash
cargo build --release                  # target/release/daer, target/release/daer-drb
cargo xtask ebpf                       # target/ebpf/datapath.o  (needs clang)
```

`daer` is the single public binary: `run`, `check`, `route`, `probe`, `schema`, `version`
(ADR-0015, `[INV-CLI-01]`). `daer-drb` is the rule-artifact producer and is *not* linked into
the daemon — `crates/daer-cli/tests/surface.rs` asserts that closure stays empty (ADR-0031).

`cargo xtask ebpf` needs a `vmlinux.h` that matches the kernel it will be loaded on. It is
per-kernel and is not vendored:

```bash
mkdir -p ebpf/headers
bpftool btf dump file /sys/kernel/btf/vmlinux format c > ebpf/headers/vmlinux.h
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
sudo ./target/release/daer run   -c config.toml --object target/ebpf/datapath.o
```

`daer.example.toml` is the annotated reference and the fixture the schema tests read; it fetches
its rule providers, so a `check` against it needs network access. For an offline run, or for a
minimal config, use the shape in [Getting Started](../tutorials/getting-started.md#3-create-a-minimal-configuration).

To ask what the daemon *would* do without touching the box, add `--dry-run`:

```bash
daer run -c config.toml --dry-run --object target/ebpf/datapath.o
```

That is the unprivileged half of the verification split in ADR-0029: it builds the generation,
validates the object against the ABI, computes the runtime parameter and reports which
capabilities the next phase would need — and returns before the port is bound, the device pair is
created, the private ingress namespace exists, any sysctl or policy route is written, or `bpf()` is
called.

A real run creates `daer0ns` and moves `daer0peer` into it before binding the listeners. If the
listener and the packet are in different namespaces, `bpf_sk_assign` can report success and the
transport stack still answers `NO_SOCKET`; the namespace is a prerequisite, not an optimization.
`ip netns list`, `ip -n daer0ns link`, and `ip -n daer0ns route` are the topology checks.

---

## 4. Verifying

The unprivileged gate, and the one to run before pushing:

```bash
cargo xtask ci
```

It runs the ABI drift check, `cargo fmt --check`, `clippy -D warnings`, `cargo test --workspace`
and `daer check --object` over the object this tree just built. It needs no capability, and
`.github/workflows/ci.yml` runs the same steps.

The two privileged gates answer different questions over different dependency closures, so
neither substitutes for the other:

```bash
cargo xtask kernel-check    # does the eBPF object load and behave?
cargo xtask e2e-check       # does a redirected flow reach the daemon and come back?
```

Both re-exec themselves under `sudo` and both report `skip` with a reason when a fixture is
missing. A skip is a fact on a laptop and a hole in CI, so `DAER_REQUIRE=<key,...>` turns a named
skip into a failure; the keys are in `docs/how-to/deployment.md`. The full script layout,
including the host-level `ops/` helpers, is documented in
[`scripts/README.md`](../../scripts/README.md).

---

## 5. Diagnosing a flow

The daemon's decisions are reachable without running it, and they come from the same loader the
daemon uses (`[INV-LOADER-01]`), so a diagnostic cannot disagree with the service:

```bash
daer route example.com --why -c config.toml
daer check -c config.toml --nodes
daer probe node <tag> -c config.toml
```
