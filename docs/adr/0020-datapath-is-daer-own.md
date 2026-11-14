# ADR-0020 — The datapath source is daer's own

- Status: accepted
- Date: 2026-11-06
- Supersedes: [ADR-0003](0003-datapath-abi.md)

## Context

ADR-0003 declared the C datapath an **external artifact with a foreign ABI**, and drew
two consequences from that premise: the C source must not be edited, and the loader must
adapt to whatever spelling it finds. Both consequences were wrong, and the second one cost
a production outage.

The premise was that `ebpf/kern/tproxy.c` is "not ours to edit" because the Go
implementation `dae` also loads it. That premise stopped being true the moment this
repository became a Rust project: nothing in the build, the test suite, the service unit or
the packaged artifact involves Go. `daer` is a Rust binary that loads an object it compiles
itself with `cargo xtask ebpf`.

What the premise bought us was a load-time ELF rewriter (`daer-ebpf/src/elf.rs`) that
renamed sections from `ebpf-go`'s spelling (`tc/<name>`, `sk_skb/tcp_offload_redirect`) to
`aya`'s (`classifier/<name>`, `sk_skb/stream_verdict`). It renamed them in the ELF section
header table and **not** in `.BTF` / `.BTF.ext`, where `aya` actually looks them up. The
lookup therefore missed, the program's own BTF `func_info` was dropped, and after `aya`
linked `.text` callees in, the first surviving record sat at instruction 3. The kernel
refused the load before executing a single instruction:

```text
the BPF_PROG_LOAD syscall returned Invalid argument (os error 22).
Verifier output: nonzero insn_off 3 for the first func info record
stack depth max 0
processed 0 insns (limit 1000000)
```

`daer.service` crash-looped until systemd's start limit tripped. The unit test suite was
green throughout, because it asserted that `func_info` was *non-empty* rather than that its
first record was at instruction 0 — the invariant the kernel checks.

Three lessons, each of which becomes a rule below:

1. A compatibility layer for a consumer that does not exist is pure liability. It is code
   that only runs in production, on the artifact nobody unit-tests.
2. Foreign vocabulary in our source (`dae_param`, `dae0`, `dae_socket_mark`) made it look
   as if the source were not ours, which is what invited rule 1 in the first place.
3. A test that asserts a weaker property than the system enforces is worse than no test: it
   manufactures confidence.

## Decision

1. **`ebpf/kern/tproxy.c` is daer's source, and it is edited freely.** There is no second
   consumer to protect. Section names, struct names, map names and program names use daer's
   vocabulary, and every choice is justified by what `aya` and the kernel need — not by what
   another loader happens to accept.
2. **Sections are written in the form `aya` parses natively.** `SEC("classifier/<name>")`
   for tc classifiers and `SEC("sk_skb/stream_verdict")` for the sockmap program. This is
   also valid `libbpf` and `ebpf-go` syntax, so the choice is not parochial; it simply
   removes the need to rewrite anything.
3. **The `dae` prefix is removed from the datapath.** `struct dae_param` → `struct
   daer_param`, `dae0_ifindex` → `daer0_ifindex`, `dae_ifindex_map` → `daer_ifindex_map`,
   `dae_event` → `daer_event`, `tproxy_dae0_ingress` → `tproxy_daer0_ingress`, and so on.
   The string values are the ABI and change with the C, in one commit, on both sides. The
   device names were already inconsistent — `daer-control` created `daer0`/`daer0peer`
   while `daer-common` still exported dead `dae0`/`dae0peer` constants — and this resolves
   that in favour of the names the running daemon actually creates.
4. **`daer-ebpf/src/elf.rs` is deleted.** With the source spelling sections natively and
   the ABI vocabulary unified, the rewriter has no input that needs it. An object built from
   this tree loads as-is. There is no compatibility path for a foreign object, because no
   such object exists: `daer` ships its own artifact, and the loader is not a distribution
   channel for somebody else's build.
5. **The loader's job is to load, not to repair.** `loader::load` hands the bytes to
   `EbpfLoader` with the runtime parameter overridden and nothing else. A section name
   `aya` does not understand is a build error caught by `tests/object.rs`, not something to
   be guessed at during startup.
6. **The ABI assertion is the kernel's, not a weaker proxy for it.** `tests/object.rs`
   reproduces `aya`'s `relocate_calls` step with the same `text_sections` set `aya::bpf`
   builds, then asserts that every program's first `func_info` record is at instruction 0.
   That runs unprivileged, fails on the pre-fix code with the production message, and is the
   regression guard this ADR exists for.

## Consequences

- One place to change a name, one artifact, one loader path. `cargo xtask ebpf` produces an
  object that loads without any post-processing.
- `daer-ebpf` loses ~370 lines of ELF surgery and the 32/64-bit, both-endiannesses test
  matrix that came with it. What remains is `abi`, `names`, `loader`, `publish`, `epoch`,
  `handoff` and `listeners` — all of which describe the object, not repair it.
- The `daer0`/`daer0peer` device names, the `daer_ifindex_map` map, the `tproxy_daer0_ingress`
  program and the `daer_param` global are all daer's to name. Nothing in the repository
  spells `dae` as an owner anymore.
- Removing the rewriter removes the only code path that could load a *third-party* object.
  That is deliberate: it was also the only code path that could corrupt one. If daer ever
  needs to accept a foreign object, that is a new ADR with its own falsifier — not a
  revived compatibility layer.
- `docs/how-to/deployment.md` keeps the `nonzero insn_off` entry in its failure table: it
  is now a *build* failure that `tests/object.rs` catches, and the entry tells a reader
  arriving from an old binary what they were looking at.

> Note (2026-11-14): the inherited TCP-offload/sockmap section names discussed above are
> historical. That path was removed because no Rust control plane attached it; see the
> amendment to [ADR-0024](0024-datapath-source-layout.md).
