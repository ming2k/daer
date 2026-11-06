# ADR-0003 — The datapath object is an external artifact with its own ABI

- Status: **Superseded by [ADR-0020](0020-datapath-is-daer-own.md)**
- Date: 2026-01-07
- Superseded: 2026-11-06

> **This decision no longer applies.** Its premise — that `ebpf/kern/tproxy.c` is a foreign
> artifact that must not be edited — stopped being true when the repository became a Rust
> project. The load-time section-name rewriter it mandated renamed sections in the ELF header
> without renaming them in `.BTF`/`.BTF.ext`, which dropped every program's `func_info` and
> made the kernel reject the load with
> `nonzero insn_off 3 for the first func info record`. That took `daer.service` down in
> production while the test suite was green.
>
> [ADR-0020](0020-datapath-is-daer-own.md) replaces it: the C source is daer's, it spells
> sections the way `aya` parses natively, and the rewriter is deleted. The constant-generation
> follow-up this ADR promised (decision 7) is [ADR-0021](0021-kernel-abi-single-source.md).
>
> The text below is kept as the record of what was decided and why it failed.

## Context

The kernel datapath is C (~4,400 lines, with kernel-version probes and its own
in-kernel tests). It is compiled by clang into an object that `daer-ebpf` loads
through `aya`; `daer` does not link it into the binary.

That makes the object an **external artifact with an ABI of its own**: map names,
program names, section names and the parameter struct are its vocabulary, not
daer's. Two kinds of coupling follow, and they need different answers:

1. **The loader must adapt to the object it is given.** A distribution may hand
   `daer` an object built by a different (older) copy of the C source.
2. **daer's own identifiers must stay daer's.** A Rust constant that happens to
   hold a foreign string value is still daer code, and must be named for the role
   it plays.

That arrangement has a seam that is easy to miss: **section names are part of the
object's interface, and the two loaders disagree about them.**

| Section in the C source | `ebpf-go` | `aya-obj` 0.3 (`ProgramSection::from_str`) |
| --- | --- | --- |
| `SEC("tc/lan_egress_l2")` | tc classifier | `InvalidProgramSection` — only `classifier` is known |
| `SEC("sk_skb/tcp_offload_redirect")` | stream verdict (attach type given by the Go side: `AttachSkSKBStreamVerdict`) | `InvalidProgramSection` — only `stream_parser` / `stream_verdict` are known |

`daer-ebpf`'s object test was red on a real object for exactly this reason
(`Object::parse` failed on `tc/lan_egress_l2`), while the map/program name tables
it asserts were correct. The ABI was fine; the *parse* was not.

`ebpf-go` accepts both spellings (`{"tc", SchedCLS}` and `{"classifier", SchedCLS}`
are adjacent entries in its `getProgType` table, and `sk_skb/stream_verdict` is the
canonical name for the attach type the Go side uses), so the disagreement is not
inherent to the shared source: it is a spelling choice that only `aya` constrains.

## Decision

1. **The C source spells sections the way `aya` accepts.** Every tc program uses
   `SEC("classifier/<name>")` and the sockmap program uses
   `SEC("sk_skb/stream_verdict")`. `ebpf-go` accepts both, so the shared source is
   compatible with both loaders without any build-time patching and without a fork.
   This is the primary fix: an object built from this tree needs no rewriting at all.
2. **The loader still normalizes, for objects it did not build.**
   `daer_ebpf::elf::normalize_section_names` (called from `loader::load`) adapts an
   object produced by an older or third-party copy of the C source, which still
   carries `tc/` and `sk_skb/tcp_offload_redirect`:
   - `tc/<name>` → `classifier/<name>` (the suffix is preserved: it is what a
     human reads in `bpftool prog show`);
   - `sk_skb/<name>` → `sk_skb/stream_verdict` when `<name>` is not one of the two
     names `aya` knows, because that is how the datapath's stream-verdict program
     is attached; `tcp_offload_redirect` is the only such program.
   Everything else is left untouched, so an unsupported program still fails
   loudly in `aya` instead of being guessed at.
3. **The rewrite is a pure function over bytes, and it does not move existing
   data.** Renamed sections are *longer* than the originals, so an in-place edit
   is impossible. Extending the existing `.shstrtab` is also unsafe: clang emits
   one string blob that serves as both the section-name table and the
   symbol-name table (`e_shstrndx` and `.symtab`'s `sh_link` point at the same
   section), so rewriting it breaks every symbol name — which is exactly the
   `BtfError(InvalidSymbolName)` observed during development. The implementation
   therefore appends a new string table *and* a new section header table, then
   repoints `e_shoff`, `e_shnum` and `e_shstrndx`; no byte that existed before
   changes meaning.
4. **A renamed section must be renamed in `.BTF` and `.BTF.ext` too.** This is a
   correction to the first version of this decision, which renamed only the ELF
   section header table. `aya` keys `btf_ext.func_info` / `line_info` by the section
   names in the `.BTF` string table and looks them up by the ELF section name; when
   the two disagree the program's own `func_info` is silently dropped, and after
   `aya` links `.text` callees in, the first record sits at instruction `N > 0`. The
   kernel rejects that load outright:
   `nonzero insn_off 3 for the first func info record` (`EINVAL`, os error 22), which
   is precisely how the packaged `daer.service` failed in production. The rewrite
   therefore appends the new names to `.BTF`'s string section, repoints every
   `sec_name_off` in `.BTF.ext`'s `func_info`, `line_info` and `core_relo`
   subsections, and updates both sections' `sh_offset` / `sh_size`.
5. **The test suite asserts the ABI against the real object, past the point where
   the bug appears.** `tests/object.rs` normalizes the object the same way the
   loader does, checks that every map and program name exists, that the licence is
   kernel-legal, and — because a parse-level check is not enough — reproduces aya's
   `relocate_calls` step with the same `text_sections` set and asserts that every
   program's first `func_info` record is at instruction 0. That assertion fails on
   the pre-fix code with the exact production message, and it needs no `CAP_BPF`.
   Without an object the tests skip; with one they are the ABI contract.
6. **daer's identifiers are `daer`'s.** The Rust side names things for their role
   (`RuntimeParam`, `device_ifindex`, `DEVICE_IFINDEX`, `set_device_ifindex`), even
   where the *value* is a foreign string (`"dae_ifindex_map"`). String values are
   the object's ABI and must match byte for byte; identifier names are ours and
   must not smuggle a product name into daer's source. The userspace-visible device
   names (`daer0`, `daer0peer`) are daer's to choose, because they are created in
   userspace.
7. **Constants have one source.** Map names, program names and
   `MAX_MATCH_SET_LEN` must be generated from upstream's
   `common/consts/ebpf_sync_spec.json` (the Go side already does this via
   `cmd/generators/gen_ebpf_sync`); hand-written duplicates in `names.rs` are a
   placeholder until that generator exists, and the object test is what keeps the
   placeholder honest.

## Consequences

- An object built by either project loads, unchanged, which is the whole point of
  keeping the C datapath shared.
- `daer-ebpf` owns a small, well-tested amount of ELF surgery (32/64-bit, both
  endiannesses). It is covered by unit tests over synthetic objects plus the
  integration test over the real one.
- If upstream renames a program or map, the test fails at the ABI assertion, not
  with a verifier error at runtime.
- The `.BTF` / `.BTF.ext` rewrite is the part that a parse-only test cannot see, and
  it failed in production once. Any future change to section naming must keep
  `every_program_keeps_a_verifier_legal_func_info_after_linking` green; that test is
  the regression guard for this ADR, not the name-table assertions.
- Follow-up, in order: (a) own the datapath source — vendor it, rename its
  identifiers to `daer*`, and revalidate the object with `cargo xtask ebpf`; (b) generate
  `names.rs` from the datapath's sync spec and fail CI on drift. Until (a) lands,
  a handful of string values still carry the old prefix, and that is visible rather
  than hidden.
