# ADR-0003 — The datapath object is an external artifact with its own ABI

- Status: accepted
- Date: 2026-01-07

## Context

The kernel datapath is C (~4,400 lines, with kernel-version probes and its own
in-kernel tests). It is compiled by clang into an object that `daer-ebpf` loads
through `aya`; `daer` does not rewrite it, and does not link it.

That makes the object an **external artifact with an ABI of its own**: map names,
program names, section names and the parameter struct are its vocabulary, not
daer's. Two kinds of coupling follow, and they need different answers:

1. **The loader must adapt to the object.** Its section syntax is `ebpf-go`'s, not
   `aya`'s.
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

## Decision

1. **Never fork the C source, and never patch the object at build time.**
   `daer` loads whatever object it is handed — built from its own datapath source,
   or by a distribution — so the loader must accept that source's section syntax.
2. **Normalize section names in the loader** (`daer_ebpf::elf::normalize_section_names`,
   called from `loader::load`):
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
4. **The test suite asserts the ABI against the real object.** `tests/object.rs`
   normalizes the object the same way the loader does, then checks that every map
   and program name `daer-ebpf` references actually exists and that the licence
   section is kernel-legal. Without an object the tests skip; with one they are
   the ABI contract.
5. **daer's identifiers are `daer`'s.** The Rust side names things for their role
   (`RuntimeParam`, `device_ifindex`, `DEVICE_IFINDEX`, `set_device_ifindex`), even
   where the *value* is a foreign string (`"dae_ifindex_map"`). String values are
   the object's ABI and must match byte for byte; identifier names are ours and
   must not smuggle a product name into daer's source. The userspace-visible device
   names (`daer0`, `daer0peer`) are daer's to choose, because they are created in
   userspace.
6. **Constants have one source.** Map names, program names and
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
- Follow-up, in order: (a) own the datapath source — vendor it, rename its
  identifiers to `daer*`, and revalidate the object with `cargo xtask ebpf`; (b) generate
  `names.rs` from the datapath's sync spec and fail CI on drift. Until (a) lands,
  a handful of string values still carry the old prefix, and that is visible rather
  than hidden.
