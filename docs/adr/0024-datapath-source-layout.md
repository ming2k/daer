# ADR-0028 — The datapath source is split by map ownership and attach domain

- Status: accepted
- Date: 2026-11-06
- Refines: [ADR-0020](0020-datapath-is-daer-own.md)
- Enforced by: [INV-DATAPATH-ABI-01](../dev/standards/invariants.md)

## Context

ADR-0020 established that `ebpf/kern/tproxy.c` is daer's own source, and made the
loader stop repairing it. It left the file's *shape* alone: 4,394 lines in one
translation unit, holding the packet parser, the connection-tracking state machines, the
rule-matching engine, the tc/cgroup/sockmap hooks, the ring-buffer event encoder, and the
debug scaffolding.

That shape is inherited, not chosen. The previous implementation was a Go project whose
`bpf2go` directive named a single `.c` file, so every subsystem had to live in it. Nothing
in this repository depends on that constraint any more, and the cost is now paid on every
read: a change to IPv6 extension-header walking and a change to the tc redirect path are
edits to the same file, reviewed by the same diff, and easy to entangle.

Two proposals were rejected before this one:

- **Split into a decorative tree** (`core/`, `subsystems/`, `hooks/`) with ten headers.
  `core/` and `subsystems/` are names that classify nothing: they say "misc" and "more
  misc". A file called `types.h` that holds half the types and `maps.h` that holds the
  other half is worse than one file, because now a reader must search two places.
- **Stay in one file and "just clean it up".** Deleting debug scaffolding and tightening
  loops is worth doing, but it does not address the review and ownership problem: 4,394
  lines in one diff is not reviewable, and the file has no boundary to defend.

The question this ADR answers is therefore: *what is an objective cut line, so the split
is not a matter of taste?*

There is one available: **kernel state ownership**. An eBPF program's maps are its
mutable interface to the rest of the system. Two pieces of code that write the same map
must agree on locking, lifetime, generation and layout; two pieces that share no map can
be understood, reviewed and changed independently. That is a property of the code, not a
preference about directory names.

## Decision

1. **A module is a set of maps plus the code that touches them.** The cut lines are the
   map boundaries; a module owns its maps exclusively and no other module writes them
   directly. Concretely:

   | File | Owns | Attach domain |
   | --- | --- | --- |
   | `packet.h` | *no maps* | pure functions over `(data, data_end)` |
   | `conn.h` | `conn_state_map`, `redirect_track` | shared by the tc hooks |
   | `policy.h` | `routing_map`, `routing_meta_map`, `active_routing_epoch_map`, `lpm_array_map`, `unused_lpm_type`, `domain_routing_map`, `routing_handoff_map`, `outbound_connectivity_map` | shared by the tc hooks |
   | `redirect.h` | `listen_socket_map`, `daer_ifindex_map`, `fast_sock` | shared by the tc hooks |
   | `event.h` | `event_ringbuf`, `alive_block_rate_map`, `bpf_stats_map` | callable from anywhere |
   | `types.h` | *no maps* | the ABI structs every module uses |
   | `maps.h` | *declares all of the above* | — |

   `packet.h` and `types.h` own no maps because they are pure: they take bytes and return
   a parsed key. Keeping them map-free is what lets them be unit-reasoned about and reused
   by the cgroup and sockmap hooks without dragging policy state along.

2. **The attach domains are separate files, because the kernel attaches them separately.**
   `tc.c` (14 `classifier/` programs), `cgroup.c` (6 `cgroup/` programs),
   `offload.c` (`sk_skb/stream_verdict`, `fentry/`, `kprobe/`). These are not a
   classification by taste: `daer-ebpf/src/loader.rs` attaches them through different
   `aya` APIs, and a bug in one cannot be reached from the others.

3. **One translation unit still produces the object, and it is `datapath.c`.**
   `datapath.c` includes the headers and compiles to a single `datapath.o`. The files
   above are *source* boundaries, not link boundaries.

   This is deliberate and it is the load-bearing decision of this ADR. Compiling each
   module to its own `.o` and joining them with `bpftool gen object` works — it was
   confirmed against a two-file prototype, and it merges `.maps` correctly — but it moves
   cross-module inlining to the linker, which is exactly the wrong place for a BPF
   program. The verifier's 512-byte stack limit is unforgiving, and the margin that keeps
   this datapath loading today comes from clang seeing the whole call graph: it can
   decide to inline `parse_packet` into its only two callers and keep the large
   `struct parsed_packet` off the stack. Give that decision to a linker and the stack
   depth becomes an emergent property nobody controls.

   The alternative — one giant file — trades a stack-depth guarantee nobody can inspect
   for a readability problem everybody has to live with. The split keeps the guarantee
   and fixes the readability.

4. **`datapath.c` contains no logic.** It is includes, the license string, and the
   generated layout assertions. Its length is a smell detector: if it grows past ~60
   lines, something that belongs in a module was written there.

5. **Debug scaffolding is deleted, not compiled out.** `bpf_printk` is currently
   neutralised by `#define bpf_printk(...) ((void)0)` when `__DEBUG` is undefined, so it
   costs nothing at run time — but 51 dead call sites and their format strings are still
   source that has to be read, and 18 of them sit inside the routing engine where they
   obscure the control flow. Whatever a maintainer needs at debug time goes through
   `event.h`'s ring buffer, which is structured, rate-limited and useful in production
   too. The `#define` that disables the macro is deleted with the call sites, so the
   question "is this compiled in?" stops existing.

6. **`struct` and map declarations move out of the logic, in one direction only.**
   `types.h` may not include `maps.h`; `maps.h` may include `types.h`; logic modules
   include both and nothing else. This is checked by the compiler (`#include` cycles do
   not compile) and keeps the dependency graph a DAG by construction.

## Consequences

- A reviewer of the IPv6 extension-header walk reads `packet.h`. A reviewer of the
  reload path reads `policy.h`. Neither has to read the other, and the diff for each is
  bounded.
- The map-ownership table above is now the specification. A module writing another's map
  is a defect with a name, not a style opinion. `tests/object.rs` already asserts every
  map in `ebpf/abi.toml` exists; that keeps the table honest against the compiled object.
- Whole-program optimisation survives, so the stack-depth margin this datapath relies on
  is unchanged by the split. That matters because the only way to observe it is
  `BPF_PROG_LOAD`, which this change does not have access to — a split that perturbed
  stack allocation would be undetectable until the kernel tests run.
- The build does not change: `cargo xtask ebpf` still runs one `clang` and produces
  `target/ebpf/datapath.o`. `bpftool gen object` is not introduced, so no new tool is
  added to the packaging requirements in `docs/how-to/deployment.md`.
- `datapath.c` is not a business-logic file and must not become one. Its length is the
  cheapest available proxy for "somebody put logic in the assembly file".
- The scratch maps (`parse_ctx_scratch_map`, `pkt_scratch_map`, `route_ctx_scratch_map`,
  `wan_egress_route_scratch_map`) are **retained by this ADR**. They exist because the
  context structs are too large for the 512-byte stack, and whether a given one can be
  replaced by a stack local is a question only the verifier answers. Removing them is a
  separate change with its own falsifier; doing it here would couple a mechanical
  reorganisation to an unverifiable behavioural risk.
