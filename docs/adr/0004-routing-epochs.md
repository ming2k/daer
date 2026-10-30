# ADR-0004 — Routing epochs: two slots, publish then switch

- Status: **accepted; sequence, map classification and the real map writes are implemented. Republishing on reload is pending**
- Date: 2026-01-07
- Scope: the kernel half of a configuration reload. The userland half is done
  (`Generations`, `Supervisor`, `tests/handover.rs`).

> **Honesty marker.** This environment has no `CAP_NET_ADMIN` and cannot create a second
> network namespace, so nothing here has been executed against a kernel. What *is* executed:
> the sequence against a fake writer with the kernel's failure modes, the map classification,
> and — per [ADR-0005](0005-kernel-policy-encoding.md) — the encoded table against the
> userspace evaluator, which is what makes the *contents* of a publish a checked claim rather
> than an intention. The verification plan at the end says what would have to pass for the
> switch itself to be called done.

## Context

A reload replaces the routing tables the kernel program reads. Three constraints shape how:

1. **The kernel cannot wait.** The tc program runs per packet on the softirq path. It cannot
   take a lock, sleep, or retry: it must read whatever is published *now* and decide.
2. **A reload must not have a window.** A packet that arrives while the tables are being
   rewritten must see either the old rules or the new ones, never a half-written table — a
   packet steered by a partially updated map is a routing decision nobody made.
3. **A bad generation must be revertible.** If the new tables turn out to be wrong (not
   invalid — *valid but misconfigured*), the operator reloads again. The previous tables must
   still be intact at that moment, not reconstructed.

The obvious implementation — clear the maps, write the new entries — violates all three.

## Decision

**Two routing slots, alternating, with a single-word switch.**

```text
  slot 0 tables ─┐
                 ├──▶  active_slot (1 word, read per packet)
  slot 1 tables ─┘
```

* A *generation* publishes into the **inactive** slot, completely, while the active slot keeps
  serving. No packet ever sees a partially written table because no packet is reading the one
  being written.
* Publication ends with **one** write that flips `active_slot`. That write is the commit point:
  before it, every packet uses the old rules; after it, every packet uses the new ones. There
  is no intermediate value an observer can see.
* The *previous* slot is left untouched until the new generation has proven itself, which is
  what makes rollback a second switch rather than a rebuild.
* The kernel program reads `active_slot` **once per packet** and uses it for every map lookup
  of that packet. Reading it twice would let a packet straddle two generations — the exact bug
  the design exists to prevent.

### Wire form

```c
/* The commit point: index of the slot the datapath must read. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);      /* 0 or 1 */
} active_routing_slot SEC(".maps");

/* Per-generation stamps, so a stale writer's late store can be rejected. */
struct routing_stamp {
    __u32 generation;
    __u32 written_at_ns;
};
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);    /* one per slot */
    __type(key, __u32);
    __type(value, struct routing_stamp);
} routing_stamp_map SEC(".maps");
```

The routing maps themselves become **per-slot**. The existing names keep their meaning and gain
a `[2]` dimension: `routing_map[slot][domain]`, `lpm_array[slot][prefix]`,
`outbound_connectivity_map[slot][outbound]`. A map that is *not* per-generation — a connection
state map, an event ring — stays single and is deliberately excluded.

### Publish sequence

```text
 1. build the generation in userland (done: Generation::build)
 2. pick slot := 1 - active_slot
 3. write every entry of the new tables into slot        (packets still use the old slot)
 4. write routing_stamp_map[slot] = { generation, now }
 5. verify: read back routing_stamp_map[slot] and compare  ──┐ mismatch → abort, old slot
 6. commit: write active_routing_slot = slot                 │ untouched, nothing to undo
 7. handoff: a short grace window during which the old slot │
    stays valid for in-flight lookups that began before (6)  │
 8. retire the old slot only after the grace window          ▼
```

Step 5 is not paranoia: a map write can fail (ENOMEM on a full hash, a table over its max
entries). Detecting that *before* the commit is the difference between a reload that did nothing
and a proxy that silently lost half its rules.

Step 7 exists because a packet may have read `active_slot` and then been preempted before its
table lookups. The grace window must exceed the time a packet can spend between those two
points; in practice that is microseconds, and the window is set in milliseconds.

### Rollback

Rollback is step 6 with the other value: `active_routing_slot = 1 - active_slot`. It requires
the old slot to still be intact, which is why step 8 is last and why retirement is not "clear
the maps" but "the slot becomes the next generation's scratch space".

A rollback triggered by *valid but wrong* configuration is the common case and needs no error
handling: the userland generation that the operator reloads compiles fresh tables and publishes
them into the now-inactive slot.

### Stale-writer defence

Two generations can be alive at once in userland (an old `Arc<Generation>` is pinned by a live
flow). Only the *publisher* writes maps, and there is exactly one publisher at a time — but
`routing_stamp_map` makes the rule checkable rather than assumed: a writer whose generation is
older than the slot's stamp must not write. This is the kernel-side analogue of
`Generations::reload` publishing only after a successful build.

### What the datapath reads, in order

```c
struct routing_stamp *stamp = lookup(&routing_stamp_map, &slot);
if (!stamp) return TC_ACT_OK;               /* unknown slot: pass through, never guess */
if (stamp->generation == 0) return TC_ACT_OK;  /* never published: pass through */
lookup routing_map[slot], lpm_array[slot], … /* one slot, read once */
```

Generation `0` is reserved as "never published" so a slot that was allocated but not filled
cannot be mistaken for a valid one — the same reason the reference implementation encodes
"unknown" as a non-zero sentinel rather than `0`.

## Consequences

- **Memory doubles for the per-generation maps.** That is the price of a window-free reload, and
  it is bounded: the tables hold rules and outbound properties, not flow state. It is stated here
  so it is a decision and not a surprise.
- **Every per-generation map must be enumerated.** A map added later that is *not* per-slot is
  either deliberately shared (connection state) or a bug: the commit does not cover it, so a
  reload would leave half of the old policy in place. `daer-ebpf::names` must therefore classify
  each map as `PerGeneration` or `Shared`, and a test must fail if a map appears in the object
  without a classification.
- **The userspace routing decision and the kernel decision must agree.** `daer-routing`'s
  `NormalizedProgram` is what both sides consume, and `tests/handover.rs` already asserts one
  connection crossing eight generations. What it cannot assert without privileges is that the
  *kernel* switched at the same commit point; that is what the verification plan below covers.
- **A generation's identity is a number, not a hash.** Operators compare log lines, and
  `GenerationId` already appears in every flow log. The policy hash stays in userland where it
  answers "did the routing change", which the kernel does not need to know.

## Verification plan (what "done" means)

Items 1–3 are done and need no privilege; item 4 needs a kernel and is not, and item 5 is
partly done.

1. ✅ **Map classification** (`daer-ebpf::names::generationality`). Every map in
   `names::map::ALL` is classified `PerGeneration` or `Shared`, and a test fails if one is not.
   The classification is a `match`, so adding a constant without classifying it is a compile
   error at that site as well.
2. ✅ **The publish sequence** (`daer-ebpf::epoch`). Written against a `MapWriter` trait and
   driven by an in-memory fake with the failure modes a real kernel has: an `ENOMEM` mid-batch,
   a stamp that writes but lands wrong, a failed commit. Asserted: **every failure leaves the
   active slot unchanged**, a stamp mismatch aborts before the commit, and generations alternate
   slots so the committed one is never the one being written.
3. ✅ **The real map writes.** `daer-control::datapath::publish_policy` writes the routing
   table, every LPM trie, the outbound connectivity entries and the two `u32` maps, in the
   order this ADR specifies. What fills the table is
   [ADR-0005](0005-kernel-policy-encoding.md), and its equivalence test is the acceptance
   criterion: an encoded table is only published when it reproduces the userspace verdict, and
   otherwise a one-entry deferral is published instead.
4. ⬜ **netns, `CAP_NET_ADMIN`:** two generations with different rules and a packet train across
   the switch. Assertion: **no packet is routed by a mix of the two generations** — the property
   the whole design exists for, and the only one that cannot be proven without a kernel.
   Republishing on reload lands with the harness, because it is the case the harness exists to
   exercise.
5. 🟡 **1000 reloads under a long-lived connection, zero drops.** The userland half passes today
   (`tests/handover.rs`, one connection crossing eight generations); the kernel half needs
   item 3's harness.

## Alternatives rejected

- **One slot, clear and rewrite.** Fastest to write and violates all three constraints: a
  window with partial rules, no rollback, and a packet can read a map mid-clear.
- **A lock in the datapath.** Not possible on the softirq path; a spinlock per packet would also
  cost more than the double memory.
- **RCU-style grace periods in the kernel.** The right tool for a kernel data structure, but the
  userspace publisher cannot express it for BPF maps, and `bpf_loop`/timers would put the
  decision on a slow path this proxy does not have.
- **Versioned map keys (`generation << 32 | key`).** Doubles the key size of every map and makes
  every lookup a shift-and-mask; the two-slot scheme gets the same property for one word read
  per packet.
