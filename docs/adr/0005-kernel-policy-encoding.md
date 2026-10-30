---
id: ADR-0005
title: "The kernel policy table is written, and it is either provably equivalent to userspace or it defers"
status: accepted
date: 2026-10-30
scope: [datapath/policy, routing/lowering, control-plane, verification]
supersedes: []
---

# 0005. The kernel policy table is written, and it is either provably equivalent to userspace or it defers

- Status: Accepted
- Date: 2026-10-30
- Deciders: Ming Li
- Related: [ADR-0003](0003-datapath-abi.md), [ADR-0004](0004-routing-epochs.md)

---

## Context and Problem Statement

`daer run` attaches the datapath and publishes **nothing** into `routing_map`, so
`routing_meta_map[slot]` holds `0`. Reading `ebpf/kern/tproxy.c` end to end makes
the consequence unambiguous, and it is not the one the old warning claimed:

```c
active_rules_len = *active_rules_len_ptr;      /* 0 */
ret = bpf_loop(active_rules_len, ...);         /* never runs */
if (ctx->result >= 0) return ctx->result;      /* ctx->result is still -ENOEXEC */
return -EPERM;                                 /* no rule hit */
```

and every caller treats a negative `route()` as a drop:

```c
if (s64_ret < 0) { bpf_printk("shot routing: %d", s64_ret); return TC_ACT_SHOT; }
```

So an attached datapath with an empty table **drops every new TCP connection on
the attached interface**. The previous log line ("every flow takes its fallback")
described an intent the C does not implement. There is no fallback path in the
kernel for "no rule matched": absence of a rule is `EPERM`, and `EPERM` is a shot.

Two questions follow, and they are different:

1. **How does the table get written?** `daer-routing` lowers a configuration into
   `MatchSet`s for the userspace evaluator; the kernel has its own
   `struct match_set` + LPM-trie + domain-bitmap layout. Something has to translate.
2. **What if the translation cannot be faithful?** `domain(...)` is matched in the
   kernel through `domain_routing_map`, a bitmap keyed by **destination IP** that
   the datapath expects the control plane to populate from DNS answers.
   `pname(...)` is matched against `cookie_pid_map`, which only a control plane that
   tracks sockets can fill. Neither exists in `daer` today. A translator that
   ignored that difference would silently send traffic somewhere the configuration
   does not say.

## Decision

### 1. The kernel table is written, always

`daer-routing` gains a compiler from its lowered `MatchSet` list into the object's
byte layout (`daer-routing/src/kernel.rs`), and `daer-control` publishes the result
through the ADR-0004 sequence. There is no configuration for which the daemon
leaves the table empty. "No policy in the kernel" is not a representable state of a
running daemon.

The encoding is 1 `MatchSet` → 1 `struct match_set`, because that is the shape the
lowering already has (`push_each` emits one set per operand and marks all but the
last `LogicalOr`, which is exactly what the C's subrule logic consumes).

### 2. Equivalence is a property, not an intention

The kernel must agree with userspace about the verdict **class** for every flow:
`direct` stays direct, `proxy` is redirected, `block` is dropped. A kernel that says
`direct` for a flow userspace would proxy is a **leak**; a kernel that says `block`
for a flow userspace would proxy is an **outage**. Both are worse than being slow.

`KernelPolicy::equivalent` is therefore computed, not assumed, and it is `false`
whenever a construct cannot be represented exactly:

| Construct | Kernel needs | Present in `daer`? | Consequence |
| --- | --- | --- | --- |
| `dip`/`sip`, `port`, `sport`, `l4proto`, `ipversion`, `mac`, `dscp` | `routing_map` + per-entry LPM tries | written by this ADR | encodable |
| `domain(...)` | `domain_routing_map`: IP-keyed bitmap derived from **DNS answers** | no DNS-derived bitmap | **not encodable** |
| `pname(...)` | `cookie_pid_map` populated from socket tracking | not tracked | **not encodable** |
| more than `MAX_MATCH_SET_LEN` sets | array bound | — | **not encodable** |

### 3. When it is not equivalent, the kernel defers — it does not guess

A partial table is never published. Instead the daemon publishes a **one-entry**
table:

```text
routing_map[slot*MAX + 0] = { type: Fallback, outbound: OUTBOUND_CONTROL_PLANE_ROUTING }
routing_meta_map[slot]    = 1
active_routing_epoch_map  = slot
```

`MatchType_Fallback` always matches, and `OUTBOUND_CONTROL_PLANE_ROUTING` is a
reserved id the datapath turns into "hand this flow to the control plane" rather
than into a proxy decision. Every flow is then routed by the userspace `Router`,
which implements the full rule language and is the authority anyway.

**The invariant, stated once:** the kernel either reproduces userspace's answer
exactly, or it hands the flow to userspace. It never invents a third answer, and it
never drops a flow because its table is empty. This is what makes an
unrepresentable rule a performance choice instead of a correctness bug, and it is
why "defer everything" is an acceptable answer: a userspace relay hop is strictly
better than a leak or a shot.

The daemon logs which tier it is in, once, with the reason:

```text
INFO datapath policy published slot=1 entries=42 equivalent=true tier=split
WARN datapath policy published slot=1 entries=1 equivalent=false tier=defer
     because=rule 3 uses domain(suffix:…) and domain_routing_map is not maintained
```

### 4. Equivalence is asserted by a test, against the object's real layout

`daer-routing/tests/kernel_policy.rs` does three things, none of which needs a
privilege:

1. It **interprets the encoded bytes** with a Rust transcription of the C decision
   loop (`route()` / `route_loop_cb` / `route_eval_match` / `route_finalize_match`),
   including the `LogicalOr` subrule rules and the `MUST`/`DNS_QUERY` paths. Two
   implementations agreeing on a *wrong* layout is the standard way a wire format
   ships broken, so the next point matters more than this one.
2. It **pins the layout against the compiled object** — `match_set` is 24 bytes,
   `lpm_key` is 20, `MAX_MATCH_SET_LEN` is 1024 — read from the object's BTF, not
   from a comment. Without an object the test skips, exactly like `tests/object.rs`.
3. It **cross-checks against `daer_routing::first_hit`** over a corpus of flows
   generated from the same rules: for every flow, the kernel interpretation and the
   userspace evaluator must return the same outbound. Any divergence fails.

That corpus is the acceptance criterion for this ADR. A rule that the encoder
cannot represent must appear as `equivalent == false`, and the same corpus must
then show the kernel deferring for *every* flow rather than for some.

## Consequences

- An attached datapath stops being a black hole, which is the single change that
  makes `daer run` safe to start at all.
- The fast path (direct traffic never leaving the kernel) is available for
  configurations whose rules the kernel can represent, and unavailable — but
  correct — for the rest. `docs/deployment.md` states which is which.
- `domain(...)` rules are the common case in real configurations, so the honest
  expectation today is `tier=defer` for most deployments. Making it `split` needs
  the DNS-derived `domain_routing_map` (a follow-up, and it is only worth doing once
  the deferred path is proven), or sniffing-side punt rules.
- The encoder is the second consumer of `MatchSet`, which makes it a real contract
  test for the lowering: a change to how rules lower now has to keep two backends
  in agreement or CI fails.
- `MAX_MATCH_SET_LEN` moves out of a C comment into `daer-ebpf::abi` and is asserted
  against the object, so a rebuild with a different bound fails the test instead of
  truncating a rule table at run time.
