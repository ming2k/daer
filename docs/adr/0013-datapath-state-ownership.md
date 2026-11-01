---
id: ADR-0013
title: "The datapath owns its box-global state, and the kernel's observed facts reach userspace"
status: accepted
date: 2026-02-14
scope: [datapath/ebpf, datapath/attach, control-plane/routing, datapath/udp]
supersedes: []
---

# 0013. The datapath owns its box-global state, and the kernel's observed facts reach userspace

- Status: Accepted
- Date: 2026-02-14
- Deciders: Ming Li
- Related: [ADR-0005](0005-kernel-policy-encoding.md), [ADR-0006](0006-wiring-ownership.md),
  [ADR-0011](0011-partitioned-kernel-routing.md), [ADR-0012](0012-optional-fake-ip-ebpf.md),
  [ADR-0007](0007-verification.md)

---

## Context and Problem Statement

An attached datapath did not work, and the reasons were all of one kind: state that the
kernel program needs was documented, or written for one family, or written at all — but never
owned by the code that attaches it. Six separate defects, each of which made the proxy
silently forward nothing or forward the wrong thing:

1. **No policy routing.** `tproxy.c` documents, in a comment, that a redirected packet needs
   `ip rule add fwmark 0x8000000/0x8000000 table 2023` and `ip route add local default dev lo
   table 2023`. `datapath::ensure_device_pair` created the veth pair and nothing else. A
   redirected packet reached `daer0peer`, the stack routed it as a *forwarded* packet, and it
   left the box again instead of reaching the `bpf_sk_assign`-ed listener.

2. **No `rp_filter` or forwarding sysctls.** A redirected packet arrives on `daer0peer` with a
   non-local source *and* destination, so reverse-path filtering dropped it before
   `bpf_sk_assign` mattered. Both are per-interface state that a daemon has to set and restore.

3. **Both link-layer variants attached to every interface.** The datapath has an `_l2` and an
   `_l3` variant of every hook. `attach` attached both, with a comment claiming "the datapath
   picks between them per packet". It does not: a TC classifier returns an action, and under
   `cls_bpf`/`tcx` the first program to return `TC_ACT_OK` decides. On an Ethernet interface
   the `_l3` variant parsed the MAC header as an IP header; on an L3 tunnel the `_l2` variant
   skipped 14 bytes into the IP header.

4. **`wan_lan_ingress` attached to WAN interfaces.** That program runs the WAN-ingress role
   *and then* the LAN-ingress role, so attaching it to a WAN device treated every packet
   arriving from the internet as LAN traffic to be proxied. It belongs on an interface that
   faces both, which a single-homed box does not have.

5. **The UDP listener slot was never published.** `listen_socket_map` is keyed `0` = tcp4,
   `1` = udp, `2` = tcp6. `publish_listeners` wrote `0` and `2`, with a comment saying UDP
   "has no listener yet". The datapath redirected datagrams anyway, `assign_listener(skb,
   IPPROTO_UDP)` looked up key `1`, found nothing, and returned `-1`: the packet was shot after
   the datapath had already taken it off the direct path. A user sees "UDP is broken" with no
   diagnostic anywhere.

6. **The kernel's observed facts were never read.** `routing_handoff_map` carries the client's
   source **MAC**, the packet's **DSCP**, and — through the cgroup hooks — the **process name**
   and pid. Nothing read it. `facts_with_domain` therefore built `MatchFacts` with
   `mac: [0; 6]`, `dscp: 0`, and an empty `process_name`, so every `mac(...)`, `dscp(...)`,
   and `pname(...)` rule after ADR-0011's partition boundary was accepted, lowered, and
   **inert**.

The common failure mode is worth naming, because it is what the decision is about: none of
these produced an error. Each produced a proxy that started, logged "datapath attached", and
forwarded nothing (or the wrong thing).

## Decision

1. **Attaching the datapath owns every piece of box-global state the datapath needs.** The
   returned [`Attached`](../../crates/daer-control/src/datapath.rs) handle owns the loaded
   object, the `fwmark` policy routing, and the per-interface sysctls. All three are installed
   before the first flow is served and removed when the handle drops. There is no separate
   "setup step" an operator can forget, and no documentation that describes state the code does
   not create.

2. **The link-layer variant is chosen from the interface's `ARPHRD` type, never both.** A
   `LinkKind` is read from `/sys/class/net/<if>/type`; Ethernet gets `_l2`, an L3 device gets
   `_l3`, and a device whose type has no parser stops the run with a message naming the
   interface. Guessing is worse than refusing: a wrong guess misparses every packet on that
   interface, silently.

3. **A hook is attached to the interface whose role it implements.** `lan` devices get
   `lan_ingress`/`lan_egress`; `wan` devices get `wan_ingress`/`wan_egress`. The dual-role
   programs (`wan_lan_ingress`, `lan_wan_egress`) exist for a device that faces both, and this
   build does not attach them: a single-homed box has no such device, and attaching one anyway
   is how inbound internet traffic came to be proxied as if it were a client's.

4. **The UDP listener is part of the same contract as TCP.** `Listeners` carries `tcp4`, `udp`,
   and `tcp6` as one value with no `Option`, in `daer-ebpf` so the ABI keys live in one place.
   A daemon that could not bind the datagram socket **refuses to attach** rather than
   publishing two of the three: with the datapath live, a datagram is redirected regardless,
   and a missing slot turns that into a silent drop.

5. **The kernel's facts reach the router through a trait, not a shared map handle.** A
   `KernelObserver` returns `KernelFacts` (MAC, DSCP, process name) for a flow;
   `HandoffObserver` implements it over `routing_handoff_map`. The router consults it on the
   flow path and falls back to `KernelFacts::default()` when there is no datapath — which is
   the honest answer for `--no-datapath`, for `daer route explain`, and for every test. A rule
   that needs a fact nobody observed must not match by accident.

6. **`pid == 0` means the process name is unknown, not empty.** The cgroup hooks populate
   `cookie_pid_map`; this build does not attach them, so the C leaves `pname` empty and `pid`
   zero. Reporting the empty array as a name would let `pname()` match the empty string.

## Consequences

- `daer run` has one ordering constraint it did not have: the observer exists only after the
  datapath is attached, so the serving generation is **rebuilt** with it (a second compile,
  through the same `Generations::reload` the `SIGHUP` path uses). A rebuild failure is a
  warning, not a refusal: address-and-domain matching is correct but degraded, and refusing to
  serve would be worse than serving without `mac(...)`.

  **Observable consequence**: a datapath run starts on `gen2`, not `gen1`, because the first
  compile is the address-only generation and the rebuild replaces it. The log says so
  (`generation rebuilt with the datapath's flow facts`), and `daer route explain` builds its own
  generation anyway, so no diagnostic depends on the number. With `--no-datapath` the daemon
  stays on `gen1`, which is what a reader comparing two logs should expect.
- The datapath's box-global state is process-global. Two `daer` instances on one box would
  fight over the same rule and table; that was already true of the veth pair, and the answer is
  the same — one instance per network namespace.
- `Attached::with_ebpf` hands out `&mut Ebpf` under a lock, because `aya`'s map writes need
  `&mut` and the observer needs the same object. The lock is held for one map operation and
  never across an `await`.
- A `mac(...)`/`pname(...)`/`dscp(...)` rule now matches on the flow path and still does not
  match in `daer route explain`, which has no flow and therefore no map key. That asymmetry is
  intentional and is the difference between "what the kernel saw for this flow" and "what the
  rules say about a hypothetical one".

## Evidence

Each defect has a falsifier that fails against the previous behaviour:

| Claim | Falsifier |
| --- | --- |
| A reply leaves from the original destination | `datagram::tests::a_relay_forwards_both_directions_through_direct` asserts the recorded source; sending from the listener fails it |
| One client port, two destinations, two sessions | `datagram::tests::one_client_port_talking_to_two_destinations_gets_two_sessions`; a client-keyed table sends the second datagram to the first origin |
| A `mac(...)` rule fires when the datapath supplied one | `decide::tests::a_mac_rule_matches_only_when_the_datapath_supplied_the_mac` |
| A `pname(...)` rule fires only for the observed process | `decide::tests::a_pname_rule_matches_only_when_the_datapath_supplied_the_process` |
| `pid == 0` is unknown, not empty | `decide::tests::a_pid_of_zero_reports_the_process_name_as_unknown` |
| The handoff value is the C's layout | `abi`'s `const` size assertions, verified against `cc` + `offsetof` (36 bytes, 4-byte align; 48 for the entry) |
| An IPv4 handoff key matches the C's `union ip6` | `handoff::tests::an_ipv4_key_matches_the_c_union_layout` |

The kernel-side claims (`policy routing delivers`, `the L2/L3 split parses correctly`) need a
privileged box; `crates/daer-ebpf/tests/kernel.rs` is the gated test that loads and attaches the
object, and it is the only place a verifier rejection is visible.

## The netune version boundary

`daer` pins `netune` at a tag (`v0.0.5`) and verifies the lock with `--locked`. The netune work
the observability half of this change wants — a `TraceSink` so a long-lived relay gets a stream
rather than a ring window (netune ADR-0010) — is carried in `v0.0.5`.

That is recorded rather than worked around:

* `daer-outbound::observe` measures the one span it can observe at a seam it owns (start of the
  dial to the dial returning) and says so in its module documentation. It does **not** claim a
  per-phase breakdown, because the phases live in a `Recorder` no connector hands back.
* `DialObserver::observe` and `DialObserverSink` bridge streaming trace events to installed
  observers.
* Local co-development uses `.cargo/config.local.toml` (git-ignored, opt-in via
  `cargo --config`), which patches the netune crates to the sibling working tree. The committed
  `Cargo.toml` keeps the tag, and `cargo check --locked` is what proves the released
  combination still builds.

The rule this leaves behind: **a capability daer needs is not consumed until the tag it depends
on carries it.** The alternative — a `[patch]` in the committed manifest, or a lock file holding
a path dependency — makes the published build depend on a working tree nobody else has.
