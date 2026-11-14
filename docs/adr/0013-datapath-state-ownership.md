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

2. **No `rp_filter`, `accept_local` or forwarding sysctls.** A redirected packet arrives on
   `daer0peer` with a non-local source *and* destination, so reverse-path filtering dropped
   it before `bpf_sk_assign` mattered. A host-generated flow is worse: its source is a local
   address on another interface, which the kernel classifies as a martian source unless
   `accept_local` is set. All of them are per-interface state that a daemon has to set and
   restore.

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
   `lan_ingress`/`lan_egress`; `wan` devices get `wan_ingress`/`wan_egress`. A device cannot
   be both: the config/startup gate rejects an interface that appears in both lists. The
   old dual-role programs (`wan_lan_ingress`, `lan_wan_egress`) were removed rather than
   left unattached; supporting a single-interface dual-role topology would be a separate
   feature with its own attach plan and falsifier.

4. **The UDP listener is part of the same contract as TCP.** `Listeners` carries `tcp4`,
   `udp4`, `tcp6`, and `udp6` as one value with no `Option`, in `daer-ebpf` so the ABI keys
   live in one place. A daemon that could not bind a datagram socket **refuses to attach**
   rather than publishing three of the four: with the datapath live, a datagram is redirected
   regardless, and a missing slot turns that into a silent drop.

5. **The kernel's facts reach the router through a trait, not a shared map handle.** A
   `KernelObserver` returns `KernelFacts` (MAC, DSCP, process name) for a flow;
   `HandoffObserver` implements it over `routing_handoff_map`. The router consults it on the
   flow path and falls back to `KernelFacts::default()` when there is no datapath — which is
   the honest answer for `--no-datapath`, for `daer route`, and for every test. A rule
   that needs a fact nobody observed must not match by accident.

6. **`pid == 0` means the process name is unknown, not empty.** The six cgroup v2 hooks
   populate `cookie_pid_map`; the loader attaches them to the unified hierarchy at startup.
   The C leaves `pname` empty and `pid` zero for sockets it did not observe (for example a
   LAN client, which has no local process). Reporting the empty array as a name would let
   `pname()` match the empty string.

## Consequences

- `daer run` has one ordering constraint it did not have: the observer exists only after the
  datapath is attached, so the serving generation is **rebuilt** with it (a second compile,
  through the same `Generations::reload` the `SIGHUP` path uses). A rebuild failure is a
  warning, not a refusal: address-and-domain matching is correct but degraded, and refusing to
  serve would be worse than serving without `mac(...)`.

  **Observable consequence**: a datapath run starts on `gen2`, not `gen1`, because the first
  compile is the address-only generation and the rebuild replaces it. The log says so
  (`generation rebuilt with the datapath's flow facts`), and `daer route` builds its own
  generation anyway, so no diagnostic depends on the number. With `--no-datapath` the daemon
  stays on `gen1`, which is what a reader comparing two logs should expect.
- The datapath's box-global state is process-global. Two `daer` instances on one box would
  fight over the same rule and table; that was already true of the veth pair, and the answer is
  the same — one instance per network namespace.
- `Attached::with_ebpf` hands out `&mut Ebpf` under a lock, because `aya`'s map writes need
  `&mut` and the observer needs the same object. The lock is held for one map operation and
  never across an `await`.
- A `mac(...)`/`pname(...)`/`dscp(...)` rule now matches on the flow path and still does not
  match in `daer route`, which has no flow and therefore no map key. That asymmetry is
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

`daer` pins `netune` at a tag (`v0.0.28`) and verifies the lock with `--locked`. The transport
observability this change consumes is carried by that release:

* `TraceCollector` is the one cold-path handle (netune ADR-0018); `Recorder` is no longer
  public, and byte events can only enter a trace through a typed `Tap`.
* A dial that nobody observes uses `TraceCollector::disabled()`: no event is recorded,
  no sink is installed, and no ring is filled. This is the production default on the
  per-flow path.
* When a `DialObserver` is installed, `ObservedDialer` creates one collector with a
  `DialObserverSink`, so netune's DNS/TCP/TLS marks stream to the observer and the final log is
  derived through netune's own `derive`. The phases are measurements, not a wall-clock total
  relabelled as a handshake.
* `DialObserver::observe` and `DialObserverSink` bridge streaming trace events to installed
  observers.
* Local co-development may patch the netune crates to the sibling working tree. The committed
  `Cargo.toml` keeps the tag, and `cargo check --locked` is what proves the released
  combination still builds.

The rule this leaves behind: **a capability daer needs is not consumed until the tag it depends
on carries it.** The alternative — a `[patch]` in the committed manifest, or a lock file holding
a path dependency — makes the published build depend on a working tree nobody else has.

## Addendum — the state is namespace-local (ADR-0038)

The decision above said the datapath owns its "box-global" state. That was true of the first
implementation, but it was also the source of a production defect: a redirected host flow and
its transparent listener shared one network namespace, and the transport stack could return
`NO_SOCKET` after a successful `bpf_sk_assign`.

[ADR-0038](0038-private-ingress-network-namespace.md) keeps the ownership principle and moves
the scope boundary:

- `daer0peer`, the transparent listeners, `table 2023`, the peer's `rp_filter`/
  `accept_local`/forwarding knobs, and the peer TC program live in the private namespace
  `daer0ns`.
- `daer0`, the host-side forwarding knobs, and the host TC program stay in the host namespace.
- The policy rule is `iif daer0peer table 2023`, not `fwmark … table 2023`. The mark remains
  the datapath's ownership signal; a mark-keyed rule in the namespace would capture the
  listener's deliberately marked replies.

Everything below about link-layer selection, listener publication, and observed facts still
applies unchanged. The `Attached` guard now also holds the namespace through its route and
sysctl guards, so dropping it removes the namespace's policy before the namespace itself is
deleted.

## Addendum — dual-stack listener slots

The original decision had three `listen_socket_map` keys and made all datagrams use key `1`.
That was sufficient for IPv4 but made a redirected IPv6 datagram look deliverable while being
assigned to a socket that could not receive it. The current ABI has four keys, one per
(protocol, family): `0` = tcp4, `1` = udp4, `2` = tcp6, `3` = udp6. `Listeners` carries all
four fds, and `Daemon::listeners` refuses to attach if either datagram socket is missing, for
the same reason it already refused a missing TCP or UDP slot. `tests/object.rs` pins the map's
`max_entries` to four, so an object built with the old layout cannot silently pass.

## Addendum — TCX is opt-in until the privileged gate proves it

> Superseded by [ADR-0042](0042-tcx-only-linux-6-6.md): TCX is now the only attachment
> mode, classic `cls_bpf` and `daer-cleanup` are deleted, and Linux 6.6 is the minimum.

Classic `cls_bpf` is the default because it is the only attachment mode this data path has
been proven on end to end. `DAER_TC_ATTACH=tcx` selects TCX (`bpf_link`) for the privileged
transparent-path test: the host filter becomes fd-owned, so a `SIGKILL` detaches it, and no
`clsact` qdisc is created.

TCX is not the default until the real-daemon delivery check
(`sudo DAER_TC_ATTACH=tcx scripts/ops/daer-netns-e2e.sh --config <config>`) shows that
`bpf_sk_assign` delivers the redirected flow on a Linux 6.6+ kernel. A successful attach is
not that proof; an earlier TCX trial attached but left the assigned packet short of the
listener's accept queue. The privileged kernel suite has the TCX attach test, but attachment
alone is not delivery. At the time, until the delivery check was green, `daer-cleanup` kept
its host-filter duty.

## Addendum — host-global forwarding settings are prerequisites

The original decision made the datapath own every box-global setting it needed, including
`ip_forward`, `all.forwarding`, `all.rp_filter` and `all.arp_filter`. That ownership is
wrong for process-independent policy: after a `SIGKILL` the value remains until the next
start, and the next start cannot distinguish daer's value from the operator's baseline.
Those settings are now checked before any mutation and never written; the daemon still owns
the per-device `daer0`/`daer0peer` knobs and the namespace-local knobs, which die with their
devices. The operator's prerequisites are in
[`docs/how-to/deployment.md`](../how-to/deployment.md#host-sysctls).
