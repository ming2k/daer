---
id: ADR-0038
title: "The transparent ingress lives in a private network namespace"
status: accepted
date: 2026-11-11
scope: [architecture/boundary, datapath, transparent-ingress, packaging, cli/run]
supersedes: []
amends: [ADR-0013, ADR-0025]
---

# 0038. The transparent ingress lives in a private network namespace

- Status: Accepted
- Date: 2026-11-11
- Deciders: Ming Li
- Related: [ADR-0013](0013-datapath-state-ownership.md),
  [ADR-0025](0025-verification-at-the-privilege-boundary.md),
  [ADR-0018](0018-userspace-data-path-is-daer-relay.md)

---

## Context

The datapath redirects a host-generated flow into the `daer0`/`daer0peer` veth pair and
assigns it to a transparent listener with `bpf_sk_assign`. The listener accepted direct
connections, the helper returned success, and the connection still timed out. Kernel
tracing showed the decisive shape:

```text
tcp_v4_rcv ... reason: NO_SOCKET
```

The socket existed and was published in `listen_socket_map`; the transport stack refused to
hand the skb to it. The listener and the redirected peer were in the **same** network
namespace as the originating socket. A host-generated packet that is redirected into a peer
and immediately reassigned inside that namespace is not, for this purpose, an ordinary
ingress packet. `bpf_sk_assign` can succeed while local delivery still finds no eligible
socket.

The reference implementation (`dae`) does not put its listener on the host side. It creates a
private namespace (`daens`), moves its peer (`dae0peer`) into it, binds the transparent
listeners there, and installs the local-delivery policy there. The host keeps only the
redirect source, the host end of the pair, and the forwarding path. The namespace boundary is
what turns the reassigned packet into a normal namespace ingress packet.

This is not an aesthetic refactor. Without the boundary there is no single remaining knob to
turn: the failure is a property of the packet's namespace context, not of the listener's
socket options. More host-side sysctls, another mark, or a second redirect cannot create a
context the packet has already lost.

## Decision

1. **A private network namespace owns the ingress half.**
   [`daer_control::netns::IngressNamespace`](../../crates/daer-control/src/netns.rs) creates
   `daer0ns` and owns it as a guard. It contains:

   - `daer0peer`, the namespace end of the veth pair, with the ingress TC program attached
     inside the namespace;
   - the TCP and UDP transparent listeners, created by a thread that has entered the
     namespace;
   - the local-delivery policy (an ingress-interface rule and a `local default` route in
     table 2023, for IPv4 and IPv6);
   - the peer address, default route, and permanent neighbor that let listener replies
     leave through `daer0`;
   - the peer's martian-source and forwarding sysctls.

   The host keeps `daer0`, the TC ingress program on it, the host-side forwarding and
   martian-source sysctls, and the WAN/LAN hooks that redirect into the pair. It does not own
   a listener for redirected flows or a table-2023 rule.

2. **The namespace is created before the listeners, and owned for their lifetime.**
   `daer run` prepares the veth pair and the namespace before `Daemon::bind_in`. The listener
   file descriptors therefore belong to `daer0ns` from `socket(2)` onward. `Daemon` holds the
   namespace guard; its field drop order guarantees the listener fds close before the
   namespace is deleted. `--no-datapath` creates no namespace because nothing is redirected.

3. **The policy rule is keyed by ingress interface, not by fwmark.**
   A redirected packet arrives on `daer0peer`; that fact is what selects the local table. The
   mark is still stamped by the datapath and is still the host's ownership signal, but a
   mark-keyed rule **inside the namespace** would also match daer's own listener replies. Those
   replies are deliberately marked so the host does not recapture them; in the namespace they
   must leave through the peer, not return to `lo`. The rule is
   `ip [-4|-6] rule add iif daer0peer table 2023`, with
   `ip [-4|-6] route add local default dev lo table 2023`. Interface and route are installed
   and removed by [`RouteTable`](../../crates/daer-control/src/datapath.rs).

4. **The reply path is explicit, not an accident of the host's routing table.**
   The peer gets `169.254.0.11/32`, a link route to `169.254.0.1`, a default route through
   it, and a permanent neighbor entry for `daer0`'s MAC. IPv6 mirrors the same shape with a
   link-local host address and default route. A listener reply carries the client's original
   destination as its source (allowed by `IP_TRANSPARENT`), leaves through `daer0peer`, and is
   forwarded by the host to the client. On the way out, the listener's socket mark identifies
   the packet as daer's own traffic so the WAN egress program does not redirect it again.

5. **The host namespace's old policy routing is removed at startup.**
   A run that crashes before this release can leave a host-level mark rule in table 2023. The
   new namespace cannot remove host state, and a stale mark rule would capture marked listener
   replies. `PreparedIngress::prepare` calls
   [`clear_host_policy_routing`](../../crates/daer-control/src/datapath.rs) before creating the
   new pair. This is a one-way migration: the current architecture never installs host policy
   routing.

6. **The privilege and lifecycle are explicit.**
   Creating the named namespace, moving a link into it, entering it with `setns(2)`, and
   mounting its `/run/netns` entry require `CAP_SYS_ADMIN`. The shipped unit adds it and
   creates `/run/netns` as a runtime directory. A stale `daer0ns` from a crashed run is
   deleted before a new one is created; a clean shutdown deletes the namespace, which removes
   the peer and therefore the host end of the pair. One daer instance owns the name, the pair,
   and table 2023.

7. **No same-namespace fallback remains.**
   There is no flag to put the listener back on the host side, no "compatibility" path that
   silently binds there, and no optional netns stage. A failure to create or enter the
   namespace is a startup failure, reported with the failing `ip` or `setns` step. A daemon
   that cannot create the context its datapath requires must not pretend to proxy.

## Consequences

- `daer run` now needs `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_PERFMON` and `CAP_SYS_ADMIN`. The
  preflight reports all four by name. `daer run --no-datapath` still needs only
  `CAP_NET_ADMIN` for `IP_TRANSPARENT`, and `daer check`/`--dry-run` still need none.
- Operators can inspect the topology with `ip netns list`, `ip -n daer0ns link`,
  `ip -n daer0ns rule`, and `ip -n daer0ns route`. Those names are part of the diagnostic
  surface, not implementation trivia.
- The host no longer has a `local default` route in table 2023. A packet that is redirected but
  somehow reaches the host side has no policy route to deliver it; that is intentional: the
  only valid path is through the namespace.
- UDP listener replies are created by the same reply-socket cache as before, but through a
  [`ReplySocketFactory`](../../crates/daer-relay/src/inbound/udp.rs) that creates the socket
  on a thread inside `daer0ns`. The host-side implementation remains the default for tests
  and `--no-datapath`. The factory is the relay's only seam into the namespace; the relay
  still does not depend on `daer-control`.
- The namespace creates a hard boundary for debugging. A capture on `daer0peer` in the host
  namespace sees nothing; it has to be taken with `ip netns exec daer0ns` (or on `daer0` for
  the host side). The diagnostics guide names both.
- A reload does not recreate the namespace or rebind the listeners: reload changes routing,
  not the ingress topology. A process restart creates a fresh namespace and pair, so stale
  per-interface sysctls and routes cannot survive a crash.

## Evidence

| Claim | Falsifier |
| --- | --- |
| The listener is bound inside the namespace | `IngressNamespace::with` runs the bind on a thread that has entered `/run/netns/daer0ns`; a host-side bind would leave the fd in the host namespace and reproduce `NO_SOCKET` in the privileged end-to-end check. |
| The policy is keyed by ingress, not mark | `datapath::tests::the_policy_rule_is_keyed_by_ingress_not_by_mark` asserts the rule contains `iif daer0peer` and no `fwmark`; a mark-keyed rule sends marked listener replies back to `lo`. |
| The peer has a reply path | `IngressNamespace::configure_peer` requires address, link route, default route, and permanent neighbor; `ip -n daer0ns route` shows it. A missing route makes the listener's SYN-ACK disappear with no error in userspace. |
| A clean shutdown removes both ends | `IngressNamespace`'s drop deletes the namespace; deleting the peer removes the veth pair. `ip link show daer0` and `ip netns list` must both be empty afterward. |
| The host does not keep the old policy | `clear_host_policy_routing` runs before the pair exists, so `ip rule show` has no table-2023 entry after startup. |

`crates/daer-control/tests/netns_lifecycle.rs` is the real-kernel topology falsifier. It is
gated on `DAER_NETNS_TEST=1` because it owns `daer0ns` and `daer0`/`daer0peer`; the privileged
e2e script runs it and checks the namespace, peer move, ingress-keyed rule, return route, and
teardown. It does **not** prove `bpf_sk_assign` delivery, which needs the loaded object and a
real node.

The end-to-end falsifier remains the deployment run in
[`docs/dev/build-and-run.md`](../dev/build-and-run.md): a redirected connection must complete a
TLS/HTTP exchange through a real node with `accepted > 0`, and the same check with the
namespace step skipped must fail at `NO_SOCKET`. That negative control is what distinguishes
this fix from a listener-option change that merely moves the failure.
