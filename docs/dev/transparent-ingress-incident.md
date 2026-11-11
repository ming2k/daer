# Transparent ingress: the `NO_SOCKET` incident and its safeguards

- Status: resolved in `0.0.11`
- Date: 2026-11-11
- Decision: [ADR-0038](../adr/0038-private-ingress-network-namespace.md)
- Applies to: `daer-control`, `daer-relay`, the eBPF datapath, the service unit

This is the internal record of why the transparent path served nothing even though
`daer` loaded the object, bound the port, and logged `datapath attached`. It exists so
the next person does not have to rediscover the same five layers from a packet capture.

## 1. The observable failure

A host-local `curl` to a proxied destination timed out. The transparent listener accepted
a direct connection, the datapath was attached, and `bpf_sk_assign` reported success, but
the transport stack dropped the assigned packet:

```text
tcp_v4_rcv ... reason: NO_SOCKET
```

The listener was in the host network namespace, the same namespace as the originating
socket. A successful `bpf_sk_assign` was not enough: the packet was not an ordinary
namespace-ingress packet when the stack tried to find a socket for it.

The rest of the failure chain only became visible after that first defect was moved:

| Symptom | Evidence | Root cause |
| --- | --- | --- |
| TCP listener queue held connections; no `accepted redirected flow` | `ss` in `daer0ns` showed `Recv-Q` on the listener | TCP accept and the datagram relay shared one task; a blocking UDP operation starved `accept(2)` |
| DNS replies disappeared | `datagram reply failed error=operation would block` | Tokio's `try_send_to` returned `WouldBlock` from stale/empty readiness without attempting the syscall |
| A slow node stalled unrelated clients | accept loop logged one flow then stopped accepting | `Decide::decide` (including the dial) ran inline in the accept loop |
| Health probes were recaptured as client traffic | UDP to the node's proxy port appeared as a `datagram flow decided` | probe sockets did not carry daer's socket mark |
| Fixed groups were probed and marked unhealthy | `node probe failed ...` for `policy = fixed(0)` | fixed groups were included in the probe table |

## 2. The topology that fixes the first defect

The host keeps only the redirect source and forwarding path. The private namespace
`daer0ns` owns the ingress half:

```text
host netns                              daer0ns
┌──────────────────────────┐            ┌──────────────────────────────┐
│ wlan0 / LAN tc hooks     │            │ daer0peer + peer ingress TC  │
│ daer0 (veth, no address) │◀── veth ──▶│ TCP/UDP transparent listeners│
│ host forwarding + sysctl │            │ iif daer0peer -> table 2023  │
└──────────────────────────┘            │ local default, return route  │
                                        └──────────────────────────────┘
```

The rule is **`iif daer0peer table 2023`**, not `fwmark ... table 2023`. Listener replies
are deliberately marked so the host treats them as daer's own egress; a mark-keyed rule
inside the namespace would route those replies back to `lo`. The listener replies leave
through the peer's default route, and the host forwards them to the client.

The implementation is split at the namespace boundary:

- [`daer-control::netns`](../../crates/daer-control/src/netns.rs) creates the namespace,
  moves the peer, configures the peer address/default route/permanent neighbor, and owns
  cleanup.
- [`daer-control::datapath`](../../crates/daer-control/src/datapath.rs) attaches the peer
  hook inside the namespace, installs the namespace-local table, and detaches the peer
  link on a thread that is inside the namespace. Aya's classic `cls_bpf` link detaches by
  ifindex in the *current* namespace; doing it on the host would target the wrong device
  after the peer moved.
- [`Daemon`](../../crates/daer-control/src/daemon.rs) owns `PreparedIngress` and binds the
  listeners inside it. The ingress field is declared after every socket, so the namespace
  outlives the listener fds.

## 3. The concurrency that fixes the second and third defects

`Daemon::serve` does not `join!` the TCP loop and UDP relay into one task. It starts the
datagram relay in its own task and drives the TCP accept loop separately:

```text
accept(2) ──▶ spawn flow task ──▶ decide + dial ──▶ splice
     │
     └── never awaits a routing decision or a dial

UDP ingress ──▶ datagram relay task ──▶ per-peer reply tasks
```

Two properties follow:

1. A slow or blocked UDP path cannot stop the TCP loop from polling `accept(2)`.
2. A slow node dial for one client cannot prevent the next client from being accepted.

The second property is implemented in
[`serve_parallel`](../../crates/daer-relay/src/serve.rs) and falsified by
`serve::tests::a_slow_decision_does_not_block_accepting_the_next_flow`: a gated decider
parks the first flow, the test connects a second client, and asserts `accepted >= 2` before
the gate is released. The old inline loop reaches one accepted flow and fails that assertion.

The datagram half remains independent on shutdown as well: the relay task observes the same
notification, is aborted after the TCP loop stops, and live peer replies are not tied to the
TCP accept loop's lifetime.

## 4. The reply-socket correction

The original reply cache used Tokio's `try_send_to`. `try_io` returns `WouldBlock` without
calling `send_to` when its readiness value is empty, which is exactly what a freshly created
namespace socket can present. That made the relay destroy the session on the first DNS reply
and report:

```text
datagram reply failed error=operation would block
```

The reply path is synchronous by design, so it now uses `std::net::UdpSocket`:

- the namespace factory creates the socket inside `daer0ns`;
- the socket is nonblocking, but the reply path calls `send_to` directly (not through Tokio
  readiness) and retries a few times on a genuine transient `WouldBlock`;
- the cache remains bounded at [`REPLY_SOCKET_CACHE`](../../crates/daer-relay/src/inbound/udp.rs);
- TCP and UDP reply sockets still carry `so-mark`.

The safeguard `inbound::udp::tests::the_reply_socket_factory_is_the_socket_that_sends`
uses a factory-created loopback socket and asserts that the bytes came from that socket.
The test would fail if the factory were bypassed and `bind_source` tried to bind a
non-local source in an unprivileged test.

## 5. The health-probe corrections

Health checkers are daer sockets. They must carry the same `so-mark` as dialers, listeners,
and UDP reply sockets, or the WAN egress hook recaptures them as client flows. The
instruments are now built with the router's socket mark.

Two related corrections avoid false node health signals:

- a bare `udp-dns` address means port 53, not a name to resolve and not the node's proxy
  port;
- a `policy = fixed(n)` group is not in the probe table. A probe must not rewrite an
  explicit operator choice.

The tests are:

- `health::tests::a_bare_udp_dns_address_uses_the_conventional_port`;
- `health::tests::a_fixed_group_has_nothing_to_probe`.

## 6. Verification and operational forensics

The path is only considered proven when a redirected flow completes an origin exchange and
the daemon log names the proxy outbound:

```text
accepted redirected flow ... destination=...
flow decided ... outbound=proxy
dial finished dial=proxy→example.com:443 ...
flow closed ... to_upstream=1921 to_client=6509
```

The real-kernel lifecycle falsifier is
[`crates/daer-control/tests/netns_lifecycle.rs`](../../crates/daer-control/tests/netns_lifecycle.rs).
It owns `daer0ns` and the pair, so it is gated on `DAER_NETNS_TEST=1` and runs in the
privileged e2e script. It asserts:

- the namespace mount exists and the peer left the host;
- the peer's captured MAC is the MAC inside `daer0ns`;
- the namespace has `iif daer0peer -> table 2023` and no mark rule;
- the peer's DNS capture can be understood, the return route exists, and the local default
  route is installed;
- a listener created through `Daemon::bind_in` is reachable from inside the namespace;
- dropping the guard removes the namespace and the host veth end (device destruction can be
  asynchronous, so the test polls).

Operationally, the three commands that distinguish the failure classes are:

```bash
ip netns list
ip -n daer0ns -4 rule show
ip -n daer0ns route show
```

If the TCP listener is in the namespace but `accepted` stays at zero, look at accept-loop
liveness, not at the datapath. If `datagram reply failed` appears, look at the reply socket,
not at routing. If `bpf_sk_assign` succeeds and `tcp_v4_rcv` reports `NO_SOCKET`, look at
the namespace boundary, not at another socket option.

The operational diagnostic recipe is also in
[`docs/how-to/diagnostics.md`](../how-to/diagnostics.md#the-listener-accepts-a-direct-connection-but-redirected-flows-time-out).

One tooling lesson belongs here because it initially masked a success: a check that greps
tracing output must strip ANSI escapes first. `flow decided ... outbound=proxy` is emitted as
separate styled fields, so a literal `grep "outbound=.*proxy"` can report failure while the
proxy returned HTTP 200. The e2e check now removes `\x1b[...m` sequences before matching.

## 7. What was deliberately not done

These alternatives were considered and rejected:

- **More host-side sysctls or another mark rule.** The first defect is a namespace-context
  failure; no socket option can add the missing context.
- **Keeping the listener on the host side.** It cannot be assigned by the datapath on this
  kernel.
- **`SO_REUSEPORT` or TCX as a fix.** Both were already ruled out by the exact-listener
  requirement of `bpf_sk_assign`; they move the failure rather than remove it.
- **A compatibility switch for the old topology.** There is one ingress owner and one
  namespace. A second path would be a second set of state to clean up and a second failure
  mode to test.

## 8. Residual limits

- **IPv6 UDP is not implemented.** The datapath has one datagram listener slot and it holds
  the IPv4 socket. IPv6 TCP ingress code exists, but the current host has no global IPv6
  route and the path is not end-to-end verified.
- **The node address can rotate.** A production config should use the node hostname, with
  DNS direct, or update the literal address.
- **A restrictive host firewall can still drop replies.** The e2e host's `nftables` input
  policy requires established/related traffic; direct tests passed, but an operator's
  ruleset remains the operator's responsibility.
- **A slow node can consume one client's dial budget.** Decisions no longer block the
  accept loop, but the default dial timeout still bounds that flow.

## 9. Convergence checklist

Use this list when changing ingress, relay, or health code:

1. Does every socket daer creates carry the configured mark? Dialers, listeners, replies,
   health probes, and namespace-created sockets all count.
2. Does the TCP accept loop ever `await` a decision or a dial? It must not.
3. Is each subsystem that can block isolated from `accept(2)` and from the other transport?
4. Does the policy rule match redirected packets by the property that distinguishes them
   from daer's own replies?
5. Does a fixed policy stay out of the measurement path?
6. Is there a test that fails if the namespace boundary, reply factory, or parallel accept
   is removed?
7. Does teardown remove the namespace, the pair, TC filters, host policy, and sysctls on
   every exit path, including SIGKILL fallback?
8. Does the diagnostic output distinguish "not redirected" from "redirected but not
   accepted" from "accepted but not dialed"?

If a future change cannot answer all eight, it should not be presented as a fix for this
class of failure.
