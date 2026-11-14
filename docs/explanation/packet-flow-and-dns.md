# Packet Flow and the DNS Name Plane

This article traces one client flow through `daer` in both directions and shows where the
built-in DNS resolver sits. It is an explanation, not a configuration guide: for the DNS keys
themselves, see [DNS configuration](../how-to/configuration/dns.md).

---

## 1. Vocabulary

`daer` uses the word **ingress** for the client side of the transparent capture, not for
traffic arriving from the internet. To avoid that collision, this article uses three
directional names:

| Name | Direction | What it means |
| :--- | :--- | :--- |
| **Client side** (`inbound` / `ingress`) | client → daer | The TC/eBPF redirect, the private `daer0ns` listeners, and original-destination recovery. |
| **Daer egress** (`outbound`) | daer → node/origin | The socket `daer` opens after the control plane chooses `direct` or an election. |
| **Return path** | node/origin → daer → client | The reverse byte direction of the established egress socket. It is not a second ingress path. |

The built-in DNS resolver is a fourth thing: the **name plane** that supplies domain facts to
the data path.

```text
Client side                 Daer egress                  Remote
(inbound)                   (outbound)

client ─────────▶ daer ─────────────▶ node / origin
       ◀──────────────────────────────
                 return path
```

---

## 2. The Name Plane and the Data Plane

DNS is not a hop in the packet-forwarding chain. It is a sibling service that writes state
which the data path reads later.

```text
                         ┌──────────────── daer process ─────────────────┐
                         │                                               │
  client                 │   ┌────────────────────────────┐              │
    │                    │   │ Name plane                 │              │
    │  DNS query         │   │ daer-dns :53               │              │
    ├───────────────────▶│   │ ├─ [dns.request]           │              │
    │                    │   │ ├─ Fake-IP / cache         │              │
    │◀───────────────────│   │ └─ upstream                │              │
    │                    │   └──────────────┬─────────────┘              │
    │                    │                  │ writes                     │
    │                    │                  ▼                            │
    │                    │        ┌───────────────────┐                  │
    │                    │        │ FakeIpPool        │                  │
    │                    │        │ DnsSnooper        │                  │
    │                    │        └─────────┬─────────┘                  │
    │                    │                  │ reads                      │
    │  TCP / UDP         │                  ▼                            │
    ├───────────────────▶│   ┌──────────────────────────┐                │
    │                    │   │ eBPF TC datapath         │                │
    │                    │   │ direct / redirect        │                │
    │                    │   └────────────┬─────────────┘                │
    │                    │                │                              │
    │                    │                ▼                              │
    │                    │   ┌──────────────────────────┐                │
    │                    │   │ daer-relay               │                │
    │                    │   │ accept / splice          │                │
    │                    │   └────────────┬─────────────┘                │
    │                    │                │                              │
    │                    │                ▼                              │
    │                    │   ┌──────────────────────────┐                │
    │                    │   │ daer-control             │                │
    │                    │   │ routing / election       │                │
    │                    │   └────────────┬─────────────┘                │
    │                    │                │                              │
    │                    │                ▼                              │
    │                    │   ┌──────────────────────────┐                │
    │                    │   │ daer-outbound / netune   │                │
    │                    │   │ dial + SO_MARK           │                │
    │                    │   └────────────┬─────────────┘                │
    └────────────────────┴────────────────┼──────────────────────────────┘
                                          │
                                          ▼
                                    node / origin
```

The important consequence:

> **The resolver does not forward payload. It binds a domain to an address and records the
> binding; the data path reads that binding when the flow arrives.**

---

## 3. Outbound: Client to Remote

```text
[client]
   │
   │ TCP SYN / UDP datagram
   │ destination = real IP or Fake-IP
   ▼
[LAN ingress TC eBPF]
   │
   ├── skb->mark == daer's own mark
   │        └──────────────────────────────▶ PASS
   │
   ├── verdict = direct
   │        └──────────────────────────────▶ Linux routing
   │                                           │
   │                                           ▼
   │                                        WAN → origin
   │
   └── verdict = proxy / control-plane
            │
            │ redirect to daer0
            ▼
       [daer0ns]
            │
            │ bpf_sk_assign
            ▼
       [daer-relay accept]
            │
            │ flow_id / source / destination
            ▼
       [daer-control decide]
            │
            │ 1. known_domain:
            │      FakeIpPool.reverse_lookup_ip(destination)
            │      then DnsSnooper.lookup(destination)
            │
            │ 2. no unique name, and [routing.sniff] enabled:
            │      peek TLS SNI / HTTP Host / QUIC Initial
            │      (bounded by routing.sniff timeout)
            │
            │ 3. evaluate [routing]
            │      direct / block / election(node)
            ▼
       [daer-outbound / netune]
            │
            ├── direct: dial the original IP
            │
            └── proxy : dial the selected node
                        authority = domain:port
            │
            │ every dial sets SO_MARK before connect(2)
            ▼
       [node / origin]
```

Two details matter:

1. **`direct` bypasses userspace entirely** when the kernel policy can prove the verdict.
   No relay, no DNS lookup, no domain fact.
2. **A proxied flow uses the domain as its authority when one is known.**
   The remote node receives `example.com:443`, not `198.18.0.42:443`; a `direct` dial keeps
   the literal destination because that address is already authoritative.

The name comes from the first source that knows it:

```text
FakeIpPool.reverse_lookup_ip(destination)
    │ miss
    ▼
DnsSnooper.lookup(destination)
    │ miss
    ▼
TLS SNI / HTTP Host sniff
    │ miss
    ▼
route by IP only
```

---

## 4. Return: Remote to Client

```text
[node / origin]
   │
   │ response bytes
   ▼
[daer egress socket]
   │
   │ SO_MARK was set before connect(2)
   ▼
[daer-relay]
   │
   │ copy_bidirectional / splice
   │ upstream → client direction
   ▼
[client-side transparent socket]
   │
   │ source = the client's original destination
   │ mark   = daer's own mark
   ▼
[host forwarding / eBPF]
   │
   │ the mark identifies daer's own traffic
   │ so it is not captured a second time
   ▼
[client]
```

For TCP, the relay preserves half-close:

```text
client finishes its request → shutdown(write)
        │
        ▼
relay forwards EOF to the upstream
        │
        ▼
origin may still send the response
        │
        ▼
relay keeps writing bytes back to the client
```

For UDP, the relay keeps a session table keyed by the client and destination, and replies use
a socket bound to the original destination. The same mark keeps the reply out of the
transparent capture path.

---

## 5. DNS Query and Response

This is the resolver's own outbound/return flow.

```text
[client]
   │
   │ UDP/TCP :53
   ▼
[daer-dns listener]
   │
   ├── [dns.request]
   │      ├── reject ─────────────▶ REFUSED
   │      ├── asis   ─────────────▶ no reply at all
   │      └── upstream tag
   │
   ├── Fake-IP branch
   │      │  A/AAAA, not excluded
   │      │
   │      ├── A    ───────────────▶ allocate/reuse 198.18.x.x
   │      │                          NOERROR, TTL 60
   │      │
   │      └── AAAA ───────────────▶ with inet6: synthesise AAAA
   │                                  without inet6: empty NOERROR
   │
   ├── cache hit ─────────────────▶ reply from cache
   │
   └── cache miss
          │
          ▼
     [DNS upstream]
       UDP / TCP / DoT / DoH
          │
          │ netune, SO_MARK
          ▼
     [upstream resolver]
          │
          ▼
     [dns.response]
       accept / reject / failover
          │
          ├── real A/AAAA
          │      └── DnsSnooper.record(IP, domain)
          │
          ├── cache store
          │
          └── return to client
```

There are two different things that can look like "DNS egress":

```text
1. A client's query to an external resolver
   client ──▶ eBPF/relay ──▶ 8.8.8.8:53
   This is an ordinary flow and is subject to [routing].

2. daer-dns asking its configured upstream
   daer-dns ──▶ netune ──▶ upstream resolver
   This uses daer's egress stack with SO_MARK, so it is not
   recaptured by daer's own datapath.
```

The built-in resolver does **not** intercept the first kind. It only answers clients that use
it as their resolver.

---

## 6. Sequence: DNS Binds the Name Before the Flow

```text
time ───────────────────────────────────────────────────────────────▶

client          daer-dns             daer-control/relay        remote
  │                │                        │                      │
  │── DNS query ──▶│                        │                      │
  │                │── [dns.request]        │                      │
  │                │── Fake-IP / upstream   │                      │
  │◀── A/AAAA ─────│                        │                      │
  │                │                        │                      │
  │                │ write FakeIpPool       │                      │
  │                │ or DnsSnooper          │                      │
  │                │                        │                      │
  │── TCP/UDP to 198.18.x.x:443 ──────────▶│                      │
  │                │                        │                      │
  │                │                        │ known_domain         │
  │                │                        │ 198.18.x.x → domain  │
  │                │                        │                      │
  │                │                        │ [routing]            │
  │                │                        │ domain(example.com)  │
  │                │                        │                      │
  │                │                        │── dial domain:443 ──▶│
  │                │                        │                      │
  │◀──────────────── relay bytes ──────────│◀─────────────────────│
```

The resolver finishes its work before the TCP handshake or the first UDP datagram. That is
what makes a name-based decision possible on the first packet.

---

## 7. Why This Is Not Reverse DNS

The built-in resolver is a **forward** DNS server: it answers `example.com → A/AAAA`. The
data path then performs a **local reverse-map lookup**:

```text
FakeIpPool:  198.18.0.42  → example.com
DnsSnooper:  93.184.216.34 → example.com
```

That lookup is an in-memory hash-table read. It is not a PTR query and does not travel over
DNS.

| Mechanism | Direction | Protocol | Used by daer? |
| :--- | :--- | :--- | :--- |
| Forward DNS | name → address | A/AAAA over UDP/TCP/DoT/DoH | Yes |
| Local reverse map | address → name | in-process table | Yes |
| Reverse DNS (PTR) | address → name | PTR over DNS | No |

ADR-0011 explicitly rejects synchronous PTR queries in the flow path: they add latency, can
recurse through the proxy, and leak traffic. The local map exists precisely to avoid that.

---

## 8. Responsibilities and Boundaries

| Dimension | DNS's position |
| :--- | :--- |
| **Layer** | Name plane / control plane, not a payload relay. |
| **Starts when** | `dns.bind` is set, or `[dns.fake-ip] enabled = true`. |
| **Input** | Client DNS query, `[dns]` configuration, upstream answers. |
| **Output** | DNS answer, `FakeIpPool` mapping, `DnsSnooper` mapping, `QueryId` events. |
| **Consumers** | `daer-control::known_domain()`, `[routing]`, and the outbound dial authority. |
| **Not responsible for** | Forwarding payload, evaluating `[routing]`, PTR lookups, intercepting DoH/DoT, or choosing the client's resolver. |

The resolver is optional. A deployment can use external DNS and rely on the
`[routing.sniff]` payload fallback, or route by IP only. The fallback is explicit: a
`domain(...)` rule requires an `enabled` answer, and `enabled = false` routes by address
when DNS cannot name the flow. The cost is that domain rules become later and less reliable:

- a TLS/HTTP/QUIC-Initial flow may work after a bounded peek;
- QUIC, ECH, raw TCP, and server-first protocols may never reveal a name;
- the first packet cannot be decided by a domain rule.

Fake-IP is also optional, and it is **disabled by default**: `[dns.fake-ip]` starts with
`enabled = false` (ADR-0012, `[INV-FAKEIP-01]`). When it is off, the pool is inert:
`contains_ip()` returns false, `reverse_lookup()` returns `None`, and `198.18.0.0/15` is
treated as ordinary address space. Fake-IP is an answer mode of the DNS listener, so it
requires an explicit `dns.bind`; enabling it never starts the listener by itself.

Real-IP plus the DNS snooper preserves domain facts without synthetic addresses, but a shared
CDN address can map to more than one domain. Fake-IP removes that ambiguity by construction:
one synthetic address maps to exactly one domain. The trade is that opting in changes what
clients see (`ping`, `traceroute`, and direct socket diagnostics no longer show real
addresses), which is why the default is isolation rather than convenience.

---

## 9. Current Implementation Status

The name binding described above is wired today. The kernel-side domain bitmap is not.

`domain_routing_map` is the datapath table that would let the kernel evaluate a `domain(...)`
predicate from a destination IP. The current build does not populate it from DNS answers.
Policy compilation therefore partitions at the first `domain(...)` rule: the prefix rules
before it remain in the kernel, and the domain rule plus everything after it is deferred to
the userspace control plane. If the domain rule is near the top, most flows take the
userspace path. See [What is not implemented](../how-to/deployment.md#what-is-not-implemented)
and [ADR-0012](../adr/0012-optional-fake-ip-ebpf.md).

So the current value of the name plane is:

1. recover the domain before the first payload byte;
2. avoid the sniffing delay;
3. support UDP/QUIC and non-TLS flows that carry no SNI or Host;
4. remove the ambiguity of shared real IPs when Fake-IP is enabled.

It is not yet kernel line-rate domain steering. That is the direction described by ADR-0012,
not the state of this build.

---

## 10. Related Reading

- [Architecture Overview](architecture-overview.md) — the two-plane model and the private
  ingress namespace.
- [eBPF Datapath & Routing Epochs](ebpf-datapath.md) — the TC hook, marks, and deferral.
- [DNS Configuration](../how-to/configuration/dns.md) — the keys, cache, upstream syntax, and
  Fake-IP settings.
- [ADR-0011](../adr/0011-partitioned-kernel-routing.md) — partitioned kernel routing and DNS
  snooping.
- [ADR-0012](../adr/0012-optional-fake-ip-ebpf.md) — the optional Fake-IP subsystem and its
  intended kernel bitmap synthesis.
- [ADR-0018](../adr/0018-userspace-data-path-is-daer-relay.md) — the relay/control boundary.
- [ADR-0038](../adr/0038-private-ingress-network-namespace.md) — `daer0ns` and the ingress
  namespace.
