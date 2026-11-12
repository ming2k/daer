---
id: ADR-0044
title: "A detour is an outbound chain: the outer protocol runs over another node's server leg"
status: accepted
date: 2026-11-12
scope: [outbound/detour, outbound/protocols, config/nodes, control-plane/health, architecture/boundary]
supersedes: []
---

# 0044. A detour is an outbound chain: the outer protocol runs over another node's server leg

- Status: Accepted
- Date: 2026-11-12
- Deciders: Ming Li
- Related: [ADR-0017](0017-proxy-protocols-crate-boundary.md),
  [ADR-0018](0018-userspace-data-path-is-daer-relay.md),
  [ADR-0028](0028-protocol-layering.md)

---

## Context and Problem Statement

A proxy protocol has two destinations that are easy to conflate:

| Destination | Where it comes from | Who sees it |
| --- | --- | --- |
| the node's **server** | `[[node]] server`/`port` | the network path between daer and the node |
| the flow's **target** | the client's original destination | the node, inside the protocol payload |

daer could only open the first destination with a direct `netune::TcpConnector` owned by each
protocol connector. The target was already carried end to end, but the **server leg** had no
seam. As a result a configuration could not say "reach server A through server B", and chained
subscription links (`a -> b`) were rejected rather than truncated.

The desired behaviour is the one every multi-hop proxy deployment uses: the client encodes the
final target once, in the outer protocol, and the outer protocol's bytes travel through an inner
outbound. The inner server sees only the outer server's address; the outer server sees the final
target. No new wire format is needed.

The naive alternatives were rejected:

- **Concatenate links** (`a -> b`): a string has no place to attach socket options, health
  semantics, or a graph validator, and it cannot reference a subscription node by name.
- **A local listener per hop**: adds ports, process state and a second routing decision to every
  flow, and a loop is discovered only at runtime.
- **A new "chain protocol"**: invents a protocol where the existing outer protocol already carries
  the target correctly.

## Decision

**1. `detour` is a node field, and it names exactly one other node.**

```toml
[[node]]
name = "inner"
type = "socks5"
server = "192.0.2.10"
port = 1080

[[node]]
name = "outer"
type = "vless"
server = "198.51.100.20"
port = 443
detour = "inner"       # the stream to 198.51.100.20:443 is opened by "inner"
```

The outer node's protocol still writes the final target into its own header. A chain is therefore
`outer(detour = inner)`, not a new framing.

**2. The server leg is an explicit trait, not a hidden constructor.**

`daer-proxy-protocols::server::ServerDialer` opens the byte stream to a node's own server. The
default is `DirectServerDialer` (the existing direct TCP path). `daer-outbound` implements the
same trait with `NodeServerDialer`, which calls the inner `NodeDialer`. Every protocol connector
takes the server leg from its `DialerOptions`, so no connector can bypass the chain by keeping a
private `TcpConnector`.

The trait also exposes the datagram form for the `direct` case; a protocol whose UDP rides inside
its own stream does not need it.

**3. The graph is a DAG, validated before any generation is built.**

`detour` references a node name/tag, never a group. A group selects a node per flow; a chain whose
hop is chosen per flow cannot be validated as a DAG, probed as a fixed route, or explained as one
route. The same reference is rejected at load time when it is unknown, self-referential, or part
of a cycle, and node names are required to be unique across the resolved pool so a reference
names exactly one node. `daer-config::validate::validate_chain_graph` is called after subscription resolution
and again by `Router::new`, so every entry point reaches the same verdict (ADR-0006).

**4. A detoured node is probed through its chain.**

A health probe of a detoured node opens the bare server stream through its detour, not a direct
socket to the outer server. Measuring the outer server directly would mark the node dead exactly
when the detour is doing its job. For stream-carried UDP (VLESS/VMess/AnyTLS), that same stream is
the datagram path, so the TCP chain probe is the correct liveness instrument.

**5. Capability boundaries are named, not silently degraded.**

- A **Hysteria 2 outer** node is refused at construction: its QUIC socket stack has no
  datagram-under-proxy seam yet. Hysteria 2 as an **inner** hop works, because the outer node
  asks it for a stream through `NodeDialer`.
- A **SOCKS5 outer** node keeps TCP chaining and reports no datagram support. A SOCKS5 UDP
  associate is a direct session with the proxy server; allowing it through a detour would send
  datagrams outside the chain.
- A detour target this build cannot construct is a `DetourBroken` error and fails the generation.
  It is never skipped like an unsupported leaf node, because the operator explicitly named it.
- A **direct** node cannot be the outer hop: it has no server leg for a detour to replace. It can
  still be the inner hop (the chain then starts at a direct connection). Routing to an
  election whose candidate set contains the inner node is the correct way to express
  "direct via X", not an alias node that reports `direct` while carrying another protocol.

## Negative Knowledge & Discarded Alternatives

- **Per-flow group detour.** Rejected because a group is a candidate set, not a transport. It
  would make the dependency graph dynamic and make "is this chain healthy" unanswerable.
- **Reusing `ProxyConnector` for the whole chain.** `netune::Connector` is not object-safe
  (`impl Future`), and nesting a proxy connector only composes a single proxy protocol. daer needs
  an arbitrarily deep, configuration-defined object graph, so the seam is a boxed `ServerDialer`
  future.
- **A second TLS/REALITY stack for chained nodes.** Rejected: the outer connector still builds the
  same layers; only the stream underneath changes.
- **Silently truncating `a -> b` links.** Rejected earlier and still rejected; a structured
  `[[node]]` with `detour` is the only representation.

## Consequences

- One target encoding, one protocol implementation, arbitrary chain depth.
- `NodeDialer` grows a chain edge and a server-probe method; the protocol connectors keep their
  own handshakes and credentials.
- Health checks, `daer route nodes`, and `daer probe node` can name the inner hop.
- The remaining unsupported combination is a QUIC outer node; adding it requires a datagram
  `ServerDialer` implementation over `QuicUdpSocket`, not a change to the config model.
