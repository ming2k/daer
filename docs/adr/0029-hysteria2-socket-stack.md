---
id: ADR-0029
title: "Hysteria 2 is carried by a socket stack, and daer implements all of it"
status: accepted
date: 2026-11-06
scope: [outbound/protocols, protocol/hysteria2, transport/udp, quic, config/nodes]
supersedes: []
---

# 0029. Hysteria 2 is carried by a socket stack, and daer implements all of it

- Status: Accepted
- Date: 2026-11-06
- Deciders: Ming Li
- Related: [ADR-0017](0017-proxy-protocols-crate-boundary.md),
  [ADR-0002](0002-netune-boundary.md),
  [ADR-0028](0028-protocol-layering.md)

---

## Context and Problem Statement

`hysteria2` shipped with `obfs` in the model, in the link parser, in the connector's fields,
in `Debug`, and in the interop test — and **not on the wire**. `Hysteria2Connector` bound a
plain `std::net::UdpSocket` and handed it to `quinn::Endpoint::new`, so a node configured
with `obfs=salamander` opened a QUIC handshake in the clear and timed out. The test that
"covered" the setting asserted that the link parsed, which is exactly the class of test
[ADR-0006](0006-wiring-ownership.md) exists to forbid: a key that is accepted must take
effect.

Three more gaps of the same kind:

1. **The UDP plane is single-session.** `Hysteria2DatagramSession` hard-codes
   `session_id = 1`, so every concurrent UDP flow through one node shares one session id and
   the server multiplexes them onto one outbound port. `frag_id = 0, frag_total = 1` is
   hard-coded too, so any datagram larger than the QUIC datagram MTU is dropped instead of
   fragmented — the reference fragments it (`core/internal/frag`).
2. **The server's answer to authentication is discarded.** `Hysteria-UDP` (may I relay
   UDP?) and `Hysteria-CC-RX` (the rate the server will take) are read by nobody. A
   datagram flow that the server has said it will not relay fails later, at the relay, with
   no attribution.
3. **No port hopping.** `hysteria2://…@host:443,8443,9443` is the reference's answer to
   single-port throttling and per-connection port rotation. daer's parser reads the port
   field with `parse_host_port` and rejects the list.

The common cause is a design one: the QUIC endpoint is built inline in a constructor
(`make_endpoint`), so there is no place to insert anything between the socket and Quinn, and
no seam a test can exercise without a live server.

## Decision

**1. The datagram plane is an explicit stack of `AsyncUdpSocket` layers.**

```text
  quinn::Endpoint
        ▲
        │  AsyncUdpSocket
  ┌─────┴──────────────────────────────┐
  │ hop    (rotate local socket+port)  │  optional
  │ obfs   (salamander → gecko)        │  optional
  │ socket (tokio UdpSocket, SO_MARK)  │  always
  └────────────────────────────────────┘
```

Each layer implements `quinn::AsyncUdpSocket` (or wraps the one below) and is composed in
`hysteria2/socket.rs`. No layer knows about QUIC framing, and Quinn does not know any layer
exists. The endpoint is created with
`quinn::Endpoint::new_with_abstract_socket`, which is the only constructor that accepts a
layer — `Endpoint::new` is not used at all, so a socket wrapper cannot be forgotten again.

**2. `obfs` is either implemented or rejected — and it is implemented.**

`salamander`: `[salt 8][payload]` with `key = BLAKE2b-256(psk ‖ salt)`, payload XORed
cyclically with the 32-byte key. `gecko`: Salamander plus fragmentation of QUIC long-header
packets into 2–8 randomly padded chunks with a 5-byte frame header and a reassembly window.
A configuration naming an obfuscation daer does not implement is a load-time error, and a
`salamander` password shorter than the reference's 4-byte minimum is a load-time error too.

**3. The UDP plane is per-flow and fragmented, and the server's verdict is honoured.**

- `session_id` is allocated from a process-wide counter, one per UDP flow, and released
  with the flow.
- Outbound datagrams larger than the negotiated datagram size are split per
  `core/internal/frag` (`frag_id` from 0, shared `packet_id`), and inbound fragments are
  reassembled with the reference's single-packet window.
- `Hysteria-UDP: false` makes a datagram dial fail immediately with that reason;
  `Hysteria-CC-RX` is **read and reported**, not applied — see 4 and the gap recorded below.

**4. Congestion control is the node's choice; Brutal pins the window to `up-mbps`.**

`congestion = "bbr" | "cubic" | "new_reno" | "brutal"`, mapped onto
`quinn::congestion::{BbrConfig, CubicConfig, NewRenoConfig}` and a daer `BrutalConfig`
implementing `quinn_proto::congestion::ControllerFactory`. Brutal is the reference's
throughput-preserving controller: it pins the window to `bps × srtt × 2 / ack_rate`, with
`ack_rate` measured over a 5-second window and clamped to `>= 0.8`.

`bps` is **`up-mbps`**, because Brutal pins the *send* window. Deriving it from `down-mbps` — the
obvious mistake, since `down-mbps` is the number that also goes out in `Hysteria-CC-RX` — makes a
client send at its receive rate, which is the congestion the controller exists to avoid.

**5. Two parts of the reference's rate negotiation are not reproduced, and are recorded as gaps.**

The reference applies the server's answer *after* authentication by mutating the live connection:

```go
// core/client/client.go
actualTx = authResp.Rx                       // Hysteria-CC-RX
if actualTx == 0 || actualTx > MaxTx { actualTx = MaxTx }   // MaxTx = up-mbps
congestion.UseBrutal(conn, actualTx, DisableLossCompensation)
```

Quinn fixes its controller in `TransportConfig`, which is consumed when the endpoint dials — there
is no post-handshake hook, and adding one means reaching into `quinn-proto`'s private state. So:

| Reference behaviour | daer |
| --- | --- |
| `actual_tx = min(server_rx, max_tx)` | `max_tx` only (`up-mbps`). `server_rx` is read and exposed as `Hysteria2Connector::server_rx`, and no controller consumes it |
| `RxAuto` ⇒ use the configured controller instead of Brutal | not distinguished: `congestion = "brutal"` always builds Brutal |

Both are conservative — a `min(..)` that omits one term can only send *faster* than the reference
would when the server caps below `up-mbps`, and the operator set `up-mbps` precisely to bound that.
Neither is silent: ADR-0006's rule is that a key either takes effect or is not in the model, and
`down-mbps` *does* take effect — it is the value sent to the server in `Hysteria-CC-RX`, which is
what the node uses to size *its* send window. What does not happen is the reply feeding back into
ours.

**6. Port hopping rotates the *source* port; the destination stays where the dial put it.**

`hysteria2://…@host:443,8443-8445` resolves to a port set, and the hop layer rotates the local
socket on an interval drawn from `[hop-min, hop-max]` via `Endpoint::rebind_abstract`, keeping the
previous socket open for a grace period so the server's acknowledgement is not lost. QUIC
connection migration is not used and is not enabled: the local port is what changes, and that
changes nothing the server's connection id has to validate.

The reference's `udpHopPacketConn` also rotates the **destination** across the set. That is not
reproduced: in quinn the destination is fixed by `connect_with`, and rotating it per packet needs
an `AsyncUdpSocket` that rewrites `Transmit::destination` — a layer this crate does not have. The
port set therefore decides the *initial* dial and nothing more. This is recorded rather than
half-implemented, which is what the previous version of this ADR did: it declared the rotation and
then dropped the value on the floor with a comment claiming the endpoint would honour it.

## Consequences

- `Hysteria2Connector` becomes a pipeline builder; `make_endpoint` disappears and with it
  the only place a socket option could be skipped.
- `daer-config` gains `[[node]]` hysteria2 keys `obfs` (nested, tagged), `congestion`,
  `hop-interval`, `hop-min-interval`, `hop-max-interval`, `init-stream-receive-window`,
  `max-stream-receive-window`, `init-conn-receive-window`, `max-conn-receive-window`,
  `max-idle-timeout`, `keep-alive-period`, `disable-path-mtu-discovery`, and `pin-sha256`.
  Every one of them is a `.field` read somewhere outside `daer-config`, which is what the
  `config_keys` gate checks.
- The port field accepts a list, so `parse_host_port` is no longer the only way a port is
  read; `PortSet` is the type, and it is shared with the hop layer.
- A test per layer: Salamander and Gecko against the reference's own vectors,
  fragmentation against `frag_test.go`'s cases, port-set parsing against `portunion.go`'s
  normalisation rules. None of them needs a live server.
- `blake2` enters the dependency graph. It is the reference's hash and a different one would
  not interoperate, so this is not a choice to revisit.

## What this ADR does not decide

- **Realm / hole punching.** The reference has it; daer does not, and it needs STUN plus a
  rendezvous server. A separate ADR if it is ever wanted.
- **ECH.** `tls.ech` is a real client feature of the reference. Out of scope here and
  rejected by name rather than ignored.
- **Peer certificate pinning beyond `pin-sha256`.** Implemented as a post-handshake digest
  comparison, which is what the reference does.
