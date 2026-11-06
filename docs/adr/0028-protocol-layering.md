---
id: ADR-0028
title: "A proxy protocol is a stack of orthogonal layers, and each layer is a type"
status: accepted
date: 2026-11-06
scope: [outbound/protocols, protocol/vless, protocol/vmess, protocol/vision, protocol/reality, transport/ws, config/nodes]
supersedes: []
---

# 0028. A proxy protocol is a stack of orthogonal layers, and each layer is a type

- Status: Accepted
- Date: 2026-11-06
- Deciders: Ming Li
- Related: [ADR-0010](0010-reality-client-ownership.md),
  [ADR-0017](0017-proxy-protocols-crate-boundary.md),
  [ADR-0006](0006-wiring-ownership.md)

---

## Context and Problem Statement

`crates/daer-proxy-protocols` shipped `vless` as *a property of REALITY*: the only
constructor of a VLESS session was `RealityConnector::from_link`, which required
`security=reality`, owned the VLESS request header, owned the Vision framing and owned the
TLS 1.3 client. `daer-config` enforced the same collapse from the other side
(`vless: missing [node.reality] configuration; daer only supports VLESS with REALITY`).

The consequence is that the crate cannot express most of the `vless` nodes in circulation,
and the ones it cannot express are not a niche:

| What a subscription actually says | Reachable before this ADR |
| --- | --- |
| `vless://…?security=reality&flow=xtls-rprx-vision` | yes |
| `vless://…?security=reality` (no flow) | yes |
| `vless://…?security=tls&flow=xtls-rprx-vision` | **no** |
| `vless://…?security=none` | **no** |
| `vless://…?security=reality&type=ws` | **no** |
| `vmess://<base64>` | **no** |

Vision is in the same shape: `reality/vision.rs` owns the XTLS framing, so the framing is
unreachable for a standard-TLS node even though the framing is defined by VLESS, not by
REALITY. Xray's own source says so: `proxy/vless/encoding/addons.go` attaches the
`VisionWriter` when *the flow* asks for it, and `proxy/proxy.go` knows nothing about which
TLS stack the record layer came from.

Three separate facts were conflated:

1. **Security layer** — what turns a TCP stream into an opaque one (`none`, `tls`,
   `reality`). It owns a handshake, a certificate policy and an ALPN offer.
2. **Transport layer** — what turns a stream into the byte stream the protocol sees
   (`tcp`, `ws`). It owns framing *below* the protocol.
3. **Protocol + flow** — what the peer parses (`vless`, `vmess`) and how its payload is
   framed (`none`, `xtls-rprx-vision`). Vision sits *inside* the security layer and is
   only correct for an inner stream that looks like TLS.

Collapsing (1) and (3) is what produced a `RealityConnector` that is 1200 lines long, half
of which is VLESS, and it is what will produce the same rot for VMess if it is added the
same way.

## Decision

**1. The three layers are separate types, composed in one place.**

```text
  node ──▶ Transport (tcp | ws)        ──▶ raw byte stream
        ──▶ Security  (none | tls | reality) ──▶ opaque byte stream
        ──▶ Protocol  (vless | vmess)        ──▶ framed byte stream
        ──▶ Flow      (none | vision)        ──▶ padded byte stream
```

The composition order is fixed by the protocol, and one function per protocol performs it:

```rust
// vless/connector.rs, in this order and nowhere else.
let stream = transport.wrap(tcp_stream).await?;      // ws upgrade if any
let stream = security.wrap(stream, alpn).await?;     // TLS / REALITY handshake
let stream = write_request_header(stream, &request).await?;
let stream = flow.wrap(stream, uuid, uplink_vision).await?;
```

**2. `reality` is a security layer, not a protocol.**

`reality::RealitySecurity` produces a `TlsLikeStream` from a byte stream and knows nothing
about VLESS. The scope rule of [ADR-0010](0010-reality-client-ownership.md) is preserved
and strengthened: the minimal TLS 1.3 client remains `pub(crate)` with no public
constructor, and the only way to obtain one is still a `security=reality` configuration —
but the reason is now "REALITY is a handshake", not "REALITY is a kind of VLESS".

**3. Vision belongs to VLESS.**

`vless/vision.rs`. Its input is the VLESS user id (which is what a Vision block repeats on
the wire) and its switch targets the record layer underneath, which is the security
layer's business. It is applied only when the node's flow asks for it, and only for a
security layer that can actually be spliced (`tls`, `reality`); a `none` + `vision`
combination is rejected at load, because the reference implementation rejects it too
(`inbound.go`: `"XTLS only supports TLS and REALITY directly for now."`).

**4. A layer that is not implemented is rejected by name at load time.**

`type=grpc`, `type=httpupgrade`, `type=xhttp`, `type=kcp`, `type=quic`, `security=xtls`
and `flow=xtls-rprx-vision-udp443` are parse errors that name the missing layer. They are
not silently downgraded to `tcp`/`none`: a node that connects and then sends nonsense costs
more to diagnose than one that refuses to load, and the refusal lists the alternative.

**5. The configuration mirrors the layers, so the schema cannot express an impossible node.**

`[[node]]` keeps one flat table per protocol (a subscription link is flat), but the
security and transport settings are nested tables whose tag is the layer's `type`:

```toml
[[node]]
tag = "jp"
type = "vless"
server = "203.0.113.7"
port = 443
uuid = "…"
flow = "vision"

[node.security]
type = "reality"
sni = "www.apple.com"
public-key = "…"
short-id = "8e3af867"
fingerprint = "chrome"

[node.transport]
type = "ws"
path = "/ray"
[node.transport.headers]
Host = "cdn.example.com"
```

A tagged enum, not a bag of `Option`s: `security.type = "reality"` *requires* the REALITY
fields by construction, and `security.type = "tls"` cannot carry a `public-key` at all.

## Consequences

- `daer-config` gains `SecurityConfig`, `TransportConfig`, `Flow` and `VmessCipher`; the
  "vless requires reality" validation is deleted rather than relaxed.
- `reality/connector.rs` loses the VLESS header, the Vision writer and the UDP session.
  What remains is the handshake plus the certificate verdict.
- VMess can be added without touching REALITY, and the next security layer (a pinned-CA
  TLS, ECH) does not touch VLESS.
- `DialerOptions::tls_profile`/`fragment` stop being special-cased for REALITY: they
  configure the security layer, whichever one it is.
- A test asserts the layer split rather than the prose: every `TransportConfig` and
  `SecurityConfig` variant must be constructible from a link and must reach a dialer, and
  each rejected value must be rejected with its own name in the message.

## What this ADR does not decide

- **Chained outbounds** (`a -> b`). Still rejected, unchanged.
- **Mux / XUDP as a general capability.** VLESS over Vision carries UDP as XUDP because
  the reference does; that is recorded in ADR-0029 and does not create a
  general-purpose mux layer.
- **`type=grpc` and `type=httpupgrade`.** Both are real, both are unimplemented, and both
  are now named errors instead of silent `tcp`.
