---
id: ADR-0030
title: "VMess is VMess AEAD only; the legacy handshake is not implemented"
status: accepted
date: 2026-11-06
scope: [outbound/protocols, protocol/vmess, crypto, config/nodes]
supersedes: []
---

# 0030. VMess is VMess AEAD only; the legacy handshake is not implemented

- Status: Accepted
- Date: 2026-11-06
- Deciders: Ming Li
- Related: [ADR-0028](0028-protocol-layering.md),
  [ADR-0017](0017-proxy-protocols-crate-boundary.md)

---

## Context and Problem Statement

`vmess` is the one Xray protocol daer does not speak at all, and every `vmess://` link in a
subscription is currently parked in `NodeEndpoint::Unsupported` — listed, unselectable,
and reported as such by `daer check --nodes`.

VMess exists in two wire formats:

| Format | Handshake | Body |
| --- | --- | --- |
| Legacy (pre-2020, "MD5") | `md5(uuid)` command key, request header encrypted with AES-CFB using the user's UUID-derived key, **no replay protection** | AES-CFB / ChaCha20 stream, optionally chunked |
| AEAD (v2, "VMess AEAD") | `AuthID = AES-ECB(KDF(uuid, "AES Auth ID Encryption"), unix_time ‖ rand ‖ crc32)`, header sealed with AES-GCM under keys derived per-connection | AES-128-GCM / ChaCha20-Poly1305 chunks, optionally with masked sizes and padding |

The legacy format is broken by design: a captured first packet is replayable forever, which
is why Xray moved to AEAD and why a modern server can be configured to refuse legacy
clients outright. Implementing it would add an attack surface daer gains nothing from, and
implementing *only* it would not connect to anything current.

There is a second decision inside the AEAD format: the `testsEnabled` string on the account
(`"AuthenticatedLength"`, `"NoTerminationSignal"`) selects optional behaviours that change
the wire format. A client that always enables them talks only to servers that implement
them; a client that never enables them is what the reference sends by default.

## Decision

**1. Only VMess AEAD is implemented. A legacy request is not constructible.**

Supporting the legacy handshake would require a second header encoder, a second body codec
(AES-CFB keyed by `md5(uuid)`), and would reintroduce replay. `daer-config` therefore has no
key that can select it: `vmess` security is `auto | aes-128-gcm | chacha20-poly1305`, and
`auto` resolves exactly like the reference's `SecurityType_AUTO`
(`common/protocol/headers.go`: AES-GCM when the CPU has AES-NI, ChaCha20-Poly1305
otherwise).

**2. `AuthenticatedLength` and `NoTerminationSignal` default to off, and are settable.**

Both are wire-format changes the server must also have enabled. Defaulting them on would
make every daer-configured VMess node fail against a default server; defaulting them off
silently would make a node that needs them fail with an authentication error that names
nothing. So they are explicit booleans (`[node] authenticated-length`,
`no-termination-signal`) and are reported by `daer check --nodes`.

**3. The layers are ADR-0028's layers.**

VMess is a protocol layer over a security layer over a transport layer, exactly like VLESS:
`vmess` over `tls` over `ws` is three composable pieces, and the connector is the
composition. VMess has no flow, so the flow layer is `Flow::None` unconditionally.

**4. The link format is the reference's base64 JSON, parsed strictly.**

`vmess://<base64(json)>` with `v`, `ps`, `add`, `port`, `id`, `aid`, `scy`, `net`, `type`,
`host`, `path`, `tls`, `sni`, `alpn`, `fp`. Unknown fields are ignored (panels add them);
a field daer cannot honour (`net = "kcp"`, `net = "quic"`) is a load-time error naming the
layer. `aid` (alterId) is accepted and required to be `0`: a non-zero alterId is the legacy
handshake's parameter, and accepting it while speaking AEAD would be a lie.

## Consequences

- `crates/daer-proxy-protocols/src/vmess/` — `kdf.rs` (the reference's nested-HMAC KDF),
  `authid.rs` (`CreateAuthID` / decoder), `header.rs` (request/response header seal and
  open), `chunk.rs` (AEAD chunk stream reader/writer, SHAKE-128 size masking, padding),
  `connector.rs` (the composition).
- `daer-config` gains `NodeEndpoint::Vmess(VmessNode)` with a `vmess://` link parser and a
  canonical `to_link`.
- The VMess KDF is a **nested HMAC**, not HKDF: `KDF(key, path…)` folds the path with
  `hmac.New(func() hash.Hash { return hmacf }, path_i)` and finally writes the key. A
  straightforward HKDF produces a header a real server rejects, and the failure is
  indistinguishable from a wrong UUID — so `kdf.rs` carries the reference's vectors as unit
  tests.
- Datagram flows are VMess packets (`TransferTypePacket`), not a byte stream: the chunk
  writer emits one AEAD chunk per datagram and the reader returns one datagram per chunk.
- An interop test starts a local `xray` VMess inbound (skipped with a reason when `xray` is
  absent, per [ADR-0007](0007-verification.md)) and asserts a round trip in both
  directions, with and without `AuthenticatedLength`.

## What this ADR does not decide

- **VMess mux (`v1.mux.cool`).** Not implemented; a UDP flow uses VMess packets directly,
  which is what the reference does when mux is off.
- **Reverse proxy (`RequestCommandRvs`).** Not implemented and not expressible in the config.
- **The `aid` compatibility path.** Accepted only as `0`; anything else is a load error.
