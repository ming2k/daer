---
id: ADR-0010
title: "REALITY and the minimal TLS 1.3 client belong to daer-outbound"
status: accepted
date: 2026-10-29
scope: [tls/reality, protocol/vless, protocol/vision, security/egress, crate-boundary]
supersedes: []
---

# 0010. REALITY and the minimal TLS 1.3 client belong to daer-outbound

- Status: Accepted
- Date: 2026-10-29
- Deciders: Ming Li
- Related: [ADR-0002](0002-netune-boundary.md),
  [netune ADR-0009](../../../netune/docs/adr/0009-reality-client-authentication-not-a-netune-capability.md),
  [netune ADR-0004](../../../netune/docs/adr/0004-tls-fingerprint-profiles-pool-isolation.md)

---

## Context and Problem Statement

A large share of the `vless` nodes in circulation use REALITY, and `xtls-rprx-vision`
(Vision) is the flow option most of them pair it with. `daer` cannot speak either.

Two questions decide the work:

1. **Who owns the TLS handshake** for a REALITY client?
2. **Where does the code live** given ADR-0002 says `daer` does not implement TLS?

The sibling project already answered question 1 for itself: [netune
ADR-0009](../../../netune/docs/adr/0009-reality-client-authentication-not-a-netune-capability.md)
records that REALITY client authentication is **not** a netune capability, and that
decision is correct. This ADR records the consequence for `daer`: since it is
nobody else's, it is ours.

## What REALITY actually requires

A REALITY client handshake is not TLS with extra options. It authenticates by
reusing fields the client is permitted to set:

1. The client generates an ephemeral X25519 keypair and derives a shared secret with
   the server's public key.
2. `auth_key = HKDF(shared_secret, "REALITY")`; a short payload carrying a timestamp
   and a short-id is sealed with AES-GCM under it.
3. **The 32-byte ciphertext replaces the ClientHello's `legacy_session_id`.**
4. SNI names a real, unrelated site. The server, holding a token for that SNI,
   verifies the tag; on success it impersonates the site, on failure it proxies the
   handshake onward so an active prober sees a valid chain.
5. Certificate verification is therefore **not** the authenticator: the client must
   accept the presented certificate without a CA chain, because the server may be
   relaying a certificate it does not own.

Steps 1–2 are protocol logic. Steps 3–5 are TLS-stack capabilities, and step 3 has no
public API.

## Verified state of the TLS stack

Checked against `rustls 0.23.46`, the version resolved in `Cargo.lock` (the sibling
ADR cites 0.23.37; the conclusion is unchanged across that range):

| Requirement | Availability | Evidence |
| --- | --- | --- |
| Write `legacy_session_id` | **No** | `session_id` is `pub(super)` (`src/client/hs.rs:75`); the only non-resumption path is `SessionId::random(config.provider.secure_random)` (`hs.rs:119`). No config field, builder method or trait. |
| Accept a certificate with no CA chain | Technically yes, policy no | `set_certificate_verifier` exists (`client_conn.rs:575`) behind `dangerous()`. |
| Observe TLS record boundaries (needed by Vision) | **No** | The record layer is private. |

So the blocker is not scheduling and not `netune`: it is a public API that does not
exist and is unlikely to be added upstream, because the only consumer class is proxy
protocols.

**Vision adds a second, independent requirement**: it needs to see TLS record
boundaries to pad the first flight and to splice the rest. That is a *hostile* thing
for a general TLS client to expose, and it is exactly what ADR-0002 withholds.

## Decision

**1. `daer-outbound` implements a minimal TLS 1.3 client, used by the REALITY
connector and by nothing else.**

It lives at `crates/daer-outbound/src/reality/tls13.rs`, is `pub(crate)`, and is
reachable only through the REALITY connector. It is not general-purpose, does not
appear in any public API, and cannot be selected by configuration for an ordinary
`tls://` dial.

**2. The connection reaches the rest of daer through netune's public `Transport`
trait, with no netune change.**

`netune::Transport` is a public blanket trait (`connect.rs:23`:
`impl<T: AsyncRead + AsyncWrite + Send + Unpin> Transport for T`), and
`Established { stream: Box<dyn Transport> }` is how a connector returns a stream.
A REALITY handshake that `daer` performs therefore produces an ordinary `Established`
value, and every layer above it — relay, sniffing, the vless framing — sees a byte
stream identical in type to a `TcpConnector` result. This is the seam that makes the
boundary hold: `daer` owns the handshake, and netune is not modified.

**3. Scope is enforced by the type system, not by review.**

The only constructor of the REALITY connector is
`RealityConnector::from_link(&str, DialerOptions)`, which parses a `vless://` link
with `security=reality`. There is no path from `[global.tls].profile`, from
`trojan://`, or from any routing decision to the TLS 1.3 client.

**4. ADR-0002 is amended, narrowly.**

The rule becomes: *`daer` does not implement TLS for any dial that netune can
perform.* REALITY is a case netune cannot perform, so it is `daer`'s — and it stays
`daer`'s only for as long as that remains true. If `rustls` ever exposes a supported
`legacy_session_id` injection point, this ADR is superseded and the client is deleted,
not maintained.

## Why not the other options

- **Ask netune to expose `ForkOptions { legacy_session_id }`** — rejected by netune
  ADR-0009, and correctly. netune's value is verifiable identity (`INV-TLS-02`); a
  bypass mode needs an exception in that invariant, the benefit accrues to one
  consumer's product semantics, and the capability would exist in a general TLS
  client for no general purpose. **No netune change is requested by this ADR.**
- **Fork or patch `rustls`** — puts a security-critical TLS implementation on a
  private branch that every netune consumer would inherit, to serve one protocol.
  The patch is two hooks; the liability is indefinite.
- **Do nothing** — leaves the most common subscription node type unusable. The
  configuration already refuses such nodes loudly (rather than downgrading them), so
  the failure is honest, but it is still a failure of the product.

## Consequences

**Accepted cost.** `daer-outbound` will contain a TLS 1.3 implementation. That is a
real, permanent security surface — larger than any other single unit in this
workspace — and it must be treated accordingly:

- **No general-purpose use.** The only consumer is the REALITY connector. A second
  consumer is a new ADR.
- **No cipher-suite negotiation beyond what REALITY needs**: TLS 1.3 only, no TLS
  1.2, no renegotiation, no client certificates, no session tickets, no ECH.
- **Certificate verification is real when it can be.** REALITY requires accepting a
  certificate that does not chain to a CA. The code must therefore be explicit that
  the *authenticator* is the REALITY tag, and must still verify that the presented
  certificate is *the one the impersonated SNI would present* where the server's
  behaviour allows it. "Accept everything" is not the requirement; "accept this one
  because the tag proved the server" is.
- **Independent interoperability evidence.** The handshake is asserted against
  captured wire vectors from a reference implementation, not only against itself:
  two implementations agreeing on a wrong layout is the standard way a protocol
  implementation ships broken.
- **A visible dependency pin.** X25519 comes from `x25519-dalek`; `aes-gcm`, `hkdf`
  and `sha2` are already daer dependencies.

**Benefit beyond REALITY.** With the TLS record layer owned here, Vision's blocking
condition disappears: record boundaries are available because the record layer is
ours. Vision still needs its own decision (it changes how the session is spliced,
not just how the ClientHello is shaped), but it is no longer blocked by ADR-0002.

**What does not change.** Ordinary TLS — `trojan://`, DoT, DoH, HTTPS dials — keeps
going through netune. The fingerprint profile mechanism, `Target::tls`, the verifier
policy and every existing invariant are untouched.

## Negative knowledge

- **`fp=` must not be silently defaulted.** A REALITY ClientHello must present the
  fingerprint the node expects (`fp=chrome` and friends). If a link omits it, the
  connector must fail at load, because the alternative is a handshake that fails on
  the wire for a reason no log will attribute to the fingerprint. This is a
  configuration error, and it must be reported as one.
- **`flow=xtls-rprx-vision` is not a flag on a normal stream.** Acting on it without
  the record-boundary work would produce a session that works until the first large
  write, which is worse than refusing it. Until Vision is implemented, a link naming
  it must be refused at load.
- **A REALITY node is not "TLS to the node" in the diagnostic sense.** Its
  `Security` identity must say REALITY, not `tls sni=…`: the certificate presented is
  not evidence of identity, and reporting it as such would make
  `daer route nodes` claim a guarantee the session does not provide.

## Links

- Related: [ADR-0002](0002-netune-boundary.md) (amended narrowly by this record),
  [netune ADR-0009](../../../netune/docs/adr/0009-reality-client-authentication-not-a-netune-capability.md),
  [netune ADR-0004](../../../netune/docs/adr/0004-tls-fingerprint-profiles-pool-isolation.md)
- Evidence: `rustls 0.23.46` `src/client/hs.rs:75,119`;
  `src/client/client_conn.rs:575`.
- Seam: `netune::Transport` (`connect.rs:23`), `Established` (`connect.rs:138`).
