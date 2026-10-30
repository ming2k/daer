# What daer needs from netune

Network capabilities live in [`netune`](../../../netune). `daer` does not
reimplement them, and does not work around their absence: a gap here is a gap in
`daer`, tracked as work on netune.

The boundary is [ADR-0002](./adr/0002-netune-boundary.md): netune owns everything
above the socket — transport, TLS identity, HTTP framing, DNS *resolution*, proxy
handshakes, socket options, timing, and datagrams. `daer` owns what is specific to
being the *end* of a transparent connection: the tproxy accept path, eBPF maps, the
routing decision, the DNS **server** role and prefix sniffing.

## Corrections to this file's earlier claims

Three items were previously listed here as blocked on netune. They were **not**.
They were daer's own missing work, recorded as another project's debt — which made
the roadmap look better founded than it was and held back a day's work for months.
They are now implemented in `daer-dns`:

| Item | Earlier claim | Truth |
| --- | --- | --- |
| DNS over UDP upstream | "needs the datagram transport from netune" | **Wrong.** A direct UDP upstream is a plain `UdpSocket`. Only datagrams *through a proxy* need netune. Implemented in `daer-dns/src/transport.rs`. |
| DoT upstream | "needs the TLS client from netune" | **Wrong.** `netune::TlsConnector` returns `Established { stream: Box<dyn Transport> }`, a byte pipe. DNS-over-TLS is the existing length-prefixed framing inside it. Implemented. |
| DoH upstream | "needs the TLS client from netune" | **Wrong.** `netune::Client::request` takes a body and returns a response; RFC 8484 is `POST` with `application/dns-message`. Implemented. |

All four upstream protocols (`udp`, `tcp`, `tls`, `https`) are now real and
verified against live resolvers. **No netune change was needed for any of them.**

The rule that this file now follows: an item is listed here only after checking
that the capability is genuinely absent from netune's public surface. "I have not
looked" is not a blocker.

## 1. UDP — delivered in netune; consumed on the daer side ✅

netune gained a datagram path in [ADR-0008](../../netune/docs/adr/0008-datagram-transport-and-socks5-udp-association.md):
`UdpConnector` (the datagram twin of `TcpConnector` — same `DnsResolver`, same
`EgressConfinement`, same `SocketConfig`, `SO_MARK` applied before `connect`),
`DatagramConnector`/`DatagramTransport` with **per-peer connected sessions**, and
`Socks5DatagramConnector` for UDP associate.

Sessions are connected to one peer by decision, so `EgressConfinement` remains a
precondition of opening a socket rather than a per-datagram filter. A protocol
that multiplexes peers opens one session per peer; the SOCKS5 associate does its
own demultiplexing where the wire format already requires it.

| Need | Where in daer | State |
| --- | --- | --- |
| UDP relay for proxied traffic | `daer-control::datagram` | ✅ per-peer sessions, bounded table, idle reaping |
| UDP relay ingress | `daer-control::ingress_udp` | ✅ `TransparentDatagramListener`; not wired to a daemon entry point |
| DNS upstream over UDP (direct) | `daer-dns::transport` | ✅ plain `UdpSocket`, **does not use netune** |
| `udp_check_dns` health probe | `daer-outbound` health check | ✅ `UdpDnsChecker` |
| SOCKS5 UDP associate | proxy protocol support | ✅ via `Socks5DatagramConnector` (literal IP destinations) |
| QUIC-based protocols (`hysteria2`, `tuic`) | outbound protocols | ⬜ still blocked: datagrams exist, **QUIC does not** |

Two limits are deliberate and named rather than latent:

- **SOCKS5 UDP destinations are literal IP addresses only.** A domain destination
  would need `Target` to carry a second address channel that TLS verification and
  the pool key both ignore — a `Target` redesign with its own ADR.
- **QUIC is not implied.** `hysteria2`/`tuic` need a QUIC stack (and, for
  `hysteria2`, a pluggable congestion controller that stock implementations do not
  expose). That remains a dependency decision worth its own record.

## 2. `Preset` vocabulary — daer's problem, not netune's

daer's `tls_implementation: utls` + `utls_imitate: chrome_120` maps onto
`Preset::ChromeCurrent` (`crates/netune/src/tls_profile.rs:73`). Browser *build*
names and netune's *current* identities are different vocabularies. That mapping is
not needed by `daer` any more — the configuration names netune presets directly —
and it must never appear in netune: netune's vocabulary is its own. **No netune
change requested.**

## 3. Already sufficient — verified, do not change

These seams are exactly right and `daer` depends on them:

- `Target::tls(authority, server_name)` (`connect.rs:67`): `authority` is the
  socket address, `server_name` is the name verified against the certificate —
  precisely what `dial_mode = "domain"` / `"domain+"` need (connect to the IP the
  routing decision used, present the sniffed domain).
- `DnsResolver` is a public trait (`dns.rs:22`), so `daer-dns` can inject its own
  resolver — including a "return exactly this cached address" implementation for
  `dial_mode = "ip"`.
- `Connector` is a public trait returning `Established { stream: Box<dyn Transport> }`
  (`connect.rs:138`), so daer's protocol implementations (shadowsocks, vmess,
  vless, trojan, REALITY) compose as connectors over a raw stream instead of
  needing a netune change per protocol. Chained proxies (`a -> b`) nest the same way.
- **`Transport` is a public blanket trait** (`connect.rs:23`: `pub trait Transport`
  with `impl<T: AsyncRead + AsyncWrite + Send + Unpin> Transport for T`). This is
  the seam that makes a REALITY client possible **without any netune change**: a
  handshake `daer` owns can hand its resulting stream to netune as an `Established`
  value. See ADR-0010.
- `EgressConfinement::Unrestricted` is the default (`connect.rs:163`) — daer must
  reach private addresses, so `strict_public()` must never be used on the data
  path.
- `SocketConfig::mark` runs before `connect(2)` (`socket.rs:39`) — this is what
  `global.so-mark` needs, applied before the SYN rather than after the handshake.
- `Client::request(target, head, Option<Bytes>)` (`client.rs:115`) is what the DoH
  upstream and the subscription fetcher use; `TlsConnector` is what the DoT upstream
  uses.

## 4. REALITY — daer's, and netune must not grow it

**No netune change is requested. This section exists to record why, so it is not
re-litigated.**

REALITY authenticates by placing an X25519/HKDF/AES-GCM tag in the ClientHello's
`legacy_session_id` and by accepting the presented certificate **without** a CA
chain (the server may be relaying a real site's certificate).

Verified against `rustls 0.23.46` (the version in `Cargo.lock`, newer than the
0.23.37 the sibling ADR cites; the conclusion is unchanged):

- `session_id` is `pub(super)` (`src/client/hs.rs:75`) — unreachable from outside.
- The only non-resumption path is `SessionId::random(config.provider.secure_random)`
  (`src/client/hs.rs:119`). There is no config field, no builder method, no trait.
- `set_certificate_verifier` **does** exist (`client_conn.rs:575`, behind
  `dangerous()`), so the *verification* half is technically possible. The
  *write* half is not. REALITY needs both.

The earlier phrasing of this file said REALITY was "blocked on netune". It is not
blocked on netune; it is blocked on `rustls`, and the answer is
**ADR-0010 in this repository**: `daer-outbound` owns a minimal TLS 1.3 client used
by the REALITY connector and by nothing else.

Why netune must not be the place:

1. **Its invariant is verifiable identity.** `INV-TLS-02` says a profile presents a
   stable, verifiable identity. A bypass mode would need an exception carved into
   it, and a security invariant with an exception is not an invariant.
2. **The benefit is one-sided.** Only a proxy protocol uses a ClientHello session-id
   channel. netune would carry the capability, the review burden and the
   fingerprinting surface, and gain nothing.
3. **`ForkOptions { legacy_session_id }` does not fix that.** A "neutral hook" is
   still a capability that exists only for one consumer's product semantics.

What `daer` may rely on from netune for REALITY: **nothing new.** The
`Transport` trait above is sufficient — a stream daer handshakes can be handed back
as `Established`.

## 5. Deferred, not requested

- **QUIC stack** for `hysteria2` / `tuic`. A dependency decision, not a netune gap:
  whichever library is chosen would sit beside netune, not inside it, because it is
  a transport *below* the HTTP layer netune owns.
- **DoQ** (DNS over QUIC, RFC 9250). Same reason.

## 6. Non-blocking observations

- `netune-trace` already parses ClientHello for JA4. If `daer-sniff` ever needs
  more than the SNI, reusing that parser would keep one implementation of a
  hostile-input parser. Non-blocking; `daer-sniff` is currently independent and
  budget-bounded.
- Health checks currently measure connect time by driving a full request. A
  `TCP_INFO`-based RTT sample (`netune::sample_tcp_info`) would remove that
  duplication and keep the measurement semantics in one place. Non-blocking.
