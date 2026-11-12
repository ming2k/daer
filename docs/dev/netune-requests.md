# What daer needs from netune

Network capabilities live in [`netune`](../../../netune). `daer` does not
reimplement them, and does not work around their absence: a gap here is a gap in
`daer`, tracked as work on netune.

The boundary is [ADR-0002](../adr/0002-netune-boundary.md): netune owns everything
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
| DNS over UDP upstream | "needs the datagram transport from netune" | **Wrong as a blocker.** A direct UDP upstream does not need proxy datagram support. Implemented in `daer-dns/src/transport.rs`; it now uses netune's `UdpConnector` so the daemon's `SocketConfig`/`SO_MARK` and trace vocabulary apply uniformly. |
| DoT upstream | "needs the TLS client from netune" | **Wrong.** `netune::TlsConnector` returns `Established { stream: Box<dyn Transport> }`, a byte pipe. DNS-over-TLS is the existing length-prefixed framing inside it. Implemented. |
| DoH upstream | "needs the TLS client from netune" | **Wrong.** `netune::Client::request` takes a body and returns a response; RFC 8484 is `POST` with `application/dns-message`. Implemented. |

All four upstream protocols (`udp`, `tcp`, `tls`, `https`) are now real and
verified against live resolvers. **No netune change was needed for any of them.**

The rule that this file now follows: an item is listed here only after checking
that the capability is genuinely absent from netune's public surface. "I have not
looked" is not a blocker.

## 1. UDP — delivered in netune; consumed on the daer side ✅

netune gained a datagram path in [ADR-0008](../../../netune/docs/adr/0008-datagram-transport-and-socks5-udp-association.md):
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
| UDP relay for proxied traffic | `daer-relay::relay::datagram` | ✅ per-peer sessions, bounded table, idle reaping (ADR-0018) |
| UDP relay ingress | `daer-relay::inbound::udp` | ✅ `TransparentDatagramListener`, wired into the daemon (ADR-0018) |
| DNS upstream over UDP (direct) | `daer-dns::transport` | ✅ netune `UdpConnector`, with the daemon's `SocketConfig` |
| `udp_check_dns` health probe | `daer-outbound` health check | ✅ `UdpDnsChecker` |
| SOCKS5 UDP associate | proxy protocol support | ✅ via `Socks5DatagramConnector` (literal IP destinations) |
| QUIC-based protocols (`hysteria2`, `tuic`) | outbound protocols | ✅ QUIC/H3 delivered in netune; `hysteria2` consumes `netune-quic`/`netune-http3` (ADR-0035) |

One limit is deliberate and named rather than latent:

- **SOCKS5 UDP destinations are literal IP addresses only.** A domain destination
  would need `Target` to carry a second address channel that TLS verification and
  the pool key both ignore — a `Target` redesign with its own ADR.

QUIC is no longer a gap: netune ADR-0016 delivered `netune-quic` (RFC 9000,
RFC 9221) and `netune-http3` (RFC 9114) under `aws-lc-rs`, and netune 0.0.28 owns their
state machines (netune ADR-0027, ADR-0028); daer ADR-0035 removes the direct `quinn`,
`h3`, `h3-quinn` and `ring` dependencies. Hysteria 2 still owns its product-specific
socket layers (Salamander/Gecko, port hopping, Brutal), but they implement netune's
`QuicUdpSocket`/`CongestionControllerFactory` seams rather than constructing a QUIC
endpoint themselves.

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
  and taking a `&TraceCollector`, so daer's protocol implementations (shadowsocks,
  vmess, vless, trojan, REALITY) compose as connectors over a raw stream instead of
  needing a netune change per protocol. A dial nobody observes passes
  `TraceCollector::disabled()`; an observed dial installs a sink before connecting.
  Chained proxies (`a -> b`) nest the same way.
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
- `QuicUdpSocketFactory` builds one socket stack per connection after egress
  confinement and before the first Initial packet, and receives the connector's
  `QuicSocketConfig`. Hysteria 2 applies that config (including `SO_MARK`) to the
  base socket, so the seam cannot silently skip a pre-connect option.
- `QuicProfile.path_mtu_discovery` (netune 0.0.28) makes DPLPMTUD policy explicit.
  daer's `disable-path-mtu-discovery` maps to it instead of being listed as an
  engine property that happened to be true; disabling advertises the 1200-byte
  QUIC floor so the probe ceiling cannot grow.

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

- **DoQ** (DNS over QUIC, RFC 9250). netune now owns a QUIC client transport
  (`netune-quic`), so this is no longer blocked by a missing stack; it is a daer
  DNS-transport feature that nobody has asked for yet.

## 6. Delivered in netune 0.0.28

The three gaps named here were closed upstream in netune 0.0.28 (ADR-0043), and
`daer` now consumes the seams:

- **Raw ALPN.** `Established.alpn_protocol: Option<Vec<u8>>` carries the exact
  negotiated name; the trace enum remains the classification. `daer` reports both
  through `Opaque`, and a private ALPN name survives the handshake.
- **QUIC authority resolution.** `QuicConnector::connect_authority` uses the
  injectable `QuicResolver` (default `SystemQuicResolver`), brackets
  `DnsStart`/`DnsEnd`, and applies `EgressConfinement` to every resolved address
  before socket creation. Hysteria 2 no longer resolves outside the connector.
- **Head-only HTTP/1.1.** `netune-http1::write_request_head` writes the caller's
  exact request line and header list with no synthetic `Content-Length` or
  `User-Agent`. The WebSocket upgrade uses it; `daer` supplies the product
  fingerprint headers and netune owns the HTTP grammar.

## 7. Non-blocking observations

- `netune-trace` already parses ClientHello for JA4. If `daer-sniff` ever needs
  more than the SNI, reusing that parser would keep one implementation of a
  hostile-input parser. Non-blocking; `daer-sniff` is currently independent and
  budget-bounded.
- Health checks currently measure connect time by driving a full request. A
  `TCP_INFO`-based RTT sample (`netune::sample_tcp_info`) would remove that
  duplication and keep the measurement semantics in one place. Non-blocking.
