# ADR-0002 — network capabilities live in netune; the data path lives here

- Status: accepted
- Amended by: [ADR-0010](0010-reality-client-ownership.md) — `daer` does not implement TLS
  for any dial **netune can perform**; REALITY is a dial netune cannot perform, so its TLS
  1.3 client lives in `daer` and nowhere else.
- Amended by: [ADR-0017](0017-proxy-protocols-crate-boundary.md) — proxy product protocols
  (shadowsocks, trojan, anytls, hysteria2, reality) and the minimal TLS 1.3 client are decoupled
  from `daer-outbound` into `daer-proxy-protocols`.
- Date: 2026-01-07
- Related: `Cargo.lock`

## Context

`daer` and [`netune`](../../../netune) are sibling projects. netune is an owned
network stack: HTTP/1.1 codec, TLS (rustls + fingerprint profiles), DNS
resolver, TCP connect (including socket options before `SYN`), connection pool,
HTTP `CONNECT` and SOCKS5 clients, `TCP_INFO` sampling, a trace model, and
fault-injection twins.

The tempting simplification is "daer does eBPF, netune does everything above the
socket". That is wrong in one direction and right in the other, and the
difference decides how both projects evolve.

`daer` needs, above the socket:

| Capability | netune today | Owner |
| --- | --- | --- |
| Outbound dialing with `SO_MARK` before `connect(2)` | yes (`SocketConfig::mark`) | netune |
| HTTP/1.1 request construction, response parsing, decompression | yes | netune |
| TLS with a configurable fingerprint (JA3/JA4) | yes (`Preset`, `TlsProfile`) | netune |
| SOCKS5 / HTTP `CONNECT` clients | yes (`ProxyConnector`) | netune |
| `TCP_INFO` sampling (RTT, retransmits, cwnd) | yes (`sample`) | netune |
| Health probes (HTTP and bare TCP) | yes, via the above | netune |
| TCP/UDP proxying for arbitrary destinations | TCP yes; **UDP transport yes** (netune ADR-0008), the *relay* is daer's | daer (relay) |
| DNS **server** role + cache + DNS message semantics | no (client resolver only) | daer |
| DNS upstream transports (UDP/TCP/DoT/DoH) | yes (`UdpConnector`, `TcpConnector`, `TlsConnector`, `Client`) | netune |
| Transparent-proxy accept path: `IP_TRANSPARENT`, original destination | no | daer |
| eBPF map access, event ring, routing epochs | no | daer |
| Prefix sniffing (TLS SNI, HTTP `Host`, QUIC) before dialing | partial (`netune-trace` parses ClientHello / JA4) | daer (thin layer over netune-trace) |
| Proxy protocols: shadowsocks, vmess, vless, trojan, hysteria2, tuic | no (`Proxy` has two variants) | daer |

## Decision

1. **Network capabilities are netune's.** Anything `daer` needs in order to
   *speak* to the network — TLS identity, HTTP framing, the `CONNECT`/SOCKS5 proxy
   handshakes, socket options, RTT sampling, and datagrams — is built in netune,
   not duplicated in `daer`. `daer-outbound` decides *which* netune primitive to
   use with which parameters; it does not open codecs, sockets or handshakes of
   its own. A capability netune lacks is a netune task
   (`../dev/netune-requests.md`), not a reason to write a second implementation
   here.

   The boundary inside "proxy handshakes" is `CONNECT`/SOCKS5 versus a proxy
   *product protocol* (shadowsocks, vmess, vless, trojan, anytls, hysteria2). The
   first two are generic tunneling primitives with no product semantics, so they
   live in netune. The rest carry protocol-specific semantics that are daer
   features, so they live in `daer-outbound`. Decision 3's wording is the
   authoritative half of that split; an earlier draft of this paragraph listed
   "proxy handshakes" unqualified, which read as a contradiction.

   The WebSocket upgrade keeps a narrow product-fingerprint exception, but not an
   HTTP implementation: `daer-proxy-protocols` supplies the exact request header
   list and order, and `netune-http1::write_request_head` serializes it with no
   synthetic `User-Agent` or `Content-Length`. The response head is parsed by
   `netune-http1`, and all frames, ping/pong and close handling remain
   `netune-ws`. `netune`'s ordinary client would add headers that change what
   every proxied node sees; the head-only writer is the generic seam that avoids
   that without a second codec.
2. **netune does not grow inbound or kernel-adjacent capabilities.** The
   tproxy listener, original-destination recovery, eBPF map I/O, the DNS server
   role and the UDP relay belong to `daer-control` / `daer-dns`. Pushing them
   into netune would turn a general, feature-gated client stack into a
   proxy-appliance framework and would put `CAP_NET_ADMIN`-shaped concerns
   behind an API that other netune consumers (which hold no such privileges)
   would have to carry.
3. **Gaps are named, not papered over.** The transport gaps this ADR once
   tracked are closed:
   - **UDP — closed in netune (ADR-0008) and consumed by daer.** netune owns the
     datagram socket (`UdpConnector`, `DatagramConnector`, SOCKS5 UDP associate);
     daer uses it for DNS upstreams, Shadowsocks, Trojan and Hysteria 2. The
     *relay* and ingress remain daer's.
   - **QUIC — closed in netune.** `netune-quic` owns the QUIC/H3 client state
     machines (netune ADR-0016, ADR-0027, ADR-0028); Hysteria 2 keeps only its
     product layers (obfuscation, port hopping, Brutal) behind netune's
     `QuicUdpSocketFactory`/`CongestionControllerFactory` seams.
   - **Proxy protocols beyond `CONNECT`/SOCKS5.** These are daer features with
     product semantics and do not belong in a generic client library. One
     exception is recorded: REALITY is blocked at the TLS-stack level, not here
     (see Decision 1's note and netune ADR-0009).

   The remaining non-netune network code is deliberate:
   - **Ingress and appliance roles** — transparent TCP/UDP listeners, the DNS
     server role, UDP reply sockets and the relay. netune is an outbound client
     stack (ADR-0002 Decision 2).
   - **Kernel datapath** — eBPF maps, TCX hooks and policy encoding.
   - **Product TLS** — REALITY's TLS 1.3 client, because rustls exposes no
     ClientHello injection point (ADR-0010).
   - **Diagnostic probes with an unmarked stack** — `daer probe` phases 1 and 2
     use netune's `SystemResolver` and `TcpConnector` with a default, unmarked
     `SocketConfig`. They deliberately do not apply daer's daemon marks or
     routing policy, because the question is whether the node is reachable
     *outside* that policy stack. Phases 3 and 4 use netune through
     `daer-outbound`.
4. **The upstream dependency is locked.** `Cargo.toml` specifies the exact
   release tag (`tag = "v0.0.28"`), and `Cargo.lock` records the exact Git commit SHA.
   CI verifies the lock file using `--locked`. Local co-development may point the
   same package names at a sibling working tree with a `[patch]`; that override is
   development scaffolding and must not decide the released combination.
5. **Where netune must change, the change is upstreamed and documented.** The
   `SO_MARK`-before-connect gap was closed in netune (`SocketConfig::mark`:
   manual socket, `SO_MARK`, non-blocking connect, wait-for-writable,
   `take_error`, `Unsupported` on non-Linux) rather than worked around in daer.
   Same rule for the next gap.

## Consequences

- `daer-outbound` is thin: latency statistics, alive-set selection, group
  assembly, policy, and the mapping from a node link to a netune connector.
- `daer-dns`, `daer-sniff`, `daer-control` may not import netune's client APIs
  for their own work; they talk to netune only where an outbound connection is
  what is actually needed.
- `cargo tree` remains a useful audit: no HTTP or TLS implementation may appear
  in daer's graph except through netune.
- UDP and QUIC ownership are resolved, not open questions. The source guards in
  `daer-proxy-protocols`, `daer-dns`, `daer-outbound` and `daer-cli` make a
  reintroduced generic dial, DNS lookup or TLS handshake fail CI; ingress,
  product TLS and the kernel datapath stay outside those guards by design.
