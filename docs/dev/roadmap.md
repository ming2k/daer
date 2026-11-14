# Roadmap

Ordered by what unblocks the next step, not by size. Each milestone has an
executable exit criterion; "looks done" is not one.

Legend: ✅ done · 🟡 partial · ⬜ not started

## Where things stand

| Area | State |
| --- | --- |
| Protocol: REALITY (tag, TLS 1.3 client, certificate check, `X25519MLKEM768`) | ✅ verified end to end against a local reference `xray` inbound, in CI (`tests/e2e/protocols_reality_interop.rs`) |
| Protocol: XTLS Vision (`flow=xtls-rprx-vision`) | ✅ verified end to end (uplink and downlink) against a local reference `xray` inbound, in CI |
| Configuration (TOML schema, expression language, loader, validation) | ✅ |
| Configuration tooling (JSON Schema + drift check; `fmt`/`example` removed by ADR-0015) | ✅ |
| Decision tooling (`daer route --why --domain`, `daer check --nodes`, node security identity) | ✅ |
| Active diagnostics (`daer probe node`, `daer probe url` — L3/L4/L7 tiers, ADR-0016) | ✅ links, names, `--all`, and `--file` (subscription bodies) all resolve through one decoder; a live VLESS+REALITY node was verified to carry a real HTTP request and a real inner-TLS request |
| Routing semantics (lowering, matching, policy identity, geodata) | ✅ reference implementation |
| Routing matcher performance | ✅ indexed, allocation-free: `suffix` is a label walk over a hash set, `keyword` Aho–Corasick, `regex` a `RegexSet`, `full` a hash set, `dip`/`sip` merged intervals + binary search. Measured on `geosite:cn` (110,249 domains): 368 µs → **89 ns** on a miss, 28.9 µs → **82 ns** on a hit. `tests/hot_path.rs` asserts the cost does not scale with set size and that a decision allocates nothing |
| Subscriptions (fetch, base64 / SIP008 / plain decoding, `persist` cache) | ✅ `daer-outbound::subscription` + `daer-control::subscription`; resolved before a generation is built, so `Router::new` stays a pure function of its configuration |
| Datapath object loading (ABI, section normalization, map/program names) | ✅ |
| Outbound: latency, alive set, resource pools, elections, direct/SOCKS5/HTTP `CONNECT`, probes | ✅ |
| Outbound: shadowsocks AEAD (aes-gcm, chacha20-poly1305) | ✅ |
| Outbound: trojan (TLS to the node via netune) | ✅ |
| Outbound: chained links (`a -> b`) | ✅ expressed as `[[node]] detour` (ADR-0044); URI chain strings are still rejected loudly |
| Outbound: anytls | ✅ multiplexed session, framing, datagrams |
| Outbound: **vless as orthogonal layers** | ✅ per [ADR-0028](../adr/0028-protocol-layering.md): transport (`tcp`, `ws`) × security (`none`, `tls`, `reality`) × flow (`none`, `xtls-rprx-vision`). `tests/layer_matrix.rs` starts one local `xray` with five inbounds and takes a round trip through each reachable row, plus a negative control (a plaintext listener dialled as `security=tls`). Vision over `ws` is **refused at load**: the reference rejects it on both ends ("XTLS only supports TLS and REALITY directly for now"), and the fixture's configured-but-unused inbound is what makes that a test rather than a claim |
| Outbound: **vmess AEAD** | ✅ per [ADR-0030](../adr/0030-vmess-aead-only.md): the reference's aliasing-hasher KDF (six vectors taken from `aead.KDF` itself), `AuthID`, the sealed header, the three size modes, both ciphers and both data planes. `tests/vmess_live.rs` takes a round trip through a real `xray` VMess inbound for `auto`/`aes-128-gcm`/`chacha20-poly1305`, with `AuthenticatedLength` on and off, and over `ws`. The legacy handshake is not expressible: a non-zero `aid` is a load error |
| Outbound: **hysteria2, complete** | ✅ per [ADR-0029](../adr/0029-hysteria2-socket-stack.md): Salamander and Gecko on the datagram path (the `obfs` key used to be parsed and never applied — the defect the ADR exists for), per-flow session ids, fragmentation/reassembly, `Hysteria-UDP`/`Hysteria-CC-RX` honoured, Brutal congestion control, and source-port hopping through netune's `QuicUdpSocket` seam. `tests/hysteria2_live.rs` starts the reference server itself — including one configured **with** Salamander, so the obfuscation is proven on the wire, not in a struct |
| Outbound: `tuic` | ⬜ the one family left: not implemented, listed and reported as unselectable |
| Outbound: `[tls] fragment` (ClientHello slicing) | ✅ honoured on the REALITY path, whose handshake daer owns; a `trojan://` node's hello is written inside netune's connector, where the setting cannot mean the same thing |
| Outbound: `[tls] profile` | ✅ applied per `Target`; an unknown name is a load-time error |
| Health checks: an election's `mode`/`url`/`method` and `udp-dns` are what probes use; `url` mode measures through the node | ✅ |
| Outbound: Vision (`xtls-rprx-vision`) | ✅ framing both ways, and the peer's `Direct` is honoured with a raw read (see below). The uplink never claims `Direct` — it sends `End` — because a splice on our side is not implemented; that costs throughput on a TLS stream and nothing else |
| Outbound: Vision, **inner TLS** | ✅ a TLS stream through the tunnel works (`curl https://…`, three runs, against a local reference node with a local TLS origin). This was broken until the peer's `Direct` was implemented: the node stops encrypting and a client that keeps decrypting reads ciphertext as plaintext (`the record was altered`). Plaintext (HTTP) inside the tunnel always worked, which is exactly why the gap survived — the e2e probe tier was a plaintext GET, so `daer probe node` reported "fully operational" for a node that could not carry a single HTTPS request |
| Outbound: REALITY | ✅ owned by `daer-outbound` per [ADR-0010](../adr/0010-reality-client-ownership.md): a minimal TLS 1.3 client (`reality/tls13`), reachable only from a `security=reality` link. Key schedule verified against RFC 8448 vectors; record layer tested for tamper detection; the tag in `legacy_session_id` is asserted on the wire; the ClientHello offers `X25519MLKEM768` and classic `X25519` over the same secret for old and new servers. **Interop is now a CI fixture**: `tests/e2e/protocols_reality_interop.rs` starts a local reference `xray` inbound and takes a session through REALITY + Vision in both directions, with four negative controls (wrong `pbk`, wrong `sid`, wrong UUID after REALITY, and a server that speaks no REALITY). It skips with a reason when no `xray` binary is present, so it never becomes a dependency on someone else's uptime |
| Datagrams: netune transport + SOCKS5 UDP associate (netune side) | ✅ |
| Datagrams: transparent UDP ingress (`IP_ORIGDSTADDR`) + relay | ✅ `TransparentDatagramListener`, per-peer sessions, bounded table, idle reaping; wired into `Daemon::serve` |
| Datapath: IPv6 TCP and UDP | ✅ separate tcp6/udp6 listener slots, family-aware `assign_listener`, IPv6 extension-header parsing, and independent IPv6 Fake-IP allocation (`dns.fake-ip.inet6`) |
| Health checks: probes + scheduler (`UdpDnsChecker`, `Scheduler`) | ✅ probe instrument follows the node's claims; results record into the live generation |
| DNS: wire format (parse/encode, compression, records) | ✅ |
| DNS: `[dns.request]` / `[dns.response]` routing | ✅ |
| DNS: cache (TTL, stale-while-revalidate, negative answers, bounds) | ✅ |
| DNS: answer pipeline (routing → cache → transport → response routing) | ✅ |
| DNS: upstream syntax + DNS over TCP | ✅ |
| DNS: UDP, DoT, DoH transports | ✅ all four upstream protocols real and verified against live resolvers; `udp` uses netune's `UdpConnector`, `tcp` uses netune's `TcpConnector`, `tls` rides netune's `TlsConnector` as a byte pipe, `https` uses netune's client. Every connector carries the daemon's `SocketConfig`, so DNS egress is marked and traced like any other outbound |
| DNS: UDP and TCP server sockets | ✅ |
| DNS: served by `daer run`, upstream usability gated by `daer check` (ADR-0015) | ✅ |
| DNS: bootstrap resolver | ⬜ |
| Sniffing (TLS SNI incl. split records, HTTP `Host`, absolute-form target) | ✅ |
| Sniffing: connection-side loop, `dial-mode = domain` wired into routing | ✅ |
| Sniffing: QUIC Initial decryption | ⬜ |
| UDP: relay wired and driven | ✅ `Daemon::serve` runs the datagram service, one session per peer, replies routed back to the right peer, counters readable |
| UDP: IPv6 proven through `tproxy` | ✅ `tests/e2e/control_transparent_udp6.rs` builds a real client/origin two-namespace topology, requires the negative control to fail without the daemon, and checks the origin's nonce plus the relay counters; CI makes its skip fatal as `3-udp6` |
| UDP: IPv4 proven through `tproxy` | ✅ `tests/e2e/control_transparent_udp4.rs` builds the same two-namespace client/origin topology as the IPv6 test, with a negative control, the origin's nonce, and relay counters; CI makes its skip fatal as `3-udp4` |
| Daemon runtime: spawned tasks are scheduled | ✅ `daer run` uses a multi-threaded runtime. A current-thread runtime starved the spawned datagram forward — session opened, reply never sent — which took a debugging pass to attribute to the runtime rather than the relay (`tests/integration/cli_runtime.rs`) |
| Configuration: every accepted key has a consumer | ✅ enforced by `daer-config::tests::config_keys` |
| Control plane: transparent accept, relay, accept loop with metrics | ✅ |
| Control plane: routing verdict + outbound dialing per flow | ✅ |
| Control plane: reload generations (atomic swap, reports, rejection) | ✅ |
| Control plane: routing-epoch design + publish sequence (ADR-0004) | ✅ userland |
| Control plane: interfaces, tc attach, kernel map writes | ✅ attach + `PARAM` + epoch/meta + routing table + LPM tries + outbound connectivity (ADR-0005); `run::reload` calls `republish_policy` after a userspace swap, so a reload reaches the kernel table too |
| Daemon (`daer run`, SIGHUP reload, drain, logging, health scheduling, UDP relay, one shared loader) | ✅ |

**`daer run` now proxies traffic.** The wiring that was missing —
`crates/daer-control/src/daemon.rs`, `datapath.rs`, and `crates/daer-cli/src/run.rs` — loads
the object, creates and attaches `daer0`/`daer0peer`, binds the transparent port, and serves.
`tests/e2e/control_transparent.rs` proves it with `nftables tproxy` into a real origin, and
[`docs/how-to/deployment.md`](../how-to/deployment.md) is the operator's side. What remains is map *writes* per reload (the
publish sequence of ADR-0004 exists and is tested against a `MapWriter` trait; the `tc`
side of a live policy swap is not wired).

## 1. Datapath ownership 🟡

The object is loaded correctly today, but its source and a few of its string
identifiers belong to another project.

- Vendor the datapath C source into `ebpf/kern/`, with the headers it needs.
- Rename its identifiers to `daer*` (`daer0`, `daer_ifindex_map`, `daer_param`).
- Revalidate with `cargo xtask ebpf` + `cargo test -p daer-ebpf`, and record the ABI in
  one place: generate the map/program name tables from the datapath's sync spec
  and fail CI on drift.

**Exit:** `cargo xtask ebpf` builds from `ebpf/kern` with no external checkout, and
`names.rs` is generated.

## 2. Data path (`daer-relay` + `daer-control`) 🟡

The largest piece. Order matters: this is what makes the binary useful.

1. **Ingress and relay** ✅ — `daer-relay` (ADR-0018): transparent listener
   (`IP_TRANSPARENT` for both families; no `SO_REUSEPORT`, because `bpf_sk_assign`
   names the exact listener),
   original destination from the accepted socket, self-connect rejection,
   half-close-correct relay, accept loop with resource-exhaustion backoff and live
   counters. The loop is driven through `Ingress`/`Decide` traits, so its failure
   modes are tested without privileges, a configuration or a protocol.
2. **Kernel wiring** ✅ — attach the datapath programs to the LAN/WAN tc hooks,
   create `daer0`/`daer0peer`, publish the listener fds, the outbound connectivity and
   the routing table itself into the maps ([ADR-0005](../adr/0005-kernel-policy-encoding.md)).
   The table is either provably equivalent to the userspace evaluator or a one-entry
   deferral, never empty and never partial: an empty table makes `route()` return
   `-EPERM`, which every caller turns into `DAER_TC_DROP`, so "no policy" was never a
   safe state. **Exit:** the encoded table agrees with `first_hit` on a generated flow
   corpus, which `tests/integration/routing_kernel_policy.rs` asserts.
3. **Routing decision** ✅ — the flow's tuple becomes `MatchFacts`, the compiled
   program yields a verdict, and `block` / `direct` / election are applied per flow.
   Facts the ingress cannot know (sniffed domain, process name, DSCP, source MAC)
   are supplied as unknown, so a rule that needs them cannot match by accident.
   The fallback is a value, not an error: an unmatched flow is *the* fallback.
4. **Proxied flow** ✅ — an election selects one node from its resource input and the node
   dialer opens the other leg (direct, SOCKS5, HTTP `CONNECT`). Nodes whose
   protocol is not implemented yet are listed but not selectable: an unknown scheme
   is never downgraded to `direct`, which would leak the flow.
5. **Reload** 🟡 — generations are immutable and published by one atomic swap; a
   generation that fails to build publishes nothing; flows are owned by a
   `Supervisor`, so stopping an accept loop does not end them; the new listener
   binds before the old one stops (`SO_REUSEPORT`). `tests/handover.rs` asserts a
   live flow surviving a reload, one connection crossing eight generations, and the
   port never being unbound. Each reload reports whether the *routing* changed (a
   semantic hash, not a file diff).

   The kernel half is designed in [ADR-0004](../adr/0004-routing-epochs.md) and its two
   privilege-free halves are implemented: every map is classified as per-generation or
   shared (an unclassified map fails a test), and the publish sequence — fill the
   inactive slot, stamp it, verify the stamp, then switch — is written against a
   `MapWriter` trait and asserted to leave the active slot unchanged on every failure.
   Remaining: 1000 reloads under a long-lived connection with zero drops — the soak that
   would turn "the swap is correct" into "the swap is correct under load". The kernel half is
   wired: `run::reload` calls `datapath::republish_policy` after publishing a new userspace
   generation, so a reload now reaches the kernel table as well as the decisions. What that
   path lacked until recently was a test that could fail at all — the *first* `SIGHUP` used to
   panic the daemon (`reload` called `block_on` from inside the runtime), which no unit test
   saw because none of them signalled a running process. `tests/e2e/cli_reload.rs`
   now starts the real binary, sends `SIGHUP`, and asserts the process is alive **and** that
   generation 2 was published; `scripts/verify/kernel-check.sh` section 8 runs it where the
   transparent port can bind. **Exit:** 1000 reloads under a long-lived connection with zero
   drops, and a kernel-tier assertion that the table was rewritten rather than merely
   republished in userspace. A reload is also synchronous inside the signal loop, so a slow
   subscription fetch delays new accepts (they queue in the listener's backlog rather than
   being dropped); spawning the reload is the fix and belongs with the soak that can measure it.

## 3. DNS (`daer-dns`) 🟡

Done: the wire format (owned, hostile-input hardened, compression-aware) and
`[dns.request]` / `[dns.response]` routing with the decisions `asis`, `reject` and a
declared upstream. The request/response distinction is enforced at compile time, so a
typo in an upstream tag fails at load rather than per query.

Done as well: the answer cache — `(name, qtype, qclass)` keys, remaining-TTL on a fresh
hit, RFC 8767 stale-while-revalidate with an explicit "needs refresh" signal, negative
answers cached and `SERVFAIL` deliberately not, `fixed-domain-ttl` overrides applied
longest-suffix-first, and a hard entry bound with deterministic eviction.

Done as well: the pipeline. A query goes through request routing, the cache, an
injected `Upstream` transport and response routing, with counters for hits, stale hits,
misses, upstream calls and failovers. Failover is one hop and a self-referential failover
is ignored rather than followed. The transport is a trait, so UDP/TCP/DoH/DoT each become
an impl and nothing above them changes.

Done as well: the `dns.upstream` entry syntax (`tag:protocol://host:port`, `+` chains,
reserved tags rejected) and DNS over TCP, which is one length-prefixed exchange per query
with an id check and a hard timeout. `Resolver::from_config` builds the transports a
configuration declares, so a real config resolves for real; a protocol this build cannot
speak becomes an `Unavailable` transport that names the protocol in the failure.

Every transport failure mode has a test: a correct exchange, a mismatched id (someone
else's answer), a malformed reply, a silent upstream (timeout), and a refused connection.

Done as well: the server. UDP and TCP sockets accept queries, hand them to the resolver and
write the answers, with the two framing rules that decide correctness — a UDP reply too
large for the client's EDNS size sets `TC` instead of being silently shortened, and a TCP
connection carries a bounded number of length-prefixed queries. `asis` is expressed as
silence on both, because the decision means "let the client's own resolver answer".

Done as well: the runnable service. `daer run` starts the resolver itself — UDP and TCP on
`dns.bind` — and installs `SIGINT`/`SIGTERM` handlers that stop it after letting in-flight
queries finish. There is no standalone DNS subcommand: `daer check` reports which upstreams
this build can use and exits non-zero when one cannot, so it is usable as a CI gate.
`tests/end_to_end.rs` drives a real UDP client through the real server to a real DNS-over-TCP
origin.

Remaining: the bootstrap resolver, and name resolution for an upstream address (an entry
must currently be `ip:port`). Every transport — `udp`, `tcp`, `tls`, `https` — is
implemented and verified against live public resolvers.

**Exit:** a client using the box as its resolver gets answers, the cache is
observable, and a request whose rule names a specific upstream is routed there.

## 4. Domain acquisition (`daer-sniff`) 🟢

Done: prefix inspection that returns a decision (`NeedMore` / `Domain` / `None` /
`Malformed`) rather than transforming a stream. TLS ClientHello SNI is reassembled across
records, and the parser is bounds-checked and budget-limited so a hostile length field
cannot make the caller buffer without limit. HTTP is covered through `Host`, including a
`host:port` split, case-insensitive header names, and absolute-form request targets.
QUIC Initial support decrypts the Initial packet and reads the SNI from its CRYPTO frame.

Done as well: the policy and the connection-side loop. `daer-control::domain` owns
`DomainPlan` and `DomainResolver`: Fake-IP first, a unique DNS-snooper candidate second,
payload inspection only when `[routing.sniff] enabled = true`, and address last.
`sniff_stream` **peeks** (never consumes, so the origin receives every byte), bounded by a
byte budget and by the configured timeout. UDP parses only the first datagram and never
waits. A configuration with no domain rule spends no syscall and no wait on it.

**Exit criterion met:** `tests/sniff_route.rs` routes a flow by its ClientHello SNI when
no IP rule matches, proves the origin received the bytes unchanged, and proves the
fallback applies for a name the rules do not cover. `daer-control::domain` tests cover
Fake-IP precedence, DNS ambiguity, and the explicit disabled mode.

## 5. Proxy protocols (`daer-outbound`) 🟡

Done: **shadowsocks AEAD**, which is the first protocol with real cryptography. Only
authenticated ciphers are implemented (`aes-128-gcm`, `aes-256-gcm`,
`chacha20-ietf-poly1305`, `xchacha20-ietf-poly1305`); the stream ciphers have no integrity
protection and a link naming one is rejected with that reason. Interoperability is asserted
against a server written independently from the protocol description, so a mistake in the
framing or the nonce order cannot cancel out on both sides.

Done as well: **trojan** — a password-authenticated session inside TLS to the node, built on
netune's TLS stack with its fingerprint profiles. That is the first protocol to exercise the
ADR-0002 boundary for real: the client owns no TLS, and the node is reached with a named
identity rather than rustls' default one. Trojan has no confidentiality of its own, so there is
no plaintext constructor: a `trojan://` node without `?sni=` and a bare-IP server is rejected
at parse time, because a certificate cannot be verified against an address.

Done as well: **REALITY**, per [ADR-0010](../adr/0010-reality-client-ownership.md). `rustls`
cannot be told what to put in `legacy_session_id`, so `daer-outbound` owns a minimal TLS 1.3
client (`reality/tls13`): the key schedule matches the RFC 8448 vectors, the record layer
rejects tampering, and the REALITY tag is asserted on the wire in `tests`. The client is
reachable only from a `security=reality` link — the boundary is enforced by the type system,
not by review.

**Interop-tested against a live node**, and the exercise found five defects that no unit test
could have caught. Each is now fixed and guarded:

1. The ClientHello omitted the 32-byte `random`, so it was not valid TLS at all — the node
   answered with `decode_error` and the flow was forwarded.
2. `parse_server_hello` and `server_key_share` skipped the same field, so *every* real
   ServerHello failed to parse. This is why the handshake had never actually run.
3. The tag was sealed with a fixed salt instead of `hello.random[..20]`, an all-zero nonce
   instead of `random[20..]`, no associated data, and a millisecond timestamp where the
   server reads a version plus unix seconds.
4. The tag was sealed with an **all-zero** session-id in its associated data, which is what
   the server actually opens against — the natural reading ("with the plaintext in place")
   produces a tag that is never examined.
5. The tag was derived from an ephemeral key **different** from the one in the hello's
   `key_share`, so the server could never compute the same key. The handshake now owns both.

Two further defects were in the record layer and the key schedule, both only reachable once
the handshake got far enough to use them: a compatibility `change_cipher_spec` was handed to
the AEAD (which every real server sends), the server's `Finished` was hashed before being
verified, application keys were derived after the client `Finished` rather than before, the
AEAD key length was hardcoded to 32 for AES-128-GCM, and TLS 1.3's inner padding was ignored
(the content type is the last *non-zero* byte).

**`X25519MLKEM768` is implemented** (`reality/hybrid.rs`), and it is not optional: REALITY
servers from `xtls/reality` v0.0.0-20260908062103 refuse to authenticate a hello without that
key share — `peerPub2 == nil` breaks out of the authentication loop *before* the tag is
examined. A pure-x25519 client therefore gets a silent forward, not a downgrade.

`verify.rs` is what makes the difference between "connected" and "connected to the node"
observable at all: the server signs its ephemeral ed25519 key with `HMAC-SHA512(auth_key, …)`,
so a forwarded flow cannot produce the signature. Without that check the earlier defects were
invisible — a request for `example.com` came back with a real HTTP reply from Apple's CDN, and
a test that only asserted "a reply arrived" passed on it.

**Vision is done and verified end to end**, after three more defects that only a local
`xray run` could show (see [`docs/how-to/vision-lab.md`](../how-to/vision-lab.md) for the harness):

6. The VLESS request header wrote the port **twice** — once from `PortThenAddress` and once
   from the shadowsocks address encoder it was reusing — so the node read the address two
   bytes late and dialled garbage (`accepted tcp:[b65:7861:6d70:...]:80`).
7. The header and the Vision opening block went out in separate writes, so the inbound read
   `firstLen = 52` — the header alone — and had no block to unpad.
8. The payload block said `Continue` where the reference says `End`, leaving the peer
   waiting for a block that never came.

Worth recording what the *absence* of this cost: before the lab existed, the working frame
and the broken one differed only in a command byte and a two-byte offset, both of which a
remote node answers with "reset".

**A fourth defect reached `main`, and the reason it did is worth stating.** After the three
above, a REALITY session authenticated correctly and then read **zero bytes**: the node
flushed a legal zero-length `application_data` record right after the handshake, and
`Tls13Connection::poll_read` answered it with `Ready(Ok(()))` and nothing written — which is
`AsyncRead`'s encoding for end-of-stream. Every proxied connection through every REALITY node
was dead while the roadmap said "live-verified".

The harness in `docs/how-to/vision-lab.md` existed and would have caught it. What did not
exist was a *reason to run it*: `tests/reality_live.rs` is `#[ignore]` and needs a credentialed
public node, so nothing in CI exercised the path, and a `✅` in this table recorded a manual
result whose relevance nobody had to re-establish. `tests/e2e/protocols_reality_interop.rs` closes that:
it starts the reference server itself, so REALITY + Vision is a fixture that CI runs on every
commit, and a skip is stated rather than silently absent.

That fixture then had to be made honest twice over, and both are worth recording because each
looked like a transport bug:

- it pointed `dest` at `www.microsoft.com:443`, so the gate depended on a third party's uptime
  and failed intermittently with `the peer closed during the handshake`. It now starts its own
  TLS 1.3 destination from checked-in fixture certificates, sized so the handshake has the record
  lengths REALITY needs to mimic;
- the tunnel assertion asked the node to reach `example.com:80`. Since Xray v26.4.15 a `freedom`
  outbound **blocks private and reserved addresses by default** for flows that arrived through a
  proxy inbound and blackholes them for 30-90 s — so a local origin was refused silently and the
  client timed out with an empty reply while the tunnel was fine. The fixture grants
  `finalRules: [{action: allow, ip: ["127.0.0.0/8"]}]`, and the assertion is now on the local
  origin's body: deterministic, offline, and unable to pass unless the bytes really made the
  round trip through REALITY + Vision.

Remaining, in subscription-usage order: vmess → plain vless → anytls → hysteria2 → tuic.
vmess, plain vless and anytls are connectors over a raw stream, so they compose with
netune's `Connector` seam. Chained links (`a -> b`) are refused at load rather than silently
truncated. Shadowsocks 2022 is a separate protocol revision, not a cipher, and is not
implemented.

The last two are QUIC-based. Both blockers are closed: netune owns datagrams
(ADR-0008) and first-class QUIC/HTTP-3 client transport (netune ADR-0016), and
hysteria2 already composes its Salamander/Gecko socket layers, port hopping and
Brutal controller over `netune-quic` (daer ADR-0035). tuic remains ordinary protocol
work rather than a dependency decision.

**Exit:** the eight protocols above interoperate against reference servers.

## 6. Performance 🟡

The routing matcher is **done**: it is indexed rather than scanned, and the decision
path is allocation-free. `tests/hot_path.rs` guards both properties — it counts
allocations on the deciding thread and asserts that a decision over 25,000 patterns
and 5,000 prefixes stays under a fixed budget, so a regression to scanning fails CI
instead of waiting for a benchmark nobody runs.

What remains is the part that needs a working data path: direct-path throughput and
P99 connect latency at parity with the reference implementation, measured end to end
rather than per component.

## 7. Observability and trace 🟢

Latency tables and health-check statistics exist, and an observed dial keeps one netune
`TraceCollector` with a `DialObserverSink`: DNS/TCP/TLS phases are derived from the transport's
own events instead of a wall-clock span. Dials with no observer use
`TraceCollector::disabled()`, so the per-flow path pays nothing.

The diagnostic plane (ADR-0040) closes the rest of the surface: typed events with a generated
catalog, `flow_id`/`query_id` correlation, `warn` events for client-visible failures, the
JSON event stream, panic/`SIGUSR1` incident bundles, `daer status`, and a userspace consumer
for all 17 `bpf_stats_map` counters and the `event_ringbuf` record types. `bpf_trace_printk`
is not needed and remains deliberately unused: the ring buffer is the structured channel.

## Open decisions

| Decision | Impact | Where |
| --- | --- | --- |
| Datagram transport: netune API vs daer-side | **resolved** — netune owns the datagram socket (netune ADR-0008); the relay is daer's | [`netune-requests.md`](netune-requests.md) |
| QUIC implementation for hysteria2/tuic | **resolved** — netune owns the QUIC/H3 client transport (netune ADR-0016); daer consumes `netune-quic`/`netune-http3` and keeps only product protocol layers (ADR-0035) | milestone 5 |
| Matcher data structures | performance ceiling of the data path | milestone 6 |
| Kernel wiring and the transparent path need `CAP_NET_ADMIN`. Both now have tests that **skip with a reason** without it and run under `unshare -Urn` with it (`tests/e2e/control_transparent.rs`, `scripts/verify/kernel-check.sh`), so the gap is a skip instead of an unverified claim | whether a change to the data path works | ADR-0007 |
