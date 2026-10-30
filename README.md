# daer

An eBPF transparent proxy for Linux, with a Rust userspace. Traffic is split in
the kernel: the eBPF program at the tc hook decides "proxy" or "direct" before a
packet enters the TCP/IP stack, so direct traffic never touches userspace.

> **Status: the data path runs, and the kernel tier is stated rather than implied.**
> `daer run` loads and attaches the kernel datapath, publishes a routing policy into it, recovers
> each flow's original destination, decides, dials and relays. Whether the kernel decides a flow
> itself or hands it to userspace is computed, logged at startup, and pinned by a test — see
> [ADR-0005](docs/adr/0005-kernel-policy-encoding.md). A configuration whose rules the kernel can
> reproduce faithfully (`dip`, `sip`, `port`, `sport`, `l4proto`, `ipversion`, `mac`, `dscp`) gets
> the fast path; one that uses `domain(...)` or `pname(...)` gets a correct, slower path, because
> those predicates need kernel tables this build does not maintain.
>
> `crates/daer-control/tests/transparent.rs` is the end-to-end evidence, and it is written to be
> able to fail: it installs its own `nftables tproxy` rule, has the origin answer a per-run nonce,
> asserts the daemon counted the flow, and carries a negative control that fails if the fixture
> ever bypasses the proxy ([ADR-0007](docs/adr/0007-verification.md)). Outbound REALITY with XTLS
> Vision is the one node protocol interop-tested against a live server.
>
> The honest gaps, all of them named where they matter:
> `docs/dev/roadmap.md` lists what is missing; UDP is relayed but not yet proven on the wire through
> `tproxy` (`docs/how-to/deployment.md` says exactly why); the vmess family, the QUIC families and the
> event ring are not implemented.
>
> Getting here found eleven defects that unit tests had missed, all of them invisible from
> the Rust side: a ClientHello that was not valid TLS, a REALITY tag sealed with the wrong
> salt and key, a missing `X25519MLKEM768` share that a current node refuses to authenticate
> without, a VLESS header that wrote the destination port twice, and a Vision block that
> never said `End`. [`docs/how-to/vision-lab.md`](docs/how-to/vision-lab.md) is the local `xray run`
> harness that made the last three observable.

## What the kernel tier means for you

`daer run` logs one of these at startup:

```text
INFO datapath policy published … "the kernel decides every flow itself"
WARN datapath policy published as a deferral: every flow is handed to the control plane …
     reasons=["rule 3 uses domain(...) and domain_routing_map is not maintained by this build"]
```

Both are correct; only the first keeps direct traffic out of userspace. The second costs one
userspace relay hop per flow and is what most real configurations get today, because `domain(...)`
is common. `daer route explain` and `daer route nodes` describe the same generation the daemon
serves, so they cannot disagree with it — that agreement is enforced by sharing one loader
([ADR-0006](docs/adr/0006-wiring-ownership.md)).

## Layout

| Crate | Responsibility | State |
| --- | --- | --- |
| `daer-common` | shared constants and network primitives | done |
| `daer-config` | TOML schema, rule expression language, loader, validation | done |
| `daer-routing` | rule lowering, userspace matching, policy identity, `geosite:`/`geoip:` expansion | done, matcher is indexed and allocation-free |
| `daer-geodata` | streaming geodata reader, asset locator | done |
| `daer-ebpf` | datapath object loading, map/program ABI, section normalization | done |
| `daer-outbound` | latency statistics, alive-set selection, groups, policies, direct / SOCKS5 / HTTP `CONNECT` / shadowsocks AEAD / trojan / **REALITY** (own TLS 1.3 client, ADR-0010), health checks (HTTP, TCP, UDP-DNS), datagram legs, subscription fetch + decode + `persist` cache | partial: vmess, plain vless, QUIC families pending |
| `daer-dns` | wire format, routing, cache, pipeline, UDP+TCP server, **all four upstream transports** (UDP, TCP, DoT, DoH) | partial: no bootstrap resolver; upstream addresses must be literal IPs |
| `daer-sniff` | TLS SNI and HTTP `Host` prefix sniffing | partial: no QUIC |
| `daer-control` | transparent ingress, sniffing, routing verdict, outbound dial, TCP relay + splice, UDP datagram relay (per-peer sessions, driven by `Daemon::serve`), accept loop, flow supervisor, health scheduling, one shared configuration loader, configuration generations and handover | partial: kernel policy is published per ADR-0005, which for `domain(...)`/`pname(...)` rules means "defer to userspace" |
| `daer-cli` | `config validate`, `config fmt`, `config example`, `config schema`, `route explain --why --domain`, `route nodes`, `dns check`, `dns serve`, `run`, `version` | done |

Network capabilities above the socket — TLS, HTTP, DNS resolution, proxy
handshakes, socket options, RTT sampling, and everything datagram-shaped — belong
to [netune](../netune), which `daer` consumes as a pinned dependency. What
`daer` needs from it is tracked in
[`docs/dev/netune-requests.md`](docs/dev/netune-requests.md)
([ADR-0002](docs/adr/0002-netune-boundary.md)).

## Configuration

TOML, typed, strict. Unknown keys are errors. Every table is optional, so an
empty file is valid and the defaults are the ones the daemon uses.

```toml
schema = 1

[global]
tproxy-port = 12345
wan-interface = ["auto"]
dial-mode = "domain"

[global.tls]
profile = "chrome-current"   # a netune TLS-fingerprint preset

[[subscription]]
tag = "my-sub"
url = "https://example.com/api/v1/client/subscribe?token=…"
persist = true                # fall back to the last good fetch

[[node]]
tag = "edge"
url = "ss://…"

[[group]]
name = "proxy"
policy = "min-moving-avg"
filters = ["subtag(my-sub) && !name(keyword: 'ExpireAt:')"]

[routing]
rules = [
    "pname(NetworkManager) -> direct",
    "dip(geoip:private) -> direct",
    "l4proto(udp) && dport(443) -> block",
    "domain(geosite:cn) -> direct",
]
fallback = "proxy"
```

### Subscriptions

A `[[subscription]]` is fetched, decoded and folded into the node pool before a
generation is built, so a fetched node is indistinguishable from an inline
`[[node]]` — including its `subtag(...)` tag, which is what makes it selectable.

Three wire formats are recognised, in this order: **SIP008** JSON, **plain** link
lines, and **base64** of link lines (standard or URL-safe alphabet, padding
optional). A body that matches none is an error that names what was tried, never an
empty node list: "this subscription has no nodes" and "this subscription could not
be read" lead an operator to opposite conclusions.

With `persist = true` the last successful fetch is cached in `persist.d/<tag>.sub`
beside the configuration. **A fetch that fails never replaces a good cache**, so an
endpoint that returns an error page at restart cannot take a working proxy down.

Supported node schemes today: `ss://` (shadowsocks AEAD), `trojan://`, `socks5://`,
`http://`, and `vless://` **with `security=reality`**. `vmess://`, plain `vless://`
(`security=tls`) and the QUIC families are **not** implemented; `daer config validate`
names every node this build cannot select rather than letting it disappear into an
empty group. A chained link (`a -> b`) is rejected loudly instead of being silently
truncated to its first hop.

A REALITY link must carry `pbk`, `fp` and `sni`. `fp` is **required** rather than
defaulted: a REALITY ClientHello that presents the wrong fingerprint fails on the
wire for a reason no log can attribute to the cause, so it is reported as a
configuration error at load. `flow=xtls-rprx-vision` and a wrapping transport
(`type=ws` and friends) are refused by name rather than ignored.

A `[[subscription]]` node carries the tag of the subscription it came from, so
`subtag(...)` selects it. That provenance used to be dropped, which made every
subscription node invisible to every `subtag` filter while `daer route nodes` still listed
it — the two diagnostics disagreed and the group silently had no members.

Rules may be written with IPv6 and MAC literals directly: `dip(2001:db8::/32)`,
`dip(::1)`, `mac(aa:bb:cc:dd:ee:ff)`. Quoting them works too and is never required. The
lexer distinguishes an address from a `key:value` parameter by shape — every parameter key in
the language is a word rather than a run of hex digits — so `domain(suffix:example.com)` and
`mac(00:11:22:33:44:55)` do not collide.

### Inspecting decisions

`daer route explain <source> <destination> -c config.toml` prints the routing
decision for one flow — the rule that fires, the outbound and its mark — from the
same compiled configuration a running daer uses, and exits non-zero when the flow
would be dropped. `--domain www.example.com` supplies the name sniffing would have
found, which is the only way to verify a `domain(...)` rule from the command line.
`--why` adds a per-rule, per-predicate trace, including rules that would have
matched but were shadowed, and the selected node's security identity
(`cipher aes-256-gcm`, `tls sni=…`) is printed with the decision.
`daer route nodes` lists every node the same way, subscriptions resolved. See
[`docs/how-to/diagnostics.md`](docs/how-to/diagnostics.md).

### Running the DNS resolver

The resolver is a complete subsystem and does not need the data path, so it has its own
subcommand:

```sh
daer dns check -c config.toml     # which upstreams this build can actually use
daer dns serve -c config.toml     # UDP + TCP on dns.bind, port 53
daer dns serve -c config.toml --listen 127.0.0.1:5353 --udp-only
```

`dns check` exits non-zero when an upstream cannot be used, so it is usable in CI. `serve`
stops on `SIGINT`/`SIGTERM` after letting in-flight queries finish.

`daer config example` prints the fully commented reference configuration
([`daer.example.toml`](./daer.example.toml)); `daer config fmt` prints the
canonical form of a file; `daer config validate` loads the whole tree (including
`include`), applies defaults and dry-runs routing, groups and outbound name
resolution; `daer config schema` prints the JSON Schema
([`daer.schema.json`](./daer.schema.json)), which editors use for completion
(`#:schema` in the reference config) and CI uses to validate a file without
building daer.

Three things are *expressions* rather than data — routing rules, group filters and
policy names. A boolean combination over arbitrary predicates has no faithful
tabular encoding, and the parsed tree is exactly what the routing engine consumes,
so the schema carries it as text and `daer-config`'s expression language parses it
once. Errors point at the expression, not just the file:

```
[routing]
rules = ["domain(a) direct"]
        ^^^^^^^^^^^^^^^^^ invalid expression "domain(a) direct"
line 1:10 domain(a) direct
              ^: expected '->' in the routing rule
```

Rules that reference geodata need `geoip.dat` / `geosite.dat`. `daer` looks next
to the configuration file, in `$DAER_LOCATION_ASSET`, in
`/usr/{local/,}share/daer`, and in the XDG data directories.

## Build and test

```sh
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

or `cargo xtask ci`. MSRV is 1.95.

Building the datapath object is optional and needs clang plus a `vmlinux.h` tree:

```sh
DAER_DATAPATH_SRC=… DAER_BPF_HEADERS=… cargo xtask ebpf   # -> target/ebpf/datapath.o
cargo test -p daer-ebpf                                  # ABI assertions against it
```

Without an object the object tests skip; with one they are the ABI contract.

## Decisions

Architecture decisions are recorded, not implied:

- [ADR-0001](docs/adr/0001-config-format.md) — the configuration format is TOML.
- [ADR-0002](docs/adr/0002-netune-boundary.md) — netune owns the network
  transport; the data path, the DNS server role and sniffing are ours.
- [ADR-0003](docs/adr/0003-datapath-abi.md) — the datapath object is an external
  artifact with its own ABI; the loader adapts to it, and identifiers are `daer*`.
- [ADR-0004](docs/adr/0004-routing-epochs.md) — a reload publishes into the inactive of
  two routing slots, then commits with one switch.
- [ADR-0005](docs/adr/0005-kernel-policy-encoding.md) — the kernel policy table is written, and
  it is either provably equivalent to the userspace evaluator or it defers the whole program to
  userspace. It never invents a third answer and never leaves the table empty.
- [ADR-0006](docs/adr/0006-wiring-ownership.md) — a subsystem is done only when `daer run`
  reaches it, and a configuration key the schema accepts must either take effect or not exist.
  `cargo test` fails otherwise.
- [ADR-0007](docs/adr/0007-verification.md) — a test that cannot fail is a liability. Every
  end-to-end claim names its falsifier, including a negative control.
- [ADR-0010](docs/adr/0010-reality-client-ownership.md) — REALITY and the minimal TLS 1.3
  client belong to `daer-outbound`, not to netune. Netune is not asked to grow a way to
  bypass certificate verification; `daer` owns the handshake, and the seam back is
  netune's public `Transport` trait.

## Requirements

Linux 5.17 or newer (`bpf_loop`, the cgroup hooks). Root or `CAP_BPF` /
`CAP_NET_ADMIN` to attach.

## License

[AGPL-3.0-only](./LICENSE).

The datapath C program and the routing semantics descend from the `dae` project by
the daeuniverse authors; that provenance is why the license and the kernel ABI
match. It is a dependency relationship, not the name of this project: everything
here is `daer`.
