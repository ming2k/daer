# Configuration Reference

`daer` uses strictly-typed TOML with `schema = 2`. Unknown keys are rejected with descriptive errors.

The default configuration file path is `/etc/daer/config.toml`.

---

## 1. Top-Level Schema

```toml
schema = 2
```

- `schema` (integer, required): Schema version. Must be `2`.

---

## 2. `[global]` Table

Controls global transparent proxy, networking, and daemon behaviors.

| Key | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `wan-interface` | list of string | `["auto"]` | Egress interfaces toward the internet. `"auto"` resolves to the interface carrying the default route; an empty list is a configuration error. |
| `lan-interface` | list of string | `[]` | Ingress interfaces receiving client traffic. |
| `so-mark` | integer (hex/dec) | `0x64616572` when omitted | Socket mark applied before outbound `connect(2)` to evade loop redirection. Omitted, a privileged run picks `0x64616572` and an unprivileged one marks nothing. |
| `log-level` | string | `"info"` | `tracing` filter directive: `"info"`, `"debug"`, or `"daer=debug,netune=trace"`. An unparseable directive fails `daer check` and startup; it never silently falls back to `info`. |
| `disable-waiting-network` | boolean | `false` | When true, fails immediately if the default route is missing rather than waiting up to 2 minutes. |
| `sniffing-timeout` | duration | `"30ms"` | How long to wait for a sniffable byte sequence before routing by IP. |
| `auto-sniff-punt` | boolean | `true` | When false, a name is only used after the flow reaches userspace, never as a reason to hold it up. |
| `allow-insecure` | boolean | `false` | Accept an invalid node certificate. |

> [!NOTE]
> Transparent listeners bind ephemerally (`port = 0`) inside the isolated `daer0ns` network namespace; traffic assignment is performed directly by the eBPF datapath via `bpf_sk_assign` into the sockmap (ADR-0043). Therefore, `tproxy-port` and `tproxy-port-protect` do not exist.

There is no `dial-mode` key: `daer` sniffs whenever a rule can use a domain and there is no
separate knob to turn that off. The name was documented and rejected by `deny_unknown_fields`,
so it was removed from this table rather than left as a trap.

### `[global.tls]` Sub-Table

| Key | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `profile` | string | unset (netune's default) | netune client TLS profile preset: `"netune-default"`, `"chrome-current"`, `"firefox-current"`, `"safari-current"`, `"codex-reqwest"`, `"codex-network-proxy"`. An unknown name is a load-time error. |
| `fragment` | boolean | `false` | Split the ClientHello across TCP segments to defeat naive SNI filtering. |
| `fragment-length` | string | `"50-100"` | Byte range for `fragment`. |
| `fragment-interval` | string | `"10-20"` | Millisecond range for the delay between fragments. |

### `[global.probe]` Sub-Table

Probe defaults for every election. An `[[election]]` may override any field.

| Key | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `mode` | string | `"server"` | `"server"` probes the node's own server port (cheap liveness); `"url"` requests a URL **through** the node and measures the end-to-end path. |
| `url` | string | unset | Required when `mode = "url"`; ignored (and rejected) when `mode = "server"`. |
| `method` | string | `"HEAD"` | HTTP method for a URL probe: `HEAD` or `GET`. |
| `udp-dns` | list of string | `["1.1.1.1:53", "8.8.8.8:53", "2001:4860:4860::8888:53"]` | Hosts probed over UDP DNS for server-mode liveness. A bare IP uses port 53; a name is reported and skipped rather than resolved silently. |
| `interval` | duration | `"30s"` | Probe interval; `0s` disables probing. A latency election must be enabled. |
| `timeout` | duration | `"5s"` | Per-probe deadline. |
| `tolerance` | duration | `"0s"` | Shifts the switching threshold of moving averages; may be negative. |

---

## 3. `[[node]]` Tables

Declares individual proxy outbound nodes. Nodes may be defined either as **structured tables** (strongly recommended for readability, explicit type validation, and IDE completion) or as **URI links**.

### Structured Node Schema

Common fields for all structured nodes:

| Key | Type | Description |
| :--- | :--- | :--- |
| `name` | string | Optional unique identifier for the node (`tag` is accepted as an alias). A `detour` references this value. |
| `type` | string | Node protocol: `"vless"`, `"shadowsocks"` (or `"ss"`), `"trojan"`, `"socks5"` (or `"socks"`), `"http"`, `"direct"`. |
| `detour` | string | Optional node name. The named node opens this node's stream to its own server; the outer protocol still carries the final target (ADR-0044). |

#### Detour chains

`detour` makes one node the transport for another node's server leg. It is an outbound chain,
not a new proxy protocol:

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
uuid = "b831381d-6324-4d53-ad4f-8cda48b30811"
detour = "inner"
```

The inner server sees `198.51.100.20:443`; the outer server sees the flow's final target. A
chain may be arbitrarily deep, but it must be a DAG: an unknown target, a self-reference, or a
cycle is a load error. A detour names a node, never a group. (A group is a candidate set,
not a transport, so it cannot be a validated hop.)

Capabilities are not silently degraded:

- a Hysteria 2 node cannot be the **outer** hop (its QUIC socket stack has no
  datagram-under-proxy seam); it can be the inner hop;
- a detoured SOCKS5 node carries TCP only, because a SOCKS5 UDP associate would send datagrams
  directly to the proxy server and bypass the chain;
- a `direct` node cannot be the outer hop (it has no server leg); it can be the inner hop;
- VLESS/VMess/AnyTLS datagrams ride their stream and are therefore carried by the chain.

#### `type = "vless"`

The security layer is a **sub-table named by its type** (`[node.security]`), not
`[node.reality]`: a `vless` node may run over no security, over TLS, or over REALITY, and which
one it is has to be stated rather than inferred from the presence of a table (ADR-0028). A
`[node.reality]` table is rejected by name, because the schema has no such key.

| Key | Type | Description |
| :--- | :--- | :--- |
| `server` | string | Remote server hostname or IP address. |
| `port` | integer | Port number (1-65535). |
| `uuid` | string | Client user ID (UUID). |
| `flow` | string | Flow framing: `"xtls-rprx-vision"`, `"xtls-rprx-vision-udp443"`. Optional. |
| `transport` | table | `type = "tcp"` (default) or `type = "ws"` with `path`/`host`. Optional. |
| `[node.security]` | table | The security layer. `type = "none"` (default), `"tls"`, or `"reality"`. |

With `type = "reality"`, the accepted keys are exactly:

| Key | Type | Description |
| :--- | :--- | :--- |
| `sni` | string | The impersonated site. Required; REALITY impersonates a *named* site. |
| `public-key` | string | Server X25519 public key (`pbk` in a link). Required. |
| `short-id` | string | Hexadecimal short ID (`sid`). Optional. |
| `alpn` | list of string | Offered ALPN protocols (e.g. `["h2", "http/1.1"]`). Optional. |

There is **no `fingerprint` key on the REALITY layer.** A REALITY ClientHello is built byte by
byte by `daer-proxy-protocols` (`reality/tls13`), not by a netune fingerprint preset, and
`RealityParams` carries an SNI, a public key, a short-id and an ALPN list — no fingerprint. A
link's `fp=` is accepted for compatibility with the panels that always send it, and has nothing
to consume it; a *config file* that sets `fingerprint` under `[node.security]` with
`type = "reality"` is refused by name rather than silently ignored. `fingerprint` **is** a real
key on `type = "tls"`, where it selects a netune preset.

```toml
[[node]]
name = "hk-01"
type = "vless"
server = "203.0.113.7"
port = 443
uuid = "2aec6a09-fb60-4461-9f28-ff6ccd184824"
flow = "xtls-rprx-vision"

[node.security]
type = "reality"
sni = "download.docker.com"
public-key = "1qA2ff-bTrVm4R-UAkRa6GGI5Dd_OrNDAELO1pxXVjI"
short-id = "d9268b533cd4d860"
```

#### `type = "shadowsocks"` / `"ss"`

| Key | Type | Description |
| :--- | :--- | :--- |
| `server` | string | Remote server hostname or IP address. |
| `port` | integer | Port number (1-65535). |
| `method` | string | AEAD cipher: `"chacha20-ietf-poly1305"`, `"aes-128-gcm"`, `"aes-256-gcm"`, `"xchacha20-ietf-poly1305"`. |
| `password` | string | Shared secret key / password. |

#### `type = "trojan"`

| Key | Type | Description |
| :--- | :--- | :--- |
| `server` | string | Remote server hostname or IP address. |
| `port` | integer | Port number (1-65535). |
| `password` | string | Authentication password. |
| `sni` | string | SNI presented in TLS handshake. Optional (defaults to server hostname). |
| `allow-insecure` | boolean | Disables certificate verification. Optional (default `false`). |

#### `type = "socks5"` / `"socks"`

| Key | Type | Description |
| :--- | :--- | :--- |
| `server` | string | Remote server hostname or IP address. |
| `port` | integer | Port number (1-65535). |
| `username` | string | Optional authentication username. |
| `password` | string | Optional authentication password. |

#### `type = "http"`

| Key | Type | Description |
| :--- | :--- | :--- |
| `server` | string | Remote server hostname or IP address. |
| `port` | integer | Port number (1-65535). |
| `username` | string | Optional authentication username. |
| `password` | string | Optional authentication password. |

#### `type = "direct"`

Direct outbound connection without proxying.

---

### Converting Existing Links

The legacy `url` string field in `[[node]]` has been retired in favor of strict, type-safe structured tables.

`daer` parses URI links at runtime, so a link from a sharing panel does not need hand-converting:
declare it as a `[[subscription]]` and the node pool is filled on load and on every reload.

```toml
[[subscription]]
name = "panel"
url = "https://example.com/api/subscribe?token=..."
# Every node this subscription contributes is carried through this node.
# detour = "inner"
```

A subscription link cannot carry a detour (it is another panel's format), so a
subscription-wide `detour` is declared here. The target may be an inline node or another
subscription node. A per-node chain is written on a structured `[[node]]` instead.

An inline `[[node]]` is still written as a structured table, and `daer check` names any field
it cannot honour.

---

## 4. `[[group]]` Tables

A group is a **resource pool**: it only decides which nodes are candidates. It owns no
selection rule and no probe. An election consumes it.

| Key | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `name` | string | Required | Unique pool name. Elections reference it with `group = "…"`. |
| `filters` | list of string | `[]` | Filter expressions selecting nodes (e.g. `sub(my-sub) && !name(keyword: 'Expire')`). |

A node that no group selects is still a resource, but no election can reach it. A single
node can be an election input directly (`node = "…"`), so a singleton group is optional.

---

## 5. `[[election]]` Tables

An election is the **routing target** and the rule that elects one node from its input.

| Key | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `name` | string | Required | Unique election name; routing rules and `fallback` reference this name. It cannot shadow a built-in outbound or a group name. |
| `group` | string | — | Candidate pool. Exactly one of `group`/`node` is required. |
| `node` | string | — | A singleton candidate set. Exactly one of `group`/`node` is required. |
| `type` | string | Required | `"manual"` (node input only), `"random"`, `"min"`, `"min-avg10"`, `"min-moving-avg"`. |
| `mode` | string | inherited | `"server"` or `"url"`; overrides `[global.probe]`. |
| `url` | string | inherited | URL for `mode = "url"`. |
| `method` | string | inherited | `HEAD` or `GET`. |
| `udp-dns` | list of string | inherited | UDP endpoints for server-mode liveness. |
| `interval` | duration | inherited | Probe cadence. |
| `timeout` | duration | inherited | Probe deadline. |
| `tolerance` | duration | inherited | Moving-average switch threshold. |

```toml
[[group]]
name = "proxy-pool"
filters = ["sub(my-sub)"]

[[election]]
name = "proxy"
group = "proxy-pool"
type = "min-moving-avg"
mode = "url"
url = "https://www.gstatic.com/generate_204"
```

The output is always at most one node. `manual` with a `node` input is a fixed choice;
`manual` with a `group` input is rejected — a runtime `daer elect <election> <node>` is the
way to pin one candidate of a group. `url` mode establishes the proxy session and asks the
URL through it; `server` mode only proves the server port is reachable.

---

## 6. `[[rule-provider]]` Tables (ADR-0014)

Declares pre-compiled DRB (`.drb`) or human-readable text rule sets from local files or remote HTTP subscriptions.

| Key | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `name` | string | Required | Unique identifier for referencing in routing rules via `provider(name)` (`tag` is accepted as an alias). |
| `type` | string | `"file"` | Provider type: `"file"` or `"http"`. |
| `url` | string | Optional | Remote download URL (required when `type = "http"`). |
| `path` | string | Optional | Local file path (required when `type = "file"`). Relative paths resolve against the configuration directory; system-wide local sets belong under `/var/lib/daer/rules/`. |
| `format` | string | `"drb"` | Artifact format: `"drb"` (binary zero-copy) or `"text"` (plain text). |
| `interval` | string | Optional | Auto-update interval for HTTP providers (e.g. `"24h"`, `"12h"`). |

---

## 7. `[routing]` Table

Defines flow matching rules and default verdicts.

| Key | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `rules` | list of string | `[]` | Ordered routing rule expressions evaluated top-to-bottom. The right-hand side of `->` is `direct`, `block`, or an election name. |
| `fallback` | string | `"direct"` | Verdict (`direct`/`block`) or election name if no rule matches. |

### Rule Predicates

- `dip(cidr)` — Match destination IP.
- `sip(cidr)` — Match source IP.
- `dport(port_range)` — Match destination port.
- `sport(port_range)` — Match source port.
- `domain(pattern)` — Match the sniffed domain (ADR-0036): a bare name (`example.com`) is a suffix matching the domain and all subdomains; `.example.com` matches subdomains only; `=example.com` matches the exact name only. `keyword:` and `regex:` are removed (ADR-0033); expand them into concrete patterns.
- `provider(name)` / `rule-set(name)` — Match IP intervals or domains from a declared `[[rule-provider]]`.
- `dip(provider:name)` / `ip(provider:name)` — Match only IP intervals from a declared rule provider.
- `domain(provider:name)` — Match only domains from a declared rule provider.
- `l4proto(tcp|udp)` — Match Layer 4 transport protocol.
- `pname(process_name)` — Match client process name.

---

## 8. `[dns]` Table

Configures the built-in DNS server, caching, and upstream transports.

| Key | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `bind` | string | unset (no server) | Listen address for DNS queries. Unset *and* Fake-IP disabled means `daer` is not the box's resolver and starts no server. |
| `upstream` | list of string | `[]` | Upstream resolvers as `tag:protocol://address:port`. The protocol is required: `udp`, `tcp`, `tls` (DoT), `https` (DoH), or a `+` chain tried in order. A hostname instead of an address is rejected (there is no bootstrap resolver yet). |
| `ipversion-prefer` | integer | `0` | `4`, `6`, or `0` for no preference. |
| `optimistic-cache` | boolean | `true` | Serve stale entries while refreshing. |
| `optimistic-cache-ttl` | integer | `60` | Seconds an optimistic entry is served. |
| `optimistic-stale-reply-ttl` | integer | `30` | Seconds a stale answer may be replayed. |
| `max-cache-size` | integer | `65536` | Bound on the cache. There is no `cache-size` key. |

`[dns.fixed-domain-ttl]` maps a domain suffix to a TTL in seconds. `[dns.request]` and
`[dns.response]` each take `rules` and a `fallback` (`"asis"` / `"accept"` are the
`[dns.request]` / `[dns.response]` defaults).

### `[dns.fake-ip]` Sub-Table

| Key | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `enabled` | boolean | `false` | Allocate synthetic addresses and serve them to clients. Enabling it also starts the DNS server. |
| `inet` | string | `"198.18.0.0/15"` | The IPv4 pool prefix. |
| `inet6` | string | unset | Optional IPv6 pool prefix. When set, `AAAA` queries receive synthetic addresses too; when unset, `AAAA` is answered with an empty NOERROR so clients fall back to the synthetic `A`. |
| `pool-size` | integer | `65535` | Number of synthetic addresses per address family. |
| `exclude` | list of string | `[]` | Domains that must never get a synthetic address. Each entry is a domain pattern: a bare name (suffix), `.name` (subdomains only), or `=name` (exact); `keyword:`/`regex:` are also accepted here (ADR-0033, ADR-0036). |

---

## 9. What is not here

The retired Protobuf `geoip:` / `geosite:` databases are gone (ADR-0014/ADR-0015): domestic and
regional routing is expressed as a `[[rule-provider]]` holding a compiled `.drb` set plus
`provider(name)` in a rule. Legacy `.dat` files can be unpacked once with `scripts/rules/dat_to_rules.py`
and compiled via `daer-drb compile`.

An outbound chain is expressed as a node's `detour` (ADR-0044). A URI chain string
(`a -> b`) is still rejected at load time rather than silently truncated to its first hop;
use structured `[[node]]` tables for a chain.

`tuic` and the QUIC families other than Hysteria 2 are not implemented; a node using one is listed
and reported as unselectable by `daer check --nodes` rather than downgraded to `direct`.

`vless` and `vmess` are three orthogonal layers (ADR-0028): a **transport** (`tcp`, `ws`), a
**security layer** (`none`, `tls`, `reality`) and a **flow** (`none`, `xtls-rprx-vision`,
`xtls-rprx-vision-udp443`). The transport sits *above* the security layer, so `transport = ws`
with `security = tls` is `wss://` — the upgrade request travels inside the tunnel. A combination
the reference cannot carry is a load-time error that names the layer:

| Rejected | Why |
| :--- | :--- |
| `flow = xtls-rprx-vision` with `security = none` | Vision splices a record layer; there is none |
| `flow = xtls-rprx-vision` with `transport = ws` | the reference requires TLS/REALITY *directly* under the protocol |
| `security = reality` on a `vmess` node | REALITY authenticates a `vless` flow; no VMess REALITY client exists |
| `transport = grpc`/`httpupgrade`/`xhttp`/`kcp`/`quic` | the framing is not implemented, and silently treating it as `tcp` sends nonsense |
| a `vmess` link with a non-zero `aid` | that selects the legacy handshake; only VMess AEAD is spoken (ADR-0030) |

`hysteria2` (ADR-0029) exposes `ports`, `obfs` (`salamander`, `gecko`), `congestion`
(`bbr`, `cubic`, `new-reno`, `brutal`), `hop-interval`/`hop-min-interval`/`hop-max-interval`,
`pin-sha256` and a `[node.quic]` table. `brutal` needs `up-mbps` or `down-mbps`; a hop
interval shorter than 5 s is refused; and `[node.quic].max-stream-receive-window` /
`max-conn-receive-window` are refused rather than ignored, because netune's flow control has no
growing window — set the `init-*-receive-window` keys instead. netune probes the path with
DPLPMTUD by default; `disable-path-mtu-discovery = true` turns that off and keeps datagrams at
the 1200-byte QUIC floor. The owned engine has no GSO, so `disable-segmentation-offload` is
already satisfied and is accepted for reference compatibility.

