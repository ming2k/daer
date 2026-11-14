# Configuration Reference

For a task-oriented guide that assembles these tables into a modular `/etc/daer` tree, see the
[Configuration Guide](../how-to/configuration/index.md).

`daer` uses strictly-typed TOML with `schema = 6`. Unknown keys are rejected with descriptive
errors, and an older schema is rejected rather than silently upgraded. Schema 4 moved domain
acquisition into `[routing.sniff]` and made `[dns].bind` the only DNS listener switch; schema 5
removed the `[global]` wrapper and made probe settings election-owned; schema 6 simplified routing
actions to bare strings (`"direct"`, `"block"`, or an election name) and renamed
`routing.fallback` / `dns.*.fallback` to `default`.

The default configuration file path is `/etc/daer/config.toml`.

---

## 1. Top-Level Schema

```toml
schema = 6
```

- `schema` (integer, required): Schema version. Must be `6`.

---

## 2. Top-Level Host and Daemon Settings

These keys apply to the whole process and sit at the top level, before the first table header.
There is no `[global]` wrapper: the top level *is* the process scope.

| Key | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `wan-interface` | string or list of string | `"auto"` | Egress interfaces toward the internet. `"auto"` resolves to the interface carrying the default route; an explicit list such as `["eth0", "wg0"]` names them. The two forms are mutually exclusive, and an empty list is a configuration error. |
| `lan-interface` | list of string | `[]` | Ingress interfaces receiving client traffic. An interface cannot also appear in `wan-interface`; one role per interface is a hard invariant. |
| `log-level` | string | `"info"` | `tracing` filter directive: `"info"`, `"debug"`, or `"daer=debug,netune=trace"`. An unparseable directive fails `daer check` and startup; it never silently falls back to `info`. |
| `disable-waiting-network` | boolean | `false` | When true, fails immediately if the default route is missing rather than waiting up to 2 minutes. |

The `SO_MARK` that keeps daer's own sockets out of its datapath is an internal
constant (`0x64616572`, ASCII `daer`). It is not configurable: a value of `0` means
"no mark" to the kernel and would defeat the loop evasion. A privileged run applies
it; `--no-datapath` and unprivileged diagnostics do not mark.

> [!NOTE]
> Transparent listeners bind ephemerally (`port = 0`) inside the isolated `daer0ns` network namespace; traffic assignment is performed directly by the eBPF datapath via `bpf_sk_assign` into the sockmap (ADR-0043). Therefore, `tproxy-port` and `tproxy-port-protect` do not exist.

There is no `dial-mode` key and no global sniff knob. Domain acquisition is a routing policy:
`[routing.sniff]` answers whether payload inspection is allowed when DNS/Fake-IP cannot name a
flow, and `[dns]` owns the DNS service itself. A rule that needs a name does not silently enable
payload inspection; the loader rejects a `domain(...)` rule with no explicit answer.

There is also no process-wide `allow-insecure`: certificate verification belongs to one node's
TLS leg. Setting it globally would let a single self-signed or expired node weaken every other
node. Use the node-level key described under the protocol that owns the TLS leg.

### `[tls]` Table

Defaults for every outbound TLS leg. A node's own TLS table may override individual parameters.

| Key | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `profile` | string | unset (netune's default) | netune client TLS profile preset: `"netune-default"`, `"chrome-current"`, `"firefox-current"`, `"safari-current"`, `"codex-reqwest"`, `"codex-network-proxy"`. An unknown name is a load-time error. |
| `fragment` | boolean | `false` | Split the ClientHello across TCP segments to defeat naive SNI filtering. |
| `fragment-length` | string | `"50-100"` | Byte range for `fragment`. |
| `fragment-interval` | string | `"10-20"` | Millisecond range for the delay between fragments. |

---

## 3. `[[node]]` Tables

Declares individual proxy outbound nodes. Nodes may be defined either as **structured tables** (strongly recommended for readability, explicit type validation, and IDE completion) or as **URI links**.

### Structured Node Schema

Common fields for all structured nodes:

| Key | Type | Description |
| :--- | :--- | :--- |
| `name` | string | Optional unique identifier for the node (`tag` is accepted as an alias). A `detour` references this value. Built-in policy names (`direct`, `block`, `must_rules`, `<OR>`, `<AND>`) are reserved and rejected. |
| `type` | string | Node protocol: `"vless"`, `"vmess"`, `"shadowsocks"` (or `"ss"`), `"trojan"`, `"anytls"`, `"hysteria2"`, `"socks5"` (or `"socks"`), `"http"`. `direct` is not a node type. |
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
- `direct` is a routing verdict, not an inner hop; omit `detour` when the server leg is direct;
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

#### `type = "vmess"`

VMess is AEAD-only (ADR-0030): a non-zero `alterId` selects the retired handshake and is not
expressible. The security and transport layers are the same shapes VLESS uses.

| Key | Type | Description |
| :--- | :--- | :--- |
| `server` | string | Remote server hostname or IP address. |
| `port` | integer | Port number (1-65535). |
| `uuid` | string | Client UUID. |
| `cipher` | string | `"auto"`, `"aes-128-gcm"`, or `"chacha20-poly1305"`. |
| `authenticated-length` | boolean | Authenticate each chunk's length. Default `false`. |
| `no-termination-signal` | boolean | Omit the terminating shutdown signal. Default `false`. |
| `[node.security]` | table | `none`, `tls`, or `reality`. REALITY is rejected for VMess. |
| `[node.transport]` | table | `tcp` (default) or `ws`. |

```toml
[[node]]
name = "vmess-01"
type = "vmess"
server = "203.0.113.15"
port = 443
uuid = "b831381d-6324-4d53-ad4f-8cda48b30811"
cipher = "auto"

[node.security]
type = "tls"
sni = "cdn.example.com"

[node.transport]
type = "ws"
path = "/vm"
host = "cdn.example.com"
```

#### `type = "shadowsocks"` / `"ss"`

| Key | Type | Description |
| :--- | :--- | :--- |
| `server` | string | Remote server hostname or IP address. |
| `port` | integer | Port number (1-65535). |
| `method` | string | AEAD cipher: `"chacha20-ietf-poly1305"`, `"aes-128-gcm"`, `"aes-256-gcm"`, `"xchacha20-ietf-poly1305"`. |
| `password` | string | Shared secret key / password. |

#### `type = "trojan"`

Trojan always speaks TLS to the node, so its TLS parameters live in `[node.tls]`, not in
`[node.security]` (that table selects an optional layer for VLESS/VMess).

| Key | Type | Description |
| :--- | :--- | :--- |
| `server` | string | Remote server hostname or IP address. |
| `port` | integer | Port number (1-65535). |
| `password` | string | Authentication password. |
| `[node.tls]` | table | `sni` (defaults to the server hostname) and `allow-insecure` (default `false`). |

```toml
[[node]]
name = "trojan-01"
type = "trojan"
server = "203.0.113.11"
port = 443
password = "secret"

[node.tls]
sni = "example.com"
allow-insecure = false
```

#### `type = "anytls"` / `"any-tls"`

| Key | Type | Description |
| :--- | :--- | :--- |
| `server` | string | Remote server hostname or IP address. |
| `port` | integer | Port number (1-65535). |
| `password` | string | Authentication password. |
| `idle-sessions` | integer | Pooled idle sessions. Default `1`. |
| `[node.tls]` | table | `sni` and `allow-insecure`. |

#### `type = "hysteria2"`

| Key | Type | Description |
| :--- | :--- | :--- |
| `server` | string | Remote server hostname or IP address. |
| `ports` | string | One port, a list, or a range: `"443"`, `"443,20000-20010"`, `"all"`. |
| `password` | string | Authentication password. |
| `[node.tls]` | table | `sni`, `allow-insecure`, `pin-sha256`. |
| `[node.bandwidth]` | table | `up-mbps`, `down-mbps`. Required by `brutal`. |
| `[node.quic]` | table | QUIC windows, `max-idle-timeout`, `keep-alive-period`, `congestion`, PMTU/GSO switches. |
| `[node.port-hopping]` | table | `interval`, `min-interval`, `max-interval`; the floor is 5s. |
| `[node.obfs]` | table | `type = "salamander"` or `"gecko"` plus its password. |

```toml
[[node]]
name = "hy2-01"
type = "hysteria2"
server = "203.0.113.13"
ports = "443,20000-20010"
password = "secret"

[node.tls]
sni = "hy2.example.com"
allow-insecure = false
pin-sha256 = "0000000000000000000000000000000000000000000000000000000000000000"

[node.bandwidth]
up-mbps = 100
down-mbps = 200

[node.quic]
congestion = "brutal"
max-idle-timeout = "30s"
keep-alive-period = "10s"

[node.port-hopping]
interval = "30s"

[node.obfs]
type = "salamander"
password = "cry_me_a_r1ver"
```

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

#### `direct` is not a node

`direct` is a built-in routing verdict, not a `[[node]]` type:

```toml
[routing]
default = "direct"
[[routing.rule]]
name = "cn"
match = "rule-set(cn)"
action = "direct"
```

Use `direct` as a rule's `action` or as `routing.default`. A `[[node]] type = "direct"`
is rejected by name, and a `direct://` link is rejected by `Node::from_link`. The probe still
accepts `daer probe node direct` as a local-path diagnostic, but it never enters the node pool.

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
| `name` | string | Required | Unique election name; routing rules and `routing.default` reference this name. It cannot shadow a built-in outbound or a group name. |
| `group` | string | — | Candidate pool. Exactly one of `group`/`node` is required. |
| `node` | string | — | A singleton candidate set. Exactly one of `group`/`node` is required. |
| `type` | string | Required | `"manual"` (node input only), `"random"`, `"min"`, `"min-avg10"`, `"min-moving-avg"`. |
| `mode` | string | `"server"` | `"server"` probes the node's own server port (cheap liveness); `"url"` requests a URL **through** the node and measures the end-to-end path. |
| `url` | string | unset | Required when `mode = "url"`; rejected when `mode = "server"`. |
| `method` | string | `"HEAD"` | HTTP method for a URL probe: `HEAD` or `GET`. |
| `udp-dns` | list of string | `["1.1.1.1:53", "8.8.8.8:53", "2001:4860:4860::8888:53"]` | Hosts probed over UDP DNS for server-mode liveness. A bare IP uses port 53; a name is reported and skipped rather than resolved silently. |
| `interval` | duration | `"30s"` | Probe cadence; `0s` disables probing. A latency election must keep probing enabled. |
| `timeout` | duration | `"5s"` | Per-probe deadline. |
| `tolerance` | duration | `"0s"` | Moving-average switch threshold; only valid for `type = "min-moving-avg"`. May be negative. |

A **manual** election is never scheduled for probing, so it rejects all probe keys; use
`daer probe node` for on-demand measurement. Probe settings belong to the election that
consumes them; there is no global probe-default table.

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

## 6. `[[rule-set]]` Tables (ADR-0014)

Declares pre-compiled DRB (`.drb`) or human-readable text rule sets from local files or remote HTTP subscriptions.

| Key | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `name` | string | Required | Unique identifier for referencing in routing rules via `rule-set(name)` (`tag` is accepted as the name field's alias). |
| `type` | string | `"file"` | Source type: `"file"` or `"http"`. |
| `url` | string | Optional | Remote download URL (required when `type = "http"`). |
| `path` | string | Optional | Local file path (required when `type = "file"`). Relative paths resolve against the configuration directory; system-wide local sets belong under `/var/lib/daer/rules/`. |
| `format` | string | `"drb"` | Artifact format: `"drb"` (binary zero-copy) or `"text"` (plain text). |
| `interval` | string | Optional | Auto-update interval for HTTP providers (e.g. `"24h"`, `"12h"`). |

---

## 7. `[routing]` Table

Defines an ordered list of routing rules and the default action.

| Key | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `rule` | array of tables | `[]` | Ordered `[[routing.rule]]` entries; the first match wins. |
| `default` | action | `"direct"` | `"direct"`, `"block"`, or a declared election name when no rule matches. |

Each `[[routing.rule]]` has exactly:

| Key | Type | Description |
| :--- | :--- | :--- |
| `name` | string | Required, unique stable identity used by diagnostics and tests. |
| `match` | string | Predicate conjunction; no `->` and no action. |
| `action` | action | `"direct"`, `"block"`, or a declared election name. |

```toml
[routing]
default = "proxy"

[[routing.rule]]
name = "ads"
match = "rule-set(ads)"
action = "block"

[[routing.rule]]
name = "ai"
match = "rule-set(openai, anthropic)"
action = "proxy"
```

### Rule Actions

`action` and `default` use the same string type:

| Value | Meaning |
| :--- | :--- |
| `"direct"` | Built-in local path. |
| `"block"` | Built-in drop verdict. |
| `"<election>"` | Dynamic outbound: the named election selects one node, and that node's dialer is the egress. |

`"direct"` and `"block"` are reserved built-in policies; any other string must name a declared
`[[election]]`. A group is a candidate pool, never an action.
`direct`, `block`, `must_rules`, `<OR>` and `<AND>` are reserved as node/group/election names.

### Rule Names

`name` is required and unique. It is the identity used by `daer route --why`, logs and tests.
Rule order is array order; there is no priority field. An empty match or duplicate name is a load
error.

### Rule Grammar

```text
match     := predicate ('&&' predicate)*
predicate := '!'? name '(' value (',' value)* ')'
```

`&&` is AND, a comma inside one predicate is OR, and `!` negates. There is no `||` and no
parenthesis; cross-predicate OR is multiple rules with the same action. The normal form maps to
one kernel match path per conjunction (ADR-0049).

### Rule Predicates

- `dip(cidr)` — Match destination IP.
- `sip(cidr)` — Match source IP.
- `dport(port_range)` — Match destination port.
- `sport(port_range)` — Match source port.
- `domain(pattern)` — Match the acquired domain (ADR-0036): a bare name (`example.com`) is a suffix matching the domain and all subdomains; `.example.com` matches subdomains only; `=example.com` matches the exact name only. `keyword:` and `regex:` are removed (ADR-0033); expand them into concrete patterns.
- `rule-set(name)` — Match IP intervals or domains from a declared `[[rule-set]]`.
- `ip-set(name)` — Match only IP intervals from a declared rule set.
- `domain-set(name)` — Match only domains from a declared rule set.
- `l4proto(tcp|udp)` — Match Layer 4 transport protocol.
- `pname(process_name)` — Match the local process that opened a host-originated flow. The
  daemon attaches the six cgroup v2 hooks that populate `cookie_pid_map`; a LAN client flow
  has no local process name and therefore does not match a positive `pname(...)`.
- `mac(address)` / `dscp(value)` — Match datapath-observed facts.
- `ipversion(4|6)` — Match the destination address family.

`&&` is AND, commas inside one predicate are OR, and `!` negates. Cross-predicate OR is
multiple rules with the same action. There is no `||` and no parenthesis; see ADR-0049.

`domain`, `pname`, `mac` and `dscp` need userspace facts. `daer route` has no live flow, so
those predicates report “not matched” in a diagnostic. On the data path, `mac`, `dscp` and
`pname` fire when the kernel handoff supplies the value; `pname` requires cgroup v2 and is
observed for locally-originated host traffic.

### `[routing.sniff]` Sub-Table

Payload-based domain recovery is a fallback, not a DNS setting. DNS/Fake-IP is always consulted
first; this table only answers what routing may do when it did not produce a unique name.

| Key | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `enabled` | boolean | unset | Required whenever a `domain(...)` rule exists (including a domain set from a rule provider). `true` allows a bounded inspection of the first bytes; `false` routes by the remaining facts. |
| `timeout` | duration | unset | Required with `enabled = true`, forbidden with `enabled = false`. The total TCP wait budget; UDP parses only the first datagram and never waits. |

The fixed source order is:

```text
Fake-IP
  > a unique DNS-snooper candidate
  > sniff (only when enabled)
  > address
```

A `domain(...)` rule with no `[routing.sniff] enabled` is a load error. A `timeout` without
`enabled = true` is also a load error: there is exactly one way to disable payload inspection.

---

## 8. `[dns]` Table

Configures the built-in DNS server, caching, and upstream transports.

| Key | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `bind` | string | unset (no server) | The only switch that starts the DNS listener. Unset means `daer` is not the box's resolver and starts no server. |
| `upstream` | list of string | `[]` | Upstream resolvers as `tag:protocol://address:port`. Required when `bind` is set. The protocol is required: `udp`, `tcp`, `tls` (DoT), `https` (DoH), or a `+` chain tried in order. A hostname instead of an address is rejected (there is no bootstrap resolver yet). |
| `ipversion-prefer` | string | `"any"` | `"ipv4"`, `"ipv6"`, or `"any"` for no preference. |
| `optimistic-cache` | boolean | `true` | Serve stale entries while refreshing. |
| `optimistic-cache-ttl` | duration | `"60s"` | How long an optimistic entry is served. |
| `optimistic-stale-reply-ttl` | duration | `"30s"` | How long a stale answer may be replayed. |
| `max-cache-size` | integer | `65536` | Bound on the cache. There is no `cache-size` key. |

`[dns.fixed-domain-ttl]` maps a domain suffix to a TTL duration (e.g. `"60s"`). `[dns.request]` and
`[dns.response]` each take `rules` and a `default` (`"asis"` / `"accept"` are the
`[dns.request]` / `[dns.response]` defaults).

### `[dns.fake-ip]` Sub-Table

| Key | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `enabled` | boolean | `false` | Allocate synthetic addresses and serve them to clients. Requires an explicit `[dns].bind`; it never starts the listener by itself. |
| `inet` | string | `"198.18.0.0/15"` | The IPv4 pool prefix. |
| `inet6` | string | unset | Optional IPv6 pool prefix. When set, `AAAA` queries receive synthetic addresses too; when unset, `AAAA` is answered with an empty NOERROR so clients fall back to the synthetic `A`. |
| `pool-size` | integer | `65535` | Number of synthetic addresses per address family. |
| `exclude` | list of string | `[]` | Domains that must never get a synthetic address. Each entry is a domain pattern: a bare name (suffix), `.name` (subdomains only), or `=name` (exact); `keyword:`/`regex:` are also accepted here (ADR-0033, ADR-0036). |

---

## 9. What is not here

The retired Protobuf `geoip:` / `geosite:` databases are gone (ADR-0014/ADR-0015): domestic and
regional routing is expressed as a `[[rule-set]]` holding a compiled `.drb` set plus
`rule-set(name)` in a rule. Legacy `.dat` files can be unpacked once with `scripts/rules/dat_to_rules.py`
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

`hysteria2` (ADR-0029) keeps its layers separate: `[node.tls]` for the intrinsic TLS leg,
`[node.bandwidth]` for `up-mbps`/`down-mbps`, `[node.quic]` for windows, timeouts, congestion
(`bbr`, `cubic`, `new-reno`, `brutal`) and PMTU/GSO switches, `[node.port-hopping]` for the hop
schedule, and `[node.obfs]` for `salamander`/`gecko`. `brutal` needs a bandwidth hint; a hop
interval shorter than 5 s is refused; and `[node.quic].max-stream-receive-window` /
`max-conn-receive-window` are refused rather than ignored, because netune's flow control has no
growing window — set the `init-*-receive-window` keys instead. netune probes the path with
DPLPMTUD by default; `disable-path-mtu-discovery = true` turns that off and keeps datagrams at
the 1200-byte QUIC floor. The owned engine has no GSO, so `disable-segmentation-offload` is
already satisfied and is accepted for reference compatibility.

