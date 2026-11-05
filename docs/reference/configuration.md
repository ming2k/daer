# Configuration Reference

`daer` uses strictly-typed TOML with `schema = 1`. Unknown keys are rejected with descriptive errors.

The default configuration file path is `/etc/daer/config.toml`.

---

## 1. Top-Level Schema

```toml
schema = 1
```

- `schema` (integer, required): Schema version. Must be `1`.

---

## 2. `[global]` Table

Controls global transparent proxy, networking, and daemon behaviors.

| Key | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `tproxy-port` | integer | `12345` | TCP/UDP port bound with `IP_TRANSPARENT` for incoming redirected traffic. |
| `tproxy-port-protect` | boolean | `true` | Reject a flow whose original destination *is* the transparent port: it was not redirected, so serving it would make the port an open relay. |
| `wan-interface` | list of string | `["auto"]` | Egress interfaces toward the internet. `"auto"` resolves to the interface carrying the default route; an empty list is a configuration error. |
| `lan-interface` | list of string | `[]` | Ingress interfaces receiving client traffic. |
| `so-mark` | integer (hex/dec) | `0x0dae` when omitted | Socket mark applied before outbound `connect(2)` to evade loop redirection. Omitted, a privileged run picks `0x0dae` and an unprivileged one marks nothing. |
| `log-level` | string | `"info"` | `tracing` filter directive: `"info"`, `"debug"`, or `"daer=debug,netune=trace"`. |
| `disable-waiting-network` | boolean | `false` | When true, fails immediately if the default route is missing rather than waiting up to 2 minutes. |
| `sniffing-timeout` | duration | `"30ms"` | How long to wait for a sniffable byte sequence before routing by IP. |
| `auto-sniff-punt` | boolean | `true` | When false, a name is only used after the flow reaches userspace, never as a reason to hold it up. |
| `allow-insecure` | boolean | `false` | Accept an invalid node certificate. |

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

### `[global.health-check]` Sub-Table

| Key | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `tcp-url` | list of string | Cloudflare's two addresses | URL first, then optional direct IPs so the probe does not depend on DNS. |
| `tcp-method` | string | `"HEAD"` | HTTP method for the TCP/HTTP probe. |
| `udp-dns` | list of string | `["dns.google:53", "8.8.8.8", "2001:4860:4860::8888"]` | Hosts probed over UDP DNS. |
| `interval` | duration | `"30s"` | Probe interval; `0s` disables probing. |
| `tolerance` | duration | `"0s"` | Shifts the switching threshold of moving averages; may be negative. |

---

## 3. `[[node]]` Tables

Declares individual proxy outbound nodes. Nodes may be defined either as **structured tables** (strongly recommended for readability, explicit type validation, and IDE completion) or as **URI links**.

### Structured Node Schema

Common fields for all structured nodes:

| Key | Type | Description |
| :--- | :--- | :--- |
| `tag` | string | Optional unique identifier for the node. |
| `type` | string | Node protocol: `"vless"`, `"shadowsocks"` (or `"ss"`), `"trojan"`, `"socks5"` (or `"socks"`), `"http"`, `"direct"`. |

#### `type = "vless"` (REALITY)

| Key | Type | Description |
| :--- | :--- | :--- |
| `server` | string | Remote server hostname or IP address. |
| `port` | integer | Port number (1-65535). |
| `uuid` | string | Client user ID (UUID). |
| `flow` | string | Flow framing (e.g. `"xtls-rprx-vision"`). Optional. |
| `[node.reality]` | table | REALITY security parameters (required). |
| `reality.sni` | string | SNI presented in ClientHello (impersonated site). |
| `reality.public-key` | string | Server X25519 public key (`pbk`). |
| `reality.short-id` | string | Hexadecimal short ID (`sid`). Optional. |
| `reality.fingerprint` | string | TLS ClientHello fingerprint (e.g. `"chrome"`). Required. |
| `reality.alpn` | list of string | Offered ALPN protocols (e.g. `["h2", "http/1.1"]`). Optional. |

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
tag = "panel"
url = "https://example.com/api/subscribe?token=..."
```

An inline `[[node]]` is still written as a structured table, and `daer check` names any field
it cannot honour.

---

## 4. `[[group]]` Tables

Groups nodes together for policy-based selection and health checking.

| Key | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `name` | string | Required | Unique group name referenced in routing rules. |
| `policy` | string | `"min-moving-avg"` | Selection policy: `"min"`, `"min-moving-avg"`, `"random"`. |
| `filters` | list of string | `[]` | Filter expressions selecting nodes (e.g. `subtag(my-sub) && !name(keyword: 'Expire')`). |

---

## 5. `[[rule-provider]]` Tables (ADR-0014)

Declares pre-compiled DRB (`.drb`) or human-readable text rule sets from local files or remote HTTP subscriptions.

| Key | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `tag` | string | Required | Unique identifier for referencing in routing rules via `provider(tag)`. |
| `type` | string | `"file"` | Provider type: `"file"` or `"http"`. |
| `url` | string | Optional | Remote download URL (required when `type = "http"`). |
| `path` | string | Optional | Local file path (required when `type = "file"`). |
| `format` | string | `"drb"` | Artifact format: `"drb"` (binary zero-copy) or `"text"` (plain text). |
| `interval` | string | Optional | Auto-update interval for HTTP providers (e.g. `"24h"`, `"12h"`). |

---

## 6. `[routing]` Table

Defines flow matching rules and default verdicts.

| Key | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `rules` | list of string | `[]` | Ordered routing rule expressions evaluated top-to-bottom. |
| `fallback` | string | `"direct"` | Verdict or group name if no rule matches. |

### Rule Predicates

- `dip(cidr)` — Match destination IP.
- `sip(cidr)` — Match source IP.
- `dport(port_range)` — Match destination port.
- `sport(port_range)` — Match source port.
- `domain(suffix|full|keyword|regex: pattern)` — Match the sniffed domain by kind.
- `provider(tag)` / `rule-set(tag)` — Match IP intervals or domains from a declared `[[rule-provider]]`.
- `dip(provider:tag)` / `ip(provider:tag)` — Match only IP intervals from a declared rule provider.
- `domain(provider:tag)` — Match only domains from a declared rule provider.
- `l4proto(tcp|udp)` — Match Layer 4 transport protocol.
- `pname(process_name)` — Match client process name.

---

## 7. `[dns]` Table

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
| `inet` | string | `"198.18.0.0/15"` | The pool's prefix. |
| `pool-size` | integer | `65535` | Number of synthetic addresses. |
| `exclude` | list of string | `[]` | Domains that must never get a synthetic address. |

---

## 8. What is not here

The retired Protobuf `geoip:` / `geosite:` databases are gone (ADR-0014/ADR-0015): domestic and
regional routing is expressed as a `[[rule-provider]]` holding a compiled `.drb` set plus
`provider(tag)` in a rule. `geodrb` converts an existing `.dat` once.

An outbound chain (`a -> b`) is rejected at load time rather than silently truncated to its first
hop. `vmess`, plain `vless` without REALITY, `hysteria2`, `tuic`, `anytls` and the QUIC families
are not implemented; a node using one is listed and reported as unselectable by
`daer check --nodes` rather than downgraded to `direct`.

