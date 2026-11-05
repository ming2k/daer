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
| `tproxy-port-protect` | boolean | `true` | When true, restricts non-local traffic to the transparent port. |
| `wan-interface` | list of string | `["auto"]` | Egress network interfaces toward the internet. |
| `lan-interface` | list of string | `[]` | Ingress network interfaces receiving client traffic. |
| `so-mark` | integer (hex/dec) | `0x0dae` | Socket mark applied before outbound `connect(2)` to evade loop redirection. |
| `dial-mode` | string | `"domain"` | Resolution mode before dialing: `"ip"` or `"domain"`. |
| `log-level` | string | `"info"` | Log verbosity: `"trace"`, `"debug"`, `"info"`, `"warn"`, `"error"`. |
| `disable-waiting-network` | boolean | `false` | When true, fails immediately if default route is missing on boot rather than waiting up to 2 minutes. |

### `[global.tls]` Sub-Table

| Key | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `profile` | string | `"chrome-current"` | netune client TLS profile preset (e.g. `"chrome-current"`, `"safari-current"`, `"firefox-current"`). |

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
| `bind` | string | `"127.0.0.1:53"` | Listen address for DNS queries. |
| `upstream` | list of string | `[]` | Upstream resolvers (`udp://...`, `tcp://...`, `tls://...`, `https://...`). |
| `cache-size` | integer | `4096` | Max entries in the DNS cache. |
