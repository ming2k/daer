# Node Protocols

Each protocol owns its authentication keys and its layers. The `type` field selects the
protocol; the loader then rejects keys that belong to another protocol.

The three layer tables are not interchangeable:

| Table | Meaning | Used by |
| :--- | :--- | :--- |
| `[node.security]` | Selects `none`, `tls` or `reality`. | VLESS, VMess |
| `[node.tls]` | Parameters of an intrinsic TLS leg. There is no `none`. | Trojan, AnyTLS, Hysteria 2 |
| `[node.transport]` | Stream framing above the security layer. | VLESS, VMess |

---

## 1. VLESS

```toml
[[node]]
name = "vless-reality"
type = "vless"
server = "203.0.113.14"
port = 443
uuid = "b831381d-6324-4d53-ad4f-8cda48b30811"
flow = "xtls-rprx-vision"

[node.security]
type = "reality"
sni = "download.docker.com"
public-key = "f26c_e2kFv8-39rQz10M_xU8vI3f9Qk2lW0mNoPqRsT"
short-id = "ab01cd02"
alpn = ["h2", "http/1.1"]

[node.transport]
type = "tcp"
```

Fields:

| Key | Meaning |
| :--- | :--- |
| `uuid` | Client UUID. |
| `flow` | `none`, `xtls-rprx-vision`, or `xtls-rprx-vision-udp443`. |
| `[node.security]` | `none`, `tls`, or `reality`. |
| `[node.transport]` | `tcp` (default) or `ws`. |

TLS instead of REALITY:

```toml
[node.security]
type = "tls"
sni = "cdn.example.com"
allow-insecure = false
alpn = ["h2", "http/1.1"]
fingerprint = "chrome-current"
```

WebSocket instead of raw TCP:

```toml
[node.transport]
type = "ws"
path = "/ray"
host = "cdn.example.com"
headers = { "X-Custom" = "value" }
```

Constraints:

- Vision requires TLS or REALITY directly under the protocol. It cannot sit behind `ws`.
- REALITY requires `sni` and `public-key`; `short-id` and `alpn` are optional.
- REALITY has no `fingerprint`. The ClientHello is built by the REALITY layer, not by a
  netune profile. `fingerprint` is valid only under `[node.security] type = "tls"`.

---

## 2. VMess

```toml
[[node]]
name = "vmess"
type = "vmess"
server = "203.0.113.15"
port = 443
uuid = "b831381d-6324-4d53-ad4f-8cda48b30811"
cipher = "auto"
authenticated-length = false
no-termination-signal = false

[node.security]
type = "tls"
sni = "cdn.example.com"

[node.transport]
type = "ws"
path = "/vm"
host = "cdn.example.com"
```

`cipher` is one of `auto`, `aes-128-gcm`, or `chacha20-poly1305`. VMess is AEAD-only; a
non-zero `alterId` selects the retired handshake and is rejected. REALITY under VMess is also
rejected: no VMess REALITY client exists.

---

## 3. Shadowsocks

```toml
[[node]]
name = "ss"
type = "shadowsocks"
server = "203.0.113.10"
port = 8388
method = "2022-blake3-aes-256-gcm"
password = "base64-encoded-key"
```

Accepted methods:

```text
aes-128-gcm
aes-256-gcm
chacha20-ietf-poly1305
xchacha20-ietf-poly1305
2022-blake3-aes-128-gcm
2022-blake3-aes-256-gcm
2022-blake3-chacha20-poly1305
```

Legacy stream ciphers (`aes-*-cfb`, `rc4-md5`, `chacha20`, `salsa20`, …) are rejected by name.
SS2022 passwords must be base64 keys of the length the method requires.

---

## 4. Trojan

```toml
[[node]]
name = "trojan"
type = "trojan"
server = "203.0.113.11"
port = 443
password = "secret"

[node.tls]
sni = "example.com"
allow-insecure = false
```

TLS is intrinsic. If `server` is an address, `sni` is required: a certificate cannot be
verified against an IP.

---

## 5. AnyTLS

```toml
[[node]]
name = "anytls"
type = "anytls"
server = "203.0.113.12"
port = 443
password = "secret"
idle-sessions = 1

[node.tls]
sni = "example.com"
allow-insecure = false
```

`any-tls` is accepted as an alias for the type. `idle-sessions` is an AnyTLS protocol
parameter, not a TLS parameter.

---

## 6. Hysteria 2

```toml
[[node]]
name = "hy2"
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
disable-path-mtu-discovery = false

[node.port-hopping]
interval = "30s"

[node.obfs]
type = "salamander"
password = "cry_me_a_r1ver"
```

- `ports` is the reference port-union syntax: `"443"`, `"443,8443"`, `"20000-30000"`, `"all"`.
- `[node.port-hopping]` is separate from the port set. The reference floor is 5 seconds;
  `min-interval` must not exceed `max-interval`.
- `congestion` is `bbr`, `cubic`, `new-reno`, or `brutal`. `brutal` requires at least one
  bandwidth hint.
- `pin-sha256` is the SHA-256 of the server's leaf certificate, in hex. It is an additional
  check, not a replacement for the chain.
- `[node.quic].max-stream-receive-window` and `max-conn-receive-window` are refused rather than
  ignored: netune has no growing-window knob. Use the `init-*-receive-window` keys.
- Hysteria 2 cannot be the outer hop of a detour.

---

## 7. SOCKS5 and HTTP

```toml
[[node]]
name = "local-socks"
type = "socks5"
server = "127.0.0.1"
port = 1080
# username = "user"
# password = "secret"
```

```toml
[[node]]
name = "local-http"
type = "http"
server = "127.0.0.1"
port = 8080
# username = "user"
# password = "secret"
```

Both are plaintext to the proxy server. HTTP is an HTTP CONNECT proxy; it is not an HTTPS
proxy. A detoured SOCKS5 node carries TCP only.

---

## 8. `direct`

`direct` is not a protocol table. Use it as a routing verdict:

```toml
[routing]
default = "direct"

[routing.sniff]
enabled = true
timeout = "30ms"

[[routing.rule]]
name = "private"
match = "rule-set(private)"
action = "direct"
```

A `[[node]] type = "direct"` is rejected with the list of supported protocols.
