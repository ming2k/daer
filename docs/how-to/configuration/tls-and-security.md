# TLS and Security

There are two different TLS questions in a transparent proxy, and keeping them separate
prevents most configuration mistakes:

1. **Destination TLS** is end-to-end between the client and the website. `daer` forwards it; it
   does not terminate or verify it.
2. **Node TLS** is between `daer` and the proxy server. `daer` is the TLS client, so it owns
   the profile, SNI and certificate policy for that leg.

`allow-insecure` applies only to the second. It never weakens the client's TLS to a website.

---

## 1. Global profile

```toml
[tls]
profile = "chrome-current"
fragment = false
fragment-length = "50-100"
fragment-interval = "10-20"
```

`profile` is a netune preset. It changes the ClientHello identity (cipher suites, groups,
extension order). `fragment` splits the ClientHello across TCP segments; the range values must
be `low-high`.

The `[tls]` table is a default. A node may override its own TLS parameters.

---

## 2. Which node table?

| Protocol | Table | Why |
| :--- | :--- | :--- |
| VLESS, VMess | `[node.security]` | The security layer is selectable: `none`, `tls`, or `reality`. |
| Trojan, AnyTLS | `[node.tls]` | TLS is intrinsic; there is nothing to select. |
| Hysteria 2 | `[node.tls]` | TLS is intrinsic; it also accepts a certificate pin. |
| Shadowsocks, SOCKS5, HTTP | none | No TLS to the node. |

Do not put `[node.tls]` on a VLESS node or `[node.security]` on a Trojan node. The protocol's
table is the only one that accepts its TLS keys.

---

## 3. Standard TLS

```toml
[node.tls]
sni = "node.example.com"
allow-insecure = false
```

```toml
[node.security]
type = "tls"
sni = "node.example.com"
allow-insecure = false
alpn = ["h2", "http/1.1"]
fingerprint = "chrome-current"
```

- `sni` is the name presented in the handshake. If the server is an IP, an explicit SNI is
  required: a certificate cannot be verified against an address.
- `alpn` is offered when set. An empty list offers no ALPN.
- `fingerprint` selects a netune profile for this node. It is valid only on the TLS layer.

---

## 4. `allow-insecure`

`allow-insecure = true` accepts any certificate chain: self-signed, expired, hostname-mismatched,
or incomplete. There is no global switch. It belongs to the one node whose certificate cannot
be verified.

Use it when:

- the node uses a self-signed certificate;
- a panel link carries `allowInsecure=1`;
- a test environment intentionally uses an invalid chain.

Do not use it to "make a node work" without understanding why verification failed. It disables
the authentication that prevents an intermediary from impersonating the node.

Subscription links map `allowInsecure=1` / `insecure=1` to the node's TLS table. `daer check
--nodes` prints `(allowInsecure requested)` next to the affected node.

---

## 5. REALITY

```toml
[node.security]
type = "reality"
sni = "download.docker.com"
public-key = "f26c_e2kFv8-39rQz10M_xU8vI3f9Qk2lW0mNoPqRsT"
short-id = "ab01cd02"
alpn = ["h2", "http/1.1"]
```

REALITY authenticates the ClientHello tag rather than the certificate chain. The certificate
the server presents belongs to the impersonated site, so there is no `allow-insecure` and no
`fingerprint` here. `sni` names the impersonated site and is required; `public-key` is the
server's X25519 public key; `short-id` is optional hex.

A REALITY node whose server selects a key-share group the client does not implement fails the
handshake by name. That is a compatibility fact about the server, not a configuration mistake.

---

## 6. Certificate pin

Hysteria 2 accepts an additional leaf-certificate pin:

```toml
[node.tls]
pin-sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
```

The value is the SHA-256 of the server's leaf certificate in hex. It is checked after the chain,
so it is a second factor, not a replacement for verification. A malformed value is a load error.

---

## 7. Security checklist

- Keep `allow-insecure = false` unless a specific node needs otherwise.
- Prefer a valid certificate over `allow-insecure`; prefer a pin over both.
- Do not put a global certificate policy in a shared module; it is node state.
- A subscription token and a node password are secrets; keep the file at `0600`.
- `daer check --nodes` is the quickest way to see which nodes are asking to skip verification.
