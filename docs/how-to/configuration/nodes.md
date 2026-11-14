# Nodes

A node is one outbound endpoint. `[[node]]` is a tagged union: `type` selects the protocol,
and the remaining keys are validated against that protocol's own table. A key from another
protocol is an unknown field, not a silently ignored option.

---

## 1. Common fields

```toml
[[node]]
name = "edge"
type = "shadowsocks"
server = "203.0.113.10"
port = 8388
method = "chacha20-ietf-poly1305"
password = "secret"
```

| Key | Meaning |
| :--- | :--- |
| `name` | Unique node name. Elections, detours and probes reference it. |
| `type` | Protocol discriminator. |
| `server` | Hostname or IP address of the proxy server. |
| `port` | Server port; Hysteria 2 uses `ports` instead. |
| `detour` | Optional inner node that carries this node's server leg. |

`name` is optional only for subscription-derived nodes, which synthesize it from the
subscription tag and the link fragment. Inline nodes should always name themselves: an
unnamed node cannot be pinned by `daer elect` and makes diagnostics ambiguous.

Built-in policy names are reserved: `direct`, `block`, `must_rules`, `<OR>` and `<AND>`.
They are routing verdicts, not node labels, and a node may not take one as its name.

---

## 2. Supported protocols

| `type` | Authentication | Layers |
| :--- | :--- | :--- |
| `vless` | `uuid`, optional `flow` | `[node.security]`, `[node.transport]` |
| `vmess` | `uuid`, `cipher` | `[node.security]`, `[node.transport]` |
| `shadowsocks` / `ss` | `method`, `password` | none |
| `trojan` | `password` | `[node.tls]` |
| `anytls` | `password`, `idle-sessions` | `[node.tls]` |
| `hysteria2` | `password` | `[node.tls]`, `[node.bandwidth]`, `[node.quic]`, `[node.port-hopping]`, `[node.obfs]` |
| `socks5` / `socks` | optional `username`, `password` | none |
| `http` | optional `username`, `password` | none |

The exact shape of each protocol is in [Node Protocols](node-protocols.md).

---

## 3. `direct` is not a node

`direct` is a built-in routing verdict:

```toml
[routing]
default = "direct"

[routing.sniff]
enabled = true
timeout = "30ms"

[[routing.rule]]
name = "cn"
match = "rule-set(cn)"
action = "direct"
```

It is not a `[[node]]` type and has no `direct://` node link. A rule that should fall through
to the local path names `direct` on the right-hand side. A detour whose inner leg is direct
simply omits `detour`; there is no inner node to name.

`daer probe node direct` remains a local-path diagnostic. It never enters the node pool.

---

## 4. Inline nodes versus links

An inline node must be a structured table. A raw URI string is not accepted in `[[node]]`:

```toml
# Rejected: a link is another panel's wire format, not a configuration table.
# [[node]]
# url = "vless://..."
```

To use links, declare them through a subscription:

```toml
[[subscription]]
name = "panel"
url = "https://panel.example.com/api/subscribe?token=..."
```

The subscription path parses the same strict link grammar and produces the same structured
nodes. An unsupported scheme is listed but not selectable.

---

## 5. Detour chains

`detour` makes the outer protocol run over the inner node's server leg:

```toml
[[node]]
name = "inner"
type = "socks5"
server = "127.0.0.1"
port = 1080

[[node]]
name = "outer"
type = "vless"
server = "203.0.113.20"
port = 443
uuid = "b831381d-6324-4d53-ad4f-8cda48b30811"
detour = "inner"
```

The inner server sees `203.0.113.20:443`; the outer server sees the flow's final target.
Chains may be arbitrarily deep but must be a DAG: unknown targets, self-references and cycles
are load errors. A detour names a node, never a group.

Capabilities are not silently degraded:

- Hysteria 2 cannot be the outer hop; its QUIC socket stack has no datagram-under-proxy seam.
- A detoured SOCKS5 node carries TCP only; a UDP associate would bypass the chain.
- VLESS, VMess and AnyTLS datagrams ride their stream and are carried by the chain.

---

## 6. Validation

```bash
daer check -c /etc/daer/config.toml --nodes
```

The node report names each node's protocol and security identity, including
`(allowInsecure requested)` when a TLS node asks to skip certificate verification. A node
whose protocol this build cannot speak is listed as unselectable, not removed.
