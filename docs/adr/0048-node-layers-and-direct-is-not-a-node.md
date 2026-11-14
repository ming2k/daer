---
id: ADR-0048
title: "Node configuration is layered, and direct is a policy rather than a node"
status: accepted
date: 2026-11-13
scope: [config/model, config/schema, outbound/protocols, cli/surface, docs]
supersedes: []
superseded_by: []
amends: [ADR-0028, ADR-0029, ADR-0030]
---

# 0048. Node configuration is layered, and direct is a policy rather than a node

- Status: Accepted
- Date: 2026-11-13
- Deciders: daer maintainers
- Related: [ADR-0028](0028-protocol-layering.md), [ADR-0029](0029-hysteria2-socket-stack.md),
  [ADR-0030](0030-vmess-aead-only.md), [ADR-0044](0044-outbound-detour-chain.md)

## Context

The schema already nested the two genuinely orthogonal layers of VLESS/VMess
(`[node.security]`, `[node.transport]`), but the same questions were answered differently
elsewhere:

- Trojan, AnyTLS and Hysteria 2 carried `sni`, `allow-insecure` and `pin-sha256` as flat node
  keys even though TLS is intrinsic to those protocols;
- Hysteria 2 mixed port selection, hopping, bandwidth, congestion and QUIC tuning in one flat
  table, and its documented `ports = "443,..."` spelling did not even deserialize;
- `direct` existed as a `NodeEndpoint` variant, so a routing verdict could also be a node and
  an inner detour hop. That duplicated the built-in policy and made
  `daer probe node direct` ambiguous with a node label;
- there was a global `allow-insecure` key that no TLS path consumed, which advertised a
  daemon-wide security downgrade that did not exist.

A flat field is not wrong by itself. Authentication keys (`uuid`, `password`, `method`) are
protocol identity and belong on the node. The defect is putting a *layer* on the node: TLS,
QUIC, transport and obfuscation are different axes with their own parameters.

## Decision

Schema version 3 makes the node a small protocol core plus explicit layers. There is no
compatibility shim for the old spellings.

### 1. `direct` is not a node

`direct` is a routing policy. Use it as an action or fallback; a `[[node]] type = "direct"` and
a `direct://` link are rejected. A detour whose inner leg is direct omits `detour`. Built-in
policy names (`direct`, `block`, `must_rules`, `<OR>`, `<AND>`) are reserved as node names so
a label cannot make the probe and the compiler disagree about what a name means.

### 2. Security is a layer, not a node field

| Protocol | Table | Reason |
| :--- | :--- | :--- |
| VLESS, VMess | `[node.security]` | `none`, `tls` or `reality` is selectable. |
| Trojan, AnyTLS | `[node.tls]` | TLS is intrinsic; there is no `none`. |
| Hysteria 2 | `[node.tls]` | TLS is intrinsic and also accepts a certificate pin. |
| Shadowsocks, SOCKS5, HTTP | none | No TLS to the node. |

`allow-insecure` exists only inside a TLS table. There is no global switch. `fingerprint` is a
standard-TLS key, never a REALITY key.

### 3. Hysteria 2 is split by behavior

```toml
[[node]]
type = "hysteria2"
server = "203.0.113.13"
ports = "443,20000-20010"
password = "secret"

[node.tls]
sni = "hy2.example.com"
allow-insecure = false
pin-sha256 = "..."

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
password = "..."
```

`ports` is a string port union. Hopping is a schedule, not part of the port set. QUIC tuning
takes durations, not hidden `-ms` integers.

### 4. Authentication stays flat

`uuid`, `password`, `method`, `flow` and `cipher` remain protocol-level keys. Nesting them
under a generic `[node.auth]` would not add type safety: `type` already selects the protocol
and the loader rejects foreign keys.

## Consequences

- A node's shape now says which layer owns a parameter, instead of relying on prose.
- `direct` has one owner: the routing policy. The node pool cannot carry a second spelling.
- The global `allow-insecure` key is deleted; certificate policy is node-local.
- This is a clean break. `schema = 3` is required; schema-2 node shapes are rejected with a
  field-level error.
- The Hysteria 2 `ports`/hopping split fixes a documented spelling that previously did not
  load.

## Enforcement

| Claim | Falsifier |
| :--- | :--- |
| `direct` is not a node | `structured_node_negative_controls`, `direct_node_is_rejected` |
| Built-in policy names are reserved | `a_node_cannot_take_a_builtin_policy_name` |
| Intrinsic TLS is `[node.tls]` | `intrinsic_tls_and_hysteria_layers_are_nested` |
| Flat TLS keys are rejected | the same test's negative control |
| Hysteria 2 port string parses | `intrinsic_tls_and_hysteria_layers_are_nested` |
| No global `allow-insecure` | `defaults_apply_and_unknown_keys_are_rejected` |
| The example and reference load | `schema_is_up_to_date`, `every_toml_block_in_the_reference_documentation_loads` |
