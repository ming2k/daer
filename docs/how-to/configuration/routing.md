# Routing

`[routing]` maps a flow to an **outbound action**. Rules are evaluated top to bottom; the first
match wins.

```text
flow ──▶ rule 0 match? ──yes──▶ action
          │ no
          ▼
        rule 1 match? ──yes──▶ action
          │ no
          ▼
        fallback action
```

---

## 1. Shape

```toml
[routing]
fallback = { election = "proxy" }

[[routing.rule]]
name = "lan"
match = "dip(192.168.0.0/16)"
action = "direct"

[[routing.rule]]
name = "network-manager"
match = "pname(NetworkManager)"
action = "direct"

[[routing.rule]]
name = "multicast"
match = "dip(224.0.0.0/3, 'ff00::/8')"
action = "direct"

[[routing.rule]]
name = "ads"
match = "rule-set(ads)"
action = "block"

[[routing.rule]]
name = "quic-block"
match = "l4proto(udp) && dport(443)"
action = "block"

[[routing.rule]]
name = "cn-direct"
match = "rule-set(cn, cn-ip)"
action = "direct"

[[routing.rule]]
name = "ai-proxy"
match = "rule-set(openai, anthropic)"
action = { election = "proxy" }
```

Each `[[routing.rule]]` has exactly three fields:

| Key | Type | Meaning |
| :--- | :--- | :--- |
| `name` | string | Required, unique stable identity used by diagnostics and tests. |
| `match` | string | A predicate conjunction. It contains no `->` and no action. |
| `action` | action | The egress the rule selects. |

`fallback` is the action used when no rule matches. It uses the same action type as a rule.

---

## 2. Actions and fallback

`action` is one of:

```text
action = "direct"                 # built-in local path
action = "block"                  # built-in drop
action = { election = "proxy" }  # dynamic: election selects one node
```

- `direct` and `block` are **built-in outbounds**, not nodes and not elections.
- An election is a **selector**, not an outbound. Its result is a node outbound: the selected
  node's dialer carries the flow.
- A bare string action is only `"direct"` or `"block"`. An election must use the table form.
  `action = "proxy"` is rejected with a message naming the replacement.
- A group is a candidate pool, never an action. `action = { election = "pool" }` is rejected
  unless an election named `pool` exists.
- Built-in policy names are reserved: `direct`, `block`, `must_rules`, `<OR>`, `<AND>` may not
  be used as node, group, or election names.

`fallback` uses the same vocabulary:

```text
fallback = "direct"
fallback = "block"
fallback = { election = "proxy" }
```

The default is `"direct"`. A runtime `daer elect proxy <node>` changes which node the
`{ election = "proxy" }` action selects; it does not change the rule.

---

## 3. Rule identity

`name` is not decoration. It is what these use:

- `daer route --why` output;
- logs and incident bundles;
- tests that assert “this rule fired”;
- review comments such as “the `quic-block` rule shadows this one”.

Rules must have a non-empty, unique name. Duplicate names are rejected both by configuration
validation and by the generation builder, so a caller that constructs `Config` directly cannot
bypass the check.

Array order is priority. There is no `priority` field and no implicit reordering.

---

## 4. Match language

The match is a small conjunction language:

```text
match     := predicate ('&&' predicate)*
predicate := '!'? name '(' value (',' value)* ')'
```

- `&&` is **AND**.
- A comma inside one predicate is **OR** over that predicate's values.
- `!` negates one predicate.
- There is no `||` and there is no parenthesis.
- Cross-predicate OR is multiple rules with the same action.
- A predicate the datapath did not observe does not match. It is not guessed.
- `match` may not contain `->`; the action is a separate field.

Examples:

```text
match = "dport(80, 443)"                    # port 80 OR 443
match = "!domain(internal.example)"          # not this domain
match = "l4proto(tcp) && dport(443)"         # TCP AND port 443
match = "domain(a.com, b.com) && dport(443)" # (a.com OR b.com) AND 443
```

The normal form is deliberate. The datapath encodes one conjunction as one kernel match path.
A boolean tree (`||`, parentheses) would either expand into multiple policies or force a
userspace deferral, so it is not part of the syntax. See
[ADR-0049](../../adr/0049-routing-action-is-an-outbound.md).

---

## 5. Predicates

| Predicate | Matches |
| :--- | :--- |
| `domain(pattern, …)` | The acquired domain: Fake-IP, a unique DNS-snooper candidate, or an explicit sniff. |
| `rule-set(name, …)` | Both IP intervals and domains from a declared `[[rule-set]]`. |
| `ip-set(name, …)` | Only IP intervals from a declared `[[rule-set]]`. |
| `domain-set(name, …)` | Only domains from a declared `[[rule-set]]`. |
| `dip(cidr, …)` | Destination IP address. |
| `sip(cidr, …)` | Source IP address. |
| `dport(port-or-range, …)` | Destination port. |
| `sport(port-or-range, …)` | Source port. |
| `l4proto(tcp\|udp)` | Layer-4 transport protocol. |
| `pname(name, …)` | Local process that opened a host-originated flow; requires cgroup v2. LAN client flows have no local process name. |
| `mac(address, …)` | Source MAC observed by the datapath. |
| `dscp(value)` | Packet DSCP observed by the datapath. |
| `ipversion(4\|6)` | Destination address family. |

### Domain patterns

- `example.com` — the domain and all subdomains.
- `.example.com` — subdomains only, not the bare name.
- `=example.com` — exactly `example.com`.

`keyword:` and `regex:` are not routing predicates. Expand them into concrete patterns
upstream.

### Port ranges

`dport(443)`, `dport(8000-8010)`, and `dport(80, 443, 8080)` are valid. The same forms apply
to `sport`.

### Rule-set dimensions

A compiled rule set can carry both IP intervals and domains. Use:

- `rule-set(cn)` for either dimension;
- `ip-set(cn)` when only its addresses should match;
- `domain-set(cn)` when only its domains should match.

### Datapath-only facts

`mac`, `dscp`, and `pname` are supplied by the eBPF datapath through the kernel handoff.
`pname` is populated by six cgroup v2 hooks attached at startup to `/sys/fs/cgroup`
(`DAER_CGROUP_PATH` overrides the mount); it describes the local process for host-originated
traffic and is unknown for a LAN client's packets. A socket established before the daemon
started may not have a process record; the cgroup hooks learn new sockets and connection
events. A
`daer route` diagnostic has no live flow and therefore cannot observe any of them; do not
use them as the only test of a routing change.

---

## 6. Ordering and shadowing

A broad rule before a narrow one makes the narrow rule unreachable:

```text
# Wrong order: the broad rule fires first.
match = "rule-set(foreign)"
action = { election = "proxy" }

match = "rule-set(openai, anthropic)"
action = { election = "proxy" }
```

Put the narrow exception before the broad set. `daer route --why` names shadowed rules instead
of leaving you to infer the order.

Pure IP/L4 predicates are representable in the kernel policy. `domain`, `pname`, `mac`, and
`dscp` require userspace facts and can move the affected suffix to userspace deferral. Keep the
cheap, deterministic rules first when that distinction matters. The full model is in
[Routing performance and rule organization](../../explanation/routing-performance-and-rule-organization.md).

---

## 7. Domain routing and first-packet policy

A `domain(...)` rule needs a name. `daer` obtains it from, in order:

1. a Fake-IP mapping, which is exact;
2. a unique DNS-snooper candidate for `(client, destination)`;
3. a TLS SNI / HTTP Host / QUIC Initial peek, only when `[routing.sniff] enabled = true`;
4. nothing, in which case the flow is routed by the remaining facts.

`[routing.sniff]` is required whenever a domain rule exists, including a domain set contributed
by a rule provider. It is not a DNS setting:

```toml
[dns]
bind = "0.0.0.0"
upstream = ["alidns:udp://223.5.5.5:53"]

[routing.sniff]
enabled = true
timeout = "30ms"
```

- `enabled = false` never inspects payload; domain rules fire only for DNS/Fake-IP-known names.
- `timeout` is the total TCP wait budget and is forbidden when `enabled = false`.
- UDP never waits: it parses only the first datagram, and only when enabled.
- DNS/Fake-IP always win; a unique name is never delayed by sniffing.

A `domain(...)` rule with no explicit answer is a load error rather than an implicit payload
inspection. See [DNS](dns.md) and [Configuration Reference](../../reference/configuration.md#routingsniff-sub-table).

---

## 8. Testing and validation

`daer check` loads the same configuration the daemon uses and reports rule errors by field:

```bash
daer check -c /etc/daer/config.toml
```

`daer route` evaluates the same compiled rules without touching the kernel:

```bash
daer route -c /etc/daer/config.toml 223.5.5.5 --domain example.cn
daer route -c /etc/daer/config.toml 1.1.1.1 --domain example.com --why
```

`--why` prints every rule, whether each predicate matched, the rule name, and which rules were
shadowed.

A domain-only target (`daer route example.com`) uses `0.0.0.0` as the destination address, so
an IP predicate such as `dip(0.0.0.0/8)` can fire before the domain rules. To test the domain
path as a real flow sees it, pass an address and `--domain`.

Validation rejects:

- an empty rule name, or a duplicate name;
- an empty `match`;
- a `match` containing `->`;
- a bare action string other than `direct`/`block`;
- an election action that names an undeclared election or a group;
- a node/group/election that uses a built-in policy name.

---

## 9. Migrating from schema 2

Schema 2’s `[routing].rules` string array is gone. Convert:

```toml
# schema 2
[routing]
rules = [
    "rule-set(cn) -> direct",
    "rule-set(ads) -> block",
    "rule-set(ai) -> proxy",
]
fallback = "proxy"
```

to:

```toml
# schema 5
[routing]
fallback = { election = "proxy" }

[routing.sniff]
enabled = true
timeout = "30ms"

[[routing.rule]]
name = "cn-direct"
match = "rule-set(cn)"
action = "direct"

[[routing.rule]]
name = "ads-block"
match = "rule-set(ads)"
action = "block"

[[routing.rule]]
name = "ai-proxy"
match = "rule-set(ai)"
action = { election = "proxy" }
```

Also replace the retired predicates:

- `provider(...)` → `rule-set(...)`
- `ip(...)` (destination) → `dip(...)`
- `port(...)` (destination) → `dport(...)`
- `dip(rule-set:name)` / `domain(rule-set:name)` → `ip-set(name)` / `domain-set(name)`

There is no compatibility shim: every older schema is rejected by `schema = 5` validation.

---

## 10. Common mistakes

- **Naming a group instead of an election.** Rules target elections; a group is only a pool.
- **Writing `action = "proxy"`.** A bare action is only `direct`/`block`; elections use
  `{ election = "proxy" }`.
- **Putting `->` inside `match`.** The action is a separate field.
- **Using `direct` as a node.** `direct` is a verdict; `[[node]] type = "direct"` is rejected.
- **Duplicating a rule name.** Names are identities, not comments.
- **Putting a broad rule before a narrow one.** The first match wins; `--why` shows the
  shadowing.
- **Blocking QUIC without a TCP fallback.** `match = "l4proto(udp) && dport(443)"` with
  `action = "block"` is valid, but the client must be able to fall back to TCP.
- **Expecting DNS rules here.** `[routing]` decides flows; `[dns.request]` and
  `[dns.response]` decide queries.
