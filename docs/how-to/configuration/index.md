# Configuration Guide

This guide explains how to build a `daer` configuration from modules instead of one giant
file. It is task-oriented: each page covers one subsystem, shows the smallest useful example,
and names the constraints the loader enforces.

The authoritative field-by-field contract remains the
[Configuration Reference](../../reference/configuration.md). This guide is the practical
counterpart: it explains **why** the tables are split the way they are and **how** to assemble
them into a working `/etc/daer` tree.

---

## 1. Recommended reading order

| Step | Page | What it decides |
| :--- | :--- | :--- |
| 1 | [File Layout and Includes](file-layout.md) | How one configuration becomes a directory of modules. |
| 2 | [Host and Daemon Settings](host.md) | Interfaces, logging, and TLS defaults. |
| 3 | [Subscriptions](subscriptions.md) | How a panel link becomes a node pool, and where its cache lives. |
| 4 | [Nodes](nodes.md) | Inline nodes, common fields, and `direct`'s real role. |
| 5 | [Node Protocols](node-protocols.md) | The complete TOML shape for every supported protocol. |
| 6 | [Groups and Elections](groups-and-elections.md) | Candidate pools and the policy that selects one node. |
| 7 | [Routing](routing.md) | Rules, match grammar, actions, predicates, and the fallback. |
| 8 | [DNS](dns.md) | Resolver, cache, Fake-IP, and DNS-level policy. |
| 9 | [Rule Sets](rule-sets.md) | Local and remote `.drb` sets. |
| 10 | [TLS and Security](tls-and-security.md) | Node TLS, REALITY, certificate pins, `allow-insecure`. |
| 11 | [Complete Examples](examples.md) | End-to-end configurations to copy and adapt. |

---

## 2. The shortest valid configuration

A configuration needs a schema and a routing fallback. It needs a node only if the fallback
names an election or a proxy pool.

```toml
schema = 5

wan-interface = "auto"

[routing]
fallback = "direct"
```

Validate it without root, without loading the datapath, and without changing the host:

```bash
daer check -c config.toml
```

`daer check` resolves subscriptions and rule sets, compiles every rule, builds every group
and election, and validates the datapath object. It exits non-zero on anything `daer run`
would refuse.

---

## 3. Design rules this guide follows

1. **One module, one question.** Global settings do not contain rules; rules do not contain
   nodes; a node does not carry DNS policy.
2. **No sentinel strings where a type can decide.** `wan-interface = "auto"` is a keyword,
   not a list element; `direct` is a verdict, not a node type.
3. **Layers are tables.** `[node.security]`, `[node.transport]`, `[node.tls]`, `[node.quic]`
   and `[node.obfs]` exist because they are orthogonal to the protocol's authentication.
4. **A key that cannot take effect must not exist.** There is no process-wide
   certificate-verification switch, no `alterId`, and no legacy Shadowsocks cipher.
5. **Validate after every module.** A broken include is easier to find when it is the only
   file that changed.

---

## 4. Directory map

```text
/etc/daer/
├── config.toml                 # schema + include list
├── conf.d/
│   ├── 10-host.toml
│   ├── 20-subscriptions.toml
│   ├── 30-nodes.toml
│   ├── 40-groups-elections.toml
│   ├── 50-rule-sets.toml
│   ├── 60-routing.toml
│   └── 70-dns.toml
└── persist.d/                  # subscription cache, written by daer
```

The next page explains the merge rules and why the numeric prefixes are only a convention.
