# File Layout and Includes

`daer` accepts a single TOML file or a tree assembled with `include`. The tree exists because
the configuration has independent questions: interfaces, node credentials, routing policy,
DNS, and rule assets change for different reasons and at different times.

---

## 1. A single file is valid

```toml
schema = 6

wan-interface = "auto"

[routing]
default = "direct"
```

A single file is the right choice for a laptop, a test fixture, or a generated container
config. It stops being the right choice when a change to one routing rule makes a review of
node credentials unavoidable.

---

## 2. A modular tree

```text
/etc/daer/
├── config.toml
├── conf.d/
│   ├── 10-host.toml
│   ├── 20-subscriptions.toml
│   ├── 30-nodes.toml
│   ├── 40-groups-elections.toml
│   ├── 50-rule-sets.toml
│   ├── 60-routing.toml
│   └── 70-dns.toml
└── persist.d/
```

`config.toml` holds the schema and the include list:

```toml
schema = 6
include = ["conf.d/*.toml"]
```

Paths are relative to the file that declares them. A glob is expanded in lexical order; the
numeric prefixes are a convention for humans, not a dependency order.

---

## 3. Merge semantics

- **Tables merge key by key.** Two files may add different top-level host keys or different
  keys to `[tls]` / `[dns]`.
- **Arrays are concatenated.** `[[node]]`, `[[group]]`, `[[election]]`, `[[rule-set]]` and
  `[[subscription]]` accumulate in include order.
- **A key set twice is an error.** It is not last-writer-wins; a duplicate is a configuration
  mistake that must fail loudly.
- **Unknown keys are errors.** `deny_unknown_fields` applies to every table, including
  included ones.
- **`schema` belongs in the root file.** Put it once; do not repeat it in every module.

This means a module can be as small as one table:

```toml
# conf.d/70-dns.toml
[dns]
bind = "127.0.0.1"
upstream = ["alidns:udp://223.5.5.5:53"]
```

---

## 4. Suggested module boundaries

| Module | Owns | Does not own |
| :--- | :--- | :--- |
| `10-host.toml` | Top-level host keys and `[tls]` | Nodes, rules, DNS, probe settings |
| `20-subscriptions.toml` | `[[subscription]]` | Manual nodes, election policy |
| `30-nodes.toml` | `[[node]]` | Routing decisions |
| `40-groups-elections.toml` | `[[group]]`, `[[election]]` | Rule predicates |
| `50-rule-sets.toml` | `[[rule-set]]` | Which action a rule takes |
| `60-routing.toml` | `[routing]`, `[routing.sniff]` | DNS service or query policy |
| `70-dns.toml` | `[dns]`, `[dns.fake-ip]`, `[dns.request]`, `[dns.response]` | Flow routing |

A module that needs a key from another module is a signal that the boundary is wrong, not
that the include order needs a new prefix.

---

## 5. Secret handling

- A subscription URL often carries a token. Keep the file mode at `0600` and do not commit it.
- `persist.d/` is a copy of the resolved node links, so it carries the same credentials. It is
  the daemon's cache, not configuration; back it up with the same care.
- A certificate pin, password, UUID and REALITY public key are all node-scoped. They belong in
  the node module, never in a shared module.

---

## 6. Validation workflow

Validate the assembled tree, not each file in isolation:

```bash
daer check -c /etc/daer/config.toml
```

Then inspect what the loader actually resolved:

```bash
daer check -c /etc/daer/config.toml --nodes
daer route -c /etc/daer/config.toml 223.5.5.5 --domain example.cn
```

A module that loads alone but changes another module's meaning is exactly what the assembled
check catches.

---

## 7. Reloading

`SIGHUP` re-reads the tree and publishes a new generation. A generation that fails to build
publishes nothing, so a typo in one module cannot stop a working proxy. `daer check` is the
same loader, so running it before `SIGHUP` is the deployment gate.
