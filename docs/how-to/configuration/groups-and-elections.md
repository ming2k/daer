# Groups and Elections

A **group** is a candidate pool. An **election** is a routing target that selects one node
from that pool (or from one explicit node). Rules and `fallback` name elections, never groups.

```text
group (resource) ──▶ election (selection policy + probe) ──▶ one node per connection
```

---

## 1. Group filters

```toml
[[group]]
name = "proxy-pool"
filters = ["sub(panel) && !name(keyword: 'Website')"]
```

- Multiple `filters` entries are **OR**-ed.
- Conditions inside one filter are **AND**-ed with `&&`.
- `!` inverts a condition.
- `name(...)` matches the node name. It accepts a bare value (exact), `keyword:`, or
  `regex:`.
- `sub(...)`, `subtag(...)` and `subscription(...)` match the subscription tag. They accept a
  bare value or `regex:`; `keyword:` is not part of their grammar.
- `filters = []` selects every node.

An annotation carries a value into the selected node:

```toml
[[group]]
name = "preferred"
filters = [
    { match = "sub(panel) && name(keyword: 'HK')", annotate = { add_latency = "-500ms" } },
]
```

`add_latency` shifts the measured latency used by the election. It is a preference, not a
priority override: a dead node still leaves the alive set.

---

## 2. Elections

Exactly one of `group` or `node` is required.

```toml
[[election]]
name = "proxy"
group = "proxy-pool"
type = "min"
mode = "url"
url = "https://www.gstatic.com/generate_204"
```

| `type` | Selection |
| :--- | :--- |
| `manual` | One fixed node; requires `node = "..."`. A group input is rejected. |
| `random` | Random alive candidate. |
| `min` | Lowest last measured latency. Reacts fastest to a spike. |
| `min-avg10` | Lowest average of the last 10 samples. |
| `min-moving-avg` | Lowest moving average, with `tolerance` as a switch threshold. |

Probe fields belong to the election; absent fields use built-in defaults:

| Key | Default | Meaning |
| :--- | :--- | :--- |
| `mode` | `server` | `server` (port reachability) or `url` (end-to-end through the node). |
| `url` | unset | Required for `url` mode. |
| `method` | `HEAD` | `HEAD` or `GET`. |
| `udp-dns` | built-in resolvers | UDP endpoints for server-mode liveness. |
| `interval` | `30s` | Probe cadence. A latency election must keep probing enabled. |
| `timeout` | `5s` | Per-probe deadline. |
| `tolerance` | `0s` | Moving-average switch threshold; only valid for `min-moving-avg`, may be negative. |

A `manual` election is never probed and rejects these keys. Use `daer probe node` for an
on-demand measurement.

A latency election should use `mode = "url"`; `server` mode proves the port answers, not that
the node can carry the flow.

---

## 3. Single-node elections

A group is optional for one node:

```toml
[[election]]
name = "local"
node = "local-socks"
type = "manual"
```

`manual` with a group is rejected. To pin one member of a group at runtime, use:

```bash
daer elect proxy supermanrex/Netherlands
daer elect proxy --reset
```

The override is runtime state under `/var/lib/daer/elections.json`, not a second
configuration file.

---

## 4. A realistic subscription pool

```toml
[[subscription]]
name = "panel"
url = "https://panel.example.com/api/subscribe?token=..."
persist = true

[[group]]
name = "auto"
filters = ["sub(panel) && !name(keyword: 'Website')"]

[[election]]
name = "proxy"
group = "auto"
type = "min"
mode = "url"
url = "https://www.gstatic.com/generate_204"
```

The name filter removes a panel's local `127.0.0.1` advert node. Without it, that node would
be a candidate and might win the election.

---

## 5. What a group does not do

A group carries no selection rule and no probe. It cannot be a routing target, a detour hop,
or a health-policy owner. Those belong to an election or to a node. A node that no group
selects is still a resource and appears in the catalog, but no election can reach it.
