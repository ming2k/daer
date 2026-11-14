# Subscriptions

A subscription is a URL that returns a list of node links. `daer` fetches it while loading the
configuration, decodes the body, and appends the parsed nodes to the same pool as inline
`[[node]]` tables. The daemon and every diagnostic use the same resolver.

---

## 1. Minimal subscription

```toml
[[subscription]]
name = "panel"
url = "https://panel.example.com/api/subscribe?token=..."
persist = true
```

`name` is the tag that `sub(...)` / `subtag(...)` filters match. It is also the cache file
name. `persist = true` keeps the last successful node list beside the configuration.

---

## 2. Wire formats

The decoder tries these formats, in this order:

1. **Plain text** — one link per line. Blank lines, `#` comments and `//` comments are skipped.
2. **Base64** — the whole body is one base64 blob; standard and URL-safe alphabets, with or
   without padding.
3. **SIP008** — a JSON document (`{"version":1,"servers":[…]}`) of Shadowsocks servers.

A line that looks like a link but cannot be parsed is reported and skipped. It is never
silently treated as a usable node. A body that matches none of the formats fails with the
formats that were tried.

---

## 3. Node naming and provenance

A subscription node's name is:

| Source | Name |
| :--- | :--- |
| Link has `#fragment` | `<subscription>/<fragment>` |
| No fragment, one link | `<subscription>` |
| No fragment, several links | `<subscription>/<index>` |

The subscription tag is kept as provenance, so a group can select only that panel:

```toml
[[group]]
name = "panel-pool"
filters = ["sub(panel)"]
```

Inline nodes are loaded first; subscription nodes are appended. A duplicate node name is
still an error: the pool requires unique names because `detour` names exactly one node.

---

## 4. Cache location and failure policy

`persist = true` writes:

```text
<configuration-directory>/persist.d/<sanitized-name>.sub
```

Example:

```text
/etc/daer/persist.d/panel.sub
```

Properties:

- one raw link per line;
- written atomically (temporary file, then rename);
- overwritten only when a fetch produced at least one node;
- keyed by tag, not by URL, so the token never appears in a file name;
- read when the fetch fails.

If a fetch fails and no cache exists, that subscription contributes zero nodes and the load
fails. A stale cache is better than an empty proxy, but a configuration that silently starts
with no outbound is worse than a clear failure.

`persist.d/` contains credentials. Treat it like the configuration, not like disposable cache.

---

## 5. Detour for every node

A subscription link cannot carry a `detour`; the chain is declared next to the subscription:

```toml
[[subscription]]
name = "panel"
url = "https://panel.example.com/api/subscribe?token=..."
detour = "local-socks"
```

Every node from that subscription then uses `local-socks` as its inner server leg. The target
must be an inline node or another subscription node, and the chain must remain a DAG.

---

## 6. Reload and refresh

Subscriptions are resolved on load and on every reload (`SIGHUP`). There is no independent
refresh timer in the daemon. To refresh a panel list, reload the configuration; to test the
panel without restarting, run:

```bash
daer check -c /etc/daer/config.toml --nodes
```

The check performs the same fetch and reports the node count and any rejected lines.

---

## 7. Security notes

- Put the token-bearing file at mode `0600`.
- Do not paste the URL into a log, an issue, or a commit.
- If the token leaks, rotate it at the panel; the cache and the configuration both need the
  new URL.
- A subscription is an input to the node pool, not a trust boundary. A link this build cannot
  speak is listed as unsupported rather than silently downgraded to `direct`.
