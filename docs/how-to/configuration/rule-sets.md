# Rule Sets

A rule set is a named collection of IP intervals and/or domain patterns. Routing rules
reference it by name. The compiled form is `.drb`; a plain-text rule file is also accepted.

---

## 1. Local `.drb`

```toml
[[rule-set]]
name = "cn"
type = "file"
path = "/var/lib/daer/rules/geosite-cn.drb"
format = "drb"
```

Relative paths resolve against the configuration directory. System-wide sets belong under
`/var/lib/daer/rules/`. `daer` does not scan the directory; only a declared path is read.

A file provider must not set `interval`; a file has no background refresh. Update the file and
reload the daemon.

---

## 2. Remote `.drb`

```toml
[[rule-set]]
name = "cn-ip"
type = "http"
url = "https://example.com/releases/latest/download/geoip-cn.drb"
format = "drb"
interval = "24h"
```

`interval` is required for automatic refresh and is valid only for `http` providers. The
daemon verifies the artifact and caches it; a failed refresh must not replace a working set.

`format` is `"drb"` (binary, zero-copy) or `"text"` (plain rule text).

---

## 3. Compiling with `daer-drb`

```bash
daer-drb compile cn.rules -o geosite-cn.drb
daer-drb inspect geosite-cn.drb
daer-drb test geosite-cn.drb example.cn
```

The audit trail is the `.rules` file that produced the artifact. Keep it with the `.drb`; a
binary cannot be reviewed by reading it.

To unpack a legacy `.dat` once:

```bash
python3 scripts/rules/dat_to_rules.py --kind geosite --dat geosite.dat --code cn -o cn.rules
daer-drb compile cn.rules -o geosite-cn.drb
```

---

## 4. Using a set in routing

```toml
[routing]
fallback = "direct"

[routing.sniff]
enabled = true
timeout = "30ms"

[[routing.rule]]
name = "rule-1"
match = "rule-set(ads)"
action = "block"

[[routing.rule]]
name = "rule-2"
match = "rule-set(openai, anthropic)"
action = { election = "proxy" }

[[routing.rule]]
name = "rule-3"
match = "rule-set(cn, cn-ip)"
action = "direct"
```

- `rule-set(name)` matches both dimensions.
- `dip(rule-set:name)` or `ip(rule-set:name)` matches only IP intervals.
- `domain(rule-set:name)` matches only domains.
- `provider(name)` is deleted; the canonical predicate is `rule-set(name)`.

Rule-set order is routing order. Put a narrow block or exception before a broad regional set;
otherwise the broad set shadows it.

---

## 5. Verification

```bash
daer check -c /etc/daer/config.toml
```

The check reports each set's interval and domain counts. A set that cannot be loaded is named,
with the cache path that was tried, rather than silently becoming an empty rule.

To test one decision:

```bash
daer route -c /etc/daer/config.toml 1.1.1.1 --domain example.com --why
```
