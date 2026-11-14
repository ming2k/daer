# Complete Examples

These configurations are complete files, not fragments. Replace placeholder addresses,
credentials and rule-set paths before running them.

---

## 1. Minimal: local SOCKS5, everything else direct

Valid offline; it declares one node and one manually selected election.

```toml
schema = 6

wan-interface = "auto"

[[node]]
name = "local-socks"
type = "socks5"
server = "127.0.0.1"
port = 1080

[[election]]
name = "local"
node = "local-socks"
type = "manual"

[routing]
default = "local"
[[routing.rule]]
name = "rule-1"
match = "dip(224.0.0.0/3, 'ff00::/8')"
action = "direct"
```

Validate:

```bash
daer check -c config.toml --nodes
```

---

## 2. Subscription user with minimum-latency election

Replace the URL and token. This config needs network access when it is loaded.

```toml
schema = 6

wan-interface = "auto"
log-level = "info"

[[subscription]]
name = "panel"
url = "https://panel.example.com/api/subscribe?token=REPLACE_ME"
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

[routing]
default = "proxy"
[[routing.rule]]
name = "rule-1"
match = "dip(192.168.0.0/16)"
action = "direct"

[[routing.rule]]
name = "rule-2"
match = "dip(224.0.0.0/3, 'ff00::/8')"
action = "direct"

[[routing.rule]]
name = "rule-3"
match = "l4proto(udp) && dport(443)"
action = "block"
```

- `sub(panel)` restricts the pool to that subscription.
- The name filter removes a panel's local advert node.
- `type = "min"` picks the lowest last probe latency. Use `min-avg10` or `min-moving-avg` if
  a single spike should not switch the election.

---

## 3. Domestic direct, foreign proxy, ads blocked

This adds compiled rule sets. The paths must exist on the host.

```toml
schema = 6

wan-interface = "auto"

[[subscription]]
name = "panel"
url = "https://panel.example.com/api/subscribe?token=REPLACE_ME"
persist = true

[[group]]
name = "auto"
filters = ["sub(panel) && !name(keyword: 'Website')"]

[[election]]
name = "proxy"
group = "auto"
type = "min-moving-avg"
mode = "url"
url = "https://www.gstatic.com/generate_204"

[[rule-set]]
name = "ads"
type = "file"
path = "/var/lib/daer/rules/geosite-category-ads-all.drb"
format = "drb"

[[rule-set]]
name = "cn"
type = "file"
path = "/var/lib/daer/rules/geosite-cn.drb"
format = "drb"

[[rule-set]]
name = "cn-ip"
type = "file"
path = "/var/lib/daer/rules/geoip-cn.drb"
format = "drb"

[[rule-set]]
name = "private"
type = "file"
path = "/var/lib/daer/rules/geoip-private.drb"
format = "drb"

[[rule-set]]
name = "foreign"
type = "file"
path = "/var/lib/daer/rules/geosite-geolocation-!cn.drb"
format = "drb"

[routing]
default = "proxy"

[routing.sniff]
# The rule sets below carry domains; DNS is consulted first, then a bounded peek.
enabled = true
timeout = "30ms"

[[routing.rule]]
name = "rule-1"
match = "dip(224.0.0.0/3, 'ff00::/8')"
action = "direct"

[[routing.rule]]
name = "rule-2"
match = "rule-set(private)"
action = "direct"

[[routing.rule]]
name = "rule-3"
match = "rule-set(ads)"
action = "block"

[[routing.rule]]
name = "rule-4"
match = "l4proto(udp) && dport(443)"
action = "block"

[[routing.rule]]
name = "rule-5"
match = "rule-set(cn, cn-ip)"
action = "direct"

[[routing.rule]]
name = "rule-6"
match = "rule-set(foreign)"
action = "proxy"
```

The order matters: private and ads are decided before the broad regional sets, and the
domestic set is before the foreign set.

---

## 4. DNS with Fake-IP

```toml
schema = 6

wan-interface = "auto"

[dns]
bind = "127.0.0.1"
ipversion-prefer = "ipv4"
upstream = ["alidns:udp://223.5.5.5:53", "googledns:tcp://8.8.8.8:53"]

[dns.fake-ip]
enabled = true
inet = "198.18.0.0/15"
exclude = ["local", "localhost", "*.lan", "*.local"]

[dns.request]
rules = []
default = "alidns"

[dns.response]
rules = []
default = "accept"

[routing]
default = "direct"
```

On a LAN gateway, change `bind` to the address clients can reach. A client that uses DoH/DoT
to another resolver bypasses Fake-IP; the flow then relies on `[routing.sniff]` or IP rules.

---

## 5. Trojan and Hysteria 2 nodes

```toml
schema = 6

wan-interface = "auto"

[[node]]
name = "trojan"
type = "trojan"
server = "203.0.113.11"
port = 443
password = "REPLACE_ME"

[node.tls]
sni = "node.example.com"
allow-insecure = false

[[node]]
name = "hy2"
type = "hysteria2"
server = "203.0.113.13"
ports = "443,20000-20010"
password = "REPLACE_ME"

[node.tls]
sni = "hy2.example.com"
allow-insecure = false

[node.bandwidth]
up-mbps = 100
down-mbps = 200

[node.quic]
congestion = "brutal"
max-idle-timeout = "30s"
keep-alive-period = "10s"

[node.port-hopping]
interval = "30s"

[[group]]
name = "nodes"
filters = ["name(trojan, hy2)"]

[[election]]
name = "proxy"
group = "nodes"
type = "min"
mode = "url"
url = "https://www.gstatic.com/generate_204"

[routing]
default = "proxy"
```

---

## 6. Multi-file assembly

`/etc/daer/config.toml`:

```toml
schema = 6
include = ["conf.d/*.toml"]
```

`/etc/daer/conf.d/10-host.toml`:

```toml
wan-interface = "auto"
```

`/etc/daer/conf.d/20-subscriptions.toml`:

```toml
[[subscription]]
name = "panel"
url = "https://panel.example.com/api/subscribe?token=REPLACE_ME"
persist = true
```

`/etc/daer/conf.d/30-groups-elections.toml`:

```toml
[[group]]
name = "auto"
filters = ["sub(panel)"]

[[election]]
name = "proxy"
group = "auto"
type = "min"
mode = "url"
url = "https://www.gstatic.com/generate_204"
```

`/etc/daer/conf.d/40-routing.toml`:

```toml
[routing]
default = "proxy"
```

Validate the assembled tree, not the files individually:

```bash
daer check -c /etc/daer/config.toml --nodes
```
