# DNS

The built-in DNS server is optional. It exists so `daer` can decide **which upstream** answers
a query, cache the answer, and optionally hand out Fake-IP addresses that preserve the domain
name for routing.

Without it, `daer` still forwards traffic; it learns domains from TLS SNI and HTTP Host
instead, and IP-only rules still work.

For where the resolver sits in the client-side, egress, and return paths, see
[Packet Flow and the DNS Name Plane](../../explanation/packet-flow-and-dns.md).

---

## 1. Minimal resolver

```toml
[dns]
bind = "127.0.0.1"
upstream = ["alidns:udp://223.5.5.5:53", "googledns:tcp://8.8.8.8:53"]
```

- `bind` is an IP, not `IP:port`; the server always listens on port 53.
- Every upstream is `name:protocol://address:port`, and at least one is required when `bind` is set.
- Protocols: `udp`, `tcp`, `tls` (DoT), `https` (DoH), or a `+` chain tried in order.
- A hostname instead of an address is rejected: there is no bootstrap resolver.
- Setting `bind` is the only way to start the listener. Omitting it starts no server.

Use a loopback bind when only the local host needs the resolver:

```toml
[dns]
bind = "127.0.0.1"
```

On a LAN gateway, bind the address clients can reach:

```toml
[dns]
bind = "192.168.1.1"
```

---

## 2. Cache

```toml
[dns]
optimistic-cache = true
optimistic-cache-ttl = "60s"
optimistic-stale-reply-ttl = "30s"
max-cache-size = 65536
```

The cache is bounded by `max-cache-size`. Optimistic caching serves a stale entry while it
refreshes, which trades freshness for latency. `max-cache-size` is the key; there is no
`cache-size` alias.

---

## 3. Query and response policy

```toml
[dns.request]
rules = ["qname(keyword: ads) -> reject"]
default = "alidns"

[dns.response]
rules = []
default = "accept"
```

`[dns.request]` selects or rejects an upstream for a query. `[dns.response]` decides what to
do with the answer. The defaults are `asis` for requests and `accept` for responses.

This is a different policy surface from `[routing]`: DNS rules see a query, not a flow.

---

## 4. Fake-IP

Fake-IP is a feature, not a default mode: `[dns.fake-ip]` starts with `enabled = false`.
It is an answer mode of the DNS listener, so enabling it requires an explicit `dns.bind`; it
never starts the listener by itself.

```toml
[dns]
bind = "192.168.1.1"
upstream = ["alidns:udp://223.5.5.5:53"]

[dns.fake-ip]
enabled = true
inet = "198.18.0.0/15"
exclude = ["local", "localhost", "*.lan", "*.local"]
```

Fake-IP answers a name with a synthetic address from the pool. When the client connects,
`daer` maps the synthetic address back to the name and applies `domain(...)` rules. It avoids
waiting for a ClientHello sniff and works for protocols that carry no SNI or Host.

Tradeoffs:

- Clients must use `daer` as their resolver.
- The synthetic address is meaningful only inside `daer`; it is not routable.
- A client using DoH/DoT directly bypasses Fake-IP; the flow falls back to `[routing.sniff]` when enabled, or to IP rules.
- Exclude local names, router pages and mDNS-style domains.
- If `inet6` is unset, AAAA queries receive an empty NOERROR so clients fall back to the
  synthetic A record. A pure IPv6 client needs `inet6` configured.

Fake-IP is optional. The alternative is real IPs plus DNS snooping (when `daer` answers the
query) or the `[routing.sniff]` payload fallback. IP-only routing needs neither.

The DNS service and the fallback are separate decisions:

```toml
[dns]
bind = "0.0.0.0"
upstream = ["alidns:udp://223.5.5.5:53"]

[dns.fake-ip]
enabled = true

[routing.sniff]
enabled = true
timeout = "30ms"
```

DNS/Fake-IP is always consulted first. A unique mapping never waits for sniffing; payload
inspection runs only when the DNS side produced no unique name. `enabled = false` is the
explicit “never inspect payload” choice, and it requires a DNS service when domain rules exist.

---

## 5. Fixed TTLs

```toml
[dns.fixed-domain-ttl]
".example.com" = "60s"
```

A suffix maps to a TTL duration. This is useful for a domain whose upstream TTL is too short
for the deployment's cache behavior.

---

## 6. What the DNS server does not do

- It does not intercept DoH/DoT sent to another resolver.
- It does not resolve the node's own server hostname through itself; bootstrapping an upstream
  by name is not implemented.
- It does not turn `[routing]` into DNS policy. Use `[dns.request]` for query policy and
  `[routing]` for flow policy.
