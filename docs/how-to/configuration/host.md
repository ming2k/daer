# Host and Daemon Settings

Top-level keys answer questions about the host and the daemon. They never name a node, a
routing verdict, or a DNS upstream. There is no `[global]` table: the top level is the process
scope, so these keys must appear before the first table header.

---

## 1. Minimal host settings

```toml
wan-interface = "auto"
```

`"auto"` resolves the interface that carries the default route by reading `/proc/net/route`.
The same field also accepts an explicit list for multi-uplink hosts:

```toml
wan-interface = ["eth0", "wg0"]
```

The two forms are mutually exclusive. `["auto"]` is not accepted; the keyword is the bare
string. An empty list and duplicate names are configuration errors.

`lan-interface` is the ingress side: the interfaces that receive client traffic. It is a list
and defaults to empty.

```toml
lan-interface = ["eth1"]
```

One interface cannot appear in both lists. The datapath attaches one role per interface;
the combined-role classifier variants were removed. An explicit overlap is rejected by
`daer check`, and `wan-interface = "auto"` is checked again after the default route is
resolved.

---

## 2. Field map

| Key | Purpose | Default |
| :--- | :--- | :--- |
| `wan-interface` | Egress interfaces; `"auto"` or a list. | `"auto"` |
| `lan-interface` | Client ingress interfaces. | `[]` |
| `log-level` | `tracing` filter: `"info"`, `"debug"`, `"daer=debug,netune=trace"`. | `"info"` |
| `disable-waiting-network` | Fail immediately when no default route exists. | `false` |
| `[tls]` | ClientHello profile and fragmentation defaults. | see below |

There is **no** process-wide `allow-insecure`. Certificate verification belongs to one node's
TLS leg. See [TLS and Security](tls-and-security.md).

---

## 3. Socket mark is internal

The datapath recognizes `daer`'s own traffic by `skb->mark`, not by port. Without a consistent
mark, an outbound connection is redirected back into the transparent listener and loops.

The mark is an implementation detail, not site policy. A privileged run applies the fixed
constant `0x64616572` (ASCII `daer`) to every socket it creates; `--no-datapath` and
unprivileged diagnostics do not mark. There is no `so-mark` key: a configured value of `0`
would mean "no mark" to the kernel and defeat the loop evasion, and any other value has to be
kept in sync with the datapath's `PARAM.socket_mark`. `daer run` logs the value it used.

---

## 4. Domain acquisition is a routing policy, not a host setting

The old `sniffing-timeout` and `auto-sniff-punt` keys are gone. Whether routing may inspect the
first bytes of a flow is answered by `[routing.sniff]`, next to the rules that consume the name:

```toml
[routing.sniff]
enabled = true
timeout = "30ms"
```

DNS is a service and lives in `[dns]`. See [Routing](routing.md#7-domain-routing-and-first-packet-policy)
and [DNS](dns.md).

---

## 5. Waiting for the network

A daemon started by systemd can reach `main` before DHCP installs a default route.
`disable-waiting-network = false` waits up to two minutes, logging every five seconds.
Set it to `true` on a box with a static route where a missing route should fail at once.

This switch only matters when `wan-interface = "auto"`. An explicit interface list does not
need a default route to resolve.

---

## 6. TLS profile and fragmentation

```toml
[tls]
profile = "chrome-current"
fragment = true
fragment-length = "50-100"
fragment-interval = "10-20"
```

The profile is a netune preset name. `fragment` splits the ClientHello across TCP segments;
both range values must be written as `low-high`. A node's own `[node.security]` or
`[node.tls]` table can override node-specific parameters, but `[tls]` is the fallback.

---

## 7. Probes belong to elections

There is no probe-default table. An `[[election]]` declares the probe it needs; omitted fields
use built-in defaults (`mode = "server"`, `interval = "30s"`, `timeout = "5s"`). A manual
election is never scheduled for probing and rejects probe keys; use `daer probe node` for an
on-demand measurement.

See [Groups and Elections](groups-and-elections.md) for the probe keys and their defaults.
