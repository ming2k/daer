# Deployment

What a box needs to run `daer` as a transparent proxy, and what to check when it does not.

## Requirements

| Thing | Why |
| --- | --- |
| Linux 5.17+ | `bpf_loop`, and the cgroup hooks the datapath uses |
| `CAP_BPF`, `CAP_NET_ADMIN` | load and attach the datapath; `IP_TRANSPARENT` on the listener |
| `ip` | creates the `daer0`/`daer0peer` pair |
| the datapath object | `make ebpf`, or one shipped with the package |
| `geoip.dat` / `geosite.dat` | only when a rule says `geoip:` / `geosite:` |

## Build

```sh
make ebpf        # -> target/ebpf/datapath.o  (needs clang + a vmlinux.h tree)
make build       # -> target/release/daer
```

`make ebpf` needs `DAER_DATAPATH_SRC` (defaults to `ebpf/kern`) and `DAER_BPF_HEADERS`
(defaults to `ebpf/headers`). `ebpf/headers/vmlinux.h` is per-kernel and is not vendored;
generate it where the object is built:

```sh
bpftool btf dump file /sys/kernel/btf/vmlinux format c > ebpf/headers/vmlinux.h
```

A `vmlinux.h` from a newer kernel than the target's is the usual cause of a verifier
rejection that names a struct offset.

## Configuration

The minimum that proxies anything:

```toml
schema = 1

[global]
tproxy-port = 12345
wan-interface = ["auto"]      # or the interface name
lan-interface = ["eth0"]      # the network you are proxying traffic *from*
# Strongly recommended; see "The socket mark" below.
so-mark = 0x0dae

[[node]]
url = "vless://…#edge"

[[group]]
name = "proxy"
policy = "min-moving-avg"

[routing]
rules = ["dip(geoip:private) -> direct", "domain(geosite:cn) -> direct"]
fallback = "proxy"
```

Check it before starting:

```sh
daer config validate -c /etc/daer/config.toml
daer route explain 10.0.0.2:1234 1.1.1.1:443 --domain example.com --why -c /etc/daer/config.toml
```

`route explain --why` prints the verdict a running daer would act on, including
"undeliverable, group X has no selectable node" — which is the failure that otherwise looks
like a network problem.

## Running

```sh
sudo daer run -c /etc/daer/config.toml
```

Startup, in order, with the log line that proves each step:

```text
INFO interfaces resolved lan=["eth0"] wan=["eth1"]
INFO configuration loaded generation=gen1 rules=2 groups=1 nodes=1 build_ms=3
INFO listening for redirected flows port=12345 generation=gen1 …
INFO datapath attached: redirected flows will be proxied port=12345 device=daer0 peer=daer0peer
```

If the last line is missing, nothing is proxied however healthy the rest looks. `daer run`
exits rather than serving when it cannot attach; `--no-datapath` is the explicit opt-in to
serving without it, and it says so at `WARN` because a daemon that forwards nothing is worse
than one that refuses to start.

`SIGHUP` reloads; `SIGTERM`/`SIGINT` stop accepting and give live flows 10s to finish. A
reload that fails to build publishes nothing, so a typo cannot stop a working proxy.

## The socket mark

The datapath redirects by port. Without a mark, daer's *own* outbound connection to the
origin matches the same rule and is redirected back into daer's listener: the flow appears to
hang with no error in any log. Setting a mark and excluding it in the redirect rule is what
separates "flows from clients" from "flows from daer".

```toml
[global]
so-mark = 0x0dae
```

```sh
nft add rule ip daer prerouting meta mark 0x0dae return
```

The mark is *not* applied by default: `SO_MARK` needs `CAP_NET_ADMIN`, so a default would make
every unprivileged run fail to dial. Set it in production.

## The redirect rules

The datapath handles redirected traffic; something has to redirect it. With nftables, for
traffic arriving on `eth0` and destined for the internet:

```sh
nft add table ip daer
nft add chain ip daer prerouting '{ type filter hook prerouting priority mangle; }'
nft add rule ip daer prerouting meta mark 0x0dae return
nft add rule ip daer prerouting iif eth0 ip daddr @local_nets return
nft add rule ip daer prerouting iif eth0 tcp tproxy to :12345
```

Two things are easy to get wrong:

* **the mark exclusion must come first**, or daer proxies itself;
* **local addresses must be excluded**, or the box cannot reach its own services — the
  proxied destination would be the box itself.

`ip rule`/`ip route` for the transparent port are not needed with `tproxy`: unlike
`REDIRECT`, the destination is preserved and daer reads it from the socket.

## systemd

```ini
[Unit]
Description=daer transparent proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/daer run -c /etc/daer/config.toml
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5
# The two capabilities the datapath needs; everything else is dropped.
AmbientCapabilities=CAP_BPF CAP_NET_ADMIN
CapabilityBoundingSet=CAP_BPF CAP_NET_ADMIN
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
# The listener and the device pair need the network, so `PrivateNetwork` is off.
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK

[Install]
WantedBy=multi-user.target
```

`ExecReload` is what makes SIGHUP usable: `systemctl reload daer` then swaps the policy
without dropping a connection.

## Verifying the kernel datapath

`./scripts/kernel-check.sh` (as root) checks everything the userspace cannot: whether the
object loads and passes the verifier, whether a tc program attaches, and whether the device
pair and its MAC/ifindex are readable. Run it before `daer run` on a new machine:

```sh
sudo ./scripts/kernel-check.sh
```

The step that matters is 3:

```text
3. loading the object into the kernel (this runs the verifier)
  ok  the object loaded and passed the verifier
```

A failure there is almost always one of:

| Message names | Cause |
| --- | --- |
| `PermissionDenied` creating a map | no `CAP_BPF` — a "root" user namespace is not enough, `unprivileged_bpf_disabled` blocks it |
| a struct offset or a `bpf_*` helper | `vmlinux.h` came from a different kernel than the target |
| `InvalidProgramSection` | the object was built without `scripts/build-ebpf.sh`, which normalizes `ebpf-go` section syntax |

Userspace tests cannot catch any of those, which is why this script exists.

## Verifying it works

```sh
# 1. is the datapath attached?
journalctl -u daer -b | grep 'datapath attached'

# 2. is the policy what you think?
daer route explain 10.0.0.2:1234 1.1.1.1:443 --domain example.com --why -c /etc/daer/config.toml

# 3. does a flow actually get proxied?
curl -sS -o /dev/null -w '%{http_code}\n' --interface eth0 https://example.com
journalctl -u daer -b | tail -20     # a `flow decided` line per connection at debug

# 4. does a reload keep flows alive?
systemctl reload daer
```

`RUST_LOG=daer=debug` overrides `log-level` for a one-off investigation, which is what makes
`docs/diagnostics.md` usable without editing the configuration.

## What is not implemented

Be aware before trusting it with traffic:

* **UDP** flows are relayed: the daemon owns a transparent datagram socket, drives one session
  per peer, remembers where each reply goes, and its counters are readable
  (`Daemon::datagram_stats`). What is **not** proven end to end is the `tproxy` *redirect* of a
  datagram, and the reason is the test topology rather than the code: `TPROXY` matches on the
  ingress interface, so proving it needs the origin in a second network namespace, which a
  development sandbox cannot create. Three single-namespace topologies were tried and each
  failed for a fixture reason — the redirect also caught the origin's reply; a veth peer's
  traffic is routed internally so `iif` is `lo` (a `counter` rule saw zero packets); and policy
  routing alone does not create an `iif`. `crates/daer-control/tests/transparent.rs` states this
  and skips with the reason. On a two-namespace box, run it there.
* A REALITY node has **no datagram transport**, so a UDP flow routed to such a group is refused
  rather than silently sent direct. Silence there would be a leak: the client would believe UDP
  was tunnelled when it was not.
* **vmess, plain vless, anytls, hysteria2, tuic** are not implemented; a link naming one is
  listed but not selectable, and is never silently downgraded to `direct`.
* The **event ring** (per-flow trace, `bpf_trace_printk`) is not consumed yet: there is no
  per-flow trace beyond the `debug` logs.
* **`domain(...)` rules keep flows on the userspace path.** The kernel cannot evaluate a domain
  predicate without `domain_routing_map`, an IP-keyed bitmap the control plane has to maintain
  from DNS answers; this build does not maintain it. Every flow is then handed to userspace,
  which is correct but costs a relay hop. The daemon says which tier it is in at startup —
  see [ADR-0005](adr/0005-kernel-policy-encoding.md).

## The socket mark, and the loop it prevents

`SO_MARK` is not optional in a working deployment, and the value must be the same in three
places: the daemon's own dials, the datapath's `PARAM.dae_socket_mark`, and the redirect rule's
exclusion. `daer run` decides it once, applies it to all three, and logs it:

```text
INFO listening for redirected flows port=12345 so_mark=Some(3566) generation=gen1 …
```

With `--no-datapath` the mark is `None` on purpose: `SO_MARK` needs `CAP_NET_ADMIN`, so an
unprivileged run must dial without one.

The failure this prevents is not theoretical. Without a consistent mark the daemon's own
connection to an origin matches the same `tproxy` rule as a client's and is redirected back into
the listener: the end-to-end test observed **17,134** accepted flows for a single client request
before the mark was threaded through, and the flow simply hung.
