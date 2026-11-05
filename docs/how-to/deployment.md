# Deployment

What a box needs to run `daer` as a transparent proxy, and what to check when it does not.

## Requirements

| Thing | Why |
| --- | --- |
| Linux 5.17+ | `bpf_loop`, and the cgroup hooks the datapath uses |
| `CAP_BPF`, `CAP_NET_ADMIN` | load and attach the datapath; `IP_TRANSPARENT` on the listener |
| `ip` | creates the `daer0`/`daer0peer` pair |
| the datapath object | `cargo xtask ebpf`, or one shipped with the package |
| `[[rule-provider]]` sources | only when a rule says `provider(<tag>)`; a `file` provider is read from disk, an `http` one is cached under `$XDG_CACHE_HOME/daer/rules` (`DAER_RULE_CACHE_DIR` overrides; the shipped unit sets it to `/var/cache/daer/rules`, which is the only path `ProtectHome=true` leaves writable) |

## Build

```sh
cargo xtask ebpf           # -> target/ebpf/datapath.o  (needs clang + a vmlinux.h tree)
cargo build --release      # -> target/release/daer
```

`cargo xtask ebpf` needs `DAER_DATAPATH_SRC` (defaults to `ebpf/kern`) and `DAER_BPF_HEADERS`
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
tag = "edge"
type = "vless"
server = "example.com"
port = 443
uuid = "b831381d-6324-4d53-ad4f-8cda48b30811"
flow = "xtls-rprx-vision"
[node.reality]
sni = "impersonate.example.com"
public-key = "f26c_e2kFv8-39rQz10M_xU8vI3f9Qk2lW0mNoPqRsT"
fingerprint = "chrome"

[[group]]
name = "proxy"
policy = "min-moving-avg"

[routing]
rules = ["provider(private) -> direct", "provider(cn) -> direct"]
fallback = "proxy"
```

Check it before starting:

```sh
daer check -c /etc/daer/config.toml
daer route 10.0.0.2:1234 1.1.1.1:443 --domain example.com --why -c /etc/daer/config.toml
# or simply:
daer route example.com --why -c /etc/daer/config.toml
```

`daer route --why` prints the verdict a running daer would act on, including
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

## The DNS server, and when it starts

`daer run` builds the resolver, its Fake-IP pool, and its DNS snooper **always**, because they
are the contract between the DNS half and the data path: the resolver writes a name-to-address
mapping and the router reads it back.

It *listens* only when the configuration asks for it:

| Configuration | DNS listener |
| --- | --- |
| `dns.bind` set | started on that address (port 53) |
| `[dns.fake-ip] enabled = true` | started on `dns.bind`, default `0.0.0.0:53` |
| neither | **not** started; the daemon logs at `INFO` that it is not the box's resolver |

Binding `0.0.0.0:53` unconditionally would be a regression, not a convenience: a box already
running `systemd-resolved` would see `daer run` fail with `EADDRINUSE`, and a box that does not
want daer as its resolver would have one installed anyway. Fake-IP counts as a request because
the feature is inert without a resolver handing out the synthetic addresses.

## The socket mark

The datapath recognises daer's own traffic by `skb->mark`, not by port. Without a consistent
mark, daer's *outbound* connection to an origin is caught by its own datapath and redirected
back into its own listener: the flow appears to hang with no error in any log. The
end-to-end test measured **17,134** accepted flows for a single client request before the mark
was threaded through.

```toml
[global]
so-mark = 0x0dae
```

`daer run` applies that value in three places and logs it once:

```text
INFO listening for redirected flows port=12345 so_mark=Some(3566) generation=gen1
```

* the generation's dialers (`SocketConfig::mark`, applied **before** `connect(2)`);
* `PARAM.dae_socket_mark`, which the datapath compares against `skb->mark`;
* the redirect exclusion, which is the datapath's own check — there is no firewall rule to
  write for it.

The mark is *not* applied by default: `SO_MARK` needs `CAP_NET_ADMIN`, so a default would make
every unprivileged run fail to dial. Set it in production.

## The redirect and the policy routing

`daer run` installs everything the redirect needs. There is no firewall rule to write and no
`ip rule` to add by hand: the datapath redirects with `bpf_redirect` into the `daer0`/`daer0peer`
pair, and `daer` owns the state that makes that work.

What it sets up, in order, before the first flow is served:

| State | Why |
| --- | --- |
| `daer0` / `daer0peer` veth pair, both up | the redirect target, and the path the listener is reachable through |
| `ip rule add fwmark 0x8000000/0x8000000 table 2023` (v4 and v6) | a redirected packet carries a **non-local** destination; the rule is what sends it to a `local` route instead of the forward path |
| `ip route add local default dev lo table 2023` (v4 and v6) | the destination of that route |
| `net.ipv4.conf.daer0peer.rp_filter = 0` | reverse-path filtering would drop a packet with a non-local source before `bpf_sk_assign` could deliver it |
| `net.ipv4.conf.daer0peer.forwarding = 1`, `net.ipv4.conf.all.forwarding = 1` | the gateway role |
| TC classifiers on every `lan`/`wan` interface | see below |
| `listen_socket_map` entries `0` (tcp4), `1` (**udp**), `2` (tcp6) | `assign_listener` looks the socket up by key; an empty slot is a flow the datapath has already taken off the direct path and then drops |

All of it is removed again when the daemon exits: the rules and routes are owned by a guard
that deletes them on drop, and the sysctls are restored to whatever they were.

### Which TC program goes on which interface

Every hook has an `_l2` and an `_l3` variant, and exactly **one** is attached per interface:

| Interface `type` (ARPHRD) | Program variant | Why |
| --- | --- | --- |
| `1` (Ethernet: `eth0`, `wlan0`, `enp*`) | `_l2` | a 14-byte Ethernet header precedes the IP header |
| `0xFFFE`/`512`/`768`/… (TUN, WireGuard, PPP, `netkit`) | `_l3` | the packet starts at the IP header |

Attaching both is not belt-and-braces: the wrong variant reads the first bytes of the IP header
as a MAC address (or skips 14 bytes into the IP header) and misclassifies every packet on that
interface. `daer run` reads `/sys/class/net/<if>/type` and refuses an interface whose type has
no parser, rather than guessing.

`lan` and `wan` are not the same attachment:

* `lan` interfaces get `lan_ingress` and `lan_egress`;
* `wan` interfaces get `wan_ingress` and `wan_egress`.

## What `--no-datapath` means

`--no-datapath` serves the accept/relay path **without attaching anything**. Nothing is
redirected into the transparent port, so no traffic is proxied: it exists to exercise the
control plane in a container without `CAP_BPF`/`CAP_NET_ADMIN`, and `daer run` says so at
`WARN`. It is not a way to run a proxy with a firewall rule instead — the firewall `tproxy`
path and the eBPF path are alternatives, and this build implements the eBPF one.

## systemd

A unit file is shipped at `install/daer.service`:

```ini
[Unit]
Description=daer transparent proxy daemon
Documentation=https://github.com/ming2k/daer
After=network-online.target
Wants=network-online.target
# Bound crash loops: give up after 5 restarts within 5 minutes.
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
Type=simple
User=root

# Resource limits
LimitNPROC=4096
LimitNOFILE=1048576
LimitMEMLOCK=infinity
OOMScoreAdjust=-100

# Validate configuration before starting. A broken configuration exits with non-zero
# and prevents starting or restarting with an invalid state. `daer check` is the one
# pre-bind gate: it resolves subscriptions and rule providers, compiles every rule and
# builds every group, so a configuration that would fail at runtime fails here instead.
ExecStartPre=/usr/bin/daer check -c /etc/daer/config.toml
ExecStart=/usr/bin/daer run -c /etc/daer/config.toml --object /usr/lib/daer/datapath.o
ExecReload=/usr/bin/kill -HUP $MAINPID

# Restart policy
Restart=on-failure
RestartSec=5s

# Timeout configuration
TimeoutStartSec=120
TimeoutStopSec=30

# The capabilities the datapath and privileged listeners (e.g. port 53) need.
AmbientCapabilities=CAP_BPF CAP_NET_ADMIN CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_BPF CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ProtectControlGroups=true
# ProtectKernelTunables must remain false: daer needs to tune sysctls on its peer
# devices (/proc/sys/net/ipv4/conf/daer0peer) and pin eBPF maps to /sys/fs/bpf.
ProtectKernelTunables=false
LockPersonality=true
RestrictRealtime=true
PrivateTmp=true
# The listener and the device pair need the network, so `PrivateNetwork` is off.
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK

# Configuration directory, BPF filesystem, and write access for subscription persistence
ConfigurationDirectory=daer
ReadWritePaths=/etc/daer /sys/fs/bpf

# Where downloaded rule sets are cached (ADR-0014). The default is `$XDG_CACHE_HOME` or
# `$HOME/.cache`, and `ProtectHome=true` above makes that unwritable — the fallback write is
# best-effort, so the failure is silent and only shows up as a provider that cannot survive
# the network going away. `CacheDirectory=daer` creates /var/cache/daer and grants write
# access to exactly it, and the variable points the loader there.
CacheDirectory=daer
Environment=DAER_RULE_CACHE_DIR=/var/cache/daer/rules

[Install]
WantedBy=multi-user.target
```

To install and enable it:

```sh
sudo cp install/daer.service /etc/systemd/system/daer.service
sudo systemctl daemon-reload
sudo systemctl enable --now daer
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
| `InvalidProgramSection` | the object was built without `cargo xtask ebpf`, which normalizes `ebpf-go` section syntax |

Userspace tests cannot catch any of those, which is why this script exists.

## Verifying it works

```sh
# 1. is the datapath attached?
journalctl -u daer -b | grep 'datapath attached'

# 2. is the policy what you think?
daer route example.com --why -c /etc/daer/config.toml

# 3. does a flow actually get proxied?
curl -sS -o /dev/null -w '%{http_code}\n' --interface eth0 https://example.com
journalctl -u daer -b | tail -20     # a `flow decided` line per connection at debug

# 4. does a reload keep flows alive?
systemctl reload daer
```

`RUST_LOG=daer=debug` overrides `log-level` for a one-off investigation, which is what makes
[Diagnostics Guide](diagnostics.md) usable without editing the configuration.

## What is not implemented

Be aware before trusting it with traffic:

* **vmess, plain vless, tuic** are not implemented; a link naming one is listed but not
  selectable, and is never silently downgraded to `direct`.
* A REALITY node has **no datagram transport**, so a UDP flow routed to such a group is
  refused rather than silently sent direct. Silence there would be a leak: the client would
  believe UDP was tunnelled when it was not.
* The **event ring** (per-flow trace) is not consumed yet: there is no per-flow trace beyond
  the `debug` logs.
* **`domain(...)` rules keep flows on the userspace path.** The kernel cannot evaluate a
  domain predicate without `domain_routing_map`, an IP-keyed bitmap the control plane would
  have to maintain from DNS answers; this build does not maintain it. Every flow is then
  handed to userspace, which is correct but costs a relay hop. The daemon says which tier it
  is in at startup — see [ADR-0005](../adr/0005-kernel-policy-encoding.md). The facts the kernel
  did observe (source MAC, DSCP, process name) **are** read back from
  `routing_handoff_map`, so `mac(...)`, `dscp(...)`, and `pname(...)` rules do match on that
  path.
* **IPv6 UDP is not proxied on the eBPF path.** The datapath's `assign_listener` uses one
  family-independent key for datagrams (`key = &one_key`) while TCP picks a key by family, so
  `listen_socket_map` has a single datagram slot and it holds the IPv4 socket. A v6 datagram
  redirected by the kernel is assigned to a socket that cannot receive it. IPv4 UDP and all TCP
  are unaffected; the daemon says so at `WARN` when it attaches. The fix belongs in the C
  datapath (a fourth key, or `bpf_sk_lookup_udp`), not in userspace, and guessing a second slot
  would silently mismatch the object.
* The **`tproxy` redirect of a datagram is not proven end to end**, and the reason is the test
  topology rather than the code: `TPROXY` matches on the ingress interface, so proving it needs
  the origin in a second network namespace, which a development sandbox cannot create. Three
  single-namespace topologies were tried and each failed for a fixture reason. On a
  two-namespace box, run `crates/daer-control/tests/transparent.rs` there; it states the
  limitation and skips with the reason. What *is* proven in one namespace: the reply leaves
  from the original destination (not from the transparent port), one client port talking to
  two destinations gets two sessions, and the reply-socket cache evicts instead of leaking fds.
