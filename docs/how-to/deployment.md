# Deployment

What a box needs to run `daer` as a transparent proxy, and what to check when it does not.

## Requirements

| Thing | Why |
| --- | --- |
| Linux 5.17+ | `bpf_loop`, and the cgroup hooks the datapath uses |
| `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_PERFMON` | load and attach the datapath (`CAP_PERFMON` enables the verifier's `allow_ptr_leaks` for variable-offset packet parsing); `IP_TRANSPARENT` on the listeners |
| `CAP_SYS_ADMIN` | create the private `daer0ns` ingress namespace, unshare its private mount namespace, move `daer0peer` into it, and `setns` to bind the listeners and attach the peer program (ADR-0038) |
| `ip` | create the `daer0`/`daer0peer` pair and configure the ingress namespace |
| Host sysctls | `net.ipv4.ip_forward=1`, `net.ipv4.conf.all.forwarding=1`, `net.ipv4.conf.all.rp_filter=0`, `net.ipv4.conf.all.arp_filter=0`; `net.ipv6.conf.all.forwarding=1` on a dual-stack kernel. `daer` checks them at startup and refuses to change them. |
| the datapath object | `cargo xtask ebpf`, or one shipped with the package |
| `[[rule-provider]]` sources | only when a rule says `provider(<tag>)`; a `file` provider is read from `/var/lib/daer/rules/` (or the declared path), an `http` one is cached under `/var/cache/daer/rules` (`DAER_RULE_CACHE_DIR` overrides; the shipped unit sets it explicitly) |

The default TC attachment is classic `cls_bpf`, which works on Linux 5.17+. The opt-in TCX
path (`DAER_TC_ATTACH=tcx`, used by the real-daemon delivery check) needs Linux 6.6+.

### Host sysctls

`daer` forwards transparently, so the host must already have forwarding enabled and
reverse-path filtering relaxed. These are host-global settings; `daer` checks them and
**does not change them**. A missing value is a startup failure that names the key.

```ini
# /etc/sysctl.d/99-daer.conf
net.ipv4.ip_forward = 1
net.ipv4.conf.all.forwarding = 1
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.all.arp_filter = 0
# Only on a dual-stack kernel:
net.ipv6.conf.all.forwarding = 1
```

```sh
sudo sysctl --system
```

`rp_filter`/`arp_filter` are relaxed because a redirected packet carries the client's source
address, which is not local to the host; strict reverse-path filtering drops it before the
datapath sees it. The daemon still owns the `daer0`/`daer0peer` per-device knobs and the
namespace-local knobs, which disappear with their devices.

## Build

```sh
cargo xtask ebpf           # -> target/ebpf/datapath.o  (needs clang + a vmlinux.h tree)
cargo build --release      # -> target/release/{daer,daer-cleanup,daer-drb}
```

To install the built artifacts and the unit under `/usr`:

```sh
cargo xtask install                      # /usr/bin, /usr/lib/daer, /usr/lib/systemd/system
cargo xtask install --prefix /usr/local  # unit paths follow the prefix
cargo xtask install --destdir /tmp/pkg   # stage a package tree
```

`cargo xtask install` installs the exact set the unit names, including `daer-cleanup`; it
does not write `/etc/daer/config.toml`, enable the unit, or start it. It runs as the
invoking user, so writing `/usr` needs the permissions to do so. Use
`scripts/ops/daer-install-netns.sh --config <path>` for those activation steps: it stages
the same tree as your user and uses `sudo` only for the copy and the service restart.

`cargo xtask ebpf` needs `DAER_DATAPATH_SRC` (defaults to `ebpf/kern`) and `DAER_BPF_HEADERS`
(defaults to `ebpf/headers`). `ebpf/headers/vmlinux.h` is per-kernel and is not vendored;
generate it where the object is built:

```sh
bpftool btf dump file /sys/kernel/btf/vmlinux format c > ebpf/headers/vmlinux.h
```

A `vmlinux.h` from a newer kernel than the target's is the usual cause of a verifier
rejection that names a struct offset.

## Filesystem layout

The supported deployment is system-wide:

| Path | Purpose |
| :--- | :--- |
| `/etc/daer/config.toml` | Configuration. |
| `/etc/daer/example.toml` | Annotated reference installed by the package. |
| `/usr/bin/daer` | Daemon and inspection CLI. |
| `/usr/lib/daer/datapath.o` | eBPF datapath object. |
| `/var/lib/daer/rules/` | Operator-managed local `.drb` / `.rules` files. |
| `/var/cache/daer/rules/` | Disposable HTTP provider cache. |

A file provider reads only the path declared in its `[[rule-provider]]` entry. The daemon
does not scan `/var/lib/daer/rules` automatically. Relative paths resolve against
`/etc/daer/`; prefer absolute paths.

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
daer check --host -c /etc/daer/config.toml   # also verifies the sysctl prerequisites
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
INFO listening for redirected flows port=12345 namespace=Some("daer0ns") generation=gen1 …
INFO datapath attached: redirected flows will be proxied port=12345 namespace=daer0ns device=daer0 peer=daer0peer
```

The listener is created inside `daer0ns`, not the host. The namespace mount is private to the
daemon's mount namespace, so the host's `ip netns list` does not show it; use the
mount-namespace path in [Diagnostics](diagnostics.md). Both `ip link show daer0` and the
namespace disappear on a clean shutdown, and the mount dies with the process even after
`SIGKILL`.

If the last line is missing, nothing is proxied however healthy the rest looks. `daer run`
exits rather than serving when it cannot attach; `--no-datapath` is the explicit opt-in to
serving without it, and it says so at `WARN` because a daemon that forwards nothing is worse
than one that refuses to start.

`SIGHUP` reloads; `SIGTERM`/`SIGINT` stop accepting and give live flows up to ten seconds
by default to finish. The shipped unit passes `--shutdown-timeout 5`, because a service
restart should not wait on idle keep-alive connections; set it to `0` for an immediate stop.
Under systemd the daemon reports `RELOADING=1`/`READY=1` around a reload and `STOPPING=1`
before draining, so `systemctl status` shows the real lifecycle rather than `active` for a
proxy that has not finished starting. A reload that fails to build publishes nothing, so a
typo cannot stop a working proxy.

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

`daer run` applies that value in every place that creates a socket and logs it once:

```text
INFO listening for redirected flows port=12345 so_mark=Some(3566) namespace=Some("daer0ns") generation=gen1
```

* the generation's dialers (`SocketConfig::mark`, applied **before** `connect(2)`);
* the TCP and UDP transparent listener sockets, so accepted replies and datagrams are
  recognised as daer's own egress;
* the UDP reply sockets that bind an original destination, created inside `daer0ns`;
* health-check TCP, HTTP and UDP sockets, so probes are not captured as client flows;
* `PARAM.socket_mark`, which the datapath compares against `skb->mark`;
* the redirect exclusion is the datapath's own check — there is no firewall rule to write for
  it.

The ingress policy rule is keyed by `iif daer0peer`, not by the mark: the mark on listener
replies is what makes the host skip them, and a mark rule inside `daer0ns` would instead route
those replies to `lo`.

When the datapath is enabled, an absent `global.so-mark` uses the non-zero default `0x0dae`
because a mark of `0` is exactly the self-capture case. `--no-datapath` uses no mark: nothing
is redirected, so there is no loop to evade.

## The redirect and the policy routing

`daer run` installs everything the redirect needs. There is no firewall rule to write and no
`ip rule` to add by hand: the datapath redirects with `bpf_redirect` into the `daer0`/`daer0peer`
pair, and `daer` owns the state that makes that work.

The ingress half is not in the host namespace. `daer0peer`, both transparent listeners, the
policy table, and the peer's sysctls live in the private namespace `daer0ns`; `daer0` and the
host forwarding path stay in the host. A redirected packet crosses the namespace boundary on
its way to the listener, which is what makes `bpf_sk_assign` land in a socket the transport
stack accepts.

What it sets up, in order, before the first flow is served. Host-global forwarding and
martian values are prerequisites (see above), not entries in this table; the table lists what
the daemon installs in the namespace and on the devices it owns.

| State | Namespace | Why |
| --- | --- | --- |
| `daer0` / `daer0peer` veth pair, both up | host / ingress | the redirect target, and the path the listener is reachable through |
| `ip rule add iif daer0peer table 2023` (v4 and v6) | ingress | a packet arriving on the private peer is ours; keying by interface is what distinguishes a redirect from a marked listener reply |
| `ip route add local default dev lo table 2023` (v4 and v6) | ingress | the destination of that rule; a redirected packet has a **non-local** destination and must reach the local stack |
| `169.254.0.11/32` on `daer0peer`, a link route to `169.254.0.1`, a default route through it, and a permanent neighbor for `daer0`'s MAC | ingress | listener replies use the client's original destination as their source and need an output route back through the host |
| `net.ipv4.conf.daer0.rp_filter = 0` (host) and `net.ipv4.conf.daer0peer.rp_filter = 0` (ingress) | host and ingress | reverse-path filtering would drop a packet with a non-local source before `bpf_sk_assign` could deliver it; the host `all` value is a prerequisite |
| `net.ipv4.conf.daer0{peer,}.accept_local = 1` | host and ingress | a host-generated flow's source is a local address on `wlan0`; without this the kernel treats it as a martian source and drops it on `daer0peer` |
| `net.ipv4.conf.daer0{peer,}.arp_filter = 0` | host and ingress | the pair must not filter ARP by the source interface; the host `all` value is a prerequisite |
| `net.ipv4.conf.daer0.forwarding = 1` | host | the reply is forwarded from `daer0` to the client; `ip_forward` and `all.forwarding` are prerequisites |
| `net.ipv4.conf.daer0peer.forwarding = 1` | ingress | the namespace gateway role |
| TC classifiers on every `lan`/`wan` interface | host | see below |
| `daer0` ingress TC, `daer0peer` ingress TC | host / ingress | the return path and the assign hook live on opposite sides of the boundary |
| `listen_socket_map` entries `0` (tcp4), `1` (udp4), `2` (tcp6), `3` (udp6) | — | `assign_listener` looks the socket up by protocol and family; an empty slot is a flow the datapath has already taken off the direct path and then drops |

All of it is removed again when the daemon exits: the namespace guard deletes `daer0ns` (and
with it the peer and the host end of the pair), the per-device `daer0` knobs disappear with
the device, Aya detaches every TC filter, and the `clsact` qdisc is removed when daer created
it. A clean shutdown leaves no host table-2023 rule and no daer-owned kernel state. The
host-global prerequisites are never changed.

The namespace mount is private to the daemon, so a `SIGKILL` releases `daer0ns`, the pair, and
the ingress policy and sysctls with the process. Host-side state that is not namespace-owned
is covered by two backstops: the daemon writes an undo journal under `/run/daer` before it
creates a qdisc, and the unit's `ExecStopPost=daer-cleanup` replays it after a `SIGKILL`,
panic or stop timeout. A current (v2) journal removes host TC filters and qdiscs only; a
pre-v2 journal also restores host sysctls and a host namespace/pair from older releases. The
same recovery runs before a new daemon starts, so a crash cannot compound leftovers.

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
control plane without `CAP_BPF`/`CAP_PERFMON`, and `daer run` says so at `WARN`. The transparent listener
still needs `CAP_NET_ADMIN` for `IP_TRANSPARENT`; use `unshare -Urn` for an unprivileged test.
It is not a way to run a proxy with a firewall rule instead — the firewall `tproxy`
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
# Readiness comes from the daemon itself (`READY=1` via sd_notify), not from a successful
# `execve`. systemd therefore reports the unit started only after the configuration loaded,
# the private ingress exists, the listeners are bound and the datapath is attached — the
# state in which traffic is actually proxied.
Type=notify
NotifyAccess=main
# A wedged control plane is restarted instead of silently accepting traffic and proxying
# nothing. The daemon feeds this at half the interval, including while a reload is running.
WatchdogSec=30s
User=root

# Resource limits
LimitNPROC=4096
LimitNOFILE=1048576
LimitMEMLOCK=infinity
OOMScoreAdjust=-100

# There is deliberately no ExecStartPre=/usr/bin/daer check:
# `daer run` performs the identical load_resolved validation before it binds a socket or
# mutates kernel state, and Type=notify above makes systemd wait for that gate. Running
# `daer check` first repeated every subscription and rule-provider fetch on each start and
# restart, doubling startup network work without adding a check.
ExecStart=/usr/bin/daer run -c /etc/daer/config.toml --object /usr/lib/daer/datapath.o --shutdown-timeout 5
ExecReload=/usr/bin/kill -HUP $MAINPID
# The Rust guards are the primary cleanup path. This runs after them — and also after a
# SIGKILL, panic or stop timeout — replaying the daemon's recovery journal. A current (v2)
# journal removes the host TC filters and qdiscs only; the namespace and pair die with the
# daemon. A pre-v2 journal also runs the full legacy restore. It is a dedicated helper,
# not a hidden flag on `daer run`: the operator CLI stays the six verbs in ADR-0015, and
# systemd's post-stop hook is not one of them.
ExecStopPost=/usr/bin/daer-cleanup

# Restart policy. One second keeps a transient failure from turning into a five-second
# outage; StartLimit above still stops a genuine crash loop.
Restart=on-failure
RestartSec=1s

# Timeout configuration.
# Startup includes the daemon's bounded wait for a default route (120s), so systemd's clock
# must not expire first. Stopping drains live flows for at most the 5s passed above, then
# tears down the namespace and datapath; 15s leaves room for that without masking a hang.
TimeoutStartSec=180
TimeoutStopSec=15
# SIGTERM goes to the main process only; the final SIGKILL covers any helper child a stuck
# teardown left behind, without signalling the daemon twice.
KillMode=mixed
KillSignal=SIGTERM
SendSIGKILL=yes

# The capabilities the datapath, private ingress namespace, and privileged listeners
# (e.g. port 53) need. CAP_PERFMON is the verifier's allow_ptr_leaks gate: the fast parser
# advances a packet pointer by the IPv4 IHL and IPv6 extension-header lengths.
# CAP_SYS_ADMIN creates and enters the private daer0ns, unshares its mount namespace and
# mounts the private /run/netns tmpfs.
AmbientCapabilities=CAP_BPF CAP_NET_ADMIN CAP_PERFMON CAP_SYS_ADMIN CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_BPF CAP_NET_ADMIN CAP_PERFMON CAP_SYS_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ProtectControlGroups=true
# ProtectKernelTunables must remain false: daer needs to tune sysctls on its peer
# devices (/proc/sys/net/ipv4/conf/daer0peer and the ingress namespace) and pin eBPF
# maps to /sys/fs/bpf.
ProtectKernelTunables=false
LockPersonality=true
RestrictRealtime=true
PrivateTmp=true
# The listener and the device pair need the network, so `PrivateNetwork` is off.
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK

# Configuration directory and runtime state. `RuntimeDirectory` creates /run/daer and
# /run/netns; the latter is the mount target for the daemon's private tmpfs.
ConfigurationDirectory=daer
# `daer` holds its crash-recovery journal in /run/daer. The ingress namespace mounts a
# private tmpfs at /run/netns inside its own mount namespace, so the host directory is not
# modified; it still has to exist as the mount target.
RuntimeDirectory=daer netns
# `/run/netns` is shared with every other network namespace on the host. Do not let systemd
# remove the whole directory when daer stops: other applications' namespaces may be there,
# and the directory is the mount target.
RuntimeDirectoryPreserve=yes
# `/run/netns` stays writable for a legacy mount an older version may have left; the daemon's
# own namespace mount is private and never writes the host path.
ReadWritePaths=/etc/daer /sys/fs/bpf /run/netns

# Persistent, operator-managed rule sets live in /var/lib/daer/rules. StateDirectory
# creates /var/lib/daer and grants write access to it under ProtectSystem=strict; the
# `rules` child is created by the package or by the operator.
StateDirectory=daer
# Where downloaded rule sets are cached (ADR-0014). CacheDirectory=daer creates
# /var/cache/daer and grants write access to exactly it under ProtectSystem=strict.
# The loader defaults to /var/cache/daer/rules; DAER_RULE_CACHE_DIR overrides it.
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

The unit does **not** run `daer check` as an `ExecStartPre=`. `daer run` performs the same
`load_resolved` validation before it binds a socket or mutates kernel state, and `Type=notify`
makes systemd wait for the daemon's `READY=1`. A separate check would repeat every subscription
and rule-provider fetch on each start and restart, doubling the startup network work without
testing anything the daemon does not test itself. Keep `daer check` in deployment pipelines and
before a manual edit; it is still the command that answers "will this configuration run".

## Verifying the kernel datapath

Two scripts, two questions. They are separate because a failure in one must not be readable as
a failure in the other:

| Script | Question | Depends on |
| --- | --- | --- |
| `sudo ./scripts/verify/kernel-check.sh` | does the eBPF object load and behave? | `daer-ebpf` + `clang` |
| `sudo ./scripts/verify/e2e-check.sh` | does a redirected flow reach the daemon and come back? | `daer-control`, `daer-cli`, the relay, nftables |

Run the kernel one before `daer run` on a new machine:

```sh
sudo ./scripts/verify/kernel-check.sh
```

The steps that matter are 4 and 7:

```text
4. loading the object (this runs the verifier)
  ok   the object loaded and passed the verifier

7. the in-kernel datapath cases (BPF_PROG_TEST_RUN)
  ok   every in-kernel datapath case passed
```

Step 7 runs 58 self-checking BPF programs (`pktgen`/`setup`/`check` triples from
`ebpf/kern/tests/bpf_test.c`) through `BPF_PROG_TEST_RUN`. It is the only check in the
repository that executes the datapath's own routing, conntrack and redirect logic inside the
kernel, so a green step 4 with a skipped step 7 means the object loads and nothing more.

A failure there is almost always one of:

| Message names | Cause |
| --- | --- |
| `PermissionDenied` creating a map | no `CAP_BPF` — a "root" user namespace is not enough, `unprivileged_bpf_disabled` blocks it |
| a struct offset or a `bpf_*` helper | `vmlinux.h` came from a different kernel than the target |
| `InvalidProgramSection` | the object's section names are not ones `aya` parses. The loader does not rewrite them (ADR-0020): a section prefix that is not `classifier/`, `cgroup/`, `sk_skb/stream_verdict`, `fentry/` or `kprobe/` is a build failure — `cargo xtask abi --check` catches it from `ebpf/abi.toml`, and `cargo xtask ebpf` rebuilds |
| `nonzero insn_off N for the first func info record` | the program's own BTF `func_info` was dropped, so the first record belongs to a linked `.text` callee. See below |

### `nonzero insn_off ... for the first func info record`

This one is worth recognising on sight, because it reaches the kernel and comes back as a
bare `EINVAL` (os error 22) that reads like a verifier complaint about the *program* when it
is really a complaint about its *metadata*:

```text
cannot attach the datapath: eBPF program error: the BPF_PROG_LOAD syscall returned
Invalid argument (os error 22). Verifier output: nonzero insn_off 3 for the first func
info record
stack depth max 0
processed 0 insns (limit 1000000)
```

`processed 0 insns` is the tell: the verifier rejected the load before looking at a single
instruction, so no amount of inspecting the C is going to explain it. The kernel requires a
program's first `func_info` record to be at instruction 0 (`check_btf_func()` in
`kernel/bpf/check_btf.c`). `aya` builds that list by appending each linked `.text` callee's
records rebased to the instruction where the callee was placed; if the program's own record
is missing, the list starts at that callee's offset instead.

The program's own record goes missing when the ELF section names and the `.BTF` string table
disagree, which is what a loader that renames sections in only one of the two places
produces. `daer` no longer renames anything: the C source spells sections the way `aya`
parses them (ADR-0020), so the two can never disagree. `cargo test -p daer-ebpf` asserts the
invariant after reproducing `aya`'s call relocation, so this failure cannot ship again without
a red test.

Userspace tests cannot catch any of the *kernel-side* failures above, which is why this
script exists; this one they can, and it is cheaper than a reboot.

## Verifying it works

```sh
# 1. what does the daemon believe right now?
daer status

# 2. is the datapath attached?
journalctl -u daer -b | grep 'datapath attached'

# 3. is the policy what you think?
daer route example.com --why -c /etc/daer/config.toml

# 4. does a flow actually get proxied?
curl -sS -o /dev/null -w '%{http_code}\n' --interface eth0 https://example.com
journalctl -u daer -b | tail -20     # a `flow decided` line per connection at debug

# 5. does a reload keep flows alive?
systemctl reload daer
```

During an incident, `kill -USR1 "$(systemctl show -p MainPID --value daer)"` writes a
redacted bundle under `/var/lib/daer/incidents/`; `daer status --flow <ID>` prints the JSON
events for one connection.

`RUST_LOG=daer=debug` overrides `log-level` for a one-off investigation, which is what makes
[Diagnostics Guide](diagnostics.md) usable without editing the configuration.

## What is not implemented

Be aware before trusting it with traffic:

* **vmess, plain vless, tuic** are not implemented; a link naming one is listed but not
  selectable, and is never silently downgraded to `direct`.
* A REALITY node has **no datagram transport**, so a UDP flow routed to such a group is
  refused rather than silently sent direct. Silence there would be a leak: the client would
  believe UDP was tunnelled when it was not.
* **The event ring and counters are consumed.** `bpf_stats_map` and `event_ringbuf` are read
  by the daemon, surfaced by `daer status`, and retained in an incident bundle after
  `SIGUSR1`, a panic or an error burst. The ring is rate-limited per key; volume comes from
  the counters, never from the event count (ADR-0040).
* **`domain(...)` rules keep flows on the userspace path.** The kernel cannot evaluate a
  domain predicate without `domain_routing_map`, an IP-keyed bitmap the control plane would
  have to maintain from DNS answers; this build does not maintain it. Every flow is then
  handed to userspace, which is correct but costs a relay hop. The daemon says which tier it
  is in at startup — see [ADR-0005](../adr/0005-kernel-policy-encoding.md). The facts the kernel
  did observe (source MAC, DSCP, process name) **are** read back from
  `routing_handoff_map`, so `mac(...)`, `dscp(...)`, and `pname(...)` rules do match on that
  path.
* The **`tproxy` redirect of a datagram is not proven end to end** in the unprivileged
  workspace suite, and the reason is the test topology rather than the code: `TPROXY` matches
  on the ingress interface, so proving it needs the origin in a second network namespace,
  which a development sandbox cannot create. The privileged e2e gate runs the same test on a
  two-namespace host. What *is* proven in one namespace: the reply leaves from the original
  destination (not from the transparent port), one client port talking to two destinations
  gets two sessions, and the reply-socket cache evicts instead of leaking fds.
* **IPv6 dual-stack** is implemented for TCP and UDP, including the `udp6` listener slot and
  independent IPv4/IPv6 Fake-IP pools. IPv6-only operation still depends on the host having
  IPv6 forwarding and a default route; the daemon configures both best-effort and reports a
  missing IPv6 ingress path at `WARN` without taking IPv4 down.
