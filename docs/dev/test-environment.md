# Test Environment Requirements

This is the clean-host procedure referenced by the [Production Readiness](production-readiness.md)
release gate.

`daer` changes host networking and attaches to the host's TC hooks. A test host that still has
another proxy, an old `dae` installation, or unrelated eBPF programs is not a clean test: a
failure may belong to the other tool, or the other tool may silently win before `daer` sees the
packet.

Use a **disposable VM or a host with a snapshot**, never a production machine, for the delivery
check. The check stops `daer`, changes host sysctls, owns `daer0`/`daer0ns`, installs temporary
test state, and restores what it can on exit.

## 1. Required host

| Requirement | Check |
| :--- | :--- |
| Linux 6.6+ with TCX | `uname -r` |
| BTF available | `test -f /sys/kernel/btf/vmlinux` |
| Root or the documented capabilities | `id`; `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_PERFMON`, `CAP_SYS_ADMIN` |
| cgroup v2 unified hierarchy | `test -f /sys/fs/cgroup/cgroup.controllers`; the six `pname` hooks attach there |
| A default route on a real WAN interface | `ip route show default` |
| `ip`, `nft`, `bpftool`, `curl`, `tcpdump`, `nsenter`, `sysctl`, `python3` | `command -v ...` |
| A built release binary and object | `target/release/daer`, `target/ebpf/datapath.bpf.o` |
| A site config outside git | `target/daer-us101-e2e.toml` or another ignored path |

For the site config, keep credentials out of the repository:

```bash
chmod 600 target/daer-us101-e2e.toml
```

Do not paste the config into an issue, a commit, or a shell command that is captured in shell
history.

## 2. Clean-host checklist

Run these before the delivery check. They are inspection commands; do not delete another
operator's rules without knowing what they are.

```bash
# Kernel and BTF
uname -r
test -f /sys/kernel/btf/vmlinux && echo BTF=ok

# Services that may own the proxy path
systemctl is-active dae daer clash mihomo sing-box v2ray xray 2>/dev/null || true
systemctl list-unit-files | grep -E '^dae\.' || true
ls -la /etc/dae 2>/dev/null || true

# Interfaces, TUN devices and default route
ip -d link show
ip route show default
ip rule show
ip route show table all | grep -E '2023|dae|daer' || true

# Namespaces and daer devices
ip netns list
ip link show daer0 2>/dev/null || true
ip link show dae0 2>/dev/null || true

# Kernel redirect, NAT and mark rules
sudo nft list ruleset
sudo iptables-save 2>/dev/null || true
sudo ip6tables-save 2>/dev/null || true

# Ports that daer or a resolver may need
ss -lntup | grep -E ':(53|12345)\b' || true

# eBPF attachment and cgroup hooks
test -f /sys/fs/cgroup/cgroup.controllers && echo cgroup-v2=ok
sudo bpftool net
sudo bpftool link show
sudo bpftool cgroup tree
sudo tc qdisc show
sudo tc filter show dev <wan-interface> ingress
sudo tc filter show dev <wan-interface> egress

# Host prerequisites daer checks
sysctl net.ipv4.ip_forward net.ipv4.conf.all.forwarding \
       net.ipv4.conf.all.rp_filter net.ipv4.conf.all.arp_filter
sysctl net.ipv6.conf.all.forwarding 2>/dev/null || true
```

A clean host for the delivery check should normally show:

- no `daer`, `dae` or other proxy service active;
- no `tun`/`utun`/proxy-owned default route;
- no `daer0` or old `dae0` link;
- no unrelated `2023` policy table on the host;
- no TC/XDP program on the target LAN/WAN interfaces, or a deliberately documented order;
- no other listener on the daer tproxy port;
- the host sysctls above set to the values `daer check --host` requires.

## 3. Removing an old `dae` installation

The project no longer ships a `dae` removal helper. If the test host has an old `dae` service,
stop and remove its state explicitly before testing `daer`.

### 3.1 Audit the old installation

Do not delete anything until you know which rules belong to the old `dae`; a shared host may
also have legitimate operator rules.

```bash
# Service and configuration
systemctl list-unit-files | grep -E '^dae\.' || true
systemctl status dae 2>/dev/null || true
ls -la /etc/dae 2>/dev/null || true

# Old devices and namespace
ip -d link show dae0 2>/dev/null || true
ip netns list | grep -E 'daens|dae0' || true

# Old host policy routing (daer keeps table 2023 inside daer0ns, not on the host)
ip -4 rule show
ip -6 rule show
ip -4 route show table 2023 2>/dev/null || true
ip -6 route show table 2023 2>/dev/null || true

# Old mark, TPROXY, DNS and port rules
sudo nft -a list ruleset | grep -Ei 'dae|0x0dae|table 2023|:12345|:53' || true
sudo iptables-save 2>/dev/null | grep -Ei 'dae|0x0dae|2023|12345|53' || true
sudo ip6tables-save 2>/dev/null | grep -Ei 'dae|0x0dae|2023|12345|53' || true

# Old eBPF objects, links and filters
sudo bpftool prog show | grep -i dae || true
sudo bpftool map show | grep -i dae || true
sudo bpftool link show
sudo tc qdisc show
sudo tc filter show dev <wan-interface> ingress
sudo tc filter show dev <wan-interface> egress

# A dae DNS listener or transparent port
ss -lntup | grep -E ':(53|12345)\b' || true
```

The old installation may have left any of:

- a `dae` systemd service or a running daemon;
- `/etc/dae` configuration and cached rules;
- a `dae0`/`dae0peer` veth pair;
- a `daens` network namespace;
- host table `2023` rules or routes;
- nftables/iptables rules using `0x0dae` or a TPROXY/REDIRECT target;
- a `dae` DNS listener on port 53, or a transparent listener on 12345;
- TC qdisc/filters or pinned eBPF maps/programs.

### 3.2 Stop and remove

```bash
# Back up first if the old configuration matters.
sudo systemctl disable --now dae 2>/dev/null || true
sudo systemctl reset-failed dae 2>/dev/null || true

# Remove the old links and namespace if they remain.
sudo ip link del dae0 2>/dev/null || true
sudo ip netns del daens 2>/dev/null || true
```

For rules, remove only what the audit identified. Do **not** run `nft flush ruleset`,
`iptables -F`, or `ip route flush table all` on a shared host.

```bash
# Show rules with handles; delete the old dae rule by handle.
sudo nft -a list ruleset
sudo nft delete rule <family> <table> <chain> handle <handle>

# Or delete the exact iptables rule you identified.
sudo iptables -D <chain> <rule-specification>

# Only when table 2023 is confirmed to be the old dae table:
sudo ip -4 rule show
sudo ip -4 rule del <the-old-dae-rule>
sudo ip -4 route flush table 2023
sudo ip -6 rule show
sudo ip -6 rule del <the-old-dae-rule>
sudo ip -6 route flush table 2023
```

If you cannot identify a filter or a pinned map with confidence, do not guess. Rebuild the test
host from a clean snapshot; a stale filter or mark rule is exactly the kind of state that makes
the delivery check prove the wrong thing.

`daer` does not adopt or repair pre-TCX state. A stale host qdisc/filter or old dae rule is
outside the supported upgrade path; remove it explicitly, or use a fresh test host.

The socket mark is internal: `0x64616572` (ASCII `daer`). It is not a configuration key, so a
test host must not carry a firewall/rule that matches a site-chosen mark; the datapath compares
the internal value itself.

### 3.3 Acceptance

The old `dae` is gone only when these are true:

```bash
systemctl is-active dae              # must not print "active"
ip link show dae0                    # must fail
ip netns list | grep daens           # must be empty
ip -4 rule show | grep 2023          # must be empty on the host
ip -6 rule show | grep 2023          # must be empty on the host
sudo nft list ruleset | grep -Ei '0x0dae|dae'  # must be empty
sudo iptables-save | grep -Ei '0x0dae|dae'      # must be empty
ss -lntup | grep -E ':(53|12345)\b'            # must not name dae
```

Then rerun the clean-host checklist in section 2 and the delivery preflight.

## 4. Removing another proxy

Stop and disable services such as Clash/Mihomo, sing-box, v2ray/xray, Trojan clients, SSH
tunnels, Tailscale/WireGuard TUN devices, and any local SOCKS/HTTP proxy. Then check for:

- a TUN device carrying the default route;
- `ip rule` entries or a table that redirects traffic into the proxy;
- `nft`/`iptables` `REDIRECT`, `TPROXY`, `TUN` or `meta mark` rules;
- a listener on `53`, `12345`, or the proxy's own transparent port;
- a local DNS resolver (`systemd-resolved`, `dnsmasq`) on port 53.

Do not assume that stopping the service removed its rules. Verify with the commands in section 2
after the service is stopped. Keep a backup of the host's rules and routes before changing them.

## 5. Other eBPF programs

Other eBPF programs can change the result even when `daer` is correctly configured.

### TC and TCX

`daer` attaches only TCX links. Other TCX programs on the same interface/hook form a kernel
chain. The order matters:

- a program before `daer` that returns `TCX_PASS` or `TCX_DROP` can prevent `daer` from seeing
  the packet;
- `daer` returns `TCX_PASS` for terminal acceptance and `TCX_NEXT` for pass-through in the paths
  that use `DAER_TC_CONTINUE`;
- a program after `daer` may never run for a packet that `daer` terminates.

`bpftool net` and `bpftool link show` show what is attached. For a clean delivery test, detach
unrelated TC/XDP programs from the target interfaces or use a clean VM. Do not delete unknown
programs on a shared host.

Classic `cls_bpf` filters and TCX links can coexist, but the kernel evaluates TCX and classic TC
in one logical pipeline with ordering rules that depend on the kernel and the return values.
That coexistence is not a tested production mode for `daer`.

### XDP

XDP runs before TC. An XDP program that drops or redirects the packet means `daer` never sees it.
A clean test host should have no unrelated XDP program on the LAN/WAN interfaces.

### cgroup hooks

cgroup `connect`, `sendmsg`, `sock_create` and socket-lookup programs can rewrite a destination
or choose a socket before `daer` is involved. They are not shown by `bpftool net`; inspect them
with:

```bash
sudo bpftool cgroup tree
sudo bpftool prog show | grep -E 'cgroup|sk_lookup|sk_msg'
```

### Netfilter and nftables

`daer` does not install host nftables/iptables redirect rules. The e2e fixture and some operators
do. A host rule that redirects, drops or marks traffic before `daer`'s TC hook can make the
delivery check fail for reasons unrelated to the datapath. Keep the production firewall rules
and the test fixture rules separate.

## 6. Run the test

```bash
# Non-root checks: kernel, tools, artifacts, config, object.
scripts/ops/daer-delivery-check.sh \
  --config target/daer-us101-e2e.toml \
  --preflight

# Real delivery + SIGKILL lifecycle check.
sudo scripts/ops/daer-delivery-check.sh \
  --config target/daer-us101-e2e.toml
```

Required output includes:

```text
TCX delivery: the redirected flow reached the daemon and returned 200
SIGKILL: no TCX links, no qdisc, no veth, no daer-owned sysctls; direct traffic works
```

If either line is missing, the environment is not ready or the build is not a production
candidate. Restore the VM snapshot before the next run so a failed run cannot leave stale state
behind.

## 7. Containers and Kubernetes

A normal container is not a suitable delivery-test host:

- it needs the host network namespace and `/sys` view for the WAN interfaces;
- it needs the four capabilities above plus a seccomp policy that permits `bpf()`;
- it needs to create a private network/mount namespace;
- running it inside a Cilium/Calico/Kubernetes node adds unrelated TC, XDP and cgroup programs
  to the path.

Use a privileged disposable VM, not a production Kubernetes node, for the delivery gate.
