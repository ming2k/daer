# Testing the kernel datapath on your machine

Two things cannot be verified from a development sandbox with `unprivileged_bpf_disabled=2` and
no `CAP_NET_ADMIN`:

1. that the datapath object **loads and passes the verifier** on the target kernel;
2. that the full path works — a packet redirected by the datapath reaching the listener, being
   decided, and coming back.

`scripts/verify/kernel-check.sh` covers (1) and the attach mechanics. (2) is what the steps
below do on a real box. Everything that *can* be verified without privilege is, and is written
to fail when it is wrong: the kernel policy table against the userspace evaluator
(`tests/integration/routing_kernel_policy.rs`), the ABI against the compiled object, and the
transparent path with a real `nftables tproxy` rule plus a negative control
(`tests/e2e/control_transparent.rs`, [ADR-0007](../adr/0007-verification.md)).

## Step 0 — build on the target machine

The object embeds nothing kernel-specific, but `vmlinux.h` does, so build it **on the machine
that will run it**:

```sh
cd /path/to/daer

# vmlinux.h from the running kernel
bpftool btf dump file /sys/kernel/btf/vmlinux format c > ebpf/kern/headers/vmlinux.h

cargo xtask ebpf       # -> target/ebpf/datapath.bpf.o
cargo build --release  # -> target/release/daer

# the userspace must be green before the kernel side is worth testing
cargo nextest run --workspace -E 'kind(lib) + kind(bin)' && cargo nextest run --workspace -E 'binary(integration)' && cargo test --workspace --doc
```

Needs `clang`, `bpftool`, `ip`, and `go` (only for the optional `docs/how-to/vision-lab.md` lab).

## Step 1 — does the object load?

```sh
./scripts/verify/kernel-check.sh          # it re-execs itself under sudo
```

Run it **without** `sudo`: `cargo` and `rustup` usually live in your home, and `sudo cargo`
does not find them. The script builds the test binaries as you and puts `sudo` only around
the binaries, which is the split that works. Logs go to `~/daer-kernel-check/` (or
`$DAER_LOG_DIR`), never to a `/tmp` file that may be owned by someone else.

Expected:

```text
3. loading the object into the kernel (this runs the verifier)
  ok  the object loaded and passed the verifier
       loaded 22 maps
       loaded 16 programs
4. attaching a TCX link to a real interface
  ok  a TCX program attached to lo
5a. attaching the pname cgroup hooks
  ok  the six pname cgroup hooks attached to cgroup v2
```

**Send me this output either way.** If step 3 fails, the log at
`~/daer-kernel-check/load.log` (or `$DAER_LOG_DIR/load.log`) names the map or the struct
offset and that tells me exactly what to change. This is the
first time this object will meet a real verifier, so a failure here is expected information,
not a surprise.

## Step 2 — a config that proxies to your REALITY node

Save as `/tmp/daer-test.toml`. Replace `wan-interface` with your outbound interface
(`ip route show default` names it) and `lan-interface` with the one clients use.

```toml
schema = 5

wan-interface = ["eth0"]        # <-- yours
lan-interface = ["eth1"]        # <-- yours, the network you proxy *from*
log-level = "debug"

[[node]]
name = "edge"
type = "vless"
server = "<host>"
port = 443
uuid = "<uuid>"
# A node whose user is configured for Vision *refuses* a client that omits the flow, so
# set this whenever the node expects it.
flow = "xtls-rprx-vision"

# `pbk`, `sid` and the clock all have to match the node, and a mismatch makes the node
# *forward* the flow to the impersonated site rather than refuse it — see the note in
# tests/e2e/protocols_reality_live.rs.
[node.security]
type = "reality"
sni = "<sni>"
public-key = "<pbk>"
short-id = "<sid>"

[node.transport]
type = "tcp"

[[group]]
name = "proxy-pool"

[[election]]
name = "proxy"
group = "proxy-pool"
type = "min-moving-avg"

[routing]
# `dip(...)` is representable in the kernel; `pname(...)` and `domain(...)` are not,
# so this pair is what decides the tier. Both are correct, and the startup log says
# which one you got.
fallback = { election = "proxy" }

[routing.sniff]
enabled = true
timeout = "30ms"

[[routing.rule]]
name = "private"
match = "rule-set(private)"
action = "direct"
```

Check it compiles before starting — `daer route` uses the same generation the data path
does:

```sh
./target/release/daer check -c /tmp/daer-test.toml
./target/release/daer route 10.0.0.2:1234 1.1.1.1:443 --domain example.com --why \
    -c /tmp/daer-test.toml
```

The second command must say `outbound: proxy (mark 33262)`. If it says
`undeliverable, election "proxy" has no electable node`, the node did not become selectable
(the REALITY link parses fine — that is tested — so it would be the group's filter).

## Step 3 — run it

```sh
sudo ./target/release/daer run -c /tmp/daer-test.toml 2>&1 | tee /tmp/daer-run.log
```

Four lines must appear, and the fourth is the one that decides whether traffic is proxied:

```text
INFO interfaces resolved lan=["eth1"] wan=["eth0"]
INFO configuration loaded generation=gen1 rules=2 groups=1 nodes=1 build_ms=2
INFO listening for redirected flows port=12345 so_mark=Some(1684104562) namespace=Some("daer0ns") generation=gen1 …
INFO datapath attached: redirected flows will be proxied port=12345 namespace=daer0ns device=daer0 peer=daer0peer
```

If the fourth line is missing the daemon exits rather than serving — send the error.

Immediately after it comes the policy tier, which says *where* a flow is decided:

```text
INFO datapath policy published: the kernel decides every flow itself
```

or

```text
WARN datapath policy published as a deferral: every flow is handed to the control plane, …
     reasons=["rule 3 uses domain(...) and domain_routing_map is not maintained by this build"]
```

Both proxy traffic. The second costs one userspace relay hop per flow, and it is what a
configuration with `domain(...)` rules gets today. The reason string names the rule, so the fix
is visible: either drop the domain predicate (if the address is enough) or accept the slower
tier.

`daer route <src> <dst>` answers the same question offline, from the *same* generation
the daemon serves — the two share one loader (ADR-0006), so they cannot disagree about the node
pool or the rules.

## Step 4 — redirect traffic into it

In a second terminal. `$WAN` is your outbound interface; `$LAN` the client one.

```sh
WAN=eth0; LAN=eth1; PORT=12345

sudo nft add table ip daer
sudo nft add chain ip daer prerouting '{ type filter hook prerouting priority mangle; }'
# 1. daer's own traffic must not be captured again, or it loops into itself
sudo nft add rule ip daer prerouting meta mark 0x64616572 return
# 2. local destinations stay local
sudo nft add rule ip daer prerouting fib daddr type local return
# 3. everything else arriving from the LAN is proxied
sudo nft add rule ip daer prerouting iif $LAN tcp tproxy to :$PORT

# and the reply path
sudo nft add table ip daer-reply
sudo nft add chain ip daer-reply prerouting '{ type filter hook prerouting priority mangle; }'
sudo nft add rule ip daer-reply prerouting fib daddr type local meta mark set 0x64616572 accept
```

Rollback:

```sh
sudo nft delete table ip daer
sudo nft delete table ip daer-reply
```

## Step 5 — prove it proxies

From a machine on the LAN interface, or from the box itself with `--interface $LAN`:

```sh
# what egress IP does the other side see? Should be the node's, not the box's.
curl -sS --interface $LAN https://api.ipify.org; echo
curl -sS --interface $LAN -o /dev/null -w '%{http_code} %{time_total}s\n' https://example.com

# and the log should show a decision per connection
grep 'flow decided' /tmp/daer-run.log | tail -5
```

Expected in the log:

```text
DEBUG daer_control::decide: flow decided generation=gen1 source=10.0.0.2:51234 \
      destination=93.184.216.34:443 rule="rule N" outbound=proxy node=Germany
```

`outbound=direct` where you expected `proxy` means the rule matched something you did not
intend — `daer route --why` with the same source/destination answers which predicate did.

## Step 6 — does a reload keep connections alive?

```sh
# long-lived download in one terminal
curl -sS --interface $LAN -o /dev/null https://speed.cloudflare.com/__down?bytes=200000000 &

sudo pkill -HUP -f 'daer run'
grep -E 'reloaded|reload rejected' /tmp/daer-run.log | tail -2
```

The download must keep running. A `reload rejected` line means the new configuration did not
compile and the old one is still serving — which is the intended behaviour.

## What to send me

Any of these, whichever is the first thing that does not match:

| Symptom | Send |
| --- | --- |
| step 1 fails | the whole `kernel-check.sh` output + `~/daer-kernel-check/load.log` |
| step 3 exits | `/tmp/daer-run.log` |
| step 5 times out | `/tmp/daer-run.log` with `log-level = "debug"`, plus `nft list ruleset` |
| step 5 reaches the wrong egress IP | `daer route --why` for the same flow, plus the log |

## What is expected to be broken already

Not bugs to chase — known gaps, so a test does not get spent on them:

* **UDP datagrams are proven through `tproxy` only by the privileged two-namespace tests.**
  `tests/e2e/control_transparent_udp4.rs` and `tests/e2e/control_transparent_udp6.rs` build real client/origin
  namespaces; a single-namespace fixture is invalid because `TPROXY` matches on the ingress
  interface. The unprivileged workspace suite still skips the UDP end-to-end cases, so use
  `scripts/verify/e2e-check.sh` (or the CI `3-udp4`/`3-udp6` gates) before claiming UDP coverage.
* **vmess / plain vless / anytls / hysteria2 / tuic** are not implemented. Only
  `vless + REALITY + Vision`, `trojan`, `shadowsocks` and `socks5`/`http` dial.
* **A `domain(...)` or `pname(...)` rule puts every flow on the userspace path.** The kernel
  table is published either as a faithful translation or as a one-entry deferral (ADR-0005).
  `domain(...)` needs the DNS-derived `domain_routing_map`; `pname(...)` has its cgroup v2
  map and hooks, but the kernel policy still defers it to the userspace evaluator. The
  startup log names the rule that forced it. Traffic is still correct; the fast path is what
  you lose.

  Verified for you: the tier decision, the entry count, the LPM tries and the outbound
  connectivity entries are all published, and `tests/integration/routing_kernel_policy.rs`
  cross-checks the encoded table against the userspace evaluator flow by flow.

  So: the datapath attaches, the redirect mechanics work, and the kernel-side *policy* is
  empty. A warning says exactly that at startup rather than leaving it to be discovered.

