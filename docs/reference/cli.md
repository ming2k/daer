# Command Line Interface (CLI) Reference

The `daer` CLI provides the runtime daemon, deployment gates, live inspection, and diagnostics
for the transparent proxy. Build-time rule producers live in the companion tool
[`daer-drb`](#4-drb-producer-tooling-daer-drb).

---

## 1. Top-Level Options

```bash
daer [OPTIONS] <COMMAND>
```

| Option | Description |
| :--- | :--- |
| `-h`, `--help` | Print help information. |
| `-V`, `--version` | Print version information. |

---

## 2. Subcommands

### 2.1 `run` — run the daemon

Runs the transparent proxy: eBPF datapath, transparent ingress (the local capture/entry side),
TCP/UDP relay, and the DNS resolver when `dns.bind` or `[dns.fake-ip]` asks for one.

```bash
daer run [OPTIONS]
```

| Option | Default | Description |
| :--- | :--- | :--- |
| `-c`, `--config <PATH>` | `/etc/daer/config.toml` | Path to the configuration file. |
| `--object <PATH>` | `target/ebpf/datapath.bpf.o` | Compiled eBPF datapath object. |
| `--no-datapath` | `false` | Serve without attaching the kernel program; removes the `CAP_BPF`/`CAP_PERFMON`/`CAP_SYS_ADMIN` requirements, but the transparent listener still needs `CAP_NET_ADMIN`. No traffic is redirected, so nothing is proxied. |
| `--dry-run` | `false` | Report what the daemon would do and **change nothing**: no port bind, no device pair, no private ingress namespace, no sysctl, no policy route, no `bpf()`. Needs no capability. |
| `--shutdown-timeout <SECONDS>` | `10` | Maximum grace period for live flows after `SIGTERM`/`SIGINT`; the listener stops accepting immediately. `0` exits without draining. The shipped systemd unit passes `5`. |

Reloads on `SIGHUP`, and refreshes `[[rule-set]]` entries on their configured `interval`.
Under systemd it reports readiness (`READY=1`), reload (`RELOADING=1`) and shutdown (`STOPPING=1`)
through `sd_notify`, so `Type=notify` units wait for the datapath to be attached before marking
the service started.

### 2.2 `check` — will this configuration run

The single pre-bind gate. It performs every step `daer run` performs before it binds a socket:
check the Linux 6.6+ TCX baseline, resolve subscriptions and rule providers, compile and lower
every rule, build every group, verify every node this build can speak, verify every DNS
upstream, and parse `dns.bind`.

With `--object` it also validates the compiled datapath object against the ABI — names,
sections, and the BTF `func_info` invariant the kernel enforces — without loading it, so the
check needs no capability and can gate a packaged artifact (ADR-0029).

With `--host` it also checks the host-specific prerequisites: the Linux 6.6+ TCX baseline,
the cgroup v2 hierarchy the `pname` hooks attach to, and the host-global sysctls (forwarding
on, `rp_filter`/`arp_filter` relaxed). It reads `uname` and `/proc`; it still needs no
capability and changes nothing. A deployment gate should
pass this flag so a host that would refuse to start is caught before the service is restarted.
Without it, `daer check` remains usable as an object/config gate on a build machine whose
kernel does not match the target.

```bash
daer check [OPTIONS]
```

| Option | Description |
| :--- | :--- |
| `-c`, `--config <PATH>` | Path to the configuration file. |
| `--nodes` | Also print every node in every group with its protocol and security identity. |
| `--object <PATH>` | Also validate the compiled datapath object. Pass `--object none` to skip it. |
| `--host` | Also check the kernel, cgroup v2, and host-global sysctl prerequisites. |

`--host` adds the kernel and sysctl prerequisites to the check. Exit status is the contract:
`0` when the configuration and every requested check would run, non-zero otherwise. That is
what a deployment gate or a systemd `ExecStartPre=` should call with `--host`.

### 2.3 `route` — resolve routing decisions offline

Evaluates how the routing engine would decide a flow, domain, or IP without sending actual traffic.

```bash
# Resolve single domain (port defaults to 443)
daer route bilibili.com

# Resolve single IP
daer route 1.1.1.1

# Resolve with custom port and detailed rule trace
daer route google.com:8443 --why

# Resolve classic 4-tuple flow with a supplied domain
daer route 192.168.1.10:41234 93.184.216.34:443 --domain example.com
```

| Argument / Option | Description |
| :--- | :--- |
| `<TARGET>` | Target domain, IP, or IP:port (or source address when 2 arguments are provided). |
| `[DESTINATION]` | Destination address (`ip:port` or `ip`) when target is used as source. |
| `--source <IP:PORT>` | Client source address (defaults to `127.0.0.1:12345`). |
| `-c`, `--config <PATH>` | Path to configuration file. |
| `--domain <NAME>` | The domain fact a `domain(...)` rule would see (auto-inferred if the target is a domain). |
| `--why` | Print every rule and predicate evaluation trace, including shadowed rules. |

Exit status: `0` when the flow has a usable outbound, non-zero when it would be dropped
(`block`, a missing group, or an empty group).

### 2.4 `probe` — active online network diagnostics

Performs active network probing across layers (L3 DNS, L4 TCP handshake, L7 proxy protocol handshake, and end-to-end HTTP access). A node is only reported operational when **real traffic** passed through it: the probe writes a request into the established tunnel and reads the destination's reply.

```bash
# 1. Probe a specific node declared in the configuration
daer probe node hk-01

# 2. Probe a node link directly, with no configuration file at all
daer probe node 'vless://uuid@203.0.113.7:443?security=reality&sni=…&pbk=…&sid=…&flow=xtls-rprx-vision#hk-01'

# 3. Shorthand: the link as the verb's argument
daer probe 'vless://uuid@203.0.113.7:443?security=reality&…#hk-01'

# 4. Every node in the configuration
daer probe node --all

# 5. Every node in a subscription file (plain links, base64, or SIP008 JSON)
daer probe node --file ~/sub.txt

# 6. Custom timeout and end-to-end URL
daer probe node us-02 --timeout 10 --url https://www.google.com/generate_204

# 7. Probe an HTTP endpoint directly, or through a node
daer probe url https://www.google.com --node hk-01
```

`NODE` is one of three things, resolved in this order: a `scheme://` **link** (parsed with no configuration file), an empty value (lists the configuration's nodes and exits), or a **name/label** looked up in `--config`.

`--file` decodes the body with the same `daer_outbound::subscription::decode` the daemon uses at load time ([INV-LOADER-01](../adr/0006-wiring-ownership.md)), so a list that probes clean here is the list the runtime would build. A line the format rejects is reported, never silently dropped. The command exits non-zero when any node fails, and prints `N/M node(s) operational`.

The `--file` and `--all` forms stop at the first failure only in the sense that the summary line reports it: every node is probed first, so one dead node does not hide the state of the rest.

Phased diagnostic reporting:
- **L3 DNS Resolution**: Resolves node server hostname to IP.
- **L4 TCP Connect**: Tests if server IP:Port is reachable (detects firewall/GFW SYN drops).
- **L7 Protocol Handshake**: Connects through `NodeDialer` (VLESS/SS/Trojan/etc.) to verify UUID, password, TLS SNI, or REALITY keys. A REALITY node that cannot authenticate this client **forwards** the flow to the impersonated site; `reality/verify.rs` turns that silent redirection into the explicit failure `the peer is not the REALITY node`.
- **End-to-End Probe**: Sends a real HTTP(S) request through the proxy tunnel and reads the reply. For an `https://` URL the TLS handshake happens *inside* the tunnel, which is what a TLS probe means.

A single probe is subject to the usual loss on a long-haul link; `--timeout` interacts with that (the default 5 s is tight for a node at 200 ms RTT on a lossy path), and a handshake reset is retried once before being reported. That is a property of the path being measured, not of `daer`: `xray` against the same node shows the same distribution.

### 2.5 `status` — read-only runtime inspector

Answers "what does the running daemon believe right now" without a packet capture or a debug
log level. It reads `/run/daer/control.sock`; when the daemon is gone it falls back to the last
`/run/daer/state.json` and prints that the answer is a file, not a live process.

```bash
daer status                 # human summary
daer status --json          # versioned snapshot for automation
daer status --bundle DIR    # redacted incident bundle
daer status --flow ID       # every JSON event for one flow/session
daer status --nodes         # live node resources
daer status --groups        # live resource pools
daer status --elections     # live elections and current results
```

The snapshot contains the current and previous generation, policy hash, datapath attachment,
live flow and datagram counters, DNS counters, health state, and the userspace mirror of the
17 `bpf_stats_map` counters. The focused views (`--nodes`, `--groups`, `--elections`) query
the admin socket and are read-only; they do not actively probe. `--nodes` reports each
resource's pool, protocol and cached health when an election currently elects it;
`--elections` reports the election's input, rule, pinned/effective node and cached health.
It cannot start, stop or reload the daemon. A missing socket and state file is a named error,
not a panic (ADR-0041).

### 2.6 `elect` — pin an election at runtime

Changes which node an election returns for new flows. Routing rules are unchanged; existing
flows keep the node they started on. The election definition in the configuration is not
rewritten, and `--reset` returns it to the configured rule.

```bash
daer elect proxy hk-01      # pin election `proxy` to candidate `hk-01`
daer elect proxy --reset    # follow the configured election again
daer elect proxy hk-01 --json
```

The command talks to `/run/daer/admin.sock`. By default that socket is `0600 root:root`, so
`daer elect` is root-only. Non-root delegation is opt-in: set `DAER_ADMIN_GROUP` in the
daemon's environment and give the daemon that supplementary group; the socket then becomes
`0660 root:<group>` and group members can run `daer elect` and the live status views without
root. The CLI itself needs no root and no file capability. The daemon persists the override
to `/var/lib/daer/elections.json` before applying it. Unknown elections, nodes that are not
candidates, and write failures are errors, not silent no-ops.
`status --nodes/--groups/--elections` use the same socket. `daer route` remains offline and
evaluates the configured election, not a runtime override; use `daer status --elections` for
the live result.

### 2.7 `schema` — JSON Schema for editors

Prints the JSON Schema of a configuration file to stdout. Point an editor at it
(`#:schema ./daer.schema.json`) or validate a file in CI.

```bash
daer schema
```

### 2.8 `version` — build information

```bash
daer version
```

---

## 3. What is deliberately not in `daer`

| Not in `daer` | Use instead |
| :--- | :--- |
| Compiling rules to `.drb`, decompiling, inspecting or unit-testing `.drb` | Companion tool [`daer-drb`](#4-drb-producer-tooling-daer-drb); unpack legacy `.dat` with `scripts/rules/dat_to_rules.py`. |
| Converting a `vless://` / `ss://` link into a `[[node]]` table | Any subscription converter, or declare a `[[subscription]]`: `daer` parses links at runtime. |
| Running a standalone DNS server | `daer run` serves DNS; `daer check` reports unusable upstreams. |
| Formatting a configuration | An editor plus `daer.example.toml`. |
| `node` / `group` / `election` subcommand trees | `daer status --nodes/--groups/--elections` for inventory and `daer elect` for the one runtime mutation. |

---

## 4. DRB Producer Tooling: `daer-drb`

`daer-drb` is the DRB producer: it compiles Canonical Rule Source (`.rules`) into DRB v2
(`.drb`), decompiles an artifact back to that text, inspects it, and tests a target against it.
Under ADR-0036, rule syntax is symbolic (`=domain` for exact match, `domain` for suffix, `.domain` for subdomains only).
It links no Protobuf reader and no `.dat` converter (ADR-0031).

```bash
# Compile plain-text rules to .drb
daer-drb compile company-direct.rules -o company-direct.drb

# Inspect metadata and counts of a .drb file
daer-drb inspect company-direct.drb

# Decompile an artifact back to reviewable rules (recompiling reproduces identical bytes)
daer-drb decompile geosite-cn.drb -o cn.rules

# Unit-test whether a domain or IP matches a .drb file
daer-drb test geosite-cn.drb bilibili.com
daer-drb test geoip-cn.drb 1.2.3.4
```
