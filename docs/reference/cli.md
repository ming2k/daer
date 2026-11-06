# Command Line Interface (CLI) Reference

The `daer` CLI provides the runtime daemon, deployment gates, and diagnostics for the
transparent proxy. Build-time producers and converter toolchains live in the companion tool [`daer-drb`](#4-drb-producer-tooling-daer-drb).

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

Runs the transparent proxy: eBPF datapath, transparent ingress, TCP/UDP relay, and the DNS
resolver when `dns.bind` or `[dns.fake-ip]` asks for one.

```bash
daer run [OPTIONS]
```

| Option | Default | Description |
| :--- | :--- | :--- |
| `-c`, `--config <PATH>` | `/etc/daer/config.toml` | Path to the configuration file. |
| `--object <PATH>` | `target/ebpf/datapath.o` | Compiled eBPF datapath object. |
| `--no-datapath` | `false` | Serve without attaching the kernel program, for unprivileged development and testing. No traffic is redirected, so nothing is proxied. |
| `--dry-run` | `false` | Report what the daemon would do and **change nothing**: no port bind, no device pair, no sysctl, no policy route, no `bpf()`. Needs no capability. |

Reloads on `SIGHUP`, and refreshes `[[rule-provider]]` entries on their configured `interval`.

### 2.2 `check` — will this configuration run

The single pre-bind gate. It performs every step `daer run` performs before it binds a socket:
resolve subscriptions and rule providers, compile and lower every rule, build every group,
verify every node this build can speak, verify every DNS upstream, and parse `dns.bind`.

With `--object` it also validates the compiled datapath object against the ABI — names,
sections, and the BTF `func_info` invariant the kernel enforces — without loading it, so the
check needs no capability and can gate a packaged artifact (ADR-0029).

```bash
daer check [OPTIONS]
```

| Option | Description |
| :--- | :--- |
| `-c`, `--config <PATH>` | Path to the configuration file. |
| `--nodes` | Also print every node in every group with its protocol and security identity. |
| `--object <PATH>` | Also validate the compiled datapath object. Pass `--object none` to skip it. |

Exit status is the contract: `0` when the configuration would run, non-zero otherwise. That is
what a deployment gate or a systemd `ExecStartPre=` should call.

### 2.3 `route` — resolve routing decisions offline

Evaluates how the routing engine would decide a flow, domain, or IP without sending actual traffic.

```bash
# Resolve single domain (port defaults to 443)
daer route bilibili.com

# Resolve single IP
daer route 1.1.1.1

# Resolve with custom port and detailed rule trace
daer route google.com:8443 --why

# Resolve classic 4-tuple flow with sniffed domain
daer route 192.168.1.10:41234 93.184.216.34:443 --domain example.com
```

| Argument / Option | Description |
| :--- | :--- |
| `<TARGET>` | Target domain, IP, or IP:port (or source address when 2 arguments are provided). |
| `[DESTINATION]` | Destination address (`ip:port` or `ip`) when target is used as source. |
| `--source <IP:PORT>` | Client source address (defaults to `127.0.0.1:12345`). |
| `-c`, `--config <PATH>` | Path to configuration file. |
| `--domain <NAME>` | The sniffed domain a `domain(...)` rule would see (auto-inferred if target is a domain). |
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

`--file` decodes the body with the same `daer_outbound::subscription::decode` the daemon uses at load time ([INV-LOADER-01](../dev/standards/invariants.md)), so a list that probes clean here is the list the runtime would build. A line the format rejects is reported, never silently dropped. The command exits non-zero when any node fails, and prints `N/M node(s) operational`.

The `--file` and `--all` forms stop at the first failure only in the sense that the summary line reports it: every node is probed first, so one dead node does not hide the state of the rest.

Phased diagnostic reporting:
- **L3 DNS Resolution**: Resolves node server hostname to IP.
- **L4 TCP Connect**: Tests if server IP:Port is reachable (detects firewall/GFW SYN drops).
- **L7 Protocol Handshake**: Connects through `NodeDialer` (VLESS/SS/Trojan/etc.) to verify UUID, password, TLS SNI, or REALITY keys. A REALITY node that cannot authenticate this client **forwards** the flow to the impersonated site; `reality/verify.rs` turns that silent redirection into the explicit failure `the peer is not the REALITY node`.
- **End-to-End Probe**: Sends a real HTTP(S) request through the proxy tunnel and reads the reply. For an `https://` URL the TLS handshake happens *inside* the tunnel, which is what a TLS probe means.

A single probe is subject to the usual loss on a long-haul link; `--timeout` interacts with that (the default 5 s is tight for a node at 200 ms RTT on a lossy path), and a handshake reset is retried once before being reported. That is a property of the path being measured, not of `daer`: `xray` against the same node shows the same distribution.

### 2.5 `schema` — JSON Schema for editors

Prints the JSON Schema of a configuration file to stdout. Point an editor at it
(`#:schema ./daer.schema.json`) or validate a file in CI.

```bash
daer schema
```

### 2.6 `version` — build information

```bash
daer version
```

---

## 3. What is deliberately not in `daer`

| Not in `daer` | Use instead |
| :--- | :--- |
| Compiling rules to `.drb`, converting `geoip.dat` / `geosite.dat`, inspecting or unit-testing `.drb` | Companion tool [`daer-drb`](#4-drb-producer-tooling-daer-drb). |
| Converting a `vless://` / `ss://` link into a `[[node]]` table | Any subscription converter, or declare a `[[subscription]]`: `daer` parses links at runtime. |
| Running a standalone DNS server | `daer run` serves DNS; `daer check` reports unusable upstreams. |
| Formatting a configuration | An editor plus `daer.example.toml`. |

---

## 4. DRB Producer Tooling: `daer-drb`

`daer-drb` is the DRB producer: it compiles Canonical Rule Source (`.rules`) into DRB v2
(`.drb`), decompiles an artifact back to that text, inspects it, and tests a target against it.
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
