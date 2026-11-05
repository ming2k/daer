# Command Line Interface (CLI) Reference

The `daer` CLI provides the runtime daemon, deployment gates, and diagnostics for the
transparent proxy. Build-time producers and converter toolchains live in the companion tool [`geodrb`](#4-drb-producer-tooling-geodrb).

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
| `--dry-run` | `false` | Attach the datapath and exit immediately without serving. |

Reloads on `SIGHUP`, and refreshes `[[rule-provider]]` entries on their configured `interval`.

### 2.2 `check` — will this configuration run

The single pre-bind gate. It performs every step `daer run` performs before it binds a socket:
resolve subscriptions and rule providers, compile and lower every rule, build every group,
verify every node this build can speak, verify every DNS upstream, and parse `dns.bind`.

```bash
daer check [OPTIONS]
```

| Option | Description |
| :--- | :--- |
| `-c`, `--config <PATH>` | Path to the configuration file. |
| `--nodes` | Also print every node in every group with its protocol and security identity. |

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

Performs active network probing across layers (L3 DNS, L4 TCP handshake, L7 proxy protocol handshake, and end-to-end HTTP access).

```bash
# 1. Probe a specific node in configuration
daer probe node hk-01

# 2. Probe a node with custom timeout and end-to-end test URL
daer probe node us-02 --timeout 10 --url http://cp.cloudflare.com/generate_204

# 3. Probe an HTTP endpoint directly or through a node
daer probe url https://www.google.com --node hk-01
```

Phased diagnostic reporting:
- **L3 DNS Resolution**: Resolves node server hostname to IP.
- **L4 TCP Connect**: Tests if server IP:Port is reachable (detects firewall/GFW SYN drops).
- **L7 Protocol Handshake**: Connects through `NodeDialer` (VLESS/SS/Trojan/etc.) to verify UUID, password, TLS SNI, or REALITY keys.
- **End-to-End Probe**: Sends HTTP probe request through the proxy tunnel to verify internet egress.

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
| Compiling rules to `.drb`, converting `geoip.dat` / `geosite.dat`, inspecting or unit-testing `.drb` | Companion tool [`geodrb`](#4-drb-producer-tooling-geodrb). |
| Converting a `vless://` / `ss://` link into a `[[node]]` table | Any subscription converter, or declare a `[[subscription]]`: `daer` parses links at runtime. |
| Running a standalone DNS server | `daer run` serves DNS; `daer check` reports unusable upstreams. |
| Formatting a configuration | An editor plus [`daer.example.toml`](https://github.com/daeuniverse/daer/blob/main/daer.example.toml). |

---

## 4. DRB Producer Tooling: `geodrb`

`geodrb` is the companion CLI dedicated to building, converting, inspecting, and unit-testing DRB rule sets.

```bash
# Compile plain-text rules to .drb
geodrb compile company-direct.rules -o company-direct.drb

# Inspect metadata and counts of a .drb file
geodrb inspect company-direct.drb

# Convert legacy geoip.dat or geosite.dat to .drb
geodrb convert geosite.dat --code cn -o geosite-cn.drb
geodrb convert geoip.dat --code cn -o geoip-cn.drb --type geoip

# Unit-test whether a domain or IP matches a .drb file
geodrb test geosite-cn.drb bilibili.com
geodrb test geoip-cn.drb 1.2.3.4
```
