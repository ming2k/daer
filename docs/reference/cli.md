# Command Line Interface (CLI) Reference

The `daer` binary provides subcommands for running the transparent proxy, inspecting routing verdicts, testing DNS, and validating configuration files.

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

### 2.1 `run`
Runs the transparent proxy daemon.

```bash
daer run [OPTIONS]
```

| Option | Default | Description |
| :--- | :--- | :--- |
| `-c`, `--config <PATH>` | `/etc/daer/config.toml` | Path to configuration file. |
| `--object <PATH>` | `target/ebpf/datapath.o` (with fallback to system paths) | Path to compiled eBPF datapath object. |
| `--no-datapath` | `false` | Serve without attaching the kernel eBPF program (for development and unprivileged testing). |
| `--dry-run` | `false` | Attach the eBPF datapath and exit immediately without serving traffic. |

### 2.2 `config`
Inspects and manipulates configuration files without running the daemon.

```bash
daer config <COMMAND>
```

| Subcommand | Description |
| :--- | :--- |
| `validate [-c <PATH>]` | Validates configuration syntax, schema types, group filters, and routing rules. Exits 0 on success. |
| `fmt [-c <PATH>]` | Formats the configuration file according to canonical TOML style. |
| `schema` | Outputs the complete JSON Schema (`daer.schema.json`) for editor integration. |
| `example` | Prints the complete reference configuration example (`daer.example.toml`). |

### 2.3 `route`
Inspects how flows would be routed against a configuration without running the daemon.

```bash
daer route <COMMAND>
```

| Subcommand | Description |
| :--- | :--- |
| `explain <SRC> <DST> [-c <PATH>] [--domain <DOMAIN>] [--why]` | Explains the routing decision for a source/destination pair (`ip:port`). Use `--why` to display evaluation of every rule and predicate. |
| `nodes [-c <PATH>]` | Lists all resolved nodes, groups, and security identities. |

### 2.4 `node`
Converts and manages outbound nodes.

```bash
daer node <COMMAND>
```

| Subcommand | Description |
| :--- | :--- |
| `convert [<LINK>]` | Converts an outbound URI link (`vless://`, `ss://`, `trojan://`, `socks5://`, `http://`, `direct://`) into a structured `[[node]]` TOML block. If `<LINK>` is omitted, reads links from standard input. |

### 2.5 `dns`
Runs or verifies the DNS subsystem.

```bash
daer dns <COMMAND>
```

| Subcommand | Description |
| :--- | :--- |
| `serve [-c <PATH>]` | Runs the standalone DNS server listening on configured ports. |
| `check [-c <PATH>]` | Probes configured upstream DNS resolvers (UDP, TCP, DoT, DoH) and prints latency/availability report. |

### 2.6 `version`
Prints detailed version and build information.
