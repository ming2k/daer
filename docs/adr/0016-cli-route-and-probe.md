---
id: ADR-0016
title: "CLI route and probe: natural networking mental model and tiered active diagnostics"
status: accepted
date: 2026-02-16
scope: [cli/surface, architecture/diagnostics, routing, outbound/probe]
supersedes: []
---

# 0016. CLI route and probe: natural networking mental model and tiered active diagnostics

- Status: Accepted
- Date: 2026-02-16
- Deciders: Ming Li
- Related: [ADR-0014](0014-drb-rule-binary-and-providers.md), [ADR-0015](0015-cli-is-four-verbs.md)

---

## Context and Problem Statement

ADR-0015 successfully purged build-time producers (such as Protobuf readers and `.dat` converters) from `daer-cli` into the standalone `geodrb` tool.

However, real-world operational experience revealed two usability bottlenecks:

1. **`explain` is database jargon, not network terminology**:
   In network engineering, diagnosing how an IP or domain is handled is universally understood as **routing lookup** (e.g. `ip route get`, `show route`). The name `explain` carried database optimization connotations and required strict 4-tuple inputs (`<SRC> <DST>`), forcing operators to invent arbitrary client IPs and ports even when only querying a domain or destination IP.
2. **Missing active network diagnostic capabilities**:
   When network proxy issues occur, the root cause spans multiple distinct layers:
   - *L3/L4 Transport*: Is the node server IP or port unreachable, firewall-blocked, or GFW-dropped?
   - *L7 Proxy Protocol*: Is the node credentials (UUID, password, TLS SNI, REALITY public key) misconfigured?
   - *End-to-End Egress*: Can traffic actually exit the proxy tunnel to reach the public internet?
   Previously, `daer` provided zero active diagnostic commands, forcing operators to inspect verbose debug logs under full daemon execution.

---

## Decision

We adopt a clean, non-compromising CLI architecture:

### 1. Replace `explain` with `route <TARGET>`
`daer route` provides natural, flexible routing lookup:
- Single domain: `daer route bilibili.com` (destination port defaults to 443; domain is auto-inferred).
- Single IP or IP:port: `daer route 1.1.1.1` or `daer route 1.1.1.1:80`.
- Classic 4-tuple: `daer route 192.168.1.10:41234 93.184.216.34:443`.
- Offline, non-privileged, deterministic evaluation using the exact compiled generation.
- Historical `daer explain` is cleanly removed, returning a direct suggestion to use `daer route`.

### 2. Introduce `daer probe` for active network diagnostics
`daer probe` provides tiered, phased diagnostic probes:
- `daer probe node <NAME>`:
  1. *L3 DNS*: Resolves remote node hostname to IP.
  2. *L4 TCP Handshake*: Measures TCP connect latency and verifies server IP:port reachability.
  3. *L7 Proxy Handshake*: Authenticates through `NodeDialer` (VLESS/SS/Trojan/etc.) to verify protocol credentials.
  4. *End-to-End HTTP Probe*: Sends an HTTP request through the tunnel to verify internet egress.
- `daer probe url <URL> [--node <NODE>]`: Direct or proxy-tunneled endpoint probe.

### 3. Surface Verbs
The `daer` CLI surface is structured as:
```text
daer run                     run the daemon (eBPF datapath + ingress + relay + DNS)
daer check [--nodes]         deployment pre-bind gate
daer route <TARGET>          offline routing decision resolution
daer probe <SUBCOMMAND>      online active network diagnostics
daer schema                  JSON Schema for editors
daer version                 build information
```

---

## Consequences

### Positive
- Intuitive mental model matching standard network engineering practices.
- Instant, multi-tiered root cause identification for proxy node failures.
- Zero extra external dependencies added to `daer-cli`.
