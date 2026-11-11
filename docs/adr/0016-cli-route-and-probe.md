---
id: ADR-0016
title: "CLI route and probe: natural networking mental model and tiered active diagnostics"
status: accepted
amended-by: [ADR-0041]
date: 2026-02-16
scope: [cli/surface, architecture/diagnostics, routing, outbound/probe]
supersedes: []
---

# 0016. CLI route and probe: natural networking mental model and tiered active diagnostics

- Status: Accepted
- Date: 2026-02-16
- Amended by: [ADR-0041](0041-runtime-status-verb.md) — `status` is the seventh verb and the
  only live, read-only inspector; `route` remains offline and `probe` remains active I/O.
- Deciders: Ming Li
- Related: [ADR-0014](0014-drb-rule-binary-and-providers.md), [ADR-0015](0015-cli-is-four-verbs.md)

---

## Context and Problem Statement

ADR-0015 successfully purged build-time producers (such as Protobuf readers and `.dat` converters) from `daer-cli` into the standalone `daer-drb` tool.

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
- `daer probe node '<LINK>'` / `daer probe '<LINK>'`: the same four tiers against a node **link** with no configuration file. A link is how a provider hands over a single node, so requiring a hand-written `config.toml` first made the one question an operator actually has ("is this node usable") the hardest one to ask. `NODE` is resolved in a fixed order — a `scheme://` link, then an empty value (list what the configuration holds), then a name looked up in `--config` — so no input is interpreted two ways. The link is parsed by `daer_config::Node::from_link`, the same parser the loader uses for a `[[node]]` table written as a link; this is not a second parser, and it is why the shortcut does not violate [INV-LOADER-01](../dev/standards/invariants.md) (a link has no configuration to disagree with).
- `daer probe node --all` / `daer probe node --file <PATH>`: probe a whole pool. `--all` walks the configuration's nodes; `--file` decodes a subscription body with `daer_outbound::subscription::decode`, the same decoder the daemon runs when it resolves a `[[subscription]]`, so the probed list is the list the runtime would build. A line the format rejects is reported and skipped, and the command exits non-zero if any node fails, printing `N/M node(s) operational`.
- `daer probe url <URL> [--node <NODE>]`: Direct or proxy-tunneled endpoint probe.

The `--file` form is why "test a subscription" is a verb and not a shell loop: the answer an operator needs is *which* of forty nodes are alive, and a loop over `probe node` prints forty unrelated reports with no total.

A probe retries a reset handshake once. A single attempt against a node 200 ms away on a lossy path fails perhaps half the time — measured identically through `xray` against the same node — and reporting that as "the node is broken" is a lie about the node. The retry does not blur a bad credential: a REALITY `pbk` mismatch forwards the flow and fails with `the peer is not the REALITY node` on every attempt.

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
- A single link, a whole configuration, or a subscription file are all probeable through one verb, and `--file` shares its decoder with the daemon, so "the node list the probe saw" and "the node list the daemon loaded" cannot diverge.

### Negative
- `NODE` carries three meanings. The order is fixed and each branch is total, but the help text has to state the order, and a user who names a node the same as a link scheme would get the link branch. This is acceptable because a link always contains `://`, which no sane node label does.
- `--all` and `--file` serialize their probes. Probing forty nodes concurrently would finish faster, but would also make the report's ordering depend on which node answered first, and the per-node latency numbers are the point.
