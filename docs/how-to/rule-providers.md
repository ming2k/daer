# Manage Rule Providers and DRB Rule Sets

This guide walks operators through creating, compiling, and distributing high-performance `.drb` (daer Rule Binary) rule sets, and integrating remote rule subscriptions using declarative `[[rule-provider]]` declarations.

---

## 1. Overview of the DRB Ecosystem

As specified in [ADR-0014](../adr/0014-drb-rule-binary-and-providers.md), `daer` uses **DRB** (`.drb`) as its native, pre-compiled rule artifact format.

- **Fastest Cold-Start**: Pre-sorted IP intervals and pre-indexed domain patterns load in microseconds (`< 0.01ms`), bypassing all protobuf streaming and interval merging.
- **Non-Root Operation**: Rule caches live under user XDG cache directories (`$XDG_CACHE_HOME/daer/rules`, or `~/.cache/daer/rules`), so an unprivileged run needs no `/usr/share/daer` access. `DAER_RULE_CACHE_DIR` overrides the location; under the shipped systemd unit (`ProtectHome=true`) it points at `/var/cache/daer/rules`, because a hardened `$HOME` makes the default unwritable.
- **Automated Lifecycle**: When an HTTP rule provider defines an `interval`, `daer` periodically checks for updates in the background, downloads updates conditionally using `If-None-Match` (ETag), and hot-reloads the active eBPF datapath generation with zero dropped connections.

---

## 2. Compiling Custom Rule Sets

You can write human-readable plain text rule lists and compile them to `.drb` using the CLI.

### Creating a Source Rule File

Create a text file (e.g. `company-direct.rules`):

```text
# Corporate subnets and intranet services
name: company-direct

# IP and CIDR rules
ip: 192.168.0.0/16
ip: 10.0.0.0/8
172.16.0.0/12

# Domain rules
suffix: internal.company.com
.corp.company.com
full: vpn.company.com
keyword: gitlab-internal
regex: ^.*\.dev\.local$
```

### Compiling to DRB

Compile the text rules into a `.drb` binary:

```bash
geodrb compile company-direct.rules -o company-direct.drb
```

Output:

```text
company-direct.drb: ok
  name:             company-direct
  version:          1
  v4 intervals:     3
  v6 intervals:     0
  ip prefixes:      3
  domain suffix:    2
  domain full:      1
  domain keyword:   1
  domain regex:     1
  total domains:    5
  binary size:      196 bytes
  sha256:           e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

### Inspecting an Existing DRB File

Verify the integrity and view the contents of any `.drb` file:

```bash
geodrb inspect company-direct.drb
```

---

## 3. Converting Legacy `geoip.dat` and `geosite.dat`

To migrate from legacy Protobuf `.dat` rule sets to `.drb`:

```bash
# Convert geosite category "cn" to DRB
geodrb convert geosite.dat --code cn -o geosite-cn.drb

# Convert geoip country "cn" to DRB
geodrb convert geoip.dat --code cn -o geoip-cn.drb --type geoip
```

---

## 4. Configuring Rule Providers in `daer.toml`

Declare local file or remote HTTP providers in your daemon configuration:

```toml
schema = 1

# 1. Local pre-compiled DRB rule set
[[rule-provider]]
tag = "company-direct"
type = "file"
path = "rules/company-direct.drb"
format = "drb"

# 2. Remote HTTP rule set with automated 24-hour background sync
[[rule-provider]]
tag = "geosite-cn"
type = "http"
url = "https://raw.githubusercontent.com/daeuniverse/geodrb/release/geosite-cn.drb"
format = "drb"
interval = "24h"

[[rule-provider]]
tag = "geoip-cn"
type = "http"
url = "https://raw.githubusercontent.com/daeuniverse/geodrb/release/geoip-cn.drb"
format = "drb"
interval = "24h"

[routing]
rules = [
    # Match both IP intervals and domains from company-direct
    "provider(company-direct) -> direct",

    # Route domestic traffic directly
    "provider(geosite-cn) -> direct",
    "provider(geoip-cn) -> direct",
]
fallback = "proxy"
```

---

## 5. Automated CI/CD Publishing with `geodrb`

For organization-wide or community distribution of pre-compiled `.drb` artifacts:

1. Maintain a dedicated repository (such as `geodrb`) to host scheduled GitHub Actions workflows.
2. In the workflow, fetch upstream sources (e.g. `v2fly/domain-list-community`, `Loyalsoldier/v2ray-rules-dat`, or MaxMind).
3. Run `geodrb convert` for each target category (`cn`, `google`, `apple`, `openai`, `telegram`, `category-ads-all`, etc.).
4. Publish the output `.drb` artifacts to a `release` branch or GitHub Releases.
5. End users reference the raw URLs in `[[rule-provider]]`, receiving automated daily updates without manual maintenance or root privileges.

---

## 6. Architecture Best Practices: Coarse-Grained Providers vs. Anti-Patterns

For complete mathematical and kernel-level performance proofs, read the deep dive in [Routing Performance, Kernel Datapath Bounds, and Rule Asset Topology](../explanation/routing-performance-and-rule-organization.md) and [ADR-0019](../adr/0019-rule-asset-topology-and-lookup-mechanics.md).

### The Recommended Topology: 3 to 6 Coarse-Grained Providers

Organize rules strictly by **outbound action** and **independent update lifecycle**:

```text
/etc/daer/
├── daer.toml
└── providers/
    ├── block-ads.drb          # Action: block (high update frequency, upstream)
    ├── geosite-cn.drb         # Action: direct (medium update frequency, upstream)
    ├── geoip-cn.drb           # Action: direct (low update frequency, upstream)
    ├── proxy-special.drb      # Action: designated proxy group (e.g. streaming, AI)
    └── corporate.drb          # Action: direct (internal IP subnets + private domains)
```

In `daer.toml`:
```toml
[routing]
rules = [
    "provider(block-ads) -> block",
    "provider(corporate) -> direct",
    "provider(geosite-cn) -> direct",
    "provider(geoip-cn) -> direct",
    "provider(proxy-special) -> specialized_proxy_group",
]
fallback = "proxy"
```

### Critical Anti-Patterns to Avoid

- **Anti-Pattern: Granular Per-Site Files**:
  Do not create individual files or providers for each website (e.g. `github.toml`, `youtube.toml`, `steam.toml`).
  - **Reason**: The outer rule iteration across `MatchSet` elements is an $O(N)$ sequential walk. Splitting rules into hundreds of statements causes CPU cache line thrashing and destroys L1/L2 cache locality.
  - **The Kernel Danger**: Lowering $> 1024$ match sets exceeds the eBPF datapath's fixed array ceiling (`MAX_MATCH_SET_LEN`), causing `daer` to emit `DeferReason::TooManySets`. When this happens, **line-rate eBPF hardware offload is immediately aborted**, forcing 100% of all packet flows to fall back to the userspace relay.
- **Anti-Pattern: Splitting IP and Domain for Composite Assets**:
  Do not maintain separate IP and domain files for a single business entity (e.g. `corp-ips.txt` and `corp-domains.txt`).
  - Combine them into a single `.rules` source file (`ip: ...` and `suffix: ...`) and compile them into a unified `.drb`. `daer-routing` automatically links them with a zero-cost logical-OR predicate under a single rule statement.
- **Format Selection**:
  - Use `format = "drb"` for external subscriptions, production workloads, and large rule sets ($> 1,000$ entries) for instant sub-millisecond cold start.
  - Use `format = "text"` only for small, human-edited local override files during active prototyping.
