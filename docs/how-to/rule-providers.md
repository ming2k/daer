# Manage Rule Providers and DRB Rule Sets

This guide walks operators through creating, compiling, and distributing high-performance `.drb` (daer Rule Binary) rule sets, and integrating remote rule subscriptions using declarative `[[rule-provider]]` declarations.

---

## 1. Overview of the DRB Ecosystem

As specified in [ADR-0014](../adr/0014-drb-rule-binary-and-providers.md), `daer` uses **DRB** (`.drb`) as its native, pre-compiled rule artifact format.

- **Fastest Cold-Start**: Pre-sorted IP intervals and pre-indexed domain patterns load in microseconds (`< 0.01ms`), bypassing all protobuf streaming and interval merging.
- **System-Wide Cache**: HTTP rule providers are cached under `/var/cache/daer/rules`; the shipped unit sets `DAER_RULE_CACHE_DIR` to that path and the loader defaults to it. Operator-managed local rule files live under `/var/lib/daer/rules`.
- **Automated Lifecycle**: When an HTTP rule provider defines an `interval`, `daer` periodically checks for updates in the background, downloads updates conditionally using `If-None-Match` (ETag), and hot-reloads the active eBPF datapath generation with zero dropped connections.

---

## 2. Compiling Custom Rule Sets

You can write human-readable plain text rule lists and compile them to `.drb` using the CLI.

### Creating a Source Rule File

Create a text file (e.g. `company-direct.rules`):

```text
---
name: company-direct
---

# IP and CIDR rules (CRS v3, ADR-0045)
192.168.0.0/16
10.0.0.0/8
172.16.0.0/12
10.0.0.1..10.0.0.50

# Domain rules (CRS v3 symbolic syntax, ADR-0036, ADR-0045)
internal.company.com         # Suffix match: internal.company.com and *.internal.company.com
.corp.company.com            # Subdomain only: *.corp.company.com
=vpn.company.com             # Exact match: strictly vpn.company.com only
```

Under CRS v3 (ADR-0045), all rules use prefix-free, orthogonal notation:
- Network rules accept bare host IPs (`1.1.1.1`, `::1`), standard CIDRs (`192.168.0.0/16`), and double-dot ranges (`10.0.0.1..10.0.0.50`). The legacy `ip:` prefix and `-` range are retired.
- Bare domain names (`example.com`) are suffixes matching the bare domain and all subdomains.
- Leading dots (`.example.com`) match subdomains only.
- Leading equals (`=example.com`) match the exact full domain.
- Metadata is declared in the frontmatter header (`--- \n name: <set-name> \n ---`) at the top of the file.

`keyword:` and `regex:` are permanently refused: they were legacy geodata codes that each required a dedicated engine on the matching path. Expand such patterns into concrete names before compilation.

> **eBPF Line-Rate Offload Tip ([INV-RULE-TOPOLOGY-01])**:
> When configuring production routing, keep pure IP rules (such as LAN subnets) in dedicated files placed at the top of the routing table in `daer.toml`. Composite rule sets containing domains force the datapath to defer to userspace on the first packet.

### Compiling to DRB

Compile the text rules into a `.drb` binary:

```bash
daer-drb compile company-direct.rules -o company-direct.drb
```

Output:

```text
company-direct.drb: ok
  name:             company-direct
  version:          2
  v4 intervals:     3
  v6 intervals:     0
  domain patterns:  2
  binary size:      191 bytes
  sha256:           e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

### Inspecting an Existing DRB File

Verify the integrity and view the contents of any `.drb` file:

```bash
daer-drb inspect company-direct.drb
```

---

## 3. Converting Legacy `geoip.dat` and `geosite.dat`

`daer-drb` has no `.dat` reader: Protobuf geodata is retired and the workspace links no decoder
(ADR-0031). Unpack the entry to Canonical Rule Source first, then compile:

```bash
# geosite category "cn"
python3 scripts/rules/dat_to_rules.py --kind geosite --dat geosite.dat --code cn -o cn.rules
daer-drb compile cn.rules -o geosite-cn.drb

# geoip country "cn"
python3 scripts/rules/dat_to_rules.py --kind geoip --dat geoip.dat --code cn -o cn-ip.rules
daer-drb compile cn-ip.rules -o geoip-cn.drb
```

---

## 4. Configuring Rule Providers in `daer.toml`

Declare local file or remote HTTP providers in your daemon configuration:

```toml
schema = 2

# 1. Local pre-compiled DRB rule set
[[rule-provider]]
name = "company-direct"
type = "file"
path = "rules/company-direct.drb"
format = "drb"

# 2. Remote HTTP rule set with automated 24-hour background sync
[[rule-provider]]
name = "geosite-cn"
type = "http"
url = "https://github.com/daeuniverse/drb-sets/releases/latest/download/geosite-cn.drb"
format = "drb"
interval = "24h"

[[rule-provider]]
name = "geoip-cn"
type = "http"
url = "https://github.com/daeuniverse/drb-sets/releases/latest/download/geoip-cn.drb"
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

### Where to put local rule files

Do not put compiled `.drb` artifacts under `/etc` just because the configuration lives
there. `/etc` is for operator configuration; rule packs are data. The supported paths are:

| Content | Path |
| :--- | :--- |
| Configuration | `/etc/daer/config.toml` |
| Local rule files (`.drb` or `.rules`) | `/var/lib/daer/rules/` |
| HTTP download cache (disposable) | `/var/cache/daer/rules/` |

Relative `path = "rules/foo.drb"` resolves against the directory containing the
configuration file. A `~` is not expanded; use an absolute path or a path relative to the
config file. The package creates `/var/lib/daer/rules`; the systemd unit creates
`/var/cache/daer` and sets `DAER_RULE_CACHE_DIR=/var/cache/daer/rules`.

---

## 5. Dedicated Rule Asset Repository: `drb-sets`

The runtime daemon `daer` consumes compiled `.drb` artifacts; it does not host scheduled upstream crawlers or data releases. Production rule distributions are maintained in a dedicated rule asset repository, typically named **`drb-sets`** (analogous to `v2fly/domain-list-community` or `Loyalsoldier/v2ray-rules-dat`).

In the `drb-sets` repository, a lightweight GitHub Actions workflow runs daily:
1. Downloads upstream `.dat` into the CI runner only (never into Git).
2. Generates base `.rules` and merges the tracked `rules/` overlays or authored sets
   selected by `config/rules.toml`.
3. Compiles `.drb` with `daer-drb`, verifies every artifact round-trips byte-for-byte, and
   computes `sha256sums.txt` plus `manifest.json`.
4. Publishes the artifacts as GitHub Release assets, and only when `content_sha256` changed.
   There is no `release` branch and no generated artifact in Git history.

The tracked source of truth is `config/geosite-tags.txt`, `config/geoip-tags.txt`,
`config/rules.toml`, and the files under `rules/`. Upstream `.dat` files and compiled `.drb`
files are build inputs/outputs, not repository content.

End users reference the public URLs in `[[rule-provider]]`, receiving automated background updates without manual maintenance or root privileges.

For a fully local install — building the artifacts, verifying them, copying them to
`/var/lib/daer/rules`, and declaring file providers — see
[Install DRB Rule Sets Manually](drb-sets-manual-install.md).

---

## 6. Architecture Best Practices: Coarse-Grained Providers vs. Anti-Patterns

For complete mathematical and kernel-level performance proofs, read the deep dive in [Routing Performance, Kernel Datapath Bounds, and Rule Asset Topology](../explanation/routing-performance-and-rule-organization.md) and [ADR-0019](../adr/0019-rule-asset-topology-and-lookup-mechanics.md).

### The Recommended Topology: 3 to 6 Coarse-Grained Providers

Organize rules strictly by **outbound action** and **independent update lifecycle**:

```text
/etc/daer/config.toml
/var/lib/daer/rules/
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
  - Combine them into a single `.rules` source file (CIDR/range lines and domain lines (`example.com`, `=host.example`)) and compile them into a unified `.drb`. `daer-routing` automatically links them with a zero-cost logical-OR predicate under a single rule statement.
- **Format Selection**:
  - Use `format = "drb"` for external subscriptions, production workloads, and large rule sets ($> 1,000$ entries) for instant sub-millisecond cold start.
  - Use `format = "text"` only for small, human-edited local override files during active prototyping.

---

## 7. Production-Grade Deployment with Loyalsoldier Datasets

The widely trusted [`Loyalsoldier/v2ray-rules-dat`](https://github.com/Loyalsoldier/v2ray-rules-dat) repository maintains canonical community categories (China direct domains, non-mainland domains, ad tracking, and APNIC IP CIDRs). In production, these are converted and hosted via `drb-sets` into verified `.drb` artifacts:
- `geosite-cn.drb` (Domestic domains for direct routing)
- `geoip-cn.drb` (Domestic IP prefixes for direct routing)
- `geosite-category-ads-all.drb` (Ad blocking and privacy tracking domains)
- `geosite-geolocation-!cn.drb` (Non-mainland domains requiring proxy egress)
- `geoip-private.drb` (RFC1918 and loopback subnets for bypass)
- `geosite-apple.drb` (Apple domains)
- `geosite-google.drb` (Google domains)

### Compiling Locally with `daer-drb`

`daer-drb` reads and writes exactly one pair of formats: Canonical Rule Source (`.rules`) in,
DRB v2 (`.drb`) out. There is no `.dat` reader inside it — that format is retired, and the
workspace links no Protobuf at all (ADR-0031).

To convert legacy geodata, unpack it to `.rules` first. `drb-sets` ships the reference
unpacker; the shape is one small script per upstream format:

```bash
# 1. Unpack the upstream .dat entry into Canonical Rule Source.
python3 scripts/rules/dat_to_rules.py --kind geosite \
    --dat geosite.dat --code cn --output geosite-cn.rules

# 2. Review it. This step is the point: the file is plain text, diffable, and committable.
$EDITOR geosite-cn.rules      # cidrs/ranges  domain.com  .sub.domain.com  =exact.com

# 3. Encode it.
daer-drb compile geosite-cn.rules -o geosite-cn.drb
```

Attribute fields in the upstream `.dat` file are ignored; CRS carries patterns, not provenance.

Any published artifact can be read back, which is how you audit a release rather than trusting
the file it came from:

```bash
daer-drb decompile geosite-cn.drb -o /tmp/check.rules
daer-drb compile /tmp/check.rules -o /tmp/check.drb   # byte-identical to geosite-cn.drb
```

Attributes are not stored in DRB — the format holds patterns, not provenance — so a round trip
through an artifact shows the same rules without their `@` markers.

### Ready-to-Use Production `daer.toml`

The following configuration deploys the compiled Loyalsoldier rule sets with automated 24-hour background synchronization and line-rate eBPF kernel offload:

```toml
schema = 2

[global]
wan-interface = ["eth0"]
lan-interface = ["lan0"]

# ── 1. Declare Rule Providers ──────────────────────────────────────────────

# Ad & tracking rejection (daily update)
[[rule-provider]]
name = "ads"
type = "http"
url = "https://github.com/daeuniverse/drb-sets/releases/latest/download/geosite-category-ads-all.drb"
format = "drb"
interval = "24h"

# Private subnets (RFC1918 / Loopback)
[[rule-provider]]
name = "private-ips"
type = "http"
url = "https://github.com/daeuniverse/drb-sets/releases/latest/download/geoip-private.drb"
format = "drb"
interval = "168h"

# Mainland China Domains (daily update)
[[rule-provider]]
name = "geosite-cn"
type = "http"
url = "https://github.com/daeuniverse/drb-sets/releases/latest/download/geosite-cn.drb"
format = "drb"
interval = "24h"

# Mainland China IP CIDRs (weekly update)
[[rule-provider]]
name = "geoip-cn"
type = "http"
url = "https://github.com/daeuniverse/drb-sets/releases/latest/download/geoip-cn.drb"
format = "drb"
interval = "168h"

# Designated GFW Proxy Domains (daily update)
[[rule-provider]]
name = "geosite-gfw"
type = "http"
url = "https://github.com/daeuniverse/drb-sets/releases/latest/download/geosite-geolocation-!cn.drb"
format = "drb"
interval = "24h"

# ── 2. Evaluation Order (Coarse-Grained Pipeline) ──────────────────────────

[routing]
rules = [
    # 1. Block ads and analytics trackers
    "provider(ads) -> block",

    # 2. Bypass private LAN subnets
    "provider(private-ips) -> direct",

    # 3. Direct route domestic IPs first, then domestic domains
    "provider(geoip-cn) -> direct",
    "provider(geosite-cn) -> direct",

    # 4. Explicit proxy for known GFW domains
    "provider(geosite-gfw) -> proxy",
]

# 5. Default fallback for unmatched traffic
fallback = "proxy"
```

This configuration lowers to fewer than **10 match sets** in the kernel, ensuring full eBPF line-rate offload with zero userspace deferrals for un-sniffed or IP-forwarded packets.
