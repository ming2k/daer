# Install DRB Rule Sets Manually

This guide installs the `.drb` artifacts produced by the `drb-sets` pipeline into the
system-wide `daer` rule directory, then wires them into `/etc/daer/config.toml` as file
providers.
Use it when the published release is unavailable, when the host cannot reach GitHub, or
when you want a reproducible, operator-controlled update.

The pipeline is not part of `daer`. It consumes the `daer-drb` compiler from this
workspace and produces data; the daemon only reads the compiled `.drb` files.

---

## 1. What the Pipeline Produces

Run from the `drb-sets` checkout, `scripts/build.sh` writes:

| Path | Purpose |
| :--- | :--- |
| `dist/*.drb` | Compiled DRB v2 artifacts; these are the only files the daemon reads. |
| `dist/rules/*.rules` | The exact Canonical Rule Source each artifact was compiled from. Audit only. |
| `dist/rules.tar.gz` | The same audit trail as one archive. |
| `dist/sha256sums.txt` | Conventional SHA-256 checksums for the release files. |
| `dist/manifest.json` | Artifact metadata, payload checksums (`content_sha256`), and upstream source hashes. |

`dist/rules/*.rules` are not loaded at runtime. Keep them for auditing and for
recompiling a pinned release; do not copy them to `/var/lib/daer/rules` unless you have
deliberately chosen a text provider.

The DRB v2 format is deterministic: rebuilding the same rule text produces the same
bytes. `content_sha256` is the payload checksum that `daer-drb inspect` prints (labelled
`sha256` in its output) and is the right field for deciding whether rule content changed.

---

## 2. Build the Compiler and Artifacts

The `drb-sets` pipeline expects the `daer` checkout as a sibling and calls its
`daer-drb` binary as an external tool. It does not build its own compiler.

```bash
# From the parent directory that contains daer/ and drb-sets/
cd daer
cargo build --release --bin daer-drb
cd ../drb-sets

DAER_DRB=../daer/target/release/daer-drb ./scripts/build.sh
```

`scripts/build.sh` downloads the upstream `geosite.dat` and `geoip.dat` into `.cache/`
when they are absent. To build offline, point it at files you already have:

```bash
GEOSITE_DAT="$PWD/.cache/geosite.dat" \
GEOIP_DAT="$PWD/.cache/geoip.dat" \
DAER_DRB=../daer/target/release/daer-drb \
./scripts/build.sh
```

A successful build ends with the artifact listing and writes `dist/manifest.json`. The
pipeline fails instead of publishing a missing, empty, or non-decodable artifact.

---

## 3. Verify Before Installing

Verify the bytes and the format before putting anything under `/var`:

```bash
cd drb-sets
set -euo pipefail

# File checksums, including rules.tar.gz.
(cd dist && sha256sum -c sha256sums.txt)

# Every artifact must decode through the same reader the daemon uses.
for artifact in dist/*.drb; do
    ../daer/target/release/daer-drb inspect "$artifact" >/dev/null
done
echo "all artifacts decode"
```

If an artifact fails `inspect`, do not install it. The usual causes are a truncated
copy, a stale `.dat` input, or a compiler built from a different `daer` revision.

---

## 4. Install the Artifacts

The supported location for operator-managed rule files is `/var/lib/daer/rules`.
`/etc/daer` is for configuration; do not put `.drb` data there just because the
configuration lives there.

```bash
sudo install -d -m 0755 /var/lib/daer/rules

# Install only the sets you will declare in the configuration.
sudo install -m 0644 \
    dist/geosite-cn.drb \
    dist/geoip-cn.drb \
    /var/lib/daer/rules/
```

You can copy the whole release in one command:

```bash
sudo install -m 0644 dist/*.drb /var/lib/daer/rules/
```

That is safe: `daer` does not scan the directory, so unused files have no effect. Only a
file named by a `[[rule-provider]]` entry is loaded. Keeping the full set locally makes a
later routing change a configuration edit rather than a redeployment.

Do not install `dist/rules.tar.gz` or `manifest.json` into `/var/lib/daer/rules`; they
are release metadata, not provider inputs.

---

## 5. Configure File Providers

Add one `[[rule-provider]]` per artifact you want to route with. File providers have no
background refresh, so an `interval` key is rejected; update the file and reload the
daemon instead.

The following configuration keeps the existing `[global]`, `[[node]]`, `[[group]]`, and
`[[election]]`
blocks and adds a domestic bypass pipeline. Replace the node values with your own.

```toml
schema = 2

[global]
wan-interface = ["auto"]
so-mark = 0x0dae
log-level = "info"
# Set this only on a gateway that receives client traffic:
# lan-interface = ["eth0"]

[global.tls]
profile = "chrome-current"

[[node]]
tag = "us-101"
type = "vless"
server = "node.example.com"
port = 443
uuid = "b831381d-6324-4d53-ad4f-8cda48b30811"
flow = "xtls-rprx-vision"

[node.security]
type = "reality"
sni = "www.example.com"
public-key = "f26c_e2kFv8-39rQz10M_xU8vI3f9Qk2lW0mNoPqRsT"
short-id = "ab01cd02"

[[group]]
name = "proxy-pool"

[[election]]
name = "proxy"
group = "proxy-pool"
type = "min-moving-avg"

# Domestic domains: direct.
[[rule-provider]]
tag = "cn-sites"
type = "file"
path = "/var/lib/daer/rules/geosite-cn.drb"
format = "drb"

# Domestic IP intervals: direct, and eligible for the kernel fast path.
[[rule-provider]]
tag = "cn-ips"
type = "file"
path = "/var/lib/daer/rules/geoip-cn.drb"
format = "drb"

# Optional: ad and tracker domains are blocked before the domestic rules.
[[rule-provider]]
tag = "ads"
type = "file"
path = "/var/lib/daer/rules/geosite-category-ads-all.drb"
format = "drb"

[routing]
# First match wins. Keep pure-IP rules ahead of domain rules so the kernel can
# terminate them without a userspace round trip.
rules = [
    # Optional: remove this line if you do not want ad blocking.
    "provider(ads) -> block",

    # DNS stays direct, so resolving the node hostname never recurses through
    # the proxy.
    "dport(53) -> direct",

    # Local, link-local, and private destinations are not internet traffic.
    "dip(10.0.0.0/8) -> direct",
    "dip(100.64.0.0/10) -> direct",
    "dip(127.0.0.0/8) -> direct",
    "dip(169.254.0.0/16) -> direct",
    "dip(172.16.0.0/12) -> direct",
    "dip(192.168.0.0/16) -> direct",

    # IPv6 is direct in this configuration; the datapath's IPv6 UDP path is
    # not part of the routing decision here.
    "ipversion(6) -> direct",

    # Broadcast and multicast never belong to a TCP/UDP proxy.
    "dip(224.0.0.0/3, 'ff00::/8') -> direct",

    # Domestic destinations bypass the proxy.
    "provider(cn-ips) -> direct",
    "provider(cn-sites) -> direct",
]
fallback = "proxy"
```

Notes:

- `provider(cn-ips)` is a pure-IP set. `provider(cn-sites)` is a domain set; flows that
  need it are evaluated in userspace after sniffing, which is expected. Keep the IP
  predicate first.
- The six `dip(...)` lines can be replaced by one `provider(private-ips) -> direct` if
  you install `geoip-private.drb` and declare that provider. The inline form has no extra
  file dependency, so it is a reasonable default.
- `geosite-cn` and `geoip-cn` are different artifacts. Declaring only one leaves either
  domains or IP addresses unmatched.
- If the daemon is also the LAN gateway, set `lan-interface` to the ingress interface.
  An empty list is correct for a host that only proxies its own traffic.
- For an HTTP provider, replace `type = "file"` and `path` with `type = "http"`, `url`,
  and `interval`. Do not set both `path` and `url` on one entry.

---

## 6. Validate, Reload, and Verify

Always run the same loader the daemon runs before restarting it:

```bash
sudo daer check -c /etc/daer/config.toml

# On the target host, also verify Linux 6.6+ TCX and the sysctl prerequisites:
sudo daer check --host -c /etc/daer/config.toml

# Show the verdict and every rule that was considered.
daer route baidu.com --why -c /etc/daer/config.toml
daer route 114.114.114.114:443 --why -c /etc/daer/config.toml

# Apply the new configuration without dropping live flows.
sudo systemctl reload daer
```

A successful `daer check` names each provider and its loaded counts, for example:

```text
rule providers: cn-sites [0 intervals, 110045 domains]; cn-ips [6611 intervals, 0 domains];
ads [0 intervals, 197248 domains]
```

After the reload, the daemon log should show the new generation and the same provider
counts. If the reload fails to build, the running generation is left untouched; fix the
configuration and reload again.

---

## 7. Update and Roll Back

A file provider is read when a generation is built, not watched continuously. To update:

```bash
# Build or download the new artifacts in drb-sets, verify them, then:
sudo install -m 0644 dist/geosite-cn.drb dist/geoip-cn.drb /var/lib/daer/rules/
sudo systemctl reload daer
```

Keep the previous files until the new generation is healthy:

```bash
sudo cp -a /var/lib/daer/rules /var/lib/daer/rules.bak-$(date +%Y%m%d-%H%M%S)
```

To roll back, copy the previous files back and reload. If the new artifact cannot be
decoded, `daer check` fails before the daemon swaps generations, so a bad file cannot
replace a working policy.

If you later publish `drb-sets` release assets, you can switch a provider from `file` to
`http` and add an `interval`. There is no automatic migration between the two forms:
edit the provider entry, keep the tag stable, and reload. An HTTP fetch that fails falls
back to its `/var/cache/daer/rules/<tag>.drb` cache when one exists.

---

## 8. Troubleshooting

| Symptom | Cause and fix |
| :--- | :--- |
| `daer check` says a file provider cannot read its path | The path is wrong, or the file was not installed. Remember that a relative `path` resolves against `/etc/daer/`, not the current shell directory; prefer absolute paths. |
| `daer check` rejects `interval` on a file provider | File providers have no background refresh. Remove `interval`, update the file, and reload. |
| `daer route --why` never matches `provider(cn-sites)` | The flow has no sniffed domain (for example, plain IP or an unsniffable protocol), or the artifact is not the expected set. Test the artifact directly with `daer-drb test dist/geosite-cn.drb baidu.com`. |
| `provider(cn-ips)` misses an address | IP geodata is coarse and changes over time; rebuild the artifact from current upstream data. |
| The service starts but traffic is unchanged | Check `journalctl -u daer -b` for `datapath attached` and the provider counts. A reload that fails validation does not swap the running generation. |
| An HTTP provider reports 404 | The release asset does not exist. Use the local file form from this guide, or verify the exact artifact name in the `drb-sets` release. |

---

## 9. Limits

- This guide installs data only. It does not publish `drb-sets`, create GitHub releases,
  or configure an update service.
- The local `drb-sets` checkout is not a release channel. A `git clone` contains the
  pipeline and tracked rule sources, not `dist/`; run the pipeline to produce artifacts.
- Copying all artifacts is a storage convenience, not a routing design. Declare only the
  providers your rules reference; every additional provider adds load-time work and, for
  domain sets, userspace matching.
- File providers require an explicit reload after replacement. If you need unattended
  updates, use an HTTP provider once a release URL is actually published and verified.
