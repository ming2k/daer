# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.0.5] - 2026-11-05

### Added

- **DRB (daer Rule Binary) rule artifacts ([ADR-0014](docs/adr/0014-drb-rule-binary-and-providers.md), `[INV-DRB-01]`)**.
  `geoip.dat` and `geosite.dat` are Protobuf streams, so loading `geosite:cn` meant running
  varint decoding, string allocation, and a runtime sort and interval merge on every start —
  a CPU burst on exactly the low-power gateways this runs on. A `.drb` artifact carries
  intervals already merged and domain patterns already sorted by kind, behind a 56-byte header
  with magic, format version, and a SHA-256 checksum, so loading performs zero merging and zero
  normalization and a corrupt or truncated file is refused rather than half-loaded.
  `crates/daer-routing/src/drb.rs`, with `IpIndex::from_merged` and
  `DomainIndex::from_composite` building the indexes directly from those sections.
- **`[[rule-provider]]` declarations (`[INV-PROVIDER-01]`)** — a rule set is
  `type = "file"` or `"http"`, `format = "drb"` or `"text"`, with an optional `interval`.
  Rules reach one through `provider(tag)`, or `ip(provider: tag)` / `domain(provider: tag)` to
  take only part of it (`rule-set`/`ruleset` are accepted as aliases). HTTP providers cache
  under `XDG_CACHE_HOME`, so a non-root user needs no `/etc` write to hold a rule set.
- **`geodrb`, a separate binary for the producers** — `compile`, `inspect`, `convert`, `test`.
  `daer` links no geodata reader and no converter, because a runtime that links a converter
  grows a converter.
- **`daer probe`** — tiered active diagnostics. `probe node <name>` reports L3 resolution, L4
  TCP reachability, and L7 protocol handshake separately, so a firewall-dropped SYN and a wrong
  REALITY key are distinguishable instead of both reading as "unreachable"; `probe url` drives
  a request end to end.
- **`daer route <target>`** — `daer route bilibili.com`, `daer route 1.1.1.1`. Routing lookup
  in the vocabulary network engineers already use, without inventing a source IP and port for a
  query that only concerns a destination. The 4-tuple form still works, and `--why` still
  traces every rule and predicate including the shadowed ones.
- **`daer-outbound/tests/reality_interop.rs`** — REALITY + Vision carried end to end against a
  local reference `xray` inbound that the test starts itself. This is the CI gate the path was
  missing: the pre-existing `reality_live.rs` is `#[ignore]` and needs a credentialed public
  node, so nothing in CI exercised the code that the defect below broke. Two negative controls
  make the positive assertion falsifiable: a wrong `pbk` must be refused rather than forwarded
  to the impersonated site, and a server that speaks no REALITY must not be accepted. Skips
  with a stated reason when no `xray` binary is present.

### Changed

- **The CLI is `run`, `check`, `route`, `probe`, `schema`, `version`
  ([ADR-0015](docs/adr/0015-cli-is-four-verbs.md), [ADR-0016](docs/adr/0016-cli-route-and-probe.md))**.
  `dns serve`, `config validate|fmt|example`, `node convert`, and `rule compile|inspect|convert`
  are gone; what they did is either a producer (`geodrb`), a declaration in the configuration
  (`[[subscription]]` fills the node pool), or part of `daer check`. `daer check` resolves
  subscriptions and rule providers, compiles every rule, builds every group, names every node
  and upstream this build cannot use, and exits non-zero — it is the deployment gate, and
  `daer run` starts the resolver itself rather than exposing a second entry point to it.
  `crates/daer-cli/tests/surface.rs` asserts the dependency closure cannot regrow a producer.
- **Every `geoip:`/`geosite:` reference is now an error that names its replacement** rather
  than a silently empty rule set. `dip(geoip:cn)` reports that the `.dat` format is retired and
  that `provider(<tag>)` is what to write.
- **Build profiles trimmed for a workspace with 23 test targets** (`Cargo.toml`). `dev` and
  `test` now use `debug = "line-tables-only"` with `split-debuginfo = "unpacked"`, and
  dependencies carry no debuginfo. Measured effect: a test binary went from 77–192 MB to
  15–25 MB, `target/debug/deps` from 62 GB to 9.3 GB, and rebuilding after touching one library
  from 666 s to 2 s. `file:line` in a panic message and in `RUST_BACKTRACE=1` frames is
  preserved, which is what the debuginfo was being used for.
- **`cargo xtask ci` bounds its parallelism** to `nproc/2` (`DAER_CI_JOBS` overrides). Cargo's
  default starts all 23 test linkers at once, and the wall-clock cost was dominated by their
  contention rather than their work. The suite now runs in 37 s.

### Removed

- `crates/daer-routing/src/dat_reader.rs` — the streaming Protobuf reader for `geoip.dat` and
  `geosite.dat`, replaced by DRB. `daer-geodata` keeps only what `geodrb convert` needs.
- The `dns`, `config`, `node`, and `rule` verbs, and `route explain`/`route nodes`. They remain
  as hidden stubs whose error names the replacement, so an existing script fails with a
  sentence rather than silence.

### Fixed

- **The shipped systemd unit could not use the features it documented** (`install/daer.service`).
  `ExecStartPre` called `daer config validate`, a verb ADR-0015 removed, so the unit's own
  pre-start gate failed and the service never started; it now calls `daer check`. Separately,
  HTTP rule providers cache under `$XDG_CACHE_HOME`/`$HOME/.cache` and that write is
  best-effort, while `ProtectHome=true` makes the path unwritable — so under this unit a
  provider silently lost its cache and the offline-resilience promise in ADR-0014 was
  unreachable. `CacheDirectory=daer` with `DAER_RULE_CACHE_DIR` points the cache at a path the
  sandbox actually grants.
- **REALITY sessions died immediately after authenticating** (`daer-outbound`). A REALITY node
  flushes a legal zero-length `application_data` record right after the handshake;
  `Tls13Connection::poll_read` answered it with `Ready(Ok(()))` and nothing written, which is
  `AsyncRead`'s encoding for end-of-stream. Every proxied connection through every REALITY node
  returned zero bytes while the node's own log showed the request served. The record is now
  skipped and the loop pulls the next one; termination remains the peer's.
- **A converted node was TOML that could not be loaded** (`daer-config`). Two defects,
  both invisible in the printed text and fatal when pasted back: a nested table rendered as
  `[reality]` instead of `[node.reality]`, and `tag` was emitted twice (once from `Node`, once
  from its flattened endpoint), which TOML rejects as a duplicate key. `to_toml_node` now
  serializes a one-element document so `toml` owns the table headers, and validates the node
  before returning it, so a mistyped cipher reports `unknown method 'aes-128-grm'` instead of
  emitting a block that fails later. `from_link` stays parse-only: for a subscription, "well
  formed and unsupported" has to survive to be reported by name.

## [0.0.4] - 2026-11-01

### Added

- **Datapath State Ownership & Lifecycle Management ([ADR-0013](docs/adr/0013-datapath-state-ownership.md), `[INV-DATAPATH-01]`)**:
  - The transparent proxy datapath owns all box-global routing prerequisites upon attach and tears them down on drop.
  - Automatic `fwmark` policy routing rules and `local default` routes across routing table 2023 for IPv4 and IPv6.
  - Automatic per-interface sysctl configuration for `rp_filter` (loose mode `2`) and IP forwarding (`forwarding = 1`), with clean restoration.
  - Link-layer hook autodetection: inspects interface `ARPHRD` link kind to attach `_l2` TC filters for Ethernet and `_l3` filters for point-to-point / tunnel interfaces, preventing packet truncation.
  - Registered UDP transparent ingress listener in `listen_socket_map` (key `1`), enabling transparent UDP packet reception and forwarding.
- **Kernel Observed Facts & Routing Telemetry ([ADR-0013](docs/adr/0013-datapath-state-ownership.md), `[INV-KERNEL-FACTS-01]`)**:
  - Read observed facts from `routing_handoff_map` (`mac`, `dscp`, `pname`, `pid`) into userspace `KernelObserver`.
  - Honest fact matching: `mac(...)`, `dscp(...)`, and `pname(...)` rules match only when observed; unknown process name (`pid = 0`) is reported as unknown rather than empty string.
- **netune 0.0.5 Upgrade**:
  - Pinned `netune` and `netune-trace` to `v0.0.5`.
  - Integrated `DialObserverSink` with `TraceSink` for streaming transport trace export during outbound dials.

## [0.0.3] - 2026-10-30

### Added

- **AnyTLS Outbound Protocol Engine & Multiplexed Session Substrate**:
  - Full support for the modern AnyTLS protocol (`type = "anytls"` in `[[node]]` and `anytls://` link parsing).
  - First-class multi-stream session multiplexing (`AnyTlsSession`), amortizing TLS handshakes across concurrent transparent proxy flows.
  - Native binary frame codec (`Waste`, `Syn`, `Push`, `Fin`, `Settings`, `Alert`, `UpdatePaddingScheme`, `SynAck`, `HeartRequest`, `HeartResponse`).
  - Robust client authentication flight with SHA-256 password hashing and obfuscation padding.
  - Full TCP and UDP datagram support via UDP-over-TCP (UoT) tunneling (`sp.v2.udp-over-tcp.arpa:53`).
  - Automatic session pooling, keep-alive heartbeat maintenance, and zero-allocation stream relaying.
- **Hysteria 2 Outbound Protocol Engine over QUIC**:
  - Full support for the Hysteria 2 protocol (`type = "hysteria2"` in `[[node]]` and `hysteria2://` / `hy2://` URI links).
  - Native QUIC client integration with `SO_MARK` pre-bind enforcement (`[INV-MARK-01]`) preventing routing loops.
  - HTTP/3 authentication flight (`POST https://hysteria/auth`) with random padding and status `233` verification.
  - Bidirectional TCP tunneling with QUIC varint framing (`0x401` request frame, server response parsing).
  - RFC 9221 QUIC datagrams for native low-latency UDP packet relay.
  - Brutal congestion control downlink advertisement (`Hysteria-CC-RX`) and bandwidth hints (`up-mbps`, `down-mbps`).


## [0.0.2] - 2026-10-30

### Added

- **First-Class Structured Outbound Nodes (`[[node]]`)**:
  - Outbound nodes in `config.toml` are now configured as 100% typed structured tables (`type = "vless"`, `"shadowsocks"`, `"trojan"`, `"socks5"`, `"http"`, `"direct"`).
  - Protocol-specific typed fields with strict schema validation (`server`, `port`, `uuid`, `flow`, `reality`, `method`, `password`, `sni`, `allow-insecure`).
  - Direct typed construction of `NodeDialer` and `Property` eliminating intermediary string-link serialization and re-parsing in the datapath.
- **Node Conversion CLI Command (`daer node convert`)**:
  - `daer node convert "<URI>"` parses any outbound link (`vless://`, `ss://`, `trojan://`, `socks5://`, `http://`, `direct://`) and emits validated `[[node]]` TOML blocks.
  - Supports standard input pipes for batch conversion (`cat links.txt | daer node convert`).
- **Resilient Subscription & Health Probe Handling**:
  - Port normalization for subscription URLs (defaulting HTTPS to 443 and HTTP to 80 when port is omitted).
  - VLESS REALITY fingerprint normalization defaulting to `chrome` when omitted in commercial airport links.
  - Graceful handling of unimplemented protocols from subscriptions (e.g. Hysteria2) as warnings rather than aborting startup.
- **Systemd service unit (`install/daer.service`)**:
  - Out-of-the-box system service definition with `Type=simple` and `ExecStartPre=/usr/bin/daer config validate -c /etc/daer/config.toml`.
  - Zero-downtime reload via `ExecReload=/usr/bin/kill -HUP $MAINPID`.
  - Least-privilege sandboxing: drops root privileges and bounds capabilities to `CAP_BPF`, `CAP_NET_ADMIN`, and `CAP_NET_BIND_SERVICE` via `AmbientCapabilities` and `CapabilityBoundingSet`.
  - Hardened isolation flags: `NoNewPrivileges=true`, `ProtectSystem=strict`, `ProtectHome=true`, `ProtectControlGroups=true`, `ProtectKernelTunables=true`, `LockPersonality=true`, `RestrictRealtime=true`, `PrivateTmp=true`, `ConfigurationDirectory=daer`, and `ReadWritePaths=/etc/daer` allowing subscription persistence in `persist.d/`.
  - High-concurrency limits (`LimitNOFILE=1048576`, `LimitNPROC=4096`, `LimitMEMLOCK=infinity`) and OOM killer protection (`OOMScoreAdjust=-100`).
- **Standardized installation target**:
  - `cargo xtask install` installs the `daer` executable (`PREFIX/bin`), eBPF datapath object (`PREFIX/lib/daer`), and systemd unit (`PREFIX/lib/systemd/system`).
- **Resilient eBPF object path resolution**:
  - When `--object` is omitted or points to default `target/ebpf/datapath.o` outside the source tree, `daer run` automatically falls back to standard system search paths (`/usr/lib/daer/datapath.o`, `/usr/local/lib/daer/datapath.o`, `/usr/share/daer/datapath.o`).
- **Engineering management & governance suite**:
  - Root `AGENTS.md` establishing operational guardrails, architectural mental model, and invariant boundaries.
  - Centralized ADR master index in `docs/adr/index.md`.
  - Engineering standards suite in `docs/dev/standards/` covering architecture, invariants, workflow verification gates, testing strategies, documentation taxonomy, and markdown style.
  - Reorganized `docs/` according to the Diátaxis information architecture: `tutorials/`, `how-to/`, `reference/`, `explanation/`, `adr/`, and `dev/`. Zero loose files at `docs/` root.

### Removed

- Retired the legacy `url` string field in `[[node]]` and bare URL string arrays in `node`. All static nodes must now be declared as structured tables.

## [0.0.1] - 2026-10-30

### Added

- **Kernel eBPF Datapath**:
  - TC hook eBPF program with dual-slot routing epochs for atomic policy switching ([ADR-0004](docs/adr/0004-routing-epochs.md)).
  - Early packet classification: direct traffic bypasses userspace entirely; proxy traffic is redirected to the transparent ingress port.
  - Provable equivalence verification: kernel policy tables encode rules identically to userspace or explicitly defer with logged reasons ([ADR-0005](docs/adr/0005-kernel-policy-encoding.md)).
- **Transparent Ingress & Relay**:
  - Linux `IP_TRANSPARENT` listener recovering original destination addresses (`SO_ORIGINAL_DST` / `IP6T_SO_ORIGINAL_DST`).
  - Zero-loop socket mark evasion ensuring proxy egress connections are never recaptured into the listener.
  - High-throughput TCP relay with `splice(2)` fast path when applicable.
  - Per-peer session tracking for transparent UDP datagram relay.
- **Outbound Dialers & Protocols**:
  - Built-in dialers: Direct, SOCKS5, HTTP CONNECT.
  - Encrypted proxy protocols: Shadowsocks AEAD, Trojan, and VLESS.
  - Native REALITY client with custom minimal TLS 1.3 implementation and XTLS-Vision protocol support ([ADR-0010](docs/adr/0010-reality-client-ownership.md)).
  - Dialer groups supporting health checks, latency tracking, alive-set filtering, and policy selection (min, min-moving-avg, random).
  - Remote subscription fetcher with base64 decoding and persistent disk fallback caching.
- **Integrated DNS Subsystem**:
  - High-performance DNS server supporting UDP and TCP listeners on port 53.
  - Multi-upstream resolution pipeline supporting bare UDP, bare TCP, DNS-over-TLS (DoT), and DNS-over-HTTPS (DoH).
  - In-memory DNS cache with TTL enforcement and routing-aware upstream dispatch.
- **Domain Sniffing**:
  - Early protocol prefix inspection for TLS ClientHello (SNI extraction), HTTP/1.1 request line (`Host` header extraction), and QUIC Initial packets (RFC 9000/9001).
- **Zero-Downtime Hot Reload**:
  - `SIGHUP` signal handler driving generation handover: compiles new routing table, republishes eBPF maps, and swaps generation pointer without dropping active proxy connections.
- **Rule Engine & GeoData**:
  - Fast, allocation-free routing rule evaluation supporting IP CIDRs, port ranges, domains, protocols, and geo tags.
  - Streaming binary reader for `geosite.dat` and `geoip.dat` databases.
- **CLI & Diagnostics**:
  - Unified configuration loader shared across runtime and diagnostics ([ADR-0006](docs/adr/0006-wiring-ownership.md)).
  - Inspection subcommands: `daer config validate`, `daer config fmt`, `daer config schema`, `daer route explain`, `daer route nodes`, and `daer dns check`.
