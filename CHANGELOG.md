# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Transparent-ingress incident record and convergence checklist.** The private-namespace
  fix, reply-socket readiness, accept-loop liveness, and health-probe failures are documented
  together in [`docs/dev/transparent-ingress-incident.md`](docs/dev/transparent-ingress-incident.md),
  with the falsifier for each and an eight-point checklist for future changes.

### Changed

- **The TCP accept loop no longer shares a task with the datagram relay or a flow decision.**
  `Daemon::serve` uses `serve_parallel`; the join-based `serve_with_datagrams` composition is
  private to the relay's tests instead of part of the public surface.
- **Fixed groups are absent from the health-probe table.** A `fixed(n)` policy is explicit
  operator intent and is not rewritten by probes.
- **Health probes and reply sockets are included in `INV-MARK-01`.** The invariant now names
  every socket daer creates, not only outbound dials.

### Tests

- `serve::tests::a_slow_decision_does_not_block_accepting_the_next_flow` fails if the accept
  loop awaits a flow decision.
- `inbound::udp::tests::the_reply_socket_factory_is_the_socket_that_sends` fails if the reply
  path bypasses the namespace factory.
- `health::tests::a_fixed_group_has_nothing_to_probe` fails if a fixed group re-enters the
  probe path.

## [0.0.11] - 2026-11-11

### Changed

- **Canonical Rule Source v2 ([ADR-0036](docs/adr/0036-canonical-rule-source-v2-and-symbolic-syntax.md)).**
  Domain rules use symbolic syntax: `example.com` is a suffix, `.example.com` matches
  subdomains only, and `=example.com` is exact. The `full:`/`suffix:` spellings are retired and
  produce a named migration warning; `.rules` rendering and `daer-drb decompile` emit the
  canonical symbolic form. Decompile→compile remains byte-identical on a 120,000-pattern
  corpus.
- **Per-provider rule refresh ([ADR-0037](docs/adr/0037-per-provider-refresh-cadence.md)).**
  HTTP providers are checked on their own declared `interval`; the daemon wakes on the shortest
  cadence and skips providers that are not due. A `304 Not Modified` or byte-identical response
  keeps the running generation (and its measured node latency); only changed content is
  republished, and a failed refresh keeps the current rules.
- **netune 0.0.24: owned QUIC and HTTP/3.** `daer` now pins the `v0.0.24` release.
  netune owns the RFC 9000/9221 QUIC engine and the RFC 9114/9204 HTTP/3 + QPACK stack,
  so `quinn`, `quinn-proto`, `h3`, `h3-quinn` and the vendored fork disappear from the
  production graph ([ADR-0035](docs/adr/0035-quic-and-http3-in-netune.md)). The bump also
  carries netune's bounded TLS/HTTP2/QUIC parsing, DPLPMTUD and per-connection QUIC
  lifecycle fixes.
- **Hysteria 2 keeps its product semantics through generic netune seams.**
  Salamander/Gecko and source-port hopping implement `netune_quic::QuicUdpSocket` and are
  built by a per-connection `QuicUdpSocketFactory`; Brutal implements
  `netune_quic::CongestionControllerFactory`; `pin-sha256` reads
  `Connection::peer_certificates`; keep-alives use `QuicProfile.keep_alive`.
  `disable-path-mtu-discovery` maps to `QuicProfile.path_mtu_discovery`, so the owned
  engine's DPLPMTUD probes are disabled rather than silently ignored. Hysteria 2 streams
  are bridged from netune's raw QUIC halves to `AsyncRead + AsyncWrite` locally, so no
  third-party QUIC stream wrapper returns.
- **Typed observation.** A dial nobody observes uses `TraceCollector::disabled()` (no event
  recorded, no sink, no ring filled); an observed dial installs one `DialObserverSink`
  before connecting, so netune's DNS/TCP/TLS marks stream to the observer and the final
  phases are derived from the actual event log. Hysteria 2 passes the collector into
  `netune-quic` and `netune-http3`, so its QUIC/H3 handshake is no longer outside the trace.

### Fixed

- **Transparent ingress lives in the private `daer0ns` network namespace.**
  A redirected host flow and its listener shared the host namespace; `bpf_sk_assign` returned
  success, but the transport stack still dropped the assigned packet with
  `tcp_v4_rcv … NO_SOCKET`. `daer0peer`, the TCP/UDP transparent listeners, table 2023 and the
  peer sysctls now live in `daer0ns`; the host keeps `daer0`, forwarding, and the redirect
  source. Policy routing is keyed by `iif daer0peer`, not fwmark, because listener replies are
  deliberately marked and must leave through the peer instead of looping to `lo`. The peer
  gets a return address/default route/permanent neighbor so listener replies can cross back to
  the host. The unit and preflight add `CAP_SYS_ADMIN`; a stale host table-2023 rule from an
  earlier run is removed at startup. See [ADR-0038](docs/adr/0038-private-ingress-network-namespace.md).
- **The datapath attaches with classic `cls_bpf`, not TCX.** Aya prefers TCX on
  kernels >= 6.6, but `bpf_sk_assign` is the classic tc-ingress helper the datapath was
  written against. Under TCX it returned success while the assigned packet never reached
  the listener's accept queue. `attach_tc` now uses the netlink/cls_bpf path explicitly,
  matching the reference implementation; `tc filter show` reports the programs again.
- **The datagram relay runs in its own task, and health probes carry the daer mark.**
  The TCP accept loop and the UDP relay previously shared one `tokio::join!` task, so a
  blocking or slow datagram operation could stop `accept(2)` from being polled. They are now
  independent tasks. Health probes use the same `so-mark` as every other daer socket instead
  of being recaptured by daer's own WAN hook, and a bare UDP DNS probe address uses port 53
  rather than falling back to the node's proxy port.
- **UDP replies attempt the syscall before reporting WouldBlock.** The reply path used
  Tokio's `try_send_to`; on a freshly created namespace socket its readiness state could still
  be empty, so every DNS reply failed with `operation would block` without a packet leaving.
  Reply sockets are now std nonblocking sockets whose reply path calls `send_to` directly,
  bypassing Tokio readiness, and the namespace factory creates them inside `daer0ns`.
- **UDP listeners and reply sockets carry daer's socket mark and live in the ingress
  namespace.** The TCP listener already did; the UDP wildcard listeners, every cached reply
  socket, and the namespace reply-socket factory now apply the same mark, so replies are not
  treated as new client flows and redirected again. Reply sockets are created through the
  relay's `ReplySocketFactory` seam, which `daer-control` implements with `daer0ns`.
- **The transparent listener carries daer's socket mark.** The listener's SYN-ACK is
  generated by the kernel, so it never went through a daer dialer and had mark 0. The
  datapath's own-traffic test then treated the reply as a new client flow and routed it
  again, leaving the client with retransmitted SYNs and an empty accept queue. The listener
  now applies the same `SO_MARK` as `PARAM.socket_mark`; the direct-listener test still
  accepts and rejects a self-connect as designed.
- **The v6 transparent listener is `IPV6_V6ONLY`.** Removing reuseport exposed a missing
  `set_only_v6`: Linux's `bindv6only=0` default made the `::` bind collide with the
  `0.0.0.0` listener and the daemon failed with `Address already in use`. The v6 socket is
  now explicitly v6-only, so both families bind the same port without reuseport.
- **The transparent listener is not a reuseport socket.** `bpf_sk_assign` names the exact
  listener that must receive the packet; `SO_REUSEPORT` let the stack run reuseport selection
  again, so the assigned connection never reached the accept queue even though the helper
  returned success. The production listener now sets `SO_REUSEADDR` only;
  `bind_shared` keeps reuseport for the handover test.
- **Redirected packets route locally even without their mark.** `RouteTable` installs
  `iif daer0peer table 2023` (v4 and v6) inside the ingress namespace. `daer0peer` is private
  to the datapath, so an arriving packet is ours by construction; this removes the
  mark-preservation assumption from the local-delivery path. There is deliberately no
  mark-keyed rule in the namespace: the listener's marked replies must leave through the
  peer, and a mark rule would send them back to `lo`.
- **The listener assignment survives the redirect.** The L4 protocol was carried only in
  `skb->cb[1]`; the veth redirect on this kernel preserves `cb[0]` but clobbers `cb[1]`, so
  `daer0peer_ingress` skipped `assign_listener` and the flow never reached the transparent
  listener. The tag now carries the listener kind in the high nibble of `cb[0]` as well, and
  a missing tag is counted (`BPF_STATS_PEER_INGRESS_NO_L4`) instead of disappearing.
- **A restarted daemon no longer inherits the previous run's connection state.**
  `conn_state_map` is pinned across restarts, while `datapath_generation` was the constant
  `1`; an old ACTIVE entry was therefore treated as belonging to the current run, and a
  reused five-tuple was refused as a mid-stream SYN rebind (`BPF_STATS_SYN_REBIND_REJECTED`)
  and then passed through without routing. Each start now uses a fresh generation.
- **Host-generated flows are accepted on `daer0peer`.** A flow the box itself opens has a
  source address that is local on `wlan0`; arriving on `daer0peer`, the kernel treated it as a
  martian source and dropped it before `bpf_sk_assign`, so local DNS and TCP timed out while
  the daemon and the node were both healthy. `datapath::Sysctl` now applies the reference's
  host-veth sysctls to both ends of the pair (`accept_local=1`, `rp_filter=0`,
  `arp_filter=0`, plus the `all` forms) and restores them on exit.
- **The redirect target is published into `daer_ifindex_map`.** The loader carried the
  `daer0` ifindex in `PARAM` and exposed `set_device_ifindex`, but `attach` never called it.
  The map therefore read zero, `bpf_redirect(0, 0)` failed, and every flow handed to the
  control plane was dropped before reaching the listener: the daemon attached and listened
  cleanly while DNS and TCP simply timed out. The C fallback now also treats a zero map
  entry as absent, so an old object cannot repeat the silent drop.
- **`listen_socket_map` is a real `SOCKMAP`.** Its value was declared as `__u64` while the
  kernel and `aya` require a 32-bit socket fd, so attaching failed with
  `listen_socket_map is not a SOCKMAP: invalid value size 4, expected 8`. The map is now
  `__u32`, pinned by the object test `the_listener_map_is_a_sockmap_with_fd_sized_values`.
- **The policy-route installer invokes `ip`.** The `ip rule`/`ip route` argument vectors began
  with the family selector, so the daemon tried to execute `-4` as a program and failed with
  `` `-4` is not installed `` before it reached the policy routing. All four forms now start
  with `ip`, pinned by a unit test.
- **The datapath loads under the shipped unit's capability set.** The fast packet parser
  advances a pointer by header lengths read at runtime (IPv4 IHL, IPv6 extension headers),
  which this kernel's verifier only permits with `CAP_PERFMON` (`allow_ptr_leaks`). The unit,
  deployment guide and `Preflight` capability report now name `CAP_PERFMON`; without it the
  load stopped at `tproxy_wan_ingress_l2` with `pointer arithmetic ... prohibited for !root`.
- **A rejected provider refresh cannot strand new rules.** Refreshes are staged in a copy of
  the provider pool and installed only after `daemon.reload` accepts them; the previous code
  mutated the live pool first, so a failed generation build made the next tick see the new
  rules as "unchanged" and never publish them.
- **An invalid `SIGHUP` no longer stops the daemon.** The provider-cadence rebuild reads the
  configuration a second time; a failed reload now keeps both the running generation and the
  previous schedule instead of propagating the load error out of the signal handler. The
  reload test now sends a second, invalid configuration and asserts the process survives.
- **Packaging plan is valid TOML again.** `packaging/daer.plan.toml` had an unterminated
  staging script, so a package build could not read its own plan; the plan now parses and the
  staging script is closed before the output hooks.
- **Malformed DRB headers are rejected, not indexed.** Every offset and interval count in a
  downloaded `.drb` header is bounds-checked before it becomes a slice index; a corrupt
  provider artifact now returns `DrbError` instead of panicking the daemon.
- **DoT/DoH trust-store failure is a configuration error.** A host without a platform trust
  store now makes the upstream fail with `UpstreamError::Failed` during load/check instead of
  aborting on an `expect` in the constructor.
- **Supply-chain advisory RUSTSEC-2026-0383.** `webpki-root-certs` is updated to 1.0.11,
  removing the distrusted emSign root. `deny.toml` now gates advisories, licenses, sources and
  the single-crypto-provider policy in CI.
- Unused direct dependencies were removed from `daer-cli`, `daer-dns`, `daer-sniff` and
  `daer-proxy-protocols`; `xtask` now inherits the workspace version and license.

## [0.0.8] - 2026-11-07

Release 0.0.8 introduces Shadowsocks 2022 (SIP022) with a dual-stack modular architecture,
rule attribute filtering in `daer-drb compile`, and an unpacker tool for legacy `.dat` rule sets.

### Added

- **Shadowsocks 2022 and AEAD dual-stack ([ADR-0034](docs/adr/0034-shadowsocks-2022-and-aead-dual-stack.md)).**
  `daer-proxy-protocols` implements both classic 2017 AEAD and Shadowsocks 2022 side-by-side with
  strict physical modularity in `v1/` and `v2/`:
  - Shadowsocks 2022 (`v2/`): `2022-blake3-aes-128-gcm`, `2022-blake3-aes-256-gcm`, and
    `2022-blake3-chacha20-poly1305` ciphers.
  - BLAKE3 key derivation with SIP022 subkey context; base64 pre-shared key (16 or 32 bytes)
    validation at load time.
  - Mandatory randomized padding (1..=900 bytes) on empty-payload initial requests.
  - Bidirectional ±30s timestamp validation and server-echoed request salt verification to
    prevent replay and active probing attacks.
  - Structured UDP datagrams with per-session client IDs, packet IDs, and AES-ECB header
    obfuscation.
  - Classic AEAD (`v1/`): `chacha20-ietf-poly1305`, `aes-128-gcm`, `aes-256-gcm`, and
    `xchacha20-ietf-poly1305` retained for full compatibility.
  - Unified SIP002 link parser supporting both legacy base64 userinfo and standard
    `method:password` authority.
- **Rule attribute filtering in `daer-drb compile`.** Added `--without <TAG>` flag to drop domain
  rules carrying specific attributes (e.g. `--without ads`) during binary artifact compilation.
- **Legacy GeoData `.dat` unpacker.** Added `scripts/dat_to_rules.py` to unpack legacy `geosite.dat`
  and `geoip.dat` files into Canonical Rule Source format without linking Protobuf into the runtime.
- **Architectural Decision Record ([ADR-0035](docs/adr/0035-quic-and-http3-in-netune.md)).**
  Ratified migration plan for QUIC and HTTP/3 client transports to `netune-quic` and `netune-http3`,
  consolidating crypto under `aws-lc-rs` and restoring [INV-NETUNE-01].

## [0.0.7] - 2026-11-06

Three subsystems were reworked around one theme: a single declaration, and a gate that proves
it is the single one. This is a patch bump because no configuration key was removed and no
node type was dropped — a 0.0.6 configuration still loads — but the rule-artifact format, the
protocol layer types and the generated kernel ABI all changed shape.

### Added

- **DRB v2 and the canonical rule source ([ADR-0031](docs/adr/0031-drb-v2-and-canonical-rules.md),
  [ADR-0027](docs/adr/0027-one-intermediate-rule-set.md), `[INV-DRB-01]`).** `daer-rule-ast` is
  the new intermediate form: every source is read into one `RuleSet`, and `daer-drb` — which
  replaces `geodrb` — writes DRB v2 from it and nothing else. Two sources naming the same rules
  therefore produce **byte-identical** artifacts, and `compile(decompile(drb)) == drb`.
  `daer-geodata` and its Protobuf decoder are deleted, so the runtime can no longer be the
  thing that speaks `.dat`. `daer-drb compile|decompile|inspect|test` is the operator's entry
  point, and `crates/daer-cli/tests/surface.rs` asserts the daemon links none of it.
- **A flat, front-coded domain table ([ADR-0032](docs/adr/0032-flat-front-coded-domain-table.md)).**
  The reverse-label radix from ADR-0031 was measured at 1.002 nodes per rule — no sharing at
  all — and 7x slower than a flat table on miss-heavy input. A reversed-label-sorted,
  front-coded flat table replaces it: every published artifact is now smaller than its DRB v1
  equivalent (geosite-cn −37%), and `crates/daer-routing/tests/artifact_budget.rs` pins size,
  decode cost and the miss-vs-hit ratio so the next such change has to argue with numbers.
- **VLESS as orthogonal layers ([ADR-0028](docs/adr/0028-protocol-layering.md)).** Transport
  (`tcp`, `ws`) × security (`none`, `tls`, `reality`) × flow (`none`, `xtls-rprx-vision`), one
  type per layer, composed in one place per protocol. Vision belongs to VLESS and REALITY is a
  security layer, so neither can be configured on a protocol that cannot carry it, and an
  unimplemented combination is a load error that names it — Vision over `ws` is refused because
  the reference refuses it on both ends. `tests/layer_matrix.rs` starts one local `xray` with
  five inbounds and takes a round trip through each reachable row, with a plaintext listener
  dialled as `security=tls` as the negative control.
- **VMess AEAD ([ADR-0030](docs/adr/0030-vmess-aead-only.md)).** The reference's KDF is a
  nested HMAC over aliasing hashers, pinned by six vectors taken from `aead.KDF` itself; the
  sealed header, the three size modes, both ciphers and both data planes are implemented. The
  legacy handshake is not expressible — a non-zero `alterId` is a load error rather than a
  silent downgrade to a replayable format. `tests/vmess_live.rs` takes a round trip through a
  real `xray` inbound for `auto`, `aes-128-gcm` and `chacha20-poly1305`.
- **Hysteria 2, complete ([ADR-0029](docs/adr/0029-hysteria2-socket-stack.md)).** The QUIC
  endpoint is built from `AsyncUdpSocket` layers via
  `Endpoint::new_with_abstract_socket`, so a wrapper cannot be forgotten: Salamander and Gecko
  obfuscation, per-flow session ids, fragmentation and reassembly, the server's congestion-
  control answer and Brutal are all on the datapath. Port hopping uses
  `Endpoint::rebind_abstract`. `tests/hysteria2_live.rs` starts the reference server itself,
  including one configured **with** Salamander, so the obfuscation is proven on the wire rather
  than in a struct.
- **`daer check --object` and `daer run --dry-run`
  ([ADR-0025](docs/adr/0025-verification-at-the-privilege-boundary.md), `[INV-PREFLIGHT-01]`).**
  `--object` validates a compiled datapath object — names, sections and BTF `func_info` —
  against the ABI without loading it, which is the gate a packaging pipeline runs against the
  artifact it is about to install. `--dry-run` reports the generation, the object and the
  capabilities the next phase needs, and returns before the port is bound, the device pair is
  created, any sysctl or policy route is written, or `bpf()` is called. Both need no
  capability, and `crates/daer-cli/src/preflight.rs` enforces the separation by type: the
  mutating calls live behind `Daemon::bind` and `datapath::attach`, which it never names.
- **`daer probe` for links and subscriptions.** `probe node` accepts a direct node link as well
  as a configured name, `--all` probes every node in a configuration, and `--file` probes every
  node a subscription lists (one link per line, base64, or SIP008 JSON). All of them resolve
  through one decoder, so a link in a file and the same link in a configuration cannot probe
  differently.

### Changed

- **The kernel ABI is generated, and the checks that guard it are gates rather than prose
  ([ADR-0021](docs/adr/0021-kernel-abi-single-source.md), `[INV-ABI-01]`).** `ebpf/abi.toml` is
  the only declaration of map names, program names, discriminants and struct layouts;
  `cargo xtask abi` writes both `ebpf/kern/daer_abi.h` and `crates/daer-ebpf/src/generated.rs`
  from it, and the header emits `_Static_assert` for every size, alignment and field offset.
  Three things had to change for that to be a mechanism instead of a claim:
  - **The generated files are tracked.** `generated.rs` is a `pub mod` of a crate
    `cargo test --workspace` compiles, and the generator lives in `xtask`, not in a `build.rs`.
    Untracked — which is what ADR-0021 originally said, on reasoning that holds for the C header
    and not for the Rust module — a fresh clone, a `git archive` tarball and the CI `test` job
    all fail with `E0583: file not found for module 'generated'`, and the tree builds only where
    a previous run happened to leave the file behind.
  - **The drift gate runs on pull requests.** `cargo xtask abi --check` regenerates and compares
    byte for byte, and is now a step in the `test` job. Its only caller had been
    `cargo xtask ci`, which `.github/workflows/ci.yml` does not run, so `[INV-ABI-01]` was
    enforced on a developer's machine and nowhere else.
  - **Two privileged CI gates could skip without the job noticing.** `kernel-datapath` set
    `DAER_REQUIRE: "7-tcp,8"` and `scripts/kernel-check.sh` emits neither key; an entry that
    matches no skip is inert, so every check in that job could skip while it stayed green. The
    keys are now the script's own (`kernel-binary,7`), the job builds the test object only
    `cargo xtask ebpf --tests` produces (without it section 7 skipped for a second reason), and
    `3-tcp,4` — the transparent data path and the `SIGHUP` reload — get the `e2e-ingress` job
    they never had, because `scripts/e2e-check.sh` could already do that work with no caller.
- **The datapath is a set of modules, and its tests are Rust
  ([ADR-0024](docs/adr/0024-datapath-source-layout.md),
  [ADR-0022](docs/adr/0022-datapath-tests-are-rust.md),
  [ADR-0020](docs/adr/0020-datapath-is-daer-own.md)).** `ebpf/kern/tproxy.c` drops from 4,436
  lines to an include list plus the licence string, with the logic split under
  `ebpf/kern/src/` by **map ownership and attach domain** — the cut lines are what a module
  writes and where it attaches, not directory convention. One translation unit is kept
  deliberately: the 512-byte stack budget depends on clang seeing the whole call graph, so the
  split is a source boundary and not a link boundary. The Go harness is replaced by
  `crates/daer-ebpf/tests/datapath.rs`, which discovers the `pktgen_`/`setup_`/`check_` triples
  from the object itself — a case list enumerated in Rust would be a second source that goes
  stale the first time somebody adds a case.
- **The loader loads; it does not repair.** `crates/daer-ebpf/src/elf.rs` is deleted. The C
  spells section names the way `aya` parses them, so the load-time ELF/BTF rewrite that used to
  paper over a mismatch is not just unnecessary but has nowhere to be added back silently. The
  section-prefix rule is checked from `ebpf/abi.toml` instead.
- **`DomainIndex`/`DomainKey` are gone
  ([ADR-0033](docs/adr/0033-one-domain-table-two-vocabularies.md)).** One `DomainTable` serves
  the artifact, the evaluator and inline rules, which removes the 38 ms per-generation bridge
  between two structures that meant the same thing. Routing accepts only `full:` and `suffix:`
  (a bare name is a suffix in both the configuration and a `.rules` file); `keyword:` and
  `regex:` move to `daer-dns`, which owns the exclusion language that actually needs them, and
  `aho-corasick` leaves `daer-routing`.
- **`OpenDatagram` returns the dial target with the connector** (`DatagramLeg`) instead of the
  relay asking twice (`dial_target` then `open_datagram`). The two calls could straddle a
  reload, so a datagram flow could be dialed to a target that the rule which opened its leg had
  never chosen.

### Fixed

- **`--dry-run` claimed to attach the datapath.** Its help text said "attach the datapath and
  exit without serving", which is the opposite of what it does and of what
  [ADR-0025](docs/adr/0025-verification-at-the-privilege-boundary.md) promises: the command
  returns before any mutation, which is the only reason it needs no capability and the only
  reason a dry run can be believed. The text now says what the code does, and distinguishes
  itself from `--no-datapath`, which does serve and skips only the kernel half.
- **The packaging plan installed a binary that no longer exists and gated on the network.**
  `packaging/daer.plan.toml` shipped `geodrb`, deleted with ADR-0031, so a package build would
  have failed at `install`; it installs `daer-drb` now. Its compile-time gate ran
  `daer check --config daer.example.toml`, whose `[[rule-provider]]` tables are `http` sources,
  so the gate needed the network and a published artifact to exist — and failed for reasons that
  had nothing to do with the object it is supposed to validate. It now checks a self-contained
  configuration, the same minimal one `cargo xtask preflight` writes, for the same reason.
- **`cargo xtask e2e-check` did not exist.** `scripts/e2e-check.sh` was written to verify the
  user-space ingress path and the `SIGHUP` reload, and nothing invoked it: `xtask` dispatched
  only `kernel-check`. The two scripts answer different questions over different dependency
  closures, so both are now named subcommands rather than one entry point.
- **Documentation that pointed at what the tree no longer has.** `AGENTS.md` routed to
  `docs/dev/standards/testing.md`, deleted in favour of
  [ADR-0007](docs/adr/0007-verification.md); `docs/dev/standards/workflow.md` told contributors
  to run `make ci`, and there is no `Makefile` — the gates live in `cargo xtask ci` — and named
  `daer-outbound/tests/*` for suites that moved to `daer-proxy-protocols`. `docs/dev/build-and-run.md`
  named crates (`daer-daemon`, `daer-ctl`), a script (`scripts/run-in-netns.sh`) and a
  configuration path that have never existed in this tree; it now describes the tasks the
  repository actually has.

## [0.0.6] - 2026-11-06

### Changed

- **The crate graph is split by reason-to-change, not by history.** Three boundaries were made
  explicit, each recorded in an ADR:
  - **ADR-0017** — proxy product protocols (shadowsocks, trojan, anytls, hysteria2, reality) and
    the minimal TLS 1.3 client moved out of `daer-outbound` into a new `daer-proxy-protocols`.
    `daer-outbound` drops from ~13k to ~4.7k lines and from 30 dependencies to 13: it is now
    only outbound governance (groups, alive sets, measured latency, probes, filters,
    subscriptions) and no longer pulls `quinn`, `h3`, `rustls`, `x25519-dalek` or `ml-kem` into
    anything that merely wants a health check.
  - **ADR-0018** — transparent ingress, `splice`, the UDP session table and flow supervision
    moved out of `daer-control` into a new `daer-relay`. `daer-control` decides; `daer-relay`
    carries. The seam is `Decide` and `DatagramRouter`, and neither names a `Verdict`, a group or
    a policy, so adding a routing concept no longer touches the accept loop and the accept loop's
    tests no longer need a configuration.
  - The ingress half is spelled `inbound` in one place everywhere (`inbound::tcp`,
    `inbound::udp`). It previously mixed `inbound` and `ingress_udp` — the packet-direction
    vocabulary and the proxy vocabulary — inside the same crate.
- `OpenDatagram` now returns the dial target **with** the connector (`DatagramLeg`) instead of
  the relay asking twice (`dial_target` then `open_datagram`). The two calls could straddle a
  reload, so a datagram flow could be dialed to a target the rule that opened its leg had never
  chosen.

### Fixed

- **HTTPS through a REALITY + Vision node did not work at all.** A reference node switches its
  downlink to an XTLS **raw copy** — `Direct` — on the first application-data record after the
  inner `ServerHello`, and stops encrypting: Xray's `VisionWriter` then writes through
  `buf.NewWriter(rawConn)`. daer's reader understood `Direct` as "stop unpadding" only, so its
  record layer kept decrypting plain socket bytes and the session died with
  `AES-128-GCM open failed: the record was altered`. `curl http://…` through the node always
  worked and `curl https://…` never did, which is why `daer probe node` (whose e2e tier was a
  plaintext GET) reported the node as fully operational while every real browsing session broke.
  `Tls13Connection` now carries a `raw_read` switch that Vision sets when it parses `Direct`, and
  `poll_read` hands back socket bytes from that point on. Verified against a local reference node
  with a local TLS origin: before, `unexpected eof while reading` on every attempt; after,
  `<!DOCTYPE HTML>` three runs in a row, with `probe node --url https://…` reaching a public site.
  `a_direct_block_asks_the_layer_below_to_stop_decrypting` pins the reporting, with `Continue` and
  `End` as the negative controls.
- **`daer probe node --url https://…` wrote a plaintext request to port 443.** The e2e tier
  hand-built `GET … HTTP/1.1` and wrote it into the tunnel, which is only correct for `http://`.
  For an HTTPS URL the bytes went out in cleartext, the peer reset, and the probe blamed the node;
  against a public site it "passed" only because an edge answered `400`. It now uses the crate's
  own HTTP client through a one-shot `TunnelConnector`, so TLS is negotiated *inside* the tunnel —
  which is what a TLS probe means.
- **The REALITY interop gate was failing for reasons that were the fixture's fault, not the
  transport's.** `tests/reality_interop.rs` pointed the node's `dest` at `www.microsoft.com:443`,
  so the one test able to catch a REALITY/Vision regression depended on Microsoft's uptime and on
  the machine's egress: it failed intermittently with `the peer closed during the handshake` and
  nothing wrong in this crate. It now starts its own TLS 1.3 destination from checked-in fixture
  certificates (`crates/daer-outbound/tests/fixtures/`, a 7-certificate chain chosen so the
  handshake has realistic record sizes — a small one makes the *node* fail its own padding check),
  and the tunnel is asserted end to end against a **local** HTTP origin instead of
  `example.com:80`. Three separate fixture defects were hiding behind that:
  - the node's log was sent to `Stdio::null()`, so every failure that said "the node's own log
    said:" printed an empty string — the one piece of evidence REALITY and Vision need, because
    both fail silently;
  - since Xray v26.4.15 a `freedom` outbound blocks private and reserved addresses by default for
    flows that arrived through a proxy inbound, and blackholes them for 30-90 s. A local origin is
    a private address, so the node accepted the request, logged `blocked target … blackholing
    connection`, and the client timed out with an empty reply — indistinguishable from a broken
    tunnel. The fixture now grants `finalRules: [{action: allow, ip: ["127.0.0.0/8"]}]`, which is
    a fixture permission and not something a production node should do;
  - a hang reported only "the reply must not hang"; it now prints the partial reply and the node's
    log.
  `DAER_REALITY_DEST` still overrides the destination with a real site,
  `DAER_REALITY_SNI` names the SNI when the destination is an address.
- **The shell's data path check called a pass a skip.** `scripts/kernel-check.sh` section 7
  grepped for any `skipped:` line and reported the whole section as a skip, so a box that cannot
  create a second network namespace (the UDP test's stated prerequisite) read as "nothing was
  proven" even though the TCP redirect, the proxy, and the nonce assertion all passed. The two
  paths are now reported separately.
- **A `SIGHUP` killed the daemon.** `reload` was synchronous and called `block_on(...)` to re-run
  the shared configuration loader, but it runs inside `daemon.serve`'s `select!` — inside the
  multi-threaded runtime — so Tokio refused it outright (`Cannot start a runtime from within a
  runtime`). The main task panicked, the process exited, and every in-flight flow died with it,
  on the *first* reload. Awaiting the loader directly is both the fix and the compile-time
  guarantee: `load_resolved` is `async`, so nothing in the reload path can block a worker again.
  `crates/daer-cli/tests/reload.rs` starts the real binary, sends `SIGHUP`, and asserts the
  process is alive *and* that generation 2 was published; it fails against the old code within
  milliseconds. `scripts/kernel-check.sh` section 8 is what runs it, because a skip in a bare
  container is not evidence about a signal handler.
- **An empty configuration was unrunnable.** `Global::default()` had `wan-interface = []` while
  `daer run` refuses an empty list ("cannot know which interface carries proxied traffic") — so
  `printf 'schema = 1\n'` was reported valid by `daer check` and rejected by `daer run`, and both
  `docs/reference/configuration.md` and `daer.example.toml` said the default was `["auto"]`. The
  default is now `["auto"]`, which is what the reference and the example always promised, and
  `the_defaults_are_a_configuration_the_daemon_can_run` pins it.
- **A `[[group]]` named after a builtin outbound silently meant the builtin.** A configuration
  with `[[group]] name = "direct"` whose only node pointed at a dead SOCKS port loaded cleanly,
  `daer route` reported that node as the selected outbound, and the daemon dialled the flow
  *directly* and returned the origin's bytes — the configuration said one thing and the daemon
  did another. `direct`, `block`, `must_rules`, `<OR>`, `<AND>` and `<Control Plane Routing>` are
  now rejected as group names at load time, from one list in `daer-common` that the rule lowering
  also uses, so the two cannot drift apart.

### Removed

- **`dial-mode` from the configuration reference.** It was documented (and in an ADR's key list)
  but never existed in the model, so `deny_unknown_fields` rejected it. `daer` sniffs whenever a
  rule can use a domain; there is no separate knob. The reference now also documents the keys it
  had been omitting (`sniffing-timeout`, `auto-sniff-punt`, `allow-insecure`, all of
  `[global.health-check]` and `[dns.fake-ip]`) and drops `cache-size`, which is spelled
  `max-cache-size`.

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
