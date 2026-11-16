# Production Readiness

This page is the release gate for putting `daer` in front of real traffic. It is not a
feature list. A build that passes unit tests is not automatically a production build.

> **Current verdict (2026-11-16): release candidate for staging; not certified for general
> traffic.**
>
> `0.1.3` is the current patch release; `0.1.0` was the first tagged release
> candidate. The build and unprivileged contract is green, and the userspace ingress,
> private-ingress lifecycle and restart behaviour pass inside a disposable user namespace.
> The privileged delivery, `SIGKILL`, systemd lifecycle, UDP
> two-namespace and soak gates have not been run on a target Linux 6.6+ host, and the known
> gaps below still exclude several production claims.
>
> Current evidence (2026-11-16): `cargo nextest run --workspace --locked` (1050 passed,
> 16 ignored), `cargo test --workspace --doc --locked`, `cargo build --release --workspace
> --locked`, `cargo +1.95.0 check --workspace --all-targets --locked`, `cargo deny check`,
> `cargo xtask preflight`, and the `control_netns_lifecycle` plus IPv4/IPv6 TCP
> `control_transparent` cases pass under `unshare -Urnm`. The kernel gate includes the six
> cgroup v2 `pname` hooks. The two-namespace IPv4/IPv6 UDP cases and all target-host runs are
> still pending.

## 1. What "production ready" means

A production candidate must pass every gate in this section on the target kernel and hardware,
not only on a developer machine.

| Gate | Command | What it proves |
| :--- | :--- | :--- |
| Build and unit contract | `cargo nextest run --workspace` + `cargo fmt --check` + `clippy` | unit/integration/doc tests, test-architecture audit, ABI/event/incident checks, unprivileged preflight |
| Kernel datapath | privileged `e2e` kernel filters (`ebpf_kernel::*`, `ebpf_datapath::*`; see [Testing §5](testing.md#5-ignored-tests-and-privileged-gates)) | verifier acceptance, TCX and cgroup v2 hook attachment, in-kernel datapath cases |
| Userspace data path | privileged `e2e` ingress filters (`control_transparent*`, `control_netns_lifecycle`, `cli_reload`; see [Testing §5](testing.md#5-ignored-tests-and-privileged-gates)) | transparent relay, IPv4/IPv6 UDP, private ingress lifecycle, `SIGHUP` reload |
| Real delivery | `sudo scripts/delivery-check.sh --config <site.toml>` | real daemon, real TCX, real node, `example.com` returns 200 |
| Termination | the same delivery check | `SIGKILL` leaves no TCX link, qdisc, veth, namespace or `daer0` sysctl |
| Install and lifecycle | `scripts/install.sh`, then repeated `systemctl restart daer` and one `stop`/`start` | the packaged unit starts, reloads, drains, and survives repeated restarts and a stop/start without stale state |
| Soak | at least 24 h of representative traffic | no fd/map/session leak and no unbounded memory growth |

The layers, their placement rules, and the reason a skip is not coverage are defined in
[Test Architecture](testing.md) (ADR-0052).

The site configuration used by the delivery check is **not** in the repository. It belongs under
the ignored `target/` directory or outside the tree, and must be readable only by the operator.

## 2. Mandatory production checklist

- [ ] `cargo nextest run --workspace` and the non-test checks pass on the release commit.
- [ ] The privileged kernel `e2e` cases pass on the target Linux 6.6+ kernel and print no
      `skipped: ` line.
- [ ] The privileged ingress `e2e` cases pass and print no `skipped: ` line.
- [ ] `scripts/delivery-check.sh` prints `TCX delivery: ... returned 200`.
- [ ] The same run prints the `SIGKILL` line proving no daer-owned network state survives.
- [ ] TCP, UDP (if required), IPv4 and IPv6 match the intended deployment.
- [ ] The host has been prepared according to [Test Environment Requirements](test-environment.md),
      including a cgroup v2 unified hierarchy for `pname`.
- [ ] No host firewall rule depends on a site-configured socket mark; the mark is internal
      (`0x64616572`) and the datapath compares it itself.
- [ ] A systemd install/upgrade/rollback path has been exercised on a disposable host.
- [ ] A 24-hour soak has completed with no leaked sessions, fds or maps.
- [ ] `daer status --json` returns a snapshot while traffic is being proxied.
- [ ] A failed daemon start leaves no `daer0`, `daer0ns`, TCX link or stale sysctl behind.
- [ ] `state.json`, `events.jsonl`, incident bundles and `persist.d` are `0600`/`0700`,
      not world-readable; the unit carries `UMask=0077`.
- [ ] A pre-TCX `/usr/bin/daer-cleanup` and `/usr/lib/daer/datapath.o` are absent after upgrade.

## 3. Known gaps

These are not documentation caveats; they are reasons a production rollout can fail.

- **UDP tproxy must be green on the target host.** IPv4 and IPv6 now each have a
  two-namespace fixture (`transparent_udp4.rs`/`transparent_udp6.rs`, required as
  `3-udp4`/`3-udp6`). A local workspace skip is not coverage; the target gate must run both.
- **The TCX delivery gate is the final proof.** A successful TCX attach is not delivery; the
  real daemon must move a real flow through the listener and return a response.
- **The `pname` cgroup hooks must attach on the target host.** The loader attaches all six
  cgroup v2 hooks at startup; if the kernel has no unified hierarchy or the attach is denied,
  the daemon refuses to start. The privileged kernel gate now includes that attach, but the
  real target-host result is still required.
- **The eBPF object no longer carries unattached classifier variants.** The inherited
  TCP-offload path and the combined-role classifiers were removed; the supported topology is
  one role per interface, and overlap is rejected. The object now consists of the attached
  TCX classifiers, the attached cgroup v2 hooks, and the maps/telemetry they use.
- **Coexistence with other eBPF programs is not a tested production mode.** TCX chain order,
  socket assignment and cgroup rewrites can preempt or bypass daer. Use a clean test host
  unless the interaction has been deliberately designed and verified.
- **No production soak or capacity test is recorded in this repository.** The unit and
  delivery gates prove correctness of a flow, not sustained load.

## 4. Release rule

A `0.x` tag is a release of the code, not a production certification. Do not describe a tag
as production-ready until the delivery check has passed on the target kernel and its output
has been attached to the release review. A green `cargo nextest run --workspace` alone is not
enough: it runs deterministic tests, not the real TCX delivery path.

For host preparation, including removal of an old `dae` installation or another proxy, see
[Test Environment Requirements](test-environment.md).
