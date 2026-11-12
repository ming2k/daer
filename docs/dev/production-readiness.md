# Production Readiness

This page is the release gate for putting `daer` in front of real traffic. It is not a
feature list. A build that passes unit tests is not automatically a production build.

> **Current verdict (2026-11-12): not production-ready for general traffic.**
>
> The tree is ready for a staging host and a controlled TCX delivery test. The final delivery
> gate has not been run on a target Linux 6.6+ host, and the known gaps below still exclude
> several production claims.

## 1. What "production ready" means

A production candidate must pass every gate in this section on the target kernel and hardware,
not only on a developer machine.

| Gate | Command | What it proves |
| :--- | :--- | :--- |
| Build and unit contract | `cargo xtask ci` | fmt, clippy, unit/integration tests, ABI/event/incident checks, unprivileged preflight |
| Kernel datapath | `cargo xtask kernel-check` | verifier acceptance, TCX attachment, in-kernel datapath cases |
| Userspace data path | `cargo xtask e2e-check` | transparent relay, IPv6 UDP, private ingress lifecycle, `SIGHUP` reload |
| Real delivery | `sudo scripts/ops/daer-delivery-check.sh --config <site.toml>` | real daemon, real TCX, real node, `example.com` returns 200 |
| Termination | the same delivery check | `SIGKILL` leaves no TCX link, qdisc, veth, namespace or `daer0` sysctl |
| Install and lifecycle | `cargo xtask install`, then systemd start/stop/reload | the packaged unit starts, reloads, drains and restarts without stale state |
| Soak | at least 24 h of representative traffic | no fd/map/session leak and no unbounded memory growth |

The site configuration used by the delivery check is **not** in the repository. It belongs under
the ignored `target/` directory or outside the tree, and must be readable only by the operator.

## 2. Mandatory production checklist

- [ ] `cargo xtask ci` passes on the release commit.
- [ ] `cargo xtask kernel-check` passes on the target Linux 6.6+ kernel.
- [ ] `cargo xtask e2e-check` passes; no `DAER_REQUIRE` check is skipped.
- [ ] `daer-delivery-check.sh` prints `TCX delivery: ... returned 200`.
- [ ] The same run prints the `SIGKILL` line proving no daer-owned network state survives.
- [ ] TCP, UDP (if required), IPv4 and IPv6 match the intended deployment.
- [ ] The host has been prepared according to [Test Environment Requirements](test-environment.md).
- [ ] The `so-mark` value used by the host firewall is `0x64616572` unless the site config
      deliberately sets another value; the nftables/iptables rules use the same value.
- [ ] A systemd install/upgrade/rollback path has been exercised on a disposable host.
- [ ] A 24-hour soak has completed with no leaked sessions, fds or maps.
- [ ] `daer status --json` returns a snapshot while traffic is being proxied.
- [ ] A failed daemon start leaves no `daer0`, `daer0ns`, TCX link or stale sysctl behind.

## 3. Known gaps

These are not documentation caveats; they are reasons a production rollout can fail.

- **IPv4 UDP tproxy is not proven end to end.** IPv6 UDP has a two-namespace fixture.
  IPv4 UDP still lacks the topology that proves the transparent reply path. If the deployment
  needs UDP, this is a blocker.
- **The TCX delivery gate is the final proof.** A successful TCX attach is not delivery; the
  real daemon must move a real flow through the listener and return a response.
- **`pname` rules are not currently backed by attached cgroup hooks.** The eBPF object still
  contains cgroup programs, but the loader does not attach them. A `pname(...)` rule therefore
  must not be treated as a working production feature until the hooks are wired or removed.
- **The eBPF object still contains unwired programs and maps** (cgroup hooks, TCP offload
  programs, and combined-role classifier variants). They do not disable the TCX path, but the
  object is not a minimal, fully-owned surface yet.
- **Coexistence with other eBPF programs is not a tested production mode.** TCX chain order,
  socket assignment and cgroup rewrites can preempt or bypass daer. Use a clean test host
  unless the interaction has been deliberately designed and verified.
- **No production soak or capacity test is recorded in this repository.** The unit and
  delivery gates prove correctness of a flow, not sustained load.

## 4. Release rule

Do not create a release tag for a production claim until the delivery check has passed on the
target kernel and its output has been attached to the release review. A green `cargo xtask ci`
alone is not enough: it runs deterministic tests, not the real TCX delivery path.

For host preparation, including removal of an old `dae` installation or another proxy, see
[Test Environment Requirements](test-environment.md).
