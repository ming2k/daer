---
id: ADR-0042
title: "TCX is the only TC attachment, and Linux 6.6 is the minimum kernel"
status: accepted
date: 2026-11-12
scope: [datapath/attach, ebpf/loader, architecture/lifetime, packaging]
supersedes: []
superseded_by: []
amends: [ADR-0013, ADR-0025, ADR-0038, ADR-0040]
---

# 0042. TCX is the only TC attachment, and Linux 6.6 is the minimum kernel

- Status: Accepted
- Date: 2026-11-12
- Deciders: daer maintainers
- Related: [ADR-0013](0013-datapath-state-ownership.md),
  [ADR-0025](0025-verification-at-the-privilege-boundary.md),
  [ADR-0038](0038-private-ingress-network-namespace.md),
  [ADR-0040](0040-typed-diagnostic-plane.md)

## Context

The datapath must attach eBPF classifiers to the host's LAN/WAN interfaces and to the
private ingress veth pair. Classic `cls_bpf` does that by creating a `clsact` qdisc and a
netlink filter. Those objects belong to the kernel, not to the daemon: they survive
`SIGKILL`, panic-abort, OOM kill and a systemd stop timeout. A stale filter keeps
redirecting traffic into a transparent listener that no longer exists.

The previous architecture therefore carried a crash journal, an `ExecStopPost=daer-cleanup`
helper, a qdisc-ownership check and a legacy restore path. That machinery worked, but it
treated the symptom: the process could not own the attachment, so another process had to
clean up after it. A separate helper also had to copy incident bundles out of tmpfs.

Linux 6.6 introduced TCX, an fd-owned `bpf_link` attachment for TC programs. A TCX link has
the same lifetime as its file descriptor: closing the last fd detaches the program, and the
kernel closes every fd when a process exits. TCX also creates no qdisc, so there is no
operator-owned qdisc to preserve and no `tc` mutation to journal.

The project has decided to stop supporting the classic path and the kernels below TCX. This
is a deliberate breaking change: no backward-compatible fallback, no legacy journal format,
no `daer-cleanup` compatibility window.

## Decision

1. **Linux 6.6 is the minimum kernel.** `daer-ebpf::loader::require_tcx` reads the running
   kernel and fails with a named error when TCX is unavailable. `daer run` calls it before
   any configuration is served or any kernel state is created. `daer check --host` calls it
   as part of the host gate; `daer check` without `--host` stays an object/config gate so a
   build machine does not have to run the target kernel.

2. **TCX is the only TC attachment.** `attach_tc` has no mode parameter. It loads the
   classifier and attaches with `TcAttachOptions::TcxOrder(LinkOrder::default())`. The
   `DAER_TC_ATTACH` environment variable, the classic netlink branch, `ensure_clsact`,
   `ClsactQdiscs`, qdisc deletion and name-based filter detach are deleted. There is no
   fallback and no compatibility switch. The datapath's verdict vocabulary is TCX too:
   `DAER_TC_NEXT/PASS/DROP/REDIRECT` are defined from the TCX action values, and product C
   does not use the classic `TC_ACT_*` names.

3. **The ingress namespace owns the veth pair from creation.** `PreparedIngress::prepare`
   creates `daer0ns` first, then creates the pair with
   `ip link add daer0 type veth peer name daer0peer netns daer0ns`. There is no interval in
   which both ends live in the host namespace. The namespace mount is private to the
   daemon's mount namespace, so process death releases the namespace, the peer, the host
   end, the namespace-local routes and the per-device sysctls together.

4. **There is no crash journal and no post-stop cleanup helper.** `daer-cleanup`, its Cargo
   binary, the systemd `ExecStopPost=` hook, `cleanup_system_state`, the restore journal,
   the legacy host-rule cleanup and the packaging/install entries are removed. Every
   daer-owned network object is either an fd-owned TCX link, a socket, or namespace-owned
   state. None of them needs a second process to release it.

5. **Host-global sysctls remain operator prerequisites.** `check_host_sysctls` reads them
   and refuses to start when they are missing. The daemon never writes them, so there is
   nothing to restore after a crash. Per-device sysctls under `daer0`/`daer0peer` disappear
   with the devices and are not journaled.

6. **Incident bundles are written directly to persistent storage.** The daemon writes
   `/var/lib/daer/incidents/<id>/` (or `DAER_INCIDENT_DIR`). The tmpfs fallback and the
   helper that copied it after a stop are deleted. An incident that only exists until the
   next stop is not an incident artifact.

7. **No legacy state is adopted or repaired at startup.** A stale qdisc/filter or journal
   left by a pre-TCX release is not a supported upgrade path. Operators upgrading across
   this boundary remove it explicitly before starting the new binary. The daemon does not
   inspect or mutate old host state to make a migration appear seamless.

8. **Two privileged gates are release requirements, not optional diagnostics.**
   - `scripts/ops/daer-delivery-check.sh` must show `example.com http=200` through the real
     daemon. Attachment alone is not delivery; the earlier TCX trial attached but did not
     put the assigned packet on the listener's accept queue.
   - The same script kills the daemon with `SIGKILL` and asserts that no TCX link, qdisc,
     veth, daemon namespace or `daer0` sysctl remains, and that direct traffic recovers.

## Negative Knowledge & Discarded Alternatives

- **Keep classic `cls_bpf` for Linux 5.17–6.5.** Rejected. It makes the kernel's TC objects
  outlive the process, which forces the journal, the helper and the qdisc-ownership
  machinery this ADR deletes. Supporting both modes would keep the old failure surface in
  the code even on 6.6+ hosts.
- **Keep `daer-cleanup` only for incident bundles.** Rejected. Incident bundles are written
  to a persistent path by the daemon; a tmpfs bundle that needs a post-stop copier is not
  self-contained.
- **Pin TCX links to bpffs for observability.** Rejected. Pinning changes the ownership
  model back to kernel-persistent and defeats automatic detach. The loader must not pin.
- **Let a fork/child hold the link fd.** Rejected. The fd would outlive the daemon. The
  process must not spawn a long-lived child that inherits TCX links.
- **Rely on `Drop`, `atexit` or a panic hook for crash cleanup.** Rejected. `SIGKILL`, OOM
  and abort paths do not run user code. The kernel owns the resources instead.
- **Treat a successful TCX attach as delivery proof.** Rejected. The prior trial proved
  attachment but not `bpf_sk_assign` delivery; the e2e gate is the falsifier.
- **Use a 5.17-compatible fallback for old enterprise kernels.** Rejected. Debian 12 (6.1)
  and RHEL 9 (5.14) are outside the support matrix. The minimum is the TCX kernel, 6.6.

## Consequences

- The support matrix starts at Linux 6.6 with `CONFIG_NET_XGRESS`/TCX. Debian 12, RHEL 9
  and other pre-6.6 kernels are not supported.
- `daer run`, `daer check`, the systemd unit and the install set no longer name
  `daer-cleanup`; the binary and the journal disappear.
- A `SIGKILL` leaves no daer-owned host TC state. The ingress namespace and the veth pair
  are destroyed with the process, and TCX links detach when their fds close.
- Upgrading from a pre-TCX release requires an explicit operator cleanup of any stale host
  TC state. That is a clean break, not a migration the daemon performs.
- The TCX delivery and `SIGKILL` lifetime checks are mandatory appended to the privileged
  verification suite. A green build that has not run them is not a release candidate.
- The current 6.6 minimum is the TCX floor, not a promise that 6.6 remains the preferred
  baseline forever. A future LTS raise is a separate ADR and must not reintroduce a
  compatibility branch.
