# ADR-0025 — Verification is split at the privilege boundary, and `--dry-run` means "change nothing"

- Status: accepted
- Date: 2026-11-06
- Refines: [ADR-0007](0007-verification.md)
- Enforced by: [INV-PREFLIGHT-01](../dev/standards/invariants.md)

## Context

The daemon has exactly one startup path, and it interleaves three things that have
different privilege requirements and different reversibility:

1. **Pure computation** — load the configuration, build a generation, lower every rule,
   decide whether the kernel policy is provably equivalent or must defer.
2. **System resource acquisition** — create the private ingress namespace, create and move
   the `daer0`/`daer0peer` pair, bind the transparent listeners inside the namespace, read
   its MAC and ifindex, write sysctls, and install the namespace-local policy route.
3. **Kernel attachment** — load the object, attach 23 programs to `clsact` and cgroup hooks.

Step 1 needs nothing. Step 2 needs `CAP_NET_ADMIN` and `CAP_SYS_ADMIN` and mutates the box.
Step 3 needs `CAP_BPF` in addition, plus `CAP_PERFMON` for the verifier's `allow_ptr_leaks`
(the fast parser advances a packet pointer by header lengths read at runtime).

`daer run --dry-run` was documented as a preflight and implemented as "do all three, then
exit". That is not a dry run. It binds a port, creates a veth pair, writes
`/proc/sys/net/ipv4/conf/daer0peer/rp_filter`, and installs a policy route before it prints
`--dry-run: datapath attached, exiting without serving`. On an unprivileged machine it dies
partway through — after some of the mutation has already happened — which is the worst of
both: it neither previews nor cleans up.

The consequence is observed, not theoretical. Verifying a datapath change on a development
box required `sudo`, and the failure that came back was
`cannot attach the datapath: … failed to create map 'daer_ifindex_map'` — a capability
failure being reported by the *attachment* code, several layers away from the check that
would have named it.

There is a second, independent hole. `daer check` validates the configuration and nothing
else. It does not look at the compiled object at all, so a `datapath.o` whose section names
`aya` cannot parse, whose BTF `func_info` drifted, or whose map set no longer matches
`ebpf/abi.toml` passes `daer check` and fails at attach time — in production, as a crash
loop. `tests/object.rs` does check those things, but a test is not a gate an operator or a
packaging script can run against the artifact they are about to install.

## Decision

1. **The split is at the privilege boundary, and it is the definition of the two gates.**
   A check belongs in the unprivileged gate if and only if it can run without `CAP_BPF` or
   `CAP_NET_ADMIN` and without mutating the box. Everything else is the privileged gate.

   | Gate | Runs | Needs |
   | --- | --- | --- |
   | `daer check` | configuration, rule lowering, kernel-policy equivalence, **object against the ABI** | nothing |
   | `daer run --dry-run` | the above, plus interface resolution, the runtime parameter that *would* be published, and a capability report | nothing |
   | `daer run` | all of the above, then namespace creation, port bind inside it, device pair, sysctls, routes, BPF load, tc attach | `CAP_BPF` + `CAP_NET_ADMIN` + `CAP_PERFMON` + `CAP_SYS_ADMIN` |

2. **`--dry-run` changes nothing, and that is enforced by construction rather than by
   discipline.** The mutation calls (`PreparedIngress::prepare`, `Daemon::bind_in`,
   `Sysctl::apply`, `RouteTable::install`, `datapath::attach`) are all downstream of a single
   `Preflight::plan()` call, and `run` returns immediately after printing the plan when
   `--dry-run` is set. There is no ordering in which a dry run can reach a mutating call,
   because the dry-run branch precedes every one of them.

   This required separating `Daemon::bind` — which both binds a port and builds the first
   generation — from generation building. A preflight builds a `Generation` directly
   (`Generation::build`, already public) and never constructs a `Daemon`. The port it
   reports is the one *the configuration asks for*, and whether it is free is checked by a
   bind-and-immediately-drop that is reported as a fact, not as a takeover.

3. **`daer check --object <path>` validates the compiled artifact against the ABI.**
   It parses the object with the same crate the loader uses and asserts the invariants that
   otherwise only fail inside the kernel:
   - every map in `ebpf/abi.toml` exists in the object, and every program name resolves;
   - every program's section is one `aya` parses (a `tc/<name>` section is a build error,
     caught here instead of at attach);
   - after reproducing `aya`'s call relocation, every program's first `func_info` record is
     at instruction 0 — the invariant whose violation took `daer.service` down with
     `nonzero insn_off 3 for the first func info record`;
   - the object declares `MAX_MATCH_SET_LEN` at least as large as the policy needs.

   `--object` defaults to the same resolution `run` uses, so `daer check -c …` on a machine
   with a built object validates it without anyone passing a flag.

4. **Kernel-policy equivalence is reported by `check`, not just logged at startup.** The
   distinction between "the kernel reproduces userspace's answer" (`split`) and "the kernel
   hands every flow to userspace" (`defer`, ADR-0005/ADR-0011) is a *performance* property
   with a large blast radius, and it is currently only discoverable from a running daemon's
   log. `check` prints the tier and, for `defer`, the reason. An operator can then see
   before deploying that `domain(...)` rules force the deferral tier.

5. **The privileged gate keeps its own script and does not depend on the unprivileged one.**
   `scripts/kernel-check.sh` already answers "does the object load and behave" and
   `scripts/e2e-check.sh` answers "does a redirected flow come back". Neither is merged into
   `daer check`, because they need capabilities and the point of this ADR is that a
   capability requirement is a property of the *check*, not of the project.

6. **A capability failure is named where it is detected.** `Preflight` reports
   `CAP_BPF`/`CAP_NET_ADMIN`/`CAP_PERFMON`/`CAP_SYS_ADMIN` by reading `CapEff` from
   `/proc/self/status` (a read-only check) and states plainly which gate cannot run here —
   instead of letting the attachment code discover it as
   `failed to create map 'daer_ifindex_map'` or a verifier rejection. `CAP_SYS_ADMIN` is
   required by the private ingress namespace (ADR-0038), not by configuration loading.

## Consequences

- A developer on an unprivileged machine can answer "is this configuration and this object
  self-consistent, and what would the daemon try to do" with `daer run --dry-run`, in the
  same second, without `sudo` and without leaving state behind.
- A packaging script can gate on `daer check` over the artifact it is about to install,
  which is the first time the *installed* object is validated rather than a freshly built
  one in `target/`.
- `--dry-run`'s previous behaviour is removed, not deprecated. There is no flag that
  partially attaches; an operator who wants the real thing runs the real thing.
- `run`'s happy path is now visibly two phases — plan, then apply — which is also where a
  future `--resume`/`--adopt` would hook in. The plan is a value, so it can be printed,
  tested and diffed.
- The object checks in `daer check` duplicate assertions that `tests/object.rs` makes. That
  duplication is deliberate: the test proves the *repository* is consistent, the gate proves
  the *artifact you are holding* is. They fail for different reasons and are read by
  different people.
- `daer check` gains a dependency on `daer-ebpf`'s object-parsing path (already a dependency
  through `daer-control`), so no new crate is introduced.

## Addendum — the gate's real position is the packaging pipeline

The decision above put the object check in `daer check`, which a human runs. That is the
right shape but the wrong *position*: the failure this gate exists to catch (`nonzero insn_off
3 …` crash-looping `daer.service`) reaches production through a package, not through a
developer typing a command.

`packaging/daer.plan.toml` therefore runs the gate twice, both unprivileged:

1. **`pipeline.compile`**, against `target/ebpf/datapath.o` and `daer.example.toml`. This
   catches a repository that is internally inconsistent — and, because `xtask ebpf`
   regenerates the ABI first, a clean checkout that has never been built here.
2. **`pipeline.staging`**, against `${STAGING_DIR}/usr/lib/daer/datapath.o` — the exact path
   the service unit passes to `daer run`. This is the one that matters: it validates the
   artifact *as it will be installed*, so a stale or drifted object fails the build instead of
   crash-looping under systemd.

The staging check is why `--object` had to accept an arbitrary path rather than only the
default: the default resolves through the install locations, which do not exist yet at
staging time.

Verified by construction, not by inspection: swapping the packaged object for the one that
caused the production outage makes the staging command exit 1 with
`invalid program section 'tc/lan_egress_l2'`.

## Addendum — the private namespace joins the privileged gate (ADR-0038)

`daer run` now creates `daer0ns`, moves `daer0peer` into it, and binds the transparent
listeners there. Creation, link movement, `setns(2)` and the `/run/netns` mount all require
`CAP_SYS_ADMIN`; the shipped unit carries it and `RuntimeDirectory=netns`/`ReadWritePaths`
make the mount point writable under `ProtectSystem=strict`.

The unprivileged gate is unchanged: `daer check` and `daer run --dry-run` still perform no
namespace creation. The preflight reports `CAP_SYS_ADMIN` alongside the three datapath
capabilities, and the dry-run mutation boundary now begins at `PreparedIngress::prepare`
rather than at `Daemon::bind`.
