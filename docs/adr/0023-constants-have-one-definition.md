# ADR-0023 — Constants have one definition and no dead ones

- Status: accepted
- Date: 2026-11-06

## Context

`daer-common/src/consts.rs` opens with a comment that states the problem:

> Replaces the Go package `common/consts`. Values are kept identical to the Go
> implementation, so a daer binary keeps the same kernel contract without changing
> kernel-side behaviour.

"Kept identical to the Go implementation" is not a property this repository can check,
and it is not a goal it should have. The file was transcribed from another project and has
since drifted from the code that actually uses it:

| Constant | Uses outside `consts.rs` | What the running daemon actually uses |
| --- | --- | --- |
| `DAE0_IFNAME` (`"dae0"`) | **0** | `daer-control::datapath::DEVICE` (`"daer0"`) |
| `DAEPEER_IFNAME` (`"dae0peer"`) | **0** | `daer-control::datapath::PEER` (`"daer0peer"`) |
| `TPROXY_PORT_DEFAULT` | **0** | a literal in the CLI default |
| `DAENS_NETNS` | **0** | nothing creates this namespace |
| `ETHERNET_MTU` | **0** | a literal in the datapath |
| `MIN_KERNEL_VERSION` | **0** | `daer check` probes the kernel directly |
| `UDP_CONN_STATE_TIMEOUT` | **0** | the datapath's own timeout |

Seven dead constants, two of which contradict live ones: a reader who trusts
`DAE0_IFNAME` will configure a device name that does not exist. This is the residue of a
migration that copied a file wholesale and never deleted what the new architecture does not
use. ADR-0006 already established the rule for configuration keys — *adapters that are not
wired are deleted, not documented* — and this file is the same failure in constant form.

The same pattern appears at the crate root: `daer-ebpf/src/lib.rs` describes the datapath as
`control/kern/tproxy.c`, a path that does not exist in this repository, and `abi.rs` opens by
explaining that it mirrors a C program "not rewritten in this migration phase" — a phase that
ADR-0020 closes.

## Decision

1. **A constant that no code reads is deleted.** Not deprecated, not commented out, not kept
   "for compatibility". `DAE0_IFNAME`, `DAEPEER_IFNAME`, `TPROXY_PORT_DEFAULT`,
   `DAENS_NETNS`, `ETHERNET_MTU`, `MIN_KERNEL_VERSION` and `UDP_CONN_STATE_TIMEOUT` are
   removed. The values that matter move to, or already live in, the crate that owns the
   behaviour.
2. **The device names have one definition, in the crate that creates the devices.**
   `daer-control::datapath::{DEVICE, PEER}` already holds `"daer0"` / `"daer0peer"` and is
   what the daemon creates. `daer-common` stops exporting a second, wrong copy. Any crate
   that needs the name depends on `daer-control`'s constant or receives it as a parameter —
   it does not re-declare it.
3. **The listening port has one definition.** `TPROXY_PORT_DEFAULT` is deleted and the CLI's
   `--port` default names the constant that the datapath parameter is built from, so the
   default cannot disagree with what is published into `PARAM`.
4. **Doc comments describe this repository.** References to `control/kern/` are corrected to
   `ebpf/kern/`; "not rewritten in this migration phase" and "kept identical to the Go
   implementation" are removed, because both describe a state the code is no longer in.
   A comment that describes a previous architecture is worse than no comment: it is a
   false claim that survives review because it looks authoritative.
5. **A dead constant is caught by the compiler, not by a reviewer.** `daer-common` gains
   `#![deny(dead_code)]`-equivalent coverage for its `pub` surface via a test that asserts
   every exported constant is referenced from at least one other crate. `pub` items are not
   dead-code-linted by `rustc`, so the check has to be explicit; it is the mechanism that
   makes rule 1 enforceable rather than a one-time cleanup.

## Consequences

- `daer-common` shrinks to the constants that are actually shared, and every one of them has
  a reader.
- The `dae0`/`daer0` contradiction is resolved in favour of the name the kernel actually sees.
  A reader can no longer be misled into configuring a device that will never exist.
- The new "every exported constant is used" test will fail when someone adds a constant in
  anticipation of a caller. That is the intended outcome: add it with the caller, in the same
  change.
- Removing `MIN_KERNEL_VERSION` loses nothing, because `daer check` probes the running
  kernel's features directly rather than comparing a version number — the probe is the
  mechanism, and the constant was a second, weaker one.
