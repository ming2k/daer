# Scripts

Executable helpers that are not part of the Rust workspace. Rust tests are selected with
`cargo nextest` (see [`docs/dev/testing.md`](../docs/dev/testing.md)); these scripts are the
cases that need a privileged shell, a standalone Python interpreter, or direct access to a
host service. xtask owns code generation, packaging and the unprivileged preflight, not test
selection.

## Layout

| Path | Runs as | Entry point | Answers |
| :--- | :--- | :--- | :--- |
| `verify/kernel-check.sh` | root (`sudo`) | direct | Does the eBPF object load, verify, attach TCX and the pname cgroup hooks, and pass the in-kernel datapath cases? |
| `verify/e2e-check.sh` | root (`sudo`) | direct | Does a real redirected flow reach the daemon and come back? |
| `rules/dat_to_rules.py` | user | `python3 scripts/rules/dat_to_rules.py` | Converts a legacy `geoip.dat` / `geosite.dat` into Canonical Rule Source (`.rules`). |
| `ops/daer-install-netns.sh` | user, then root (re-execs `sudo`) | direct | Stages the local `daer` and `daer-drb` binaries, datapath object, and systemd unit with `cargo xtask install`, copies the staged tree into `/usr`, installs a site config, and restarts `daer`. |
| `ops/daer-delivery-check.sh` | root (`sudo`); `--preflight` as user | direct | Runs the private-ingress diagnostic and restores the host's prior network state. `--preflight` checks the kernel, tools, artifacts, and config without root. |

## Verification scripts

The two `verify/` scripts are deliberately separate: they have different dependency
closures and different failure meanings (ADR-0007, ADR-0025). Both re-exec themselves
under `sudo`; run them as your normal user so `cargo` stays on `PATH`.

`scripts/verify/e2e-check.sh` is deterministic: it builds the root `e2e` test binary and
drives the userspace relay through nftables, but it does **not** exercise the real TCX hooks. The real-daemon delivery and `SIGKILL` gate is
`ops/daer-delivery-check.sh`; it needs a site config, a real node and a clean disposable host.
The host preparation and release checklist live in
[`docs/dev/test-environment.md`](../docs/dev/test-environment.md) and
[`docs/dev/production-readiness.md`](../docs/dev/production-readiness.md).

`DAER_REQUIRE=<key,...>` turns a named **skip** into a failure. The keys belong to the
script that emits them; the current list and the key-consistency audit are defined in
[`docs/dev/testing.md`](../docs/dev/testing.md) (ADR-0052).

| Variable | Script | Meaning |
| :--- | :--- | :--- |
| `DAER_REQUIRE` | both | Comma-separated check keys whose skip must fail. |
| `DAER_OBJECT` | kernel | Datapath object to load (default `target/ebpf/datapath.bpf.o`). |
| `DAER_LOG_DIR` | kernel | Log directory (default `~/daer-kernel-check` under sudo). |
| `DAER_E2E_LOGS` | e2e | Log directory (default `~/daer-e2e-check` under sudo). |

## Host scripts

The `ops/` scripts change the machine, not just the workspace. Read the header of the
script before running it.

`daer-install-netns.sh` stages with `cargo xtask install --destdir target/install-root`
and then re-execs itself under `sudo` to copy the staged tree, install the config, and
restart the service. It is not a second artifact list: `cargo xtask install` owns the
binaries, object and unit, and this script adds only the privileged deployment steps
(config install, `daer check --host`, systemd restart). Run it as your normal user so
`cargo` stays on `PATH`; `--staged` is the internal root-half option. It and
`daer-delivery-check.sh` takes the deployment/test config with `--config <path>`. Configs are
site-specific and may contain node credentials, so they are **not** kept in the repository:
keep them under the ignored `target/` directory or outside the tree. `daer-delivery-check.sh`
also accepts:

| Variable | Meaning |
| :--- | :--- |
| `DAER_E2E_WAN` | WAN interface to watch (default: the default route's device). |
| `DAER_E2E_LOG` | Daemon log path (default `target/daer-e2e.log`). |
| `DAER_E2E_RESTORE_DIR` | Host-state snapshot directory (default `target/daer-e2e-restore`). |

## What is not here

CI steps and the packaging plan keep their shell inline. Those snippets consume
runner-provided variables (`$WORKDIR`, `$STAGING_DIR`, `$VERSION`) and are not standalone
entry points; extracting them would add an indirection without a caller that benefits.

## Conventions

- Shell scripts start with `#!/usr/bin/env bash` and use `set -euo pipefail` (the
  verification scripts use `set -uo pipefail` because they count failures instead of
  aborting on the first one).
- A script finds the repository root from its own location, never from a hardcoded
  absolute path.
- Python tooling uses only the standard library.
