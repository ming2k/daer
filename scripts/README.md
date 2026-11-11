# Scripts

Executable helpers that are not part of the Rust workspace. A task that fits the
workspace belongs in [`cargo xtask`](../crates/xtask/src/main.rs); the files here are
the cases that need a privileged shell, a standalone Python interpreter, or direct
access to a host service.

## Layout

| Path | Runs as | Entry point | Answers |
| :--- | :--- | :--- | :--- |
| `verify/kernel-check.sh` | root (`sudo`) | `cargo xtask kernel-check` | Does the eBPF object load, verify, attach, and pass the in-kernel datapath cases? |
| `verify/e2e-check.sh` | root (`sudo`) | `cargo xtask e2e-check` | Does a real redirected flow reach the daemon and come back? |
| `rules/dat_to_rules.py` | user | `python3 scripts/rules/dat_to_rules.py` | Converts a legacy `geoip.dat` / `geosite.dat` into Canonical Rule Source (`.rules`). |
| `ops/daer-install-netns.sh` | user, then root (re-execs `sudo`) | direct | Stages the local `daer`, `daer-cleanup`, and `daer-drb` binaries, datapath object, and systemd unit with `cargo xtask install`, copies the staged tree into `/usr`, installs a site config, and restarts `daer`. |
| `ops/daer-netns-e2e.sh` | root (`sudo`); `--preflight` as user | direct | Runs the private-ingress diagnostic and restores the host's prior network state. `--preflight` checks the kernel, tools, artifacts, and config without root. |
| `ops/remove-dae.sh` | root (`sudo`) | direct | Removes a legacy `dae` installation after backing up `/etc/dae`. |

## Verification scripts

The two `verify/` scripts are deliberately separate: they have different dependency
closures and different failure meanings (ADR-0007, ADR-0025). Both re-exec themselves
under `sudo`; run them as your normal user so `cargo` stays on `PATH`.

`DAER_REQUIRE=<key,...>` turns a named **skip** into a failure. The keys belong to the
script that emits them; see `docs/how-to/deployment.md` for the full list.

| Variable | Script | Meaning |
| :--- | :--- | :--- |
| `DAER_REQUIRE` | both | Comma-separated check keys whose skip must fail. |
| `DAER_OBJECT` | kernel | Datapath object to load (default `target/ebpf/datapath.o`). |
| `DAER_LOG_DIR` | kernel | Log directory (default `~/daer-kernel-check` under sudo). |
| `DAER_E2E_LOGS` | e2e | Log directory (default `~/daer-e2e-check` under sudo). |

## Host scripts

The `ops/` scripts change the machine, not just the workspace. Read the header of the
script before running it.

`daer-install-netns.sh` stages with `cargo xtask install --destdir target/install-root`
and then re-execs itself under `sudo` to copy the staged tree, install the config, and
restart the service. Run it as your normal user so `cargo` stays on `PATH`; `--staged`
is the internal root-half option. It and `daer-netns-e2e.sh` take the deployment/test
config with `--config <path>`. Configs are site-specific and may contain node credentials,
so they are **not** kept in the repository: keep them under the ignored `target/` directory
or outside the tree. `daer-netns-e2e.sh` also accepts:

| Variable | Meaning |
| :--- | :--- |
| `DAER_E2E_WAN` | WAN interface to watch (default: the default route's device). |
| `DAER_E2E_LOG` | Daemon log path (default `target/daer-netns-e2e.log`). |
| `DAER_E2E_RESTORE_DIR` | Host-state snapshot directory (default `target/daer-netns-restore`). |

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
