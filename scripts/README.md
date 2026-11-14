# Scripts

Only the entry points that are not tests live here. Unit, integration and end-to-end tests
are Rust targets under `tests/` and are selected with `cargo nextest`; privileged CI jobs run
the `e2e` binary directly with the filters and environment the job needs. There is no
project-specific test runner script.

## Layout

| Path | Runs as | Entry point | Answers |
| :--- | :--- | :--- | :--- |
| `install.sh` | user; `sudo` for the copy | `scripts/install.sh` | Builds the release binaries and datapath object, installs them under `/usr`, and reloads the systemd unit. |
| `delivery-check.sh` | root (`sudo`); `--preflight` as user | direct | Manual release gate: real daemon, real TCX, a real node, and the `SIGKILL` lifetime proof. Needs a site config and a disposable host. |
| `rules/dat_to_rules.py` | user | `python3 scripts/rules/dat_to_rules.py` | Converts a legacy `geoip.dat` / `geosite.dat` into Canonical Rule Source (`.rules`). It is a producer tool, not a test runner. |

## Install

```sh
scripts/install.sh
```

The builds and the staging step run as the invoking user, so `cargo`, `rustup` and the build
cache stay usable, and a compromised `target/` is never executed as root. `sudo` is used only
to install each staged file under `/usr`, remove the two legacy paths, and run
`systemctl daemon-reload`. The artifact list is owned by `cargo xtask install`; this script
does not restate it. Start or restart the daemon explicitly after installing.

## Delivery check

```sh
sudo scripts/delivery-check.sh --config <site.toml>
```

This one cannot move into `cargo nextest`: it needs a real node, root, a disposable host and
it changes host network state (then restores it). It is the release gate for "a real
redirected flow reaches the daemon and returns 200" and for "`SIGKILL` leaves no TCX link,
veth, namespace or daer-owned sysctl behind". The site config is not kept in the repository;
keep it under the ignored `target/` directory or outside the tree.

## Legacy `.dat` converter

`rules/dat_to_rules.py` is used by `tests/integration/drb_dat_unpack.rs` and by the operator
guides for one-time migration of legacy GeoData files. It is a producer, not an orchestration
layer, so it stays out of the test-harness rewrite.
