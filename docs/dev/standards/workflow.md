# Engineering Workflow & Verification Gates

This document codifies the operational workflows, PR review gates, and verification criteria for changes to `daer`.

---

## 1. Pull Request Review Gates

Before any change is merged or released, it must clear the verification gates that `cargo xtask ci` runs. It is one command, not a `Makefile`: the gate list and the code that runs it live in the same place, so a gate cannot be added to one and forgotten in the other.

```text
┌─────────────────────────────────────────────────────────────┐
│ 0. ABI Drift Gate: `cargo xtask abi --check`                │
│    ebpf/abi.toml, daer_abi.h and generated.rs agree byte    │
│    for byte; the CI `test` job runs this step separately    │
├─────────────────────────────────────────────────────────────┤
│ 1. Formatting Gate: `cargo fmt --all -- --check`            │
│    Zero formatting deviations, consistent style across tree │
├─────────────────────────────────────────────────────────────┤
│ 2. Lint & Static Analysis Gate:                             │
│    `cargo clippy --workspace --all-targets --locked`        │
│    Zero clippy warnings, zero dead code or type ambiguities │
├─────────────────────────────────────────────────────────────┤
│ 3. Automated Test & Invariants Gate:                        │
│    `cargo test --workspace --locked -j<nproc/2>`            │
│    All unit, integration, and falsifiable tests pass,       │
│    including schema integrity and unconsumed keys gates     │
├─────────────────────────────────────────────────────────────┤
│ 4. Unprivileged Preflight: `daer check --object <built>`    │
│    The object the repository just built is one `daer check`  │
│    accepts — the same gate a package runs before shipping    │
└─────────────────────────────────────────────────────────────┘
```

CI additionally runs `cargo deny check` against `deny.toml` in the `supply-chain` job:
advisories, license expressions, source registries and the single-crypto-provider policy. It is
kept out of `cargo xtask ci` so a developer without `cargo-deny` still has the fast local gate,
but a release must have it green.

### What the test gate needs on the machine

Two suites are *fixtures* rather than dependencies: they start what they need and **skip with a
stated reason** when it is absent (ADR-0007 — a skip that says why is a fact).

| Fixture | Suite | Without it |
| :--- | :--- | :--- |
| `xray` on `PATH` or `$XRAY_BIN` | `daer-proxy-protocols/tests/reality_interop.rs` | REALITY + Vision interop is skipped, which is the only end-to-end coverage of that path |
| `xray` on `PATH` or `$XRAY_BIN` | `daer-proxy-protocols/tests/vision_tls_inside.rs` | the only coverage of Vision's **raw-copy** path. Plaintext through the tunnel does not exercise it, so a client that cannot carry a TLS stream passes every plaintext test — that is how the `Direct` defect shipped, with `curl https://…` failing on every request while the suite was green |
| `xray` on `PATH` or `$XRAY_BIN` | `daer-proxy-protocols/tests/{layer_matrix,vmess_live,hysteria2_live}.rs` | the layer matrix, VMess AEAD and the complete Hysteria 2 stack lose their only real-peer coverage (ADR-0028, ADR-0029, ADR-0030) |
| `nftables` + `CAP_NET_ADMIN` | `daer-control/tests/transparent.rs` | the user-space data path is not exercised; `scripts/verify/e2e-check.sh` runs it with the capability |
| `CAP_SYS_ADMIN` + writable `/run/netns` + `DAER_NETNS_TEST=1` | `daer-control/tests/netns_lifecycle.rs` | the namespace guard, peer move, `iif` rule and return route lose their real-kernel falsifier; run it in a disposable `unshare -Urnm` (ADR-0038) |
| `nftables` + `CAP_NET_ADMIN` | `daer-cli/tests/reload.rs` | the `SIGHUP` test needs the transparent port, so it skips with a reason; `scripts/verify/e2e-check.sh` section 4 runs it |

A release should not be cut from a run where the interop suite skipped: the `✅` in
`docs/dev/roadmap.md` for REALITY means "CI exercised it", and a skip is the absence of that.

`DAER_REQUIRE` is what enforces that in `scripts/verify/kernel-check.sh` and
`scripts/verify/e2e-check.sh`: a comma-separated list of check keys (`4`, `3-tcp`, `3-udp`, …)
whose **skip is a failure**. Without it, a green run over a skipped check is indistinguishable
from a green run over a passing one — and that is precisely the failure ADR-0007 exists to
prevent.

### Why `-j<nproc/2>`

Every test target links the whole dependency graph, and on a many-core machine cargo starts all
of them at once. Measured on a 16-core box: an uncontended `cargo test --no-run --workspace`
takes 169 ms, while the same command after touching one library took 666 s — every second of it
inside 23 concurrent `rust-lld` processes competing for the same page cache and disk queue.
`DAER_CI_JOBS` overrides the default.

---

## 2. Code-to-Doc Synchronization (Atomic Commits)

Any commit or pull request that modifies user-visible or operator-facing surfaces must update the corresponding documentation within the **same atomic commit**:

| Modified Surface | Required Documentation Synchronization |
| :--- | :--- |
| CLI commands, arguments, or flags (`daer-cli`) | `README.md`, `docs/deployment.md` |
| Configuration keys or structures (`daer-config`) | `daer.example.toml`, `daer.schema.json` (`cargo xtask schema --write`) |
| Service lifecycle, signals, systemd units | `install/daer.service`, `docs/deployment.md` |
| Architectural boundaries or invariants | Relevant ADR in `docs/adr/`, `docs/dev/standards/invariants.md` |
| User-facing features or bug fixes | `CHANGELOG.md` under `[Unreleased]` |

---

## 3. Pre-Release Quality Checklist

Prior to creating a release tag:

1. **Compilation Cleanliness**: Run `cargo check --workspace --all-targets` with zero warnings.
2. **Full CI Ladder**: Run `cargo xtask ci` (fmt, clippy, tests, the ABI drift gate and the unprivileged preflight) and verify every gate passes cleanly, then confirm the `test` job in `.github/workflows/ci.yml` runs the same `cargo xtask abi --check`.
3. **eBPF Datapath Compilation**: Run `cargo xtask ebpf` to produce `target/ebpf/datapath.o`.
4. **Privileged Verification**: Run `cargo xtask kernel-check` on a test kernel to verify verifier acceptance and TC attachment, and `cargo xtask e2e-check` to verify that a real redirected flow reaches the daemon. They are separate gates over separate dependency closures; passing one says nothing about the other.
5. **Changelog Integrity**: Ensure all changes under `[Unreleased]` in `CHANGELOG.md` are accurately documented under the new release version header with current date.
6. **Clean Git State**: Verify no untracked or dangling files remain in the working directory (`git status --porcelain`).
7. **Installation Target Check**: Verify `cargo xtask install --destdir /tmp/test-pkg` produces the expected binaries (`daer`, `daer-cleanup`, `daer-drb`), datapath object, and systemd service files.
8. **Release Build**: `cargo build --workspace --release` succeeds.
