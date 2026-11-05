# Engineering Workflow & Verification Gates

This document codifies the operational workflows, PR review gates, and verification criteria for changes to `daer`.

---

## 1. Pull Request Review Gates

Before any change is merged or released, it must clear the five verification gates codified in `make ci`:

```text
┌─────────────────────────────────────────────────────────────┐
│ 1. Formatting Gate: `make fmt-check`                        │
│    `cargo fmt --all -- --check`                             │
│    Zero formatting deviations, consistent style across tree │
├─────────────────────────────────────────────────────────────┤
│ 2. Lint & Static Analysis Gate:                             │
│    `cargo clippy --workspace --all-targets --locked`        │
│    Zero clippy warnings, zero dead code or type ambiguities │
├─────────────────────────────────────────────────────────────┤
│ 3. Automated Test & Invariants Gate:                        │
│    `cargo xtask ci`  (fmt, clippy, test -j<nproc/2>)        │
│    All unit, integration, and falsifiable tests pass,       │
│    including schema integrity and unconsumed keys gates     │
└─────────────────────────────────────────────────────────────┘
```

### What the test gate needs on the machine

Two suites are *fixtures* rather than dependencies: they start what they need and **skip with a
stated reason** when it is absent (ADR-0007 — a skip that says why is a fact).

| Fixture | Suite | Without it |
| :--- | :--- | :--- |
| `xray` on `PATH` or `$XRAY_BIN` | `daer-outbound/tests/reality_interop.rs` | REALITY + Vision interop is skipped, which is the only end-to-end coverage of that path |
| `xray` on `PATH` or `$XRAY_BIN` | `daer-outbound/tests/vision_tls_inside.rs` | the only coverage of Vision's **raw-copy** path. Plaintext through the tunnel does not exercise it, so a client that cannot carry a TLS stream passes every plaintext test — that is how the `Direct` defect shipped, with `curl https://…` failing on every request while the suite was green |
| `nftables` + `CAP_NET_ADMIN` | `daer-control/tests/transparent.rs` | the kernel datapath tests are skipped; CI runs them under `unshare -Urn` via `scripts/kernel-check.sh` |
| `nftables` + `CAP_NET_ADMIN` | `daer-cli/tests/reload.rs` | the `SIGHUP` test needs the transparent port, so it skips with a reason; `scripts/kernel-check.sh` section 8 runs it |

A release should not be cut from a run where the interop suite skipped: the `✅` in
`docs/dev/roadmap.md` for REALITY means "CI exercised it", and a skip is the absence of that.

`DAER_REQUIRE` is what enforces that in `scripts/kernel-check.sh`: a comma-separated list of
check keys (`7-tcp`, `8`, …) whose **skip is a failure**. Without it, a green run over a skipped
check is indistinguishable from a green run over a passing one — and that is precisely the failure
ADR-0007 exists to prevent.

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
2. **Full CI Ladder**: Run `make ci` and verify all five gates pass cleanly.
3. **eBPF Datapath Compilation**: Run `cargo xtask ebpf` to produce `target/ebpf/datapath.o`.
4. **Kernel Check Verification**: Run `cargo xtask kernel-check` on a test kernel to verify verifier acceptance and TC attachment.
5. **Changelog Integrity**: Ensure all changes under `[Unreleased]` in `CHANGELOG.md` are accurately documented under the new release version header with current date.
6. **Clean Git State**: Verify no untracked or dangling files remain in the working directory (`git status --porcelain`).
7. **Installation Target Check**: Verify `cargo xtask install --destdir /tmp/test-pkg` produces the expected binary, datapath object, and systemd service files.
8. **Release Build**: `cargo build --workspace --release` succeeds.
