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
│    `cargo test --workspace --locked`                        │
│    All unit, integration, and falsifiable tests pass,       │
│    including schema integrity and unconsumed keys gates     │
└─────────────────────────────────────────────────────────────┘
```

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
