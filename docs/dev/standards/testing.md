# Automated Verification & Testing Guide

This guide establishes the automated testing strategy, execution commands, and regression prevention practices for developers working on `daer`.

---

## 1. The Test Pyramid for an eBPF Transparent Proxy

`daer` organizes automated verification across four structured tiers:

```text
                  ▲
                 / \
                /   \     Tier 4: End-to-End Kernel Verification
               / E2E \    (tc hook, nftables tproxy, dynamic nonces, negative controls)
              /───────\
             /  Integ  \  Tier 3: Subsystem Integration Tests
            /  -ration  \ (TCP/UDP relay, generation handover, DNS pipeline, REALITY live)
           /─────────────\
          /   Property    \ Tier 2: Differential & Policy Verification
         /   & Equivalence \ (Kernel policy encoding vs userspace matcher, map layout)
        /───────────────────\
       /        Unit         \ Tier 1: Fast Unit Tests
      /      Assertions       \ (AST parser, domain sniffing, DNS wire codecs, filters)
     /─────────────────────────\
```

---

## 2. Testing Principles

### 2.1 Falsifiable Verification (ADR-0007)
A test that cannot fail is a liability:
- Every integration test asserting that traffic was proxied must carry a **negative control** that deliberately bypasses or removes the proxy mechanism and proves the test fails.
- Tests that verify data paths must use **per-run dynamic nonces** in payloads so that stale caches or short-circuited loops cannot produce a false positive pass.

### 2.2 Deterministic Execution & Leak-Free Fixtures
- Tests must not rely on unstable public third-party servers.
- Local mock servers (`wiremock`, local TCP/UDP listeners, fake upstream resolvers) must be used for protocol and relay testing.
- Network devices created during tests (e.g. `veth` pairs, temporary namespaces) must be wrapped in RAII guards to guarantee cleanup on drop or test panic.

### 2.3 Fast Feedback
- Tier 1 unit tests must execute in milliseconds to support immediate developer feedback in `make ci`.

---

## 3. Running the Test Suite

```bash
# Run all workspace tests (includes schema drift and unconsumed keys gates)
cargo test --workspace --locked

# Run tests with all CI gates (formatting, clippy, test suite)
cargo xtask ci

# Run tests for a specific crate
cargo test -p daer-routing
cargo test -p daer-control

# Run eBPF kernel check (requires root and CAP_BPF / CAP_NET_ADMIN)
cargo xtask kernel-check
```
