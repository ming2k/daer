---
id: ADR-0056
title: "Single-instance daemon lock and deterministic ingress teardown"
status: accepted
date: 2026-11-14
scope: [control-plane/ingress, systemd/lifecycle]
supersedes: []
superseded_by: []
---

# 0056. Single-instance daemon lock and deterministic ingress teardown

- Status: Accepted
- Date: 2026-11-14
- Deciders: daer maintainers
- Related: [ADR-0038](0038-private-ingress-network-namespace.md)

## Context

Previously, `PreparedIngress::prepare` relied solely on `IngressNamespace::drop` unmounting `/run/netns/daer0ns` and kernel asynchronous `cleanup_net` to destroy the `daer0`/`daer0peer` veth pair. Because `create_device_pair` could not distinguish a live sibling `daer` process from a dead run's lingering `daer0` (for example, orphan TCP sockets in `FIN_WAIT1`/`LAST_ACK` holding the namespace refcount or a `SIGKILL`ed process), it waited up to 10 seconds and failed. Under `systemd` `Restart=on-failure`, five consecutive 10-second failures tripped `start-limit-hit` and left the proxy daemon stopped.

## Decision

1. **`DaemonLock` (`/run/daer/daer.lock`)**: `IngressNamespace::create` acquires a non-blocking exclusive `flock(LOCK_EX | LOCK_NB)` on `/run/daer/daer.lock` for the daemon's lifetime. A second concurrent `daer` instance fails immediately with a clear error.
2. **Synchronous teardown on drop**: `IngressNamespace::drop` explicitly deletes `daer0` in the host namespace before unmounting `/run/netns/daer0ns`.
3. **Deterministic stale-link reclamation**: Because holding `DaemonLock` proves no other `daer` instance owns `daer0`, `datapath::create_device_pair` immediately deletes any pre-existing stale `daer0` before creating the fresh veth pair.

## Consequences

- Rapid `systemctl restart daer` and crash-recovery restarts no longer stall for 10 seconds or hit `start-limit-hit` due to lingering `daer0`.
- Concurrent `daer` daemons are rejected immediately at lock acquisition instead of racing on `daer0`.
