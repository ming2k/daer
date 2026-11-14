# Architecture Overview

`daer` is an eBPF-based transparent proxy for Linux with a modern, memory-safe Rust userspace.

## Terminology: ingress and egress

**Ingress** is the side where local traffic enters daer: the TC/eBPF redirect, the private
`daer0ns` listeners, and original-destination recovery. It is not a public HTTP `Ingress`
resource, not an inbound service on the internet, and not a separate crate. The word describes
the transparent-capture boundary; the implementation is spread across `daer-ebpf`,
`daer-control`, `daer-relay` and `daer-dns`.

**Egress** is the side where daer opens its own outbound connection after the control plane has
chosen a node or `direct`. That path belongs to netune.

The built-in DNS resolver is neither ingress nor egress: it is the name plane that supplies
domain facts before a flow is decided. [Packet Flow and the DNS Name Plane](packet-flow-and-dns.md)
traces both directions end to end and shows where that state is written and read.

---

## 1. The Two-Plane Model

`daer` divides packet handling into two distinct planes:

```text
               CLIENT PACKET (eth0)
                        │
                        ▼
            ┌───────────────────────┐
            │   TC eBPF Datapath    │
            │   (In-Kernel Hook)    │
            └───────────┬───────────┘
                        │
           ┌────────────┴────────────┐
           │                         │
     (Match Direct)            (Match Proxy)
           │                         │
           ▼                         ▼
      Linux TCP/IP Stack       Redirect to daer0ns
     (Zero userspace cost)    (bpf_sk_assign / SOCKMAP)
                                     │
                                     ▼
                            ┌─────────────────┐
                            │   daer-relay    │
                            │  - Ephemeral listener
                            │  - Sniff SNI/Host
                            │  - Relay / Splice
                            └────────┬────────┘
                                     │ (so-mark stamped)
                                     ▼
                               Remote Origin
```

1. **Kernel Fast Path (eBPF at TC hook)**:
   Packets entering from client LAN interfaces hit the eBPF classifier before the kernel allocates heavyweight socket buffers or enters the local IP stack.
   - Traffic matched to a `direct` rule bypasses userspace entirely and continues routing natively in Linux.
   - Traffic requiring proxying is redirected to `daer0` and directly assigned to userspace listeners via `bpf_sk_assign` in `daer0ns` (ADR-0038, ADR-0043).
2. **Userspace Data Path (`daer-relay`) and Decision Plane (`daer-control`)**:
   `daer-relay` dynamically binds ephemeral listeners (`port = 0`) inside `daer0ns`, recovers original destination IPs via `getsockopt(SO_ORIGINAL_DST)`, and relays payload streams via zero-copy `splice(2)`. It decides nothing and does not inspect application payloads: `daer-control` acquires the domain (Fake-IP, DNS snooper, or explicit sniff fallback), resolves each flow to an election (a routing target), elects one node from that election's resource input, then hands back the other leg (ADR-0018, ADR-0050, ADR-0051, ADR-0046).
3. **Private ingress namespace (`daer0ns`, ADR-0038)**:
   `daer0peer`, the transparent listeners, table 2023 and the peer sysctls live in a private network namespace. The host keeps `daer0`, forwarding and the redirect hooks. A redirected packet crosses the namespace boundary before `bpf_sk_assign`; without that context the transport stack can return `NO_SOCKET` even when the helper succeeded. Listener replies use the peer's return route and are marked so the host treats them as daer's own egress.
4. **Concurrency is part of the data path**:
   The TCP accept loop never awaits a routing decision or a dial, and the UDP relay runs in its own task. A slow node or a blocked datagram operation must not stop `accept(2)` from accepting unrelated clients; the liveness falsifier is `serve::tests::a_slow_decision_does_not_block_accepting_the_next_flow`.

---

## 1b. The Diagnostic Plane

`daer-observe` (Layer 1) is the typed diagnostic interface every layer emits through. A flow
or DNS query receives an ID at the ingress boundary (`FlowId`, `QueryId`); every decision,
dial, relay and DNS event carries it. The catalog in `crates/daer-observe/events.toml` declares
each event's severity, required fields, counter and remediation; `cargo xtask events --check`
generates the Rust enum and reference and fails on drift or a raw `tracing` call.

The daemon consumes the datapath's `bpf_stats_map` and `event_ringbuf`, writes a JSON event
stream, and keeps a read-only snapshot at `/run/daer/state.json` and
`/run/daer/control.sock`. `daer status` is the read-only inspector; a panic or `SIGUSR1`
writes a redacted incident bundle (ADR-0040, ADR-0041).

---

## 2. Ingress & Egress Isolation

A common failure mode in transparent proxies is the "self-proxy loop": when the proxy dials out to an origin server, its own outbound packets are caught by the firewall or eBPF filter and redirected back into itself.

`daer` solves this through **Socket Mark Loop Evasion (`[INV-MARK-01]`)**:
- Every socket daer creates is marked with `SO_MARK` (`0x64616572`): outbound dials before `connect(2)`, transparent listeners, UDP reply sockets, and health-check probes.
- The eBPF kernel program inspects `skb->mark`. If the mark matches, the packet is immediately passed through (`DAER_TC_PASS`) without inspection or redirection.

---

## 3. Configuration Generations & Single Source of Truth

Configuration in `daer` is compiled into immutable **Generations**.
- When `daer run` starts, it compiles Generation 1, publishes policy maps into the kernel eBPF datapath, and begins serving.
- Upon receiving `SIGHUP`, the daemon loads and compiles Generation 2 in the background. If compilation succeeds, it updates the kernel eBPF tables, flips the active generation pointer, and smoothly drains old flows without dropping active connections.
- Diagnostics (`daer route`) share the identical generation loader as the daemon (`[INV-LOADER-01]`), guaranteeing that what the CLI tool explains matches what the running kernel and daemon execute.
- A runtime `daer elect <election> <node>` is not a configuration generation. It writes an override in `/var/lib/daer/elections.json` and changes the named election's current result; the rules and the generation remain immutable. `--reset` removes the override (ADR-0047).
