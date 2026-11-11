# Architecture Overview

`daer` is an eBPF-based transparent proxy for Linux with a modern, memory-safe Rust userspace.

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
      Linux TCP/IP Stack       Redirect to Ingress
     (Zero userspace cost)     (TPROXY port 12345)
                                     │
                                     ▼
                            ┌─────────────────┐
                            │   daer-relay    │
                            │  - IP_TRANSPARENT
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
   - Traffic requiring proxying is redirected to the transparent proxy port.
2. **Userspace Data Path (`daer-relay`) and Decision Plane (`daer-control`)**:
   `daer-relay` listens on the transparent port with `IP_TRANSPARENT`, recovers original destination IPs via `getsockopt(SO_ORIGINAL_DST)`, sniffs early domain names from TLS ClientHello or HTTP headers, and relays payload streams via zero-copy `splice(2)`. It decides nothing: `daer-control` resolves each flow to an outbound (a rule, a group and a node) and hands back the other leg (ADR-0018).
3. **Private ingress namespace (`daer0ns`, ADR-0038)**:
   `daer0peer`, the transparent listeners, table 2023 and the peer sysctls live in a private network namespace. The host keeps `daer0`, forwarding and the redirect hooks. A redirected packet crosses the namespace boundary before `bpf_sk_assign`; without that context the transport stack can return `NO_SOCKET` even when the helper succeeded. Listener replies use the peer's return route and are marked so the host treats them as daer's own egress.
4. **Concurrency is part of the data path**:
   The TCP accept loop never awaits a routing decision or a dial, and the UDP relay runs in its own task. A slow node or a blocked datagram operation must not stop `accept(2)` from accepting unrelated clients; the liveness falsifier is `serve::tests::a_slow_decision_does_not_block_accepting_the_next_flow`.

---

## 2. Ingress & Egress Isolation

A common failure mode in transparent proxies is the "self-proxy loop": when the proxy dials out to an origin server, its own outbound packets are caught by the firewall or eBPF filter and redirected back into itself.

`daer` solves this through **Socket Mark Loop Evasion (`[INV-MARK-01]`)**:
- Every socket daer creates is marked with `SO_MARK` (`0x0dae`): outbound dials before `connect(2)`, transparent listeners, UDP reply sockets, and health-check probes.
- The eBPF kernel program inspects `skb->mark`. If the mark matches, the packet is immediately passed through (`TC_ACT_OK`) without inspection or redirection.

---

## 3. Configuration Generations & Single Source of Truth

Configuration in `daer` is compiled into immutable **Generations**.
- When `daer run` starts, it compiles Generation 1, publishes policy maps into the kernel eBPF datapath, and begins serving.
- Upon receiving `SIGHUP`, the daemon loads and compiles Generation 2 in the background. If compilation succeeds, it updates the kernel eBPF tables, flips the active generation pointer, and smoothly drains old flows without dropping active connections.
- Diagnostics (`daer route`) share the identical generation loader as the daemon (`[INV-LOADER-01]`), guaranteeing that what the CLI tool explains matches what the running kernel and daemon execute.
