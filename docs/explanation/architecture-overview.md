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
                            │  daer-control   │
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
2. **Userspace Control Plane (`daer-control`)**:
   Listens on the transparent port with `IP_TRANSPARENT`. It recovers original destination IPs via `getsockopt(SO_ORIGINAL_DST)`, sniffs early domain names from TLS ClientHello or HTTP headers, selects outbound nodes from groups, and relays payload streams via zero-copy `splice(2)`.

---

## 2. Ingress & Egress Isolation

A common failure mode in transparent proxies is the "self-proxy loop": when the proxy dials out to an origin server, its own outbound packets are caught by the firewall or eBPF filter and redirected back into itself.

`daer` solves this through **Socket Mark Loop Evasion (`[INV-MARK-01]`)**:
- All egress sockets dialed by `daer` are marked with `SO_MARK` (`0x0dae`) before `connect(2)`.
- The eBPF kernel program inspects `skb->mark`. If the mark matches, the packet is immediately passed through (`TC_ACT_OK`) without inspection or redirection.

---

## 3. Configuration Generations & Single Source of Truth

Configuration in `daer` is compiled into immutable **Generations**.
- When `daer run` starts, it compiles Generation 1, publishes policy maps into the kernel eBPF datapath, and begins serving.
- Upon receiving `SIGHUP`, the daemon loads and compiles Generation 2 in the background. If compilation succeeds, it updates the kernel eBPF tables, flips the active generation pointer, and smoothly drains old flows without dropping active connections.
- Diagnostics (`daer route explain`) share the identical generation loader as the daemon (`[INV-LOADER-01]`), guaranteeing that what the CLI tool explains matches what the running kernel and daemon execute.
