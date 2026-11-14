# Explanation

Conceptual discussions and architectural deep dives explaining how and why `daer` is designed the way it is.

---

## Articles

| Article | Explains |
| :--- | :--- |
| **[Architecture Overview](architecture-overview.md)** | The two-plane separation between the kernel eBPF datapath and the Rust userspace control plane. |
| **[Packet Flow and the DNS Name Plane](packet-flow-and-dns.md)** | Client-side, egress, and return packet paths, and how DNS supplies domain facts without sitting in the forwarding chain. |
| **[eBPF Datapath & Routing Epochs](ebpf-datapath.md)** | TC hook packet classification, dual-slot routing epochs, atomic generation swaps, and socket mark evasion. |
| **[Routing Performance & Rule Topology](routing-performance-and-rule-organization.md)** | Mathematical scale of `IpIndex` and `DomainIndex`, the 1024-match-set kernel limit, rejection of monolithic archives, and coarse-grained rule provider topology. |

---

For technical API contracts and CLI flags, consult [Reference](../reference/index.md). For historical architectural decisions and their rationales, consult the [Architectural Decision Records](../adr/index.md).
