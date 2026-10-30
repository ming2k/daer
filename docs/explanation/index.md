# Explanation

Conceptual discussions and architectural deep dives explaining how and why `daer` is designed the way it is.

---

## Articles

| Article | Explains |
| :--- | :--- |
| **[Architecture Overview](architecture-overview.md)** | The two-plane separation between the kernel eBPF datapath and the Rust userspace control plane. |
| **[eBPF Datapath & Routing Epochs](ebpf-datapath.md)** | TC hook packet classification, dual-slot routing epochs, atomic generation swaps, and socket mark evasion. |

---

For technical API contracts and CLI flags, consult [Reference](../reference/index.md). For historical architectural decisions and their rationales, consult the [Architectural Decision Records](../adr/index.md).
