# eBPF Datapath & Routing Epochs

This article explains the mechanics of `daer`'s kernel datapath: how the tc hook program classifies packets, how routing policies are updated without downtime, and how dual-slot routing epochs guarantee atomic updates.

---

## 1. TC Hook & Packet Ingress

`daer` attaches its eBPF program to the **Traffic Control (tc)** hook on the ingress network interfaces (`lan-interface` and `wan-interface`).

```text
               sk_buff at TC Ingress
                         │
                         ▼
           ┌───────────────────────────┐
           │ Check SO_MARK == 0x64616572?  │ ──(Yes)──> Pass (DAER_TC_PASS)
           └─────────────┬─────────────┘
                         │ (No)
                         ▼
           ┌───────────────────────────┐
           │ Lookup Policy Table       │
           │ (Current Active Epoch)    │
           └─────────────┬─────────────┘
                         │
         ┌───────────────┴───────────────┐
         ▼                               ▼
    Verdict: Direct                Verdict: Proxy
    (DAER_TC_PASS)                 (Redirect to daer0 / bpf_sk_assign)
```

1. **Mark Exemption**: The program first inspects `skb->mark`. If marked with `so-mark`, the packet originated from `daer` itself and is passed through immediately.
2. **5-Tuple Lookup**: Source IP, destination IP, source port, destination port, and protocol are extracted and evaluated against the active epoch's kernel policy maps.
3. **Action Execution**:
   - `DIRECT`: Continues native Linux kernel forwarding.
   - `PROXY`: Redirected via veth into `daer0ns` and assigned directly to the ephemeral listener via `bpf_sk_assign` (ADR-0038, ADR-0043).
   - `DEFER`: Redirected to userspace control plane for domain/process evaluation.

---

## 2. Dual-Slot Routing Epochs ([INV-EPOCH-01])

Mutating in-kernel BPF hash maps while packets are being processed can lead to transient race conditions or partial policy states. `daer` solves this through **Dual-Slot Routing Epochs** (ADR-0004).

The kernel datapath maintains two slots for routing policies:
- `Slot 0`
- `Slot 1`

An atomic integer `active_slot` determines which slot the eBPF classifier queries for live traffic:

```text
Step 1: Live traffic reads from Slot 0 (active_slot = 0).
┌────────────────┐          ┌────────────────┐
│ Slot 0: Active │          │ Slot 1: Idle   │
└────────────────┘          └────────────────┘

Step 2: On SIGHUP reload, userspace compiles new rules and writes them into Slot 1.
┌────────────────┐          ┌────────────────┐
│ Slot 0: Active │          │ Slot 1: New Gen│
└────────────────┘          └────────────────┘

Step 3: Atomic write flips active_slot to 1.
┌────────────────┐          ┌────────────────┐
│ Slot 0: Idle   │          │ Slot 1: Active │
└────────────────┘          └────────────────┘
```

Because `Slot 1` is populated completely before `active_slot` is flipped, the kernel datapath transitions from the old policy to the new policy instantaneously and atomically.

---

## 3. Provable Equivalence vs Deferral ([INV-KERNEL-01])

Not all routing predicates can be executed in the kernel.
- Predicates like `dip(cidr)`, `sport(range)`, `l4proto(tcp)` are lowerable directly to BPF LPM trie and hash tables.
- `domain(...)` requires early TLS/HTTP sniffing in userspace. `pname(...)` is observed by the
  six cgroup v2 hooks and carried through `routing_handoff_map`; the raw packet itself does
  not carry a process name.

`daer` verifies whether the compiled policy is **provably equivalent** to userspace rules (ADR-0005):
- If all firing rules are kernel-supported, the policy runs on the kernel fast path.
- If any rule requires a userspace fact, the datapath publishes a **deferral** action from that
  rule's boundary: the suffix is handed to `daer-control`, which applies the
  `[routing.sniff]` policy (DNS/Fake-IP first, payload inspection only when enabled), logging
  the exact reason at startup.
