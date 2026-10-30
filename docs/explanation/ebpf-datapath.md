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
           │ Check SO_MARK == 0x0dae?  │ ──(Yes)──> Pass (TC_ACT_OK)
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
    (TC_ACT_OK)                    (Redirect to daer0 / TPROXY)
```

1. **Mark Exemption**: The program first inspects `skb->mark`. If marked with `so-mark`, the packet originated from `daer` itself and is passed through immediately.
2. **5-Tuple Lookup**: Source IP, destination IP, source port, destination port, and protocol are extracted and evaluated against the active epoch's kernel policy maps.
3. **Action Execution**:
   - `DIRECT`: Continues native Linux kernel forwarding.
   - `PROXY`: Redirected via peer veth pair into the transparent port listener.
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
- Predicates like `domain(...)` (which requires early TLS/HTTP sniffing in userspace) or `pname(...)` (client process name recovery) cannot be evaluated at the raw packet TC hook before TCP handshake.

`daer` verifies whether the compiled policy is **provably equivalent** to userspace rules (ADR-0005):
- If all firing rules are kernel-supported, the policy runs on the kernel fast path.
- If any rule requires domain sniffing, the datapath publishes a **deferral** action: all traffic is handed to `daer-control` for userspace sniffing and decision, logging the exact reason at startup.
