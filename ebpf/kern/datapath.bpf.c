// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2022-2026, daer contributors

// The datapath translation unit.
//
// This file contains no logic, and it is not allowed to grow any. It is the
// include list that turns the modules under `src/` into one object, plus the
// licence string the kernel requires.
//
// # Why one translation unit
//
// The modules are *source* boundaries, not link boundaries (ADR-0024). Building each
// one into its own `.o` and joining them with `bpftool gen object` works, but it moves
// cross-module inlining to the linker — and the 512-byte stack budget this datapath
// lives inside depends on clang seeing the whole call graph. Keeping one `clang`
// invocation is what preserves that margin; the split fixes readability without
// touching the guarantee.
//
// # Order
//
// The includes are ordered by dependency, and clang enforces it: a module cannot use
// a type or map declared after it. `state.h` holds every map declaration and the
// structs they are keyed by; `preamble.h` holds the build flags, constants and the
// architecture detection that must precede any header.

#include "src/preamble.h"

// Every map, and every struct a map is keyed or valued by.
#include "src/state.h"

// Structured events: the ring buffer, its rate limiter, and the bpf_stats counters.
#include "src/event.h"

// Packet parsing. Owns no maps: it takes bytes and returns a parsed key.
#include "src/packet.h"

// The rule-matching engine and the routing epoch it reads.
#include "src/policy.h"

// TPROXY: listener assignment, the daer0 ifindex, and the redirect handoff to the
// control plane.
#include "src/redirect.h"

// Connection tracking: the TCP/UDP state machines the fast path depends on.
#include "src/conn.h"

// The ingress hooks (LAN and WAN), including the dual-role hook.
#include "src/ingress.h"

// The egress hooks (LAN and WAN) and the daer0/daer0peer reply path.
#include "src/egress.h"

// The cgroup hooks: socket cookie to process name.
#include "src/cgroup.h"

// The sockmap TCP offload path. Its `#include "include/tcp_offload.h"` resolves
// against `ebpf/kern/include/`, which the build symlinks next to the sources.
#include "src/offload.h"

// The kernel requires a licence section and refuses GPL-only helpers without it.
char __license[] SEC("license") = "Dual BSD/GPL";

// The layout assertions for every struct `ebpf/abi.toml` declares. They come last
// because they assert properties of types declared above, and `cargo xtask abi`
// regenerates them — `cargo xtask abi --check` fails the build when they drift
// (ADR-0021).
#include "daer_abi_assertions.h"
