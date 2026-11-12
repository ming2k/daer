// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2022-2026, daer contributors
//
// Part of the datapath translation unit. See ADR-0024 for why the split is by
// map ownership and attach domain rather than by directory convention.


// +build ignore

// Disable implicit CO-RE from vmlinux.h to bypass bad relocation.
// Note: Previously misattributed to GCC 15 DTE. The actual root cause is that
// pahole fails to parse DWARF5 debug info correctly, which strips UAPI structs
// from the generated BTF.
// Workaround for implicit CO-RE: compile kernel with CONFIG_DEBUG_INFO_DWARF4=y.
// However, it is highly recommended to keep this macro defined, as it still
// significantly improves overall compatibility across different environments.
#define BPF_NO_PRESERVE_ACCESS_INDEX 1

#include "headers/errno-base.h"
#include "headers/if_ether_defs.h"
#include "headers/pkt_cls_defs.h"
#include "headers/socket_defs.h"
#include "headers/upai_in6_defs.h"
#include "headers/vmlinux.h"

#include "headers/bpf_core_read.h"
#include "headers/bpf_endian.h"
#include "headers/bpf_helpers.h"
/* bpf_tracing.h (kprobe arg accessors) needs a target arch; mirror the
 * vmlinux.h fallback (x86) unless the build already selects one. */
#if !defined(__TARGET_ARCH_x86) && !defined(__TARGET_ARCH_arm) && \
	!defined(__TARGET_ARCH_arm64) && !defined(__TARGET_ARCH_riscv) && \
	!defined(__TARGET_ARCH_loongarch) &&                              \
	!defined(__TARGET_ARCH_powerpc) && !defined(__TARGET_ARCH_s390) && \
	!defined(__TARGET_ARCH_mips)
#define __TARGET_ARCH_x86
#endif
#include "headers/bpf_tracing.h"
#include "daer_abi.h"
// #define likely(x) x
// #define unlikely(x) x
#define likely(x) __builtin_expect((x), 1)
#define unlikely(x) __builtin_expect((x), 0)
// TCX action values. Attachment is TCX-only (ADR-0042), so the datapath uses these names
// and never the classic TC_ACT_* vocabulary. The numeric values are the kernel ABI; the
// arm64 and riscv vendored vmlinux headers predate the TCX enum names, but the values are
// identical on every architecture.
#define DAER_TC_NEXT (-1)
#define DAER_TC_PASS 0
#define DAER_TC_DROP 2
#define DAER_TC_REDIRECT 7
#define DAER_TC_CONTINUE DAER_TC_NEXT
#ifndef BIT
#define BIT(nr) (1UL << (nr))
#endif

#define IPV6_BYTE_LENGTH 16
#define TASK_COMM_LEN 16

#define PACKET_HOST 0
#define PACKET_OTHERHOST 3

#define NOWHERE_IFINDEX 0

#define MAX_INTERFACE_NUM 256
#ifndef MAX_MATCH_SET_LEN
#define MAX_MATCH_SET_LEN \
	(32 * 32) // Should be sync with common/consts/ebpf_sync_spec.json.
#endif
#define ROUTING_EPOCH_SLOT_NUM 2
#define ROUTING_EPOCH_SLOT_UNKNOWN 0
#define ROUTING_EPOCH_SLOT_RESULT_SHIFT 41
#define ROUTING_EPOCH_SLOT_RESULT_MASK 0x3
#define MAX_LPM_SIZE 2048000
#define MAX_LPM_NUM (ROUTING_EPOCH_SLOT_NUM * MAX_MATCH_SET_LEN + 8)
#define MAX_CONN_STATE_NUM (65536 * 4)
#define MAX_REDIRECT_TRACK_NUM 65536
// A reply binding (redirect_track entry) may only be rebound by a different
// publisher (interface/MAC) once it has been silent for this long. The window
// must be long enough that a roaming LAN client's gap (Wi-Fi roam, VM
// migration) does not freeze its binding, and short enough that a competing
// writer cannot hand a live flow's reply path to itself. Userspace injects
// EVENT_RATE.redirect_rebind_stale_ns; this is the clang-side fallback.
#define REDIRECT_REBIND_STALE_NS_FALLBACK 2000000000ULL
#define MAX_ROUTING_HANDOFF_NUM 65536
#define MAX_COOKIE_PID_PNAME_MAPPING_NUM 65536
#define MAX_DOMAIN_ROUTING_NUM 65536
// MAX_TCP_OFFLOAD_NUM bounds concurrent TCP relay offload sessions. Each
// session occupies two fast_sock entries (one per direction).
#define MAX_TCP_OFFLOAD_NUM 16384
#define MAX_ARG_LEN 128
#define IPV6_MAX_EXTENSIONS 8

#define ipv6_optlen(p) (((p)+1) << 3)

#define TPROXY_MARK 0x8000000

#define NDP_REDIRECT 137

// Param keys:
static const __u32 zero_key;
static const __u32 one_key = 1;
static const __u32 two_key = 2;
static const __u32 three_key = 3;

// Outbound Connectivity Map:

// Key format: outbound_id * 6 + domain * 2 + ipversion
// domain: 0=TCP, 1=DNS UDP, 2=data UDP; ipversion: 0=IPv4, 1=IPv6

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32); // true, false
	__uint(max_entries, 1536); // 256 outbounds * 3 domains * 2 ipversions
} outbound_connectivity_map SEC(".maps");



