// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2022-2026, daer contributors
//
// Part of the datapath translation unit. See ADR-0024 for why the split is by
// map ownership and attach domain rather than by directory convention.

// Sockmap:
struct {
	__uint(type, BPF_MAP_TYPE_SOCKMAP);
	__type(key, __u32); // 0 is tcp4, 1 is udp4, 2 is tcp6, 3 is udp6.
	__type(value, __u32); // fd of socket; SOCKMAP values are `int`, not `u64`.
	__uint(max_entries, 4);
} listen_socket_map SEC(".maps");

union ip6 {
	__u8 u6_addr8[16];
	__be16 u6_addr16[8];
	__be32 u6_addr32[4];
	__be64 u6_addr64[2];
};

struct redirect_tuple {
	union ip6 sip;
	union ip6 dip;
};

struct redirect_entry {
	__u32 ifindex;
	__u8 smac[6];
	__u8 dmac[6];
	__u8 from_wan;
	__u8 padding[3];
	__u64 last_seen_ns;
};

// redirect_track: reply traffic routing; HASH with timestamp-based cleanup.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct redirect_tuple);
	__type(value, struct redirect_entry);
	__uint(max_entries, MAX_REDIRECT_TRACK_NUM);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} redirect_track SEC(".maps");

struct ip_port {
	union ip6 ip;
	__be16 port;
};

// routing_result: routing decision for userspace cache and first-packet handoff.
struct routing_result {
	__u32 mark;
	__u8 must;
	__u8 mac[6];
	__u8 outbound;
	__u8 pname[TASK_COMM_LEN];
	__u32 pid;
	__u8 dscp;
	// 0 is unknown; active routing slots 0 and 1 are encoded as 1 and 2.
	__u8 routing_epoch_slot;
	__u16 datapath_generation;
};

static __always_inline __u8 routing_epoch_slot_encode(__u32 slot)
{
	if (slot >= ROUTING_EPOCH_SLOT_NUM)
		return ROUTING_EPOCH_SLOT_UNKNOWN;
	return (__u8)(slot + 1);
}

static __always_inline __u8 routing_epoch_slot_sanitize(__u8 encoded_slot)
{
	return encoded_slot <= ROUTING_EPOCH_SLOT_NUM ? encoded_slot :
		ROUTING_EPOCH_SLOT_UNKNOWN;
}

static __always_inline __u8
routing_epoch_slot_from_route_result(__s64 route_result)
{
	return routing_epoch_slot_sanitize(
		(__u8)(((__u64)route_result >> ROUTING_EPOCH_SLOT_RESULT_SHIFT) &
		       ROUTING_EPOCH_SLOT_RESULT_MASK));
}

struct tuples_key {
	union ip6 sip;
	union ip6 dip;
	__u16 sport;
	__u16 dport;
	__u8 l4proto;
};

struct tuples {
	struct tuples_key five;
	__u8 dscp;
};

struct routing_handoff_entry {
	__u64 last_seen_ns;
	struct routing_result result;
};

/* `struct daer_param`, `struct daer_event`, `enum MatchType`, `OUTBOUND_*`,
 * `L4ProtoType`, `IpVersionType`, `enum bpf_stats_key` and `enum daer_event_type`
 * come from `daer_abi.h`, which `cargo xtask abi` generates from `ebpf/abi.toml`
 * (ADR-0021, amended by ADR-0040). They are not declared here: one declaration, two
 * languages, and `cargo xtask abi --check` fails the build if the generated header drifts. */
const volatile struct daer_param PARAM = {};

/* daer_ifindex_map holds the runtime-updatable ifindex of the daer0 device.
 * Unlike PARAM.device_ifindex (frozen in .rodata at load time), this ARRAY map
 * can be updated from userspace without reloading the BPF program. This allows
 * hot-recovery when the kernel recreates the netkit/veth device and assigns a
 * new ifindex. BPF falls back to PARAM.device_ifindex if the map is uninitialized.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1);
} daer_ifindex_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct tuples_key);
	__type(value, struct routing_handoff_entry);
	__uint(max_entries, MAX_ROUTING_HANDOFF_NUM);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} routing_handoff_map SEC(".maps");

// Array of LPM tries:
struct lpm_key {
	/* Keep the LPM trie header layout local to avoid unnecessary CO-RE
	 * relocations against struct bpf_lpm_trie_key. The map ABI only
	 * requires prefixlen to be the first u32 in the key. */
	__u32 prefixlen;
	__be32 data[4];
};

struct map_lpm_type {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, MAX_LPM_SIZE);
	__uint(key_size, sizeof(struct lpm_key));
	__uint(value_size, sizeof(__u32));
} unused_lpm_type SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, MAX_LPM_NUM);
	// __uint(pinning, LIBBPF_PIN_BY_NAME);
	__array(values, struct map_lpm_type);
} lpm_array_map SEC(".maps");

struct port_range {
	__u16 port_start;
	__u16 port_end;
};

/*
 * Rule is like as following:
 *
 * domain(geosite:cn, suffix: google.com) && l4proto(tcp) -> my_group
 *
 * pseudocode: domain(geosite:cn || suffix:google.com) && l4proto(tcp) ->
 * my_group
 *
 * A match_set can be: IP set geosite:cn, suffix google.com, tcp proto
 */
struct match_set {
	union {
		__u8 __value[16]; // Placeholder for bpf2go.

		__u32 index;
		struct port_range port_range;
		enum L4ProtoType l4proto_type;
		enum IpVersionType ip_version;
		__u32 pname[TASK_COMM_LEN / 4];
		__u8 dscp;
	};
	__u8 not; // Subrule inversion flag.
	enum MatchType type;
	__u8 outbound; // User-defined value range is [0, 252].
	__u8 must;
	__u32 mark;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct match_set);
	__uint(max_entries, ROUTING_EPOCH_SLOT_NUM * MAX_MATCH_SET_LEN);
	// __uint(pinning, LIBBPF_PIN_BY_NAME);
} routing_map SEC(".maps");

// Each slot holds the active routing rules length for that epoch.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, ROUTING_EPOCH_SLOT_NUM);
} routing_meta_map SEC(".maps");

// key=0: active routing epoch slot. The zero-initialized value selects slot 0.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1);
} active_routing_epoch_map SEC(".maps");

struct domain_routing {
	__u32 bitmap[MAX_MATCH_SET_LEN / 32];
};

struct routing_epoch_ip {
	__u32 slot;
	__be32 addr[4];
};

// domain_routing_map: epoch+address → routing bitmap cache (HASH, no LRU).
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct routing_epoch_ip);
	__type(value, struct domain_routing);
	__uint(max_entries, ROUTING_EPOCH_SLOT_NUM * MAX_DOMAIN_ROUTING_NUM);
} domain_routing_map SEC(".maps");

struct ip_port_proto {
	__u32 ip[4];
	__be16 port;
	__u8 proto;
};

struct pid_pname {
	__u64 last_seen_ns;
	__u32 pid;
	char pname[TASK_COMM_LEN];
};

#define COOKIE_PID_UPDATE_INTERVAL_NS 1000000000ULL  // 1 second

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, struct pid_pname);
	__uint(max_entries, MAX_COOKIE_PID_PNAME_MAPPING_NUM);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} cookie_pid_map SEC(".maps");

// conn_state: shared TCP/UDP connection state with embedded routing.
union routing_meta {
	struct {
		__u32 mark;
		__u8 outbound;
		__u8 must;
		__u8 dscp;
		__u8 has_routing;
	} data;
	__u64 raw;
} __attribute__((aligned(8)));

static __always_inline union routing_meta
build_routing_meta(__u8 outbound, __u32 mark, __u8 must, __u8 dscp)
{
	union routing_meta meta = { 0 };

	meta.data.outbound = outbound;
	meta.data.mark = mark;
	meta.data.must = must;
	meta.data.dscp = dscp;
	meta.data.has_routing = 1;
	return meta;
}

static __always_inline void
publish_routing_meta(union routing_meta *dst, union routing_meta meta)
{
	/* Publish routing only after side fields (mac/pname/pid) are ready.
	 *
	 * barrier() is a COMPILER-ONLY fence: it orders the generated machine
	 * code but emits no CPU fence, so the store-release guarantee is
	 * architecture-dependent. On strongly ordered targets (x86 TSO) the
	 * prior writes to mac/pname/pid are observed before has_routing=1.
	 * On weakly ordered targets a reader that observes has_routing=1 may
	 * briefly read stale side fields. This is an accepted trade-off: the
	 * side fields are advisory per-flow metadata consumed through the
	 * conn_state cache domain, the window is a single first-packet
	 * publication, and a full __sync_synchronize() fence in this hot path
	 * would need verification across the whole kernel matrix before it
	 * could be considered.
	 */
	barrier();
	*(volatile __u64 *)&dst->raw = meta.raw;
}

static __always_inline bool bpf_sock_is_daer_socket(const struct bpf_sock *sk)
{
	if (!sk || !PARAM.socket_mark)
		return false;

	struct bpf_sock *fullsock = bpf_sk_fullsock((struct bpf_sock *)sk);

	return fullsock && fullsock->mark == PARAM.socket_mark;
}

/* Whether the matched host socket is bound to the packet's exact destination
 * address. A wildcard-bound socket (bound address zero) answers for every
 * destination, so its presence says nothing about whether the packet was
 * addressed to this host; only an exact match is proof that the packet is
 * addressed to a service this host runs. */
static __always_inline bool
sock_bound_to_daddr(const struct bpf_sock *sk, const struct tuples *tuples,
		    __be16 h_proto)
{
	if (h_proto == bpf_htons(ETH_P_IP)) {
		__u32 bound = sk->src_ip4; // inet_rcv_saddr, 0 == wildcard

		return bound != 0 && bound == tuples->five.dip.u6_addr32[3];
	}

	if (h_proto == bpf_htons(ETH_P_IPV6)) {
		const __u32 *bound = sk->src_ip6;
		bool wildcard = !(bound[0] | bound[1] | bound[2] | bound[3]);

		return !wildcard &&
		       bound[0] == tuples->five.dip.u6_addr32[0] &&
		       bound[1] == tuples->five.dip.u6_addr32[1] &&
		       bound[2] == tuples->five.dip.u6_addr32[2] &&
		       bound[3] == tuples->five.dip.u6_addr32[3];
	}

	return false;
}

struct conn_state {
	// For each flow (echo symmetric path), note the original flow direction.
	// Mark as true if traffic go through wan ingress.
	// For traffic from lan that go through wan ingress, daer parses them in lan egress
	bool is_wan_ingress_direction;

	// TCP state. UDP entries leave this as TCP_STATE_ACTIVE.
	__u8 state;

	// Last seen timestamp in nanoseconds (bpf_ktime_get_ns).
	// Userspace janitor periodically cleans up expired entries by protocol.
	__u64 last_seen_ns;

	// Embedded routing decision result for this flow.
	// This avoids a separate routing_tuples_map lookup and ensures consistency.
	union routing_meta meta;
	__u8 mac[6];               // Next hop MAC for redirected packets
	__u8 padding[2];           // Alignment
	__u8 pname[TASK_COMM_LEN]; // Process name (for WAN egress; empty for LAN)
	__u32 pid;                 // Process ID (for WAN egress; 0 for LAN)
	// 0 is unknown; active routing slots 0 and 1 are encoded as 1 and 2.
	__u8 routing_epoch_slot;
	__u8 padding_after_pid;
	__u16 datapath_generation;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_CONN_STATE_NUM);
	__type(key, struct tuples_key);
	__type(value, struct conn_state);
	__uint(pinning, LIBBPF_PIN_BY_NAME);  // Loader may override pinning on cold start.
	__uint(map_flags, BPF_F_NO_PREALLOC);
} conn_state_map SEC(".maps");


// Per-packet datapath counters, indexed by enum bpf_stats_key. Userspace reads
// them on the janitor tick (readMapOverflowCounters / checkBpfMapHealth); the
// pre-existing conn-state overflow keys additionally drive the janitor's
// pressure mode. Keys are a userspace-visible contract: mirror any change in
// control/event_rate_contract.go (guarded by
// TestBpfStatsKeysParityWithKernelSource).
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, BPF_STATS_MAX);
} bpf_stats_map SEC(".maps");

// bump_stat increments a datapath counter. The ARRAY map cannot fail its
// lookup for an in-range key, but keep the NULL check: a silent miss here is
// exactly the kind of invisible degradation these counters exist to remove.
static __always_inline void bump_stat(__u32 key)
{
	__u64 *counter = bpf_map_lookup_elem(&bpf_stats_map, &key);

	if (counter)
		__sync_fetch_and_add(counter, 1);
}

// Event rate-limit constants are owned by userspace and injected through the
// .rodata datasec at load time (same mechanism as struct daer_param). The
// initializers below are clang-side fallbacks: Go overwrites the variable
// before LoadAndAssign, and the ARRAY capacity is derived from the same
// userspace key there, so the key-domain/capacity pairing has a single
// owner instead of a two-sided convention.
struct daer_event_rate {
	__u64 window_ns;                // per-key minimum spacing between emissions
	__u64 redirect_rebind_stale_ns; // reply-binding freeze window
	__u32 blocked_key;              // reserved rate key for DAER_EVENT_BLOCKED
	__u32 redirect_rebind_key;      // ... DAER_EVENT_REDIRECT_REBIND_REJECTED
	__u32 overflow_key;             // ... the conn-state/map overflow events
	__u32 syn_rebind_key;           // ... DAER_EVENT_SYN_REBIND_REJECTED
	// stateless_tcp_key and frag_tail_key are reserved: the two event types
	// they throttled (6 and 7) are no longer emitted, because a by-design
	// passthrough must not warn per event. They stay in place so the .rodata
	// layout, the ARRAY capacity derived from the highest key, and the
	// userspace mirror (eventRateSpec in control/event_rate_contract.go) stay
	// byte-identical.
	__u32 stateless_tcp_key;        // reserved: DAER_EVENT_RESERVED_* (6)
	__u32 frag_tail_key;            // reserved: DAER_EVENT_RESERVED_* (7)
	// Explicit padding: the Go mirror is written with packed binary encoding,
	// so the C layout must not carry implicit alignment holes either.
	__u32 padding[2];
};

// window_ns first keeps the struct free of implicit padding.
const volatile struct daer_event_rate EVENT_RATE = {
	.window_ns = 1000000000ULL,
	.redirect_rebind_stale_ns = REDIRECT_REBIND_STALE_NS_FALLBACK,
	.blocked_key = 256,
	.redirect_rebind_key = 257,
	.overflow_key = 258,
	.syn_rebind_key = 259,
	.stateless_tcp_key = 260,
	.frag_tail_key = 261,
};

// Map definitions need an integer constant expression for max_entries, so
// the fallback stays a macro; the authoritative capacity is re-derived from
// the injected EVENT_RATE keys on the Go side (tuneEventRateMap).
#define EVENT_RATE_KEY_MAX_FALLBACK 261

// alive_block_rate_map rate-limits event emission: key = outbound id for
// DAER_EVENT_BLOCKED_ALIVE, or one of the reserved EVENT_RATE keys beyond the
// 0..255 outbound domain for the datapath-wide event types; value = last
// emission time (CLOCK_MONOTONIC ns). Without this, an outbound that is not
// alive (or a blocked-flow / overflow / rebind flood) would emit one event per
// packet and flood the ringbuf, starving the consumed event types. Key domains
// cannot collide: outbound ids live in the 0..255 u8 domain while the reserved
// keys start at 256.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, EVENT_RATE_KEY_MAX_FALLBACK + 1);
} alive_block_rate_map SEC(".maps");

// Events delivered to userspace via ring buffer.


struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);  // 256KB ring buffer
} event_ringbuf SEC(".maps");

// TCP connection state constants.
enum tcp_state {
	TCP_STATE_ACTIVE = 0,
	TCP_STATE_CLOSING = 1,  // FIN or RST seen
};

// Parsed header state; lives in per-CPU scratch map to stay under 512-byte stack.
struct parse_transport_ctx {
	struct ethhdr ethh;
	struct iphdr iph;
	struct ipv6hdr ipv6h;
	struct icmp6hdr icmp6h;
	struct tcphdr tcph;
	struct udphdr udph;
	__u8 ihl;
	__u8 l4proto;
	__u8 listener_l4proto;
	__u8 pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct parse_transport_ctx);
	__uint(max_entries, 1);
} parse_ctx_scratch_map SEC(".maps");


