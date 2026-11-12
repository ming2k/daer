// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2022-2026, daer contributors
//
// Part of the datapath translation unit. See ADR-0024 for why the split is by
// map ownership and attach domain rather than by directory convention.

struct route_ctx {
	__u32 flag[8];
	__u8 is_wan;
	__be32 mac[4];
	__u16 h_dport;
	__u16 h_sport;
	__s64 result;
	struct lpm_key lpm_key_saddr, lpm_key_daddr, lpm_key_mac;
	__u32 domain_word_idx;
	__u32 domain_word_bits;
	__u32 routing_epoch_slot;
	bool domain_word_cached;
	__u8 route_state;
};

struct route_loop_ctx {
	struct route_ctx *work;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct route_ctx);
	__uint(max_entries, 1);
} route_ctx_scratch_map SEC(".maps");

enum route_state_flags {
	ROUTE_STATE_BAD_RULE = 1U << 0,
	ROUTE_STATE_GOOD_SUBRULE = 1U << 1,
	ROUTE_STATE_MUST = 1U << 2,
	ROUTE_STATE_DNS_QUERY = 1U << 3,
};

struct wan_egress_route_scratch {
	__u32 flag[8];
	__be32 mac_be[4];
	__u8 is_wan;
	__u8 must_val;
	__u8 mac[6];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct wan_egress_route_scratch);
	__uint(max_entries, 1);
} wan_egress_route_scratch_map SEC(".maps");

// Per-CPU scratch to tunnel conntrack args past the BPF 5-argument limit.
#define CT_ARGS_HAS_ROUTING  BIT(0)
#define CT_ARGS_HAS_MAC      BIT(1)
#define CT_ARGS_HAS_PNAME    BIT(2)
/* Set by __mark_tcp_seen when a pure SYN reached a live ACTIVE flow and must
  * not rewrite its routing decision or reply binding . */
#define CT_ARGS_REBIND_LOCKED BIT(3)

struct conntrack_args {
	__u8 flags;        // CT_ARGS_HAS_* bitmask
	__u8 outbound;
	__u8 must;
	__u8 dscp;
	__u32 mark;
	__u32 pid;
	__u8 mac[6];
	__u8 routing_epoch_slot;
	__u8 padding;
	__u8 pname[TASK_COMM_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct conntrack_args);
	__uint(max_entries, 1);
} conntrack_args_map SEC(".maps");

static __always_inline void
conntrack_args_set(struct conntrack_args *a,
		   __u8 *outbound, __u32 *mark, __u8 *must, __u8 *mac,
		   __u8 dscp, const char *pname, __u32 pid,
		   __u8 routing_epoch_slot)
{
	__u8 flags = 0;

	a->outbound = 0;
	a->must = 0;
	a->dscp = dscp;
	a->mark = 0;
	a->pid = 0;
	a->routing_epoch_slot = ROUTING_EPOCH_SLOT_UNKNOWN;
	__builtin_memset(a->mac, 0, sizeof(a->mac));
	__builtin_memset(a->pname, 0, sizeof(a->pname));

	if (outbound) {
		flags |= CT_ARGS_HAS_ROUTING;
		a->outbound = *outbound;
		a->mark = *mark;
		a->must = *must;
		a->routing_epoch_slot =
			routing_epoch_slot_sanitize(routing_epoch_slot);
	}
	if (mac) {
		flags |= CT_ARGS_HAS_MAC;
		__builtin_memcpy(a->mac, mac, 6);
	}
	if (pname) {
		flags |= CT_ARGS_HAS_PNAME;
		__builtin_memcpy(a->pname, pname, TASK_COMM_LEN);
	}
	a->pid = pid;
	a->flags = flags;
}

static __always_inline int
route_match_lpm(struct route_ctx *ctx, const struct match_set *match_set,
		struct lpm_key *lpm_key)
{
	struct map_lpm_type *lpm;
	__u32 lpm_index;

	if (unlikely(ctx->routing_epoch_slot >= ROUTING_EPOCH_SLOT_NUM ||
		     match_set->index >= MAX_MATCH_SET_LEN)) {
		ctx->result = -EFAULT;
		return 1;
	}

	lpm_index = ctx->routing_epoch_slot * MAX_MATCH_SET_LEN +
		match_set->index;

	lpm = bpf_map_lookup_elem(&lpm_array_map, &lpm_index);
	if (unlikely(!lpm)) {
		ctx->result = -EFAULT;
		return 1;
	}

	if (bpf_map_lookup_elem(lpm, lpm_key)) {
		// match_set hits.
		ctx->route_state |= ROUTE_STATE_GOOD_SUBRULE;
	}
	return 0;
}

static __always_inline struct lpm_key *
route_select_lpm_key(struct route_ctx *ctx, __u8 match_type)
{
	if (match_type == MatchType_Mac)
		return &ctx->lpm_key_mac;
	if (match_type == MatchType_IpSet)
		return &ctx->lpm_key_daddr;
	return &ctx->lpm_key_saddr;
}

static __always_inline int route_match_domain_set(struct route_ctx *ctx,
						  __u32 index)
{
	__u32 bitmap_word_idx;
	struct domain_routing *domain_routing;

	if (unlikely(index >= MAX_MATCH_SET_LEN)) {
		ctx->result = -EFAULT;
		return 1;
	}
	bitmap_word_idx = index >> 5;

	if (!ctx->domain_word_cached || ctx->domain_word_idx != bitmap_word_idx) {
		// Refresh one 32-rule bitmap word at a time.
		struct routing_epoch_ip daddr = {
			.slot = ctx->routing_epoch_slot,
		};

		__builtin_memcpy(daddr.addr, ctx->lpm_key_daddr.data,
				 sizeof(daddr.addr));
		domain_routing = bpf_map_lookup_elem(&domain_routing_map, &daddr);
		ctx->domain_word_idx = bitmap_word_idx;
		if (domain_routing)
			ctx->domain_word_bits =
				domain_routing->bitmap[bitmap_word_idx];
		else
			ctx->domain_word_bits = 0;
		ctx->domain_word_cached = true;
	}

	if ((ctx->domain_word_bits >> (index % 32)) & 1)
		ctx->route_state |= ROUTE_STATE_GOOD_SUBRULE;
	return 0;
}

static __always_inline int
route_eval_match(struct route_ctx *ctx, const struct match_set *match_set,
		 __u32 index, __u8 l4proto_type, __u8 ipversion_type,
		 const __u32 *pname, __u8 is_wan, __u8 dscp)
{
	__u8 match_type = match_set->type;

	switch (match_type) {
	case MatchType_Mac:
	case MatchType_IpSet:
	case MatchType_SourceIpSet:
	{
		struct lpm_key *lpm_key = route_select_lpm_key(ctx, match_type);

		if (route_match_lpm(ctx, match_set, lpm_key))
			return 1;
		break;
	}
	case MatchType_Port:
	case MatchType_SourcePort:
	{
		__u16 check_port = match_type == MatchType_Port ? ctx->h_dport :
						      ctx->h_sport;
		if (check_port >= match_set->port_range.port_start &&
		    check_port <= match_set->port_range.port_end)
			ctx->route_state |= ROUTE_STATE_GOOD_SUBRULE;
		break;
	}
	case MatchType_L4Proto:
	case MatchType_IpVersion:
	{
		__u8 value = match_type == MatchType_L4Proto ? l4proto_type :
							      ipversion_type;
		__u8 mask = match_type == MatchType_L4Proto ?
				    match_set->l4proto_type :
				    match_set->ip_version;
		if (value & mask)
			ctx->route_state |= ROUTE_STATE_GOOD_SUBRULE;
		break;
	}
	case MatchType_DomainSet:
		if (route_match_domain_set(ctx, index))
			return 1;
		break;
	case MatchType_ProcessName:
		if (is_wan && equal16(match_set->pname, pname))
			ctx->route_state |= ROUTE_STATE_GOOD_SUBRULE;
		break;
	case MatchType_Dscp:
		if (dscp == match_set->dscp)
			ctx->route_state |= ROUTE_STATE_GOOD_SUBRULE;
		break;
	case MatchType_Fallback:
		ctx->route_state |= ROUTE_STATE_GOOD_SUBRULE;
		break;
	default:
		ctx->result = -EINVAL;
		return 1;
	}

	return 0;
}

static __always_inline int
route_finalize_match(struct route_ctx *ctx, const struct match_set *match_set)
{
	__u8 match_outbound = match_set->outbound;
	bool match_not = match_set->not;

	if (match_outbound != OUTBOUND_LOGICAL_OR) {
		// This match_set reaches the end of subrule.
		// We are now at end of rule, or next match_set belongs to another
		// subrule.
		if (!!(ctx->route_state & ROUTE_STATE_GOOD_SUBRULE) == match_not)
			// This subrule does not hit.
			ctx->route_state |= ROUTE_STATE_BAD_RULE;

		// Reset good_subrule.
		ctx->route_state &= ~ROUTE_STATE_GOOD_SUBRULE;
	}
	if ((match_outbound & OUTBOUND_LOGICAL_MASK) != OUTBOUND_LOGICAL_MASK) {
		// Tail of a rule (line).
		// Decide whether to hit.
		if (!(ctx->route_state & ROUTE_STATE_BAD_RULE)) {
			// DNS requests should routed by control plane if outbound is not
			// must_direct.
			if (unlikely(match_outbound == OUTBOUND_MUST_RULES)) {
				ctx->route_state |= ROUTE_STATE_MUST;
			} else {
				bool must = !!(ctx->route_state & ROUTE_STATE_MUST) ||
					    match_set->must;

				if (!must &&
				    (ctx->route_state & ROUTE_STATE_DNS_QUERY)) {
					ctx->result =
						(__s64)OUTBOUND_CONTROL_PLANE_ROUTING |
						((__s64)match_set->mark << 8) |
						((__s64)must << 40);
					return 1;
				}
				ctx->result = (__s64)match_outbound |
					      ((__s64)match_set->mark << 8) |
					      ((__s64)must << 40);
				return 1;
			}
		}
		ctx->route_state &= ~ROUTE_STATE_BAD_RULE;
	}
	return 0;
}

static __noinline int route_loop_cb(__u32 index, void *data)
{
	struct route_loop_ctx *loop = data;
	struct route_ctx *ctx = loop->work;
	struct match_set *match_set;
	__u8 l4proto_type = ctx->flag[0];
	__u8 ipversion_type = ctx->flag[1];
	const __u32 *pname = &ctx->flag[2];
	__u8 is_wan = ctx->is_wan;
	__u8 dscp = ctx->flag[6];
	volatile __u32 logical_index;

	// Rule is like: domain(suffix:baidu.com, suffix:google.com) && port(443) ->
	// proxy Subrule is like: domain(suffix:baidu.com, suffix:google.com) Match
	// set is like: suffix:baidu.com
	// Preserve the callback's u32 bound in the verifier.
	logical_index = index;

	if (unlikely(logical_index >= MAX_MATCH_SET_LEN)) {
		ctx->result = -EFAULT;
		return 1;
	}

	if (unlikely(ctx->routing_epoch_slot >= ROUTING_EPOCH_SLOT_NUM)) {
		ctx->result = -EFAULT;
		return 1;
	}

	__u32 k = ctx->routing_epoch_slot * MAX_MATCH_SET_LEN + logical_index;

	match_set = bpf_map_lookup_elem(&routing_map, &k);
	if (unlikely(!match_set)) {
		ctx->result = -EFAULT;
		return 1;
	}

	if (!(ctx->route_state &
	      (ROUTE_STATE_BAD_RULE | ROUTE_STATE_GOOD_SUBRULE))) {
		if (route_eval_match(ctx, match_set, logical_index, l4proto_type,
				     ipversion_type, pname, is_wan, dscp))
			return 1;
	} else {
	}

	return route_finalize_match(ctx, match_set);
}

static __noinline __s64 route(const __u32 *flag, const void *l4hdr,
			      const __be32 *saddr, const __be32 *daddr,
			      const __be32 *mac)
{
#define _l4proto_type flag[0]
#define _ipversion_type flag[1]
#define _pname (&flag[2])
#define _is_wan flag[7]
#define _dscp flag[6]

	__u32 scratch_key = 0;
	struct route_ctx *ctx =
		bpf_map_lookup_elem(&route_ctx_scratch_map, &scratch_key);

	if (!ctx)
		return -EFAULT;

	__builtin_memset(ctx, 0, sizeof(*ctx));
	__builtin_memcpy(ctx->flag, flag, sizeof(ctx->flag));
	ctx->is_wan = _is_wan;
	__builtin_memcpy(ctx->mac, mac, sizeof(ctx->mac));
	ctx->result = -ENOEXEC;

	// Variables for further use.
	if (_l4proto_type == L4ProtoType_TCP) {
		ctx->h_dport = bpf_ntohs(((struct tcphdr *)l4hdr)->dest);
		ctx->h_sport =
			bpf_ntohs(((struct tcphdr *)l4hdr)->source);
	} else {
		ctx->h_dport = bpf_ntohs(((struct udphdr *)l4hdr)->dest);
		ctx->h_sport =
			bpf_ntohs(((struct udphdr *)l4hdr)->source);
	}

	// Rule is like: domain(suffix:baidu.com, suffix:google.com) && port(443) ->
	// proxy Subrule is like: domain(suffix:baidu.com, suffix:google.com) Match
	// set is like: suffix:baidu.com
	ctx->route_state =
		(ctx->h_dport == 53 &&
		 (_l4proto_type == L4ProtoType_UDP ||
		  _l4proto_type == L4ProtoType_TCP))
		? ROUTE_STATE_DNS_QUERY
		: 0;

	ctx->lpm_key_saddr.prefixlen = IPV6_BYTE_LENGTH * 8;
	ctx->lpm_key_daddr.prefixlen = IPV6_BYTE_LENGTH * 8;
	ctx->lpm_key_mac.prefixlen = IPV6_BYTE_LENGTH * 8;
	__builtin_memcpy(ctx->lpm_key_saddr.data, saddr,
			 IPV6_BYTE_LENGTH);
	__builtin_memcpy(ctx->lpm_key_daddr.data, daddr,
			 IPV6_BYTE_LENGTH);
	__builtin_memcpy(ctx->lpm_key_mac.data, mac, IPV6_BYTE_LENGTH);

	__u32 active_routing_epoch_slot = 0;
	__u32 *active_routing_epoch_slot_ptr =
		bpf_map_lookup_elem(&active_routing_epoch_map, &zero_key);
	__u32 active_rules_len = MAX_MATCH_SET_LEN;
	__u32 *active_rules_len_ptr =
		NULL;
	int ret;

	if (active_routing_epoch_slot_ptr) {
		active_routing_epoch_slot = *active_routing_epoch_slot_ptr;
		if (unlikely(active_routing_epoch_slot >= ROUTING_EPOCH_SLOT_NUM))
			return -EFAULT;
	}
	ctx->routing_epoch_slot = active_routing_epoch_slot;
	active_rules_len_ptr = bpf_map_lookup_elem(&routing_meta_map, &active_routing_epoch_slot);

	if (active_rules_len_ptr && *active_rules_len_ptr <= MAX_MATCH_SET_LEN)
		active_rules_len = *active_rules_len_ptr;

	struct route_loop_ctx loop_ctx = {
		.work = ctx,
	};
	ret = bpf_loop(active_rules_len, route_loop_cb, &loop_ctx, 0);
	if (unlikely(ret < 0))
		return ret;
	if (ctx->result >= 0) {
		// Preserve the policy slot alongside the existing packed result bits.
		return ctx->result |
		       ((__s64)routing_epoch_slot_encode(ctx->routing_epoch_slot)
			<< ROUTING_EPOCH_SLOT_RESULT_SHIFT);
	}
	return -EPERM;
#undef _l4proto_type
#undef _ipversion_type
#undef _pname
#undef _is_wan
#undef _dscp
}

