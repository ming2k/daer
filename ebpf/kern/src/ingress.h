// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
//
// Part of the datapath translation unit. See ADR-0024 for why the split is by
// map ownership and attach domain rather than by directory convention.

// Reverse-direction conntrack refresh for LAN egress. When out is provided,
// retain the parsed packet for the combined LAN/WAN egress role.
static __noinline int
do_tproxy_lan_egress(struct __sk_buff *skb, __u32 link_h_len,
		     struct parsed_packet *out)
{
	__u32 scratch_key = 0;
	struct parse_transport_ctx *ctx =
		bpf_map_lookup_elem(&parse_ctx_scratch_map, &scratch_key);

	if (!ctx)
		return TC_ACT_SHOT;

	int ret = parse_transport(skb, link_h_len, ctx);

	if (ret) {
		// Negative: error - drop; Positive: unsupported protocol - pass through
		if (ret < 0) {
			return TC_ACT_SHOT;
		}
		report_parse_passthrough(ret);
		return TC_ACT_OK;
	}

	if (skb->ingress_ifindex == NOWHERE_IFINDEX &&  // Only drop NDP_REDIRECT packets from localhost
		ctx->l4proto == IPPROTO_ICMPV6 && ctx->icmp6h.icmp6_type == NDP_REDIRECT) {
		// REDIRECT (NDP)
		return TC_ACT_SHOT;
	}

	if (out) {
		populate_parsed_packet(skb, ctx, out);
		return tproxy_lan_egress_refresh(&out->tuples, &out->tcph, &out->udph,
						out->l4proto);
	}

	struct tuples tuples;

	get_tuples(skb, &tuples, &ctx->iph, &ctx->ipv6h,
		   &ctx->tcph, &ctx->udph, ctx->l4proto);
	return tproxy_lan_egress_refresh(&tuples, &ctx->tcph, &ctx->udph,
					ctx->l4proto);
}

SEC("classifier/lan_egress_l2")
int tproxy_lan_egress_l2(struct __sk_buff *skb)
{
	return do_tproxy_lan_egress(skb, 14, NULL);
}

SEC("classifier/lan_egress_l3")
int tproxy_lan_egress_l3(struct __sk_buff *skb)
{
	return do_tproxy_lan_egress(skb, 0, NULL);
}

static __noinline bool
wan_outbound_is_alive(struct __sk_buff *skb, __u8 outbound, __u8 l4proto,
		      __be16 dport);

static __noinline int
redirect_lan_packet_to_control_plane(struct __sk_buff *skb, __u32 link_h_len,
				     struct parsed_packet *pkt,
				     __u64 routing_meta_raw,
				     __u8 routing_epoch_slot)
{
	union routing_meta routing_meta = {
		.raw = routing_meta_raw,
	};

	if (prep_redirect_to_control_plane(skb, link_h_len, &pkt->tuples,
					   &pkt->ethh, 0)) {
		return TC_ACT_SHOT;
	}

	skb->cb[0] = TPROXY_MARK;
	skb->cb[1] = pkt->listener_l4proto;

	if (pkt->handoff_required) {
		struct routing_handoff_entry handoff = {};

		handoff.last_seen_ns = bpf_ktime_get_ns();
		handoff.result.mark = routing_meta.data.mark;
		handoff.result.must = routing_meta.data.must;
		handoff.result.outbound = routing_meta.data.outbound;
		handoff.result.dscp = routing_meta.data.dscp;
		handoff.result.routing_epoch_slot =
			routing_epoch_slot_sanitize(routing_epoch_slot);
		handoff.result.datapath_generation = pkt->datapath_generation;
		__builtin_memcpy(handoff.result.mac, pkt->ethh.h_source, 6);
		bpf_map_update_elem(&routing_handoff_map, &pkt->tuples.five,
				    &handoff, BPF_ANY);
	}
	return redirect_to_control_plane_ingress();
}

/* LAN-ingress role body. Takes the packet already parsed by the middle layer
 * so that a dual-role attachment (wan_lan_ingress) parses exactly once. Kept
 * inline so the role's locals live in whichever middle-layer frame drives it
 * (the combined 512-byte stack budget of the call chains is tight). */
static __always_inline int
tproxy_lan_ingress_role(struct __sk_buff *skb, __u32 link_h_len,
			struct parsed_packet *pkt)
{
	/*
   * ip rule add fwmark 0x8000000/0x8000000 table 2023
   * ip route add local default dev lo table 2023
   * ip -6 rule add fwmark 0x8000000/0x8000000 table 2023
   * ip -6 route add local default dev lo table 2023

   * ip rule del fwmark 0x8000000/0x8000000 table 2023
   * ip route del local default dev lo table 2023
   * ip -6 rule del fwmark 0x8000000/0x8000000 table 2023
   * ip -6 route del local default dev lo table 2023
   */
	if (pkt->l4proto == IPPROTO_TCP &&
	    !is_new_tcp_connection(&pkt->tcph)) {
		__u8 outbound;
		__u32 mark;
		struct conn_state *tcp_state;

		// Track TCP connection state; reuse returned pointer.
		tcp_state = mark_tcp_seen(&pkt->tuples.five, &pkt->tcph, false,
					  NULL, NULL, NULL, NULL,
					  0, NULL, 0,
					  ROUTING_EPOCH_SLOT_UNKNOWN);
		/* No cached state for an established packet: keep the historical
		 * passthrough behavior instead of recomputing routing, and count
		 * it without warning per event. This is what every
		 * pre-existing TCP flow does after a restart, and it silently
		 * bypasses routing today: a steady state must not log one line
		 * per second, so the counter is the per-packet record and
		 * userspace reports its interval delta
		 * (reportDatapathPassthroughSummary in control/control_plane.go).
		 */
		if (!tcp_state) {
			bump_stat(BPF_STATS_STATELESS_TCP_PASSTHROUGH);
			return TC_ACT_OK;
		}

		/* Compatibility restore for 030902f behavior and align with WAN
		 * non-SYN session handling: reuse cached routing result for
		 * established TCP packets.
		 */
		if (!tcp_state->meta.data.has_routing) {
			/* No cache: keep historical direct-pass semantics (e.g.
			 * single-arm / reply-path traffic).
			 */
			return TC_ACT_OK;
		}

		// Load routing from the conn_state we already looked up
		outbound = tcp_state->meta.data.outbound;
		mark = tcp_state->meta.data.mark;

		if (outbound == OUTBOUND_DIRECT) {
			skb->mark = mark;
			return TC_ACT_OK;
		}
		if (unlikely(outbound == OUTBOUND_BLOCK))
			return TC_ACT_SHOT;
		pkt->datapath_generation = tcp_state->datapath_generation;
		return redirect_lan_packet_to_control_plane(
			skb, link_h_len, pkt, tcp_state->meta.raw,
			tcp_state->routing_epoch_slot);
	}

	// Routing for new connection.
	__u32 route_flag[8] = {};
	struct conn_state *tcp_state = NULL;
	struct conn_state *udp_state = NULL;
	__u8 udp_state_status = UDP_CONN_STATE_STATUS_UNAVAILABLE;

	if (pkt->l4proto == IPPROTO_TCP) {
		// Track TCP connection state for new connections from LAN.
		// This ensures routing cache entries can be cleaned up via
		// cascade deletion when the connection expires.
		tcp_state = mark_tcp_seen(&pkt->tuples.five, &pkt->tcph, false,
					  NULL, NULL, NULL, NULL,
					  pkt->tuples.dscp, NULL, 0,
					  ROUTING_EPOCH_SLOT_UNKNOWN);
		route_flag[0] = L4ProtoType_TCP;
	} else {
		if (!is_short_lived_udp_traffic(&pkt->tuples.five)) {
			// Fast path: Check conn state for established UDP flows
			udp_state = mark_udp_seen_with_status(
				&pkt->tuples.five, false, NULL, NULL, NULL, NULL,
				pkt->tuples.dscp, NULL, 0,
				ROUTING_EPOCH_SLOT_UNKNOWN, &udp_state_status);
			if (udp_state && udp_state->is_wan_ingress_direction) {
				// Replay (outbound) of an inbound flow => direct.
				return TC_ACT_OK;
			}

			// Fast path: Use cached routing if available
			if (udp_state && udp_state->meta.data.has_routing) {
				// Load routing from conn state - skip expensive route call!
				__u8 outbound = udp_state->meta.data.outbound;
				__u32 mark = udp_state->meta.data.mark;

				if (outbound == OUTBOUND_DIRECT) {
					skb->mark = mark;
					goto direct;
				} else if (unlikely(outbound == OUTBOUND_BLOCK)) {
					goto block;
				}

				/* last_seen_ns already refreshed by mark_udp_seen. */
				pkt->datapath_generation = udp_state->datapath_generation;
				return redirect_lan_packet_to_control_plane(
					skb, link_h_len, pkt, udp_state->meta.raw,
					udp_state->routing_epoch_slot);
			}
		}
		route_flag[0] = L4ProtoType_UDP;
	}
	route_flag[1] = (skb->protocol == bpf_htons(ETH_P_IP)) ? IpVersionType_4 :
							      IpVersionType_6;
	route_flag[6] = pkt->tuples.dscp;
	__be32 mac_be[4] = {
		0,
		0,
		bpf_htonl(((__u32)pkt->ethh.h_source[0] << 8) |
			  (__u32)pkt->ethh.h_source[1]),
		bpf_htonl(((__u32)pkt->ethh.h_source[2] << 24) |
			  ((__u32)pkt->ethh.h_source[3] << 16) |
			  ((__u32)pkt->ethh.h_source[4] << 8) |
			  (__u32)pkt->ethh.h_source[5]),
	};

	// Socket lookup before routing to detect a service on this host that the
	// packet is addressed to (NAT loopback). Only a socket bound to the
	// packet's exact destination address proves that: a wildcard-bound socket
	// answers for any destination, so it must not capture traffic addressed
	// elsewhere, and it must never capture DNS. TCP is not looked up here
	// because every non-SYN TCP packet already returned above.
	if (pkt->l4proto == IPPROTO_UDP &&
	    pkt->tuples.five.dport != bpf_htons(53)) {
		struct bpf_sock_tuple tuple = { 0 };
		__u32 tuple_size;
		struct bpf_sock *sk;

		// Use ethh->h_proto instead of skb->protocol for consistency
		// with parse_transport and to handle L3-only packets correctly
		if (pkt->ethh.h_proto == bpf_htons(ETH_P_IP)) {
			tuple.ipv4.daddr = pkt->tuples.five.dip.u6_addr32[3];
			tuple.ipv4.saddr = pkt->tuples.five.sip.u6_addr32[3];
			tuple.ipv4.dport = pkt->tuples.five.dport;
			tuple.ipv4.sport = pkt->tuples.five.sport;
			tuple_size = sizeof(tuple.ipv4);
		} else {
			__builtin_memcpy(tuple.ipv6.daddr, &pkt->tuples.five.dip,
					 IPV6_BYTE_LENGTH);
			__builtin_memcpy(tuple.ipv6.saddr, &pkt->tuples.five.sip,
					 IPV6_BYTE_LENGTH);
			tuple.ipv6.dport = pkt->tuples.five.dport;
			tuple.ipv6.sport = pkt->tuples.five.sport;
			tuple_size = sizeof(tuple.ipv6);
		}

		/* Look up in the netns of the hook (the LAN-side host netns):
		 * netns_id would search daer's own netns, which can only ever
		 * match daer sockets and makes the local-service branch below
		 * unreachable. -1 selects "the netns of ctx".
		 */
		sk = bpf_sk_lookup_udp(skb, &tuple, tuple_size,
				       (__u64)(s32)-1, 0);
		if (sk) {
			if (!bpf_sock_is_daer_socket(sk) &&
			    sock_bound_to_daddr(sk, &pkt->tuples,
						pkt->ethh.h_proto)) {
				bpf_sk_release(sk);
				return TC_ACT_OK;
			}
			bpf_sk_release(sk);
		}
	}

	__s64 s64_ret;

	s64_ret = route(route_flag,
			pkt->l4proto == IPPROTO_TCP ? (const void *)&pkt->tcph :
						      (const void *)&pkt->udph,
			pkt->tuples.five.sip.u6_addr32,
			pkt->tuples.five.dip.u6_addr32,
			mac_be);
	if (s64_ret < 0) {
		return TC_ACT_SHOT;
	}

	__u8 outbound = s64_ret & 0xff;
	__u32 mark = s64_ret >> 8;
	__u8 must = (s64_ret >> 40) & 1;
	__u8 routing_epoch_slot =
		routing_epoch_slot_from_route_result(s64_ret);

	// Cache routing in conn state (skip DNS to avoid map churn).
	if (pkt->l4proto == IPPROTO_UDP &&
	    is_short_lived_udp_traffic(&pkt->tuples.five)) {
		// Skip cache for short-lived DNS to avoid map churn.
	} else if (pkt->l4proto == IPPROTO_TCP && tcp_state) {
		// Directly update the TCP conn state we already looked up
		__builtin_memcpy(tcp_state->mac, pkt->ethh.h_source, 6);
		tcp_state->routing_epoch_slot = routing_epoch_slot;
		tcp_state->datapath_generation = PARAM.datapath_generation;
		union routing_meta _m = build_routing_meta(outbound, mark, must,
						    pkt->tuples.dscp);
		publish_routing_meta(&tcp_state->meta, _m);
	} else if (pkt->l4proto == IPPROTO_UDP && udp_state) {
		// Directly update the UDP conn state we already looked up
		__builtin_memcpy(udp_state->mac, pkt->ethh.h_source, 6);
		udp_state->routing_epoch_slot = routing_epoch_slot;
		udp_state->datapath_generation = PARAM.datapath_generation;
		union routing_meta _m = build_routing_meta(outbound, mark, must,
							    pkt->tuples.dscp);
		publish_routing_meta(&udp_state->meta, _m);
	}

	// Fail-closed: TCP without conn state must drop to prevent traffic leakage.
	if (pkt->l4proto == IPPROTO_TCP && !tcp_state) {
		if (outbound == OUTBOUND_DIRECT && mark == 0) {
			skb->mark = mark;
			goto direct;
		}
		goto block;
	}


	if (outbound == OUTBOUND_DIRECT) {
		skb->mark = mark;
		goto direct;
	} else if (unlikely(outbound == OUTBOUND_BLOCK)) {
		send_blocked_event(outbound, pkt->l4proto,
				   pkt->tuples.five.sip.u6_addr32,
				   pkt->tuples.five.dip.u6_addr32,
				   pkt->tuples.five.sport, pkt->tuples.five.dport);
		goto block;
	}

	if (!wan_outbound_is_alive(skb, outbound, pkt->l4proto,
				   pkt->tuples.five.dport)) {
		send_blocked_alive_event(outbound, pkt->l4proto,
					 pkt->tuples.five.sip.u6_addr32,
					 pkt->tuples.five.dip.u6_addr32,
					 pkt->tuples.five.sport,
					 pkt->tuples.five.dport);
		goto block;
	}
	pkt->datapath_generation = PARAM.datapath_generation;
	pkt->handoff_required =
		(pkt->l4proto == IPPROTO_TCP && tcp_state) ||
		(pkt->l4proto == IPPROTO_UDP &&
		 udp_state_status != UDP_CONN_STATE_STATUS_EXISTING);
	return redirect_lan_packet_to_control_plane(
		skb, link_h_len, pkt,
		build_routing_meta(outbound, mark, must, pkt->tuples.dscp).raw,
		routing_epoch_slot);

direct:
	return TC_ACT_OK;

block:
	return TC_ACT_SHOT;
}

/* Middle layer: parse once, then run the LAN-ingress role. One call frame, as
 * before the role was split out, so the callers' stack chains do not grow. */
static __noinline int do_tproxy_lan_ingress(struct __sk_buff *skb, __u32 link_h_len)
{
	// Per-CPU scratch to stay under 512-byte stack limit.
	__u32 scratch_key = 0;
	struct parsed_packet *pkt =
		bpf_map_lookup_elem(&pkt_scratch_map, &scratch_key);

	if (!pkt)
		return TC_ACT_SHOT;

	/* Ensure scratch bytes are initialized even if verifier can't precisely
	 * track writes done through callee pointer arguments. */
	__builtin_memset(pkt, 0, sizeof(*pkt));
	int ret = parse_packet(skb, link_h_len, pkt);

	if (ret) {
		if (ret < 0) {
			return TC_ACT_SHOT;
		}
		report_parse_passthrough(ret);
		return TC_ACT_OK;
	}

	return tproxy_lan_ingress_role(skb, link_h_len, pkt);
}

SEC("classifier/lan_ingress_l2")
int tproxy_lan_ingress_l2(struct __sk_buff *skb)
{
	return do_tproxy_lan_ingress(skb, 14);
}

SEC("classifier/lan_ingress_l3")
int tproxy_lan_ingress_l3(struct __sk_buff *skb)
{
	return do_tproxy_lan_ingress(skb, 0);
}

static __always_inline void
refresh_cookie_pid_last_seen(struct pid_pname *pid_pname)
{
	__u64 now = bpf_ktime_get_ns();

	if (now - pid_pname->last_seen_ns > COOKIE_PID_UPDATE_INTERVAL_NS)
		pid_pname->last_seen_ns = now;
}

// Cookie will change after the first packet, so we just use it for
// handshake.
static __always_inline bool pid_is_control_plane(struct __sk_buff *skb,
						 struct pid_pname **p)
{
	struct pid_pname *pid_pname;
	__u64 cookie = bpf_get_socket_cookie(skb);

	pid_pname = bpf_map_lookup_elem(&cookie_pid_map, &cookie);
	if (pid_pname) {
		refresh_cookie_pid_last_seen(pid_pname);
		if (p) {
			// Assign.
			*p = pid_pname;
		}
		// Get tproxy pid and compare if they are equal.
		__u32 pid_tproxy;

		pid_tproxy = PARAM.control_plane_pid;
		if (!pid_tproxy) {
			return false;
		}
		return pid_pname->pid == pid_tproxy;
	}
	if (p)
		*p = NULL;
	/* Fallback for sockets that missed cookie_pid_map (e.g. non-handshake
	 * packets): compare the exact fwmark configured for daer's own sockets.
	 * Comparing the whole mark is what keeps a foreign mark that merely
	 * carries the reserved bit (0x105, 0x1100, ...) from being classified
	 * as daer's own traffic and skipping the entire routing pass. The
	 * reserved-bit test survives only as the last resort for a datapath
	 * whose so_mark was never injected, and it is counted so that such a
	 * deployment is visible instead of silently over-matching. */
	if (PARAM.socket_mark)
		return skb->mark == PARAM.socket_mark;
	bump_stat(BPF_STATS_SOCKMARK_FALLBACK);
	return (skb->mark & 0x100) == 0x100;
}

/* WAN-ingress role body. Takes the packet already parsed by the middle layer
 * so a dual-role attachment (wan_lan_ingress) parses exactly once. */
static __always_inline int
tproxy_wan_ingress_role(struct __sk_buff *skb, __u32 link_h_len,
			struct parsed_packet *pkt)
{
	// Reverse-direction conntrack refresh.
	if (pkt->l4proto == IPPROTO_TCP) {
		struct tuples_key reversed_tuples_key;

		copy_reversed_tuples(&pkt->tuples.five, &reversed_tuples_key);
		mark_tcp_seen(&reversed_tuples_key, &pkt->tcph, true,
			      NULL, NULL, NULL, NULL,
			      0, NULL, 0, ROUTING_EPOCH_SLOT_UNKNOWN);
	} else if (pkt->l4proto == IPPROTO_UDP) {
		struct tuples_key reversed_tuples_key;
		__u8 state_status = UDP_CONN_STATE_STATUS_UNAVAILABLE;

		if (pkt->udph.source == bpf_htons(53) ||
		    pkt->udph.dest == bpf_htons(53))
			return DAE_TC_CONTINUE;

		copy_reversed_tuples(&pkt->tuples.five, &reversed_tuples_key);
		/* Observability only: an unsolicited WAN-ingress UDP flow would
		 * otherwise create conn_state from the outside (262144 entries
		 * over a 300s TTL is only ~874 new flows per second). Rejecting
		 * it would also drop the is_wan_ingress_direction marker that the
		 * wan_egress pass-through depends on (host-terminated UDP
		 * services), so this is counted, not enforced. See fix-plan.md
		 * decision A20. */
		mark_udp_seen_with_status(&reversed_tuples_key, true,
					  NULL, NULL, NULL, NULL,
					  0, NULL, 0,
					  ROUTING_EPOCH_SLOT_UNKNOWN, &state_status);
		if (state_status != UDP_CONN_STATE_STATUS_EXISTING &&
		    state_status != UDP_CONN_STATE_STATUS_UNAVAILABLE)
			bump_stat(BPF_STATS_UNSOLICITED_UDP_SEEN);
	}

	return DAE_TC_CONTINUE;
}

/* Middle layer for the WAN-ingress role; see do_tproxy_lan_ingress. */
static __noinline int do_tproxy_wan_ingress(struct __sk_buff *skb, __u32 link_h_len)
{
	__u32 scratch_key = 0;
	struct parsed_packet *pkt =
		bpf_map_lookup_elem(&pkt_scratch_map, &scratch_key);

	if (!pkt)
		return TC_ACT_SHOT;

	__builtin_memset(pkt, 0, sizeof(*pkt));
	int ret = parse_packet(skb, link_h_len, pkt);

	if (ret) {
		// Negative: error - drop; Positive: unsupported protocol - pass through
		if (ret < 0) {
			return TC_ACT_SHOT;
		}
		report_parse_passthrough(ret);
		return TC_ACT_OK;
	}

	return tproxy_wan_ingress_role(skb, link_h_len, pkt);
}

SEC("classifier/wan_ingress_l2")
int tproxy_wan_ingress_l2(struct __sk_buff *skb)
{
	return do_tproxy_wan_ingress(skb, 14);
}

SEC("classifier/wan_ingress_l3")
int tproxy_wan_ingress_l3(struct __sk_buff *skb)
{
	return do_tproxy_wan_ingress(skb, 0);
}

/* Dual-role hook: parse the packet once and run both roles on the same parsed
 * result. Parsing twice was both wasteful and a correctness hazard: the two
 * roles could observe different parser outcomes (e.g. the fast path falling
 * back to the slow path between calls) and disagree on forwarding. */
static __noinline int
do_tproxy_wan_lan_ingress(struct __sk_buff *skb, __u32 link_h_len)
{
	__u32 scratch_key = 0;
	struct parsed_packet *pkt =
		bpf_map_lookup_elem(&pkt_scratch_map, &scratch_key);

	if (!pkt)
		return TC_ACT_SHOT;

	__builtin_memset(pkt, 0, sizeof(*pkt));
	int ret = parse_packet(skb, link_h_len, pkt);

	if (ret) {
		if (ret < 0) {
			return TC_ACT_SHOT;
		}
		report_parse_passthrough(ret);
		/* The wan_ingress role used to consume the packet first and
		 * return TC_ACT_OK for an unclassifiable frame, which made the
		 * dual-role hook stop before the lan_ingress role. Preserve
		 * that forwarding decision. */
		return TC_ACT_OK;
	}

	ret = tproxy_wan_ingress_role(skb, link_h_len, pkt);
	if (ret != DAE_TC_CONTINUE)
		return ret;
	return tproxy_lan_ingress_role(skb, link_h_len, pkt);
}

SEC("classifier/wan_lan_ingress_l2")
int tproxy_wan_lan_ingress_l2(struct __sk_buff *skb)
{
	return do_tproxy_wan_lan_ingress(skb, 14);
}

SEC("classifier/wan_lan_ingress_l3")
int tproxy_wan_lan_ingress_l3(struct __sk_buff *skb)
{
	return do_tproxy_wan_lan_ingress(skb, 0);
}

