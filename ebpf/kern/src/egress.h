// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2022-2026, daer contributors
//
// Part of the datapath translation unit. See ADR-0024 for why the split is by
// map ownership and attach domain rather than by directory convention.

// Routing and redirect the packet back.
// We cannot modify the dest address here. So we cooperate with wan_ingress.


static __noinline bool
wan_outbound_is_alive(struct __sk_buff *skb, __u8 outbound, __u8 l4proto,
		      __be16 dport)
{
	/* Reserved outbounds (must_rules, control-plane routing, logical
	 * markers) have no connectivity entries: the map below is sized for
	 * user-defined ids only, so a reserved id would read a zeroed entry
	 * and silently drop the flow. This includes the control-plane punt
	 * outbound used by implicit sniff-punt rules; DNS bypasses below for
	 * the same reason. */
	if (outbound >= OUTBOUND_MUST_RULES)
		return true;

	/* DNS must always reach control plane; userspace handles fallback. */
	if (dport == bpf_htons(53))
		return true;

	// ARRAY map key: outbound_id * 6 + domain * 2 + ipversion
	// domain: 0=TCP, 1=DNS UDP, 2=data UDP; ipversion: 0=IPv4, 1=IPv6
	__u32 domain_idx = 0;
	__u32 ip_idx = skb->protocol == bpf_htons(ETH_P_IP) ? 0 : 1;
	__u32 key;
	__u32 *alive;

	if (l4proto == IPPROTO_UDP) {
		if (dport == bpf_htons(53))
			domain_idx = 1;
		else
			domain_idx = 2;
	}
	key = ((__u32)outbound * 6) + (domain_idx * 2) + ip_idx;
	alive = bpf_map_lookup_elem(&outbound_connectivity_map, &key);
	if (alive && *alive == 0)
		return false;
	return true;
}

static __noinline int
do_tproxy_wan_egress_tcp(struct __sk_buff *skb, __u32 link_h_len,
			 struct tuples *tuples, struct ethhdr *ethh,
			 struct tcphdr *tcph)
{
	bool tcp_state_syn = is_new_tcp_connection(tcph);
	__u8 outbound;
	bool must;
	__u32 mark;
	struct pid_pname *pid_pname = NULL;
	const char *handoff_pname = NULL;
	__u32 handoff_pid = 0;
	__u8 handoff_mac[6] = {};
	__u8 routing_epoch_slot = ROUTING_EPOCH_SLOT_UNKNOWN;
	__u16 datapath_generation = PARAM.datapath_generation;
	__u32 scratch_key = 0;
	struct wan_egress_route_scratch *scratch =
		bpf_map_lookup_elem(&wan_egress_route_scratch_map, &scratch_key);

	if (!scratch)
		return DAER_TC_DROP;

	if (unlikely(tcp_state_syn)) {
		__builtin_memset(scratch, 0, sizeof(*scratch));
		scratch->flag[0] = L4ProtoType_TCP;
		if (skb->protocol == bpf_htons(ETH_P_IP))
			scratch->flag[1] = IpVersionType_4;
		else
			scratch->flag[1] = IpVersionType_6;
		scratch->flag[6] = tuples->dscp;
		if (pid_is_control_plane(skb, &pid_pname))
			return DAER_TC_CONTINUE;
		if (pid_pname)
			__builtin_memcpy(&scratch->flag[2], pid_pname->pname,
					 TASK_COMM_LEN);
		scratch->flag[7] = 1;
		if (link_h_len == ETH_HLEN) {
			scratch->mac_be[2] = bpf_htonl(((__u32)ethh->h_source[0] << 8) |
						  (__u32)ethh->h_source[1]);
			scratch->mac_be[3] = bpf_htonl(((__u32)ethh->h_source[2] << 24) |
						  ((__u32)ethh->h_source[3] << 16) |
						  ((__u32)ethh->h_source[4] << 8) |
						  (__u32)ethh->h_source[5]);
			__builtin_memcpy(scratch->mac, ethh->h_source, 6);
		}

		__s64 s64_ret = route(scratch->flag, tcph,
				      tuples->five.sip.u6_addr32,
				      tuples->five.dip.u6_addr32,
				      scratch->mac_be);

		if (s64_ret < 0) {
			return DAER_TC_DROP;
		}

		outbound = s64_ret & 0xff;
		mark = s64_ret >> 8;
		must = (s64_ret >> 40) & 1;
		routing_epoch_slot = routing_epoch_slot_from_route_result(s64_ret);
		scratch->must_val = must;

		__u8 dscp = tuples->dscp;
		const char *pname_str = NULL;
		__u32 pid_val = 0;

		if (pid_pname) {
			pname_str = pid_pname->pname;
			pid_val = pid_pname->pid;
			handoff_pname = pid_pname->pname;
			handoff_pid = pid_pname->pid;
		}
		__builtin_memcpy(handoff_mac, scratch->mac, 6);

		__u8 *outbound_ptr = &outbound;
		__u32 *mark_ptr = &mark;
		__u8 *must_ptr = &scratch->must_val;

		if (outbound == OUTBOUND_DIRECT && mark == 0 && !must) {
			outbound_ptr = NULL;
			mark_ptr = NULL;
			must_ptr = NULL;
		}

		struct conn_state *tcp_conn = mark_tcp_seen(
			&tuples->five, tcph, false, outbound_ptr, mark_ptr,
			must_ptr, scratch->mac, dscp, pname_str, pid_val,
			routing_epoch_slot);

		if (!tcp_conn) {
			if (outbound == OUTBOUND_DIRECT && mark == 0)
				return DAER_TC_CONTINUE;
			return DAER_TC_DROP;
		}

	} else {
		// Established TCP: only proxied connections have cached state.
		struct conn_state *tcp_conn = mark_tcp_seen(
			&tuples->five, tcph, false,
			NULL, NULL, NULL, NULL,
			0, NULL, 0, ROUTING_EPOCH_SLOT_UNKNOWN);

		if (!tcp_conn) {
			/* No conn state for an established TCP packet: this is
			 * what every pre-existing flow does after a restart, and
			 * it silently bypasses routing. Keep the
			 * historical passthrough and count it; no per-event
			 * warning, for the same reason as the LAN-ingress twin
			 * above. */
			bump_stat(BPF_STATS_STATELESS_TCP_PASSTHROUGH);
			return DAER_TC_CONTINUE;
		}
		if (!tcp_conn->meta.data.has_routing)
			return DAER_TC_CONTINUE;

		outbound = tcp_conn->meta.data.outbound;
		mark = tcp_conn->meta.data.mark;
		must = tcp_conn->meta.data.must;
		__builtin_memcpy(handoff_mac, tcp_conn->mac, 6);
		__builtin_memcpy(scratch->mac, tcp_conn->mac, 6);
		handoff_pname = (const char *)tcp_conn->pname;
		handoff_pid = tcp_conn->pid;
		routing_epoch_slot =
			routing_epoch_slot_sanitize(tcp_conn->routing_epoch_slot);
		datapath_generation = tcp_conn->datapath_generation;
	}

	if (!wan_egress_needs_control_plane(outbound, mark)) {
		skb->mark = mark;
		return DAER_TC_CONTINUE;
	} else if (unlikely(outbound == OUTBOUND_BLOCK)) {
		return DAER_TC_DROP;
	}

	if (tcp_state_syn &&
	    !wan_outbound_is_alive(skb, outbound, IPPROTO_TCP,
				   tuples->five.dport))
		return DAER_TC_DROP;

	struct routing_result routing_result = {};

	fill_routing_result(&routing_result, mark, must, outbound, handoff_mac,
			    tuples->dscp, handoff_pname, handoff_pid,
			    routing_epoch_slot, datapath_generation);
	/* TCP has embedded conn-state routing metadata after the SYN. Keep
	 * handoff for the initial redirect only; established packets are read
	 * from conn_state_map by userspace. */
	if (tcp_state_syn)
		publish_routing_handoff(&tuples->five, &routing_result);

	/* TCP needs redirect_track before the kernel-side handshake completes.
	 * Publishing it later from userspace is too late for the first SYN path.
	 */
	if (prep_redirect_to_control_plane(skb, link_h_len, tuples,
					   ethh, 1))
		return DAER_TC_DROP;
	set_tproxy_cb(skb, tcp_listener_l4proto(tcph));
	return redirect_to_control_plane_egress();
}

static __noinline int
do_tproxy_wan_egress_udp(struct __sk_buff *skb, __u32 link_h_len,
			 struct tuples *tuples, struct ethhdr *ethh,
			 struct udphdr *udph)
{
	struct pid_pname *pid_pname;
	__u8 outbound;
	__u32 mark;
	bool must;
	struct conn_state *udp_conn_state = NULL;
	__u8 mac[6] = {};
	const char *handoff_pname = NULL;
	__u32 handoff_pid = 0;
	__u8 routing_epoch_slot = ROUTING_EPOCH_SLOT_UNKNOWN;
	__u16 datapath_generation = PARAM.datapath_generation;
	bool cached_routing = false;
	__u8 udp_state_status = UDP_CONN_STATE_STATUS_UNAVAILABLE;

	__u32 scratch_key = 0;
	struct wan_egress_route_scratch *scratch =
		bpf_map_lookup_elem(&wan_egress_route_scratch_map, &scratch_key);
	if (!scratch)
		return DAER_TC_DROP;

	__builtin_memset(scratch, 0, sizeof(*scratch));
	scratch->flag[0] = L4ProtoType_UDP;
	if (skb->protocol == bpf_htons(ETH_P_IP))
		scratch->flag[1] = IpVersionType_4;
	else
		scratch->flag[1] = IpVersionType_6;
	scratch->flag[6] = tuples->dscp;
	if (pid_is_control_plane(skb, &pid_pname))
		return DAER_TC_CONTINUE;

	if (!is_short_lived_udp_traffic(&tuples->five)) {
		udp_conn_state = mark_udp_seen_with_status(
			&tuples->five, false, NULL, NULL, NULL, NULL,
			0, NULL, 0, ROUTING_EPOCH_SLOT_UNKNOWN, &udp_state_status);
		if (udp_conn_state && udp_conn_state->is_wan_ingress_direction)
			return DAER_TC_CONTINUE;

		if (udp_conn_state && udp_conn_state->meta.data.has_routing) {
			outbound = udp_conn_state->meta.data.outbound;
			mark = udp_conn_state->meta.data.mark;
			must = udp_conn_state->meta.data.must;
			__builtin_memcpy(mac, udp_conn_state->mac, 6);
			handoff_pname = (const char *)udp_conn_state->pname;
			handoff_pid = udp_conn_state->pid;
			routing_epoch_slot = routing_epoch_slot_sanitize(
				udp_conn_state->routing_epoch_slot);
			datapath_generation = udp_conn_state->datapath_generation;
			cached_routing = true;
			goto fast_path_skip_routing;
		}
	}

	if (pid_pname) {
		__builtin_memcpy(&scratch->flag[2], pid_pname->pname,
				 TASK_COMM_LEN);
		handoff_pname = pid_pname->pname;
		handoff_pid = pid_pname->pid;
	}
	scratch->flag[7] = 1;
	if (ethh) {
		scratch->mac_be[2] = bpf_htonl(((__u32)ethh->h_source[0] << 8) |
					  (__u32)ethh->h_source[1]);
		scratch->mac_be[3] = bpf_htonl(((__u32)ethh->h_source[2] << 24) |
					  ((__u32)ethh->h_source[3] << 16) |
					  ((__u32)ethh->h_source[4] << 8) |
					  (__u32)ethh->h_source[5]);
		__builtin_memcpy(mac, ethh->h_source, 6);
		__builtin_memcpy(scratch->mac, ethh->h_source, 6);
	}

	__s64 s64_ret = route(scratch->flag, udph,
			      tuples->five.sip.u6_addr32,
			      tuples->five.dip.u6_addr32,
			      scratch->mac_be);

	if (s64_ret < 0) {
		return DAER_TC_DROP;
	}

	outbound = s64_ret & 0xff;
	mark = s64_ret >> 8;
	must = (s64_ret >> 40) & 1;
	routing_epoch_slot = routing_epoch_slot_from_route_result(s64_ret);

fast_path_skip_routing:
	/* last_seen_ns is owned by mark_udp_seen's 1s lazy refresh. Do not
	 * rewrite it here: that undoes the rate-limit and contends the
	 * conn_state_map cacheline on high-PPS WAN flows.
	 */
	if (udp_conn_state && tuples->five.dport != bpf_htons(53) &&
	    (outbound != OUTBOUND_DIRECT || mark != 0 || must)) {
		__builtin_memcpy(udp_conn_state->mac, mac, 6);
		if (pid_pname) {
			__builtin_memcpy(udp_conn_state->pname,
					 pid_pname->pname,
					 TASK_COMM_LEN);
			udp_conn_state->pid = pid_pname->pid;
		}
		udp_conn_state->routing_epoch_slot = routing_epoch_slot;
		udp_conn_state->datapath_generation = datapath_generation;
		union routing_meta _m = build_routing_meta(outbound,
						   mark,
						   must,
						   tuples->dscp);
		publish_routing_meta(&udp_conn_state->meta, _m);
	}


	if (!wan_egress_needs_control_plane(outbound, mark))
		return DAER_TC_CONTINUE;
	else if (unlikely(outbound == OUTBOUND_BLOCK))
		return DAER_TC_DROP;

	if (!cached_routing &&
	    !wan_outbound_is_alive(skb, outbound, IPPROTO_UDP,
				   tuples->five.dport))
		return DAER_TC_DROP;

	struct routing_result routing_result = {};
	bool handoff_mandatory =
		is_short_lived_udp_traffic(&tuples->five) ||
		udp_state_status != UDP_CONN_STATE_STATUS_EXISTING;

	fill_routing_result(&routing_result, mark, must, outbound, mac,
			    tuples->dscp, handoff_pname, handoff_pid,
			    routing_epoch_slot, datapath_generation);
	if (handoff_mandatory &&
	    publish_routing_handoff(&tuples->five, &routing_result))
		return DAER_TC_DROP;

	if (prep_redirect_to_control_plane(skb, link_h_len, tuples,
					   ethh, 1))
		return DAER_TC_DROP;
	set_tproxy_cb(skb, IPPROTO_UDP);
	return redirect_to_control_plane_egress();
}

// Per-CPU scratch to stay under 512-byte stack limit across the call chain.
//
// Pass-through returns DAER_TC_CONTINUE (TCX_NEXT), not DAER_TC_PASS, so later TCX programs
// see the packet instead of the chain terminating at this one.
static __noinline int
do_tproxy_wan_egress(struct __sk_buff *skb, __u32 link_h_len,
		     struct parsed_packet *provided_pkt)
{
	if (skb->ingress_ifindex != NOWHERE_IFINDEX)
		return DAER_TC_CONTINUE;

	__u32 scratch_key = 0;
	struct parsed_packet *pkt = provided_pkt;

	if (!pkt) {
		pkt = bpf_map_lookup_elem(&pkt_scratch_map, &scratch_key);
		if (!pkt)
			return DAER_TC_DROP;

		/* Zero-init for verifier. */
		__builtin_memset(pkt, 0, sizeof(*pkt));
		int ret = parse_packet(skb, link_h_len, pkt);

		if (ret) {
			if (ret < 0) {
				return DAER_TC_DROP;
			}
			report_parse_passthrough(ret);
			return DAER_TC_CONTINUE;
		}
	}

	if (pkt->l4proto == IPPROTO_TCP)
		return do_tproxy_wan_egress_tcp(skb, link_h_len, &pkt->tuples,
						&pkt->ethh, &pkt->tcph);
	if (pkt->l4proto == IPPROTO_UDP)
		return do_tproxy_wan_egress_udp(skb, link_h_len, &pkt->tuples,
						&pkt->ethh, &pkt->udph);
	/* parse_packet classifies ICMPv6 as unsupported before reaching here.
	 * The combined egress path uses parse_transport directly to preserve the
	 * LAN role's NDP handling, so report that equivalent classification here. */
	if (pkt->l4proto == IPPROTO_ICMPV6)
		report_parse_passthrough(PARSE_UNSUPPORTED_L4);
	return DAER_TC_CONTINUE;
}

SEC("classifier/wan_egress_l2")
int tproxy_wan_egress_l2(struct __sk_buff *skb)
{
	return do_tproxy_wan_egress(skb, 14, NULL);
}

SEC("classifier/wan_egress_l3")
int tproxy_wan_egress_l3(struct __sk_buff *skb)
{
	return do_tproxy_wan_egress(skb, 0, NULL);
}

static __always_inline int
do_tproxy_lan_wan_egress(struct __sk_buff *skb, __u32 link_h_len)
{
	__u32 scratch_key = 0;
	struct parsed_packet *pkt =
		bpf_map_lookup_elem(&pkt_scratch_map, &scratch_key);

	if (!pkt)
		return DAER_TC_DROP;

	int ret = do_tproxy_lan_egress(skb, link_h_len, pkt);

	if (ret != DAER_TC_CONTINUE)
		return ret;
	return do_tproxy_wan_egress(skb, link_h_len, pkt);
}

SEC("classifier/lan_wan_egress_l2")
int tproxy_lan_wan_egress_l2(struct __sk_buff *skb)
{
	return do_tproxy_lan_wan_egress(skb, 14);
}

SEC("classifier/lan_wan_egress_l3")
int tproxy_lan_wan_egress_l3(struct __sk_buff *skb)
{
	return do_tproxy_lan_wan_egress(skb, 0);
}

SEC("classifier/daer0peer_ingress")
int tproxy_daer0peer_ingress(struct __sk_buff *skb)
{
	bump_stat(BPF_STATS_PEER_INGRESS);
	/* Only packets redirected from wan_egress or lan_ingress have this cb mark.
	 * The L4 protocol travels in the high nibble of the same word: cb[1] is
	 * overwritten by the redirect path on some kernels, and losing it makes
	 * assign_listener skip the flow entirely. */
	__u32 cb0 = skb->cb[0];
	if ((cb0 & 0x0fffffff) != TPROXY_MARK) {
		bump_stat(BPF_STATS_PEER_INGRESS_UNMARKED);
		return DAER_TC_DROP;
	}

	/* ip rule add fwmark 0x8000000/0x8000000 table 2023
   * ip route add local default dev lo table 2023
   */
	skb->mark = TPROXY_MARK;
	bpf_skb_change_type(skb, PACKET_HOST);

	/* listener_l4proto is stored in skb->cb[1] only when the control-plane
	 * handoff needs an explicit listener assignment (UDP or TCP SYN, including
	 * first fragments that still expose those headers). Established TCP can
	 * return to the stack without bpf_sk_assign.
	 */
	__u32 kind = (cb0 >> 28) & 0xf;
	__u8 l4proto = kind == 1 ? IPPROTO_TCP : (kind == 2 ? IPPROTO_UDP : 0);
	if (l4proto == 0)
		l4proto = skb->cb[1];
	if (l4proto != 0)
		assign_listener(skb, l4proto);
	else
		bump_stat(BPF_STATS_PEER_INGRESS_NO_L4);
	return DAER_TC_PASS;
}

// load_redirect_tuple_fast returns this code when it cannot safely parse via
// direct packet access and should fall back to bpf_skb_load_bytes.
#define LOAD_REDIRECT_TUPLE_FALLBACK 2

static __always_inline int
load_redirect_tuple_fast(struct __sk_buff *skb,
			 struct redirect_tuple *redirect_tuple)
{
	void *data, *data_end;

	// Pull header data to linear region for direct access.
	// 128 bytes is enough for: ethhdr(14) + iphdr(40) + addresses.
#define REDIRECT_PULL_SIZE 128
	if (bpf_skb_pull_data(skb, REDIRECT_PULL_SIZE))
		return LOAD_REDIRECT_TUPLE_FALLBACK;

	data = (void *)(long)skb->data;
	data_end = (void *)(long)skb->data_end;
	struct ethhdr *eth = data;

	if ((void *)(eth + 1) > data_end)
		return LOAD_REDIRECT_TUPLE_FALLBACK;
	if (eth->h_proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *iph = data + ETH_HLEN;

		if ((void *)(iph + 1) > data_end)
			return LOAD_REDIRECT_TUPLE_FALLBACK;
		// Use IPv4-mapped IPv6 format with ffff marker to match insert side
		redirect_tuple->sip.u6_addr32[2] = bpf_htonl(0x0000ffff);
		redirect_tuple->sip.u6_addr32[3] = iph->daddr;
		redirect_tuple->dip.u6_addr32[2] = bpf_htonl(0x0000ffff);
		redirect_tuple->dip.u6_addr32[3] = iph->saddr;
		return 0;
	}
	if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ipv6h = data + ETH_HLEN;

		if ((void *)(ipv6h + 1) > data_end)
			return LOAD_REDIRECT_TUPLE_FALLBACK;
		__builtin_memcpy(&redirect_tuple->sip, &ipv6h->daddr,
				 sizeof(redirect_tuple->sip));
		__builtin_memcpy(&redirect_tuple->dip, &ipv6h->saddr,
				 sizeof(redirect_tuple->dip));
		return 0;
	}
	return 1;
}

static __always_inline int
load_redirect_tuple_slow(struct __sk_buff *skb,
			 struct redirect_tuple *redirect_tuple)
{
	int ret;

	if (skb->protocol == bpf_htons(ETH_P_IP)) {
		// Set ffff marker first for IPv4-mapped IPv6 format
		__u32 ffff_marker = bpf_htonl(0x0000ffff);

		redirect_tuple->sip.u6_addr32[2] = ffff_marker;
		redirect_tuple->dip.u6_addr32[2] = ffff_marker;

		ret = bpf_skb_load_bytes(skb,
					 ETH_HLEN + offsetof(struct iphdr, daddr),
					 &redirect_tuple->sip.u6_addr32[3],
					 sizeof(redirect_tuple->sip.u6_addr32[3]));
		if (ret)
			return ret;
		ret = bpf_skb_load_bytes(skb,
					 ETH_HLEN + offsetof(struct iphdr, saddr),
					 &redirect_tuple->dip.u6_addr32[3],
					 sizeof(redirect_tuple->dip.u6_addr32[3]));
		if (ret)
			return ret;
		return 0;
	}
	if (skb->protocol == bpf_htons(ETH_P_IPV6)) {
		ret = bpf_skb_load_bytes(skb,
					 ETH_HLEN + offsetof(struct ipv6hdr, daddr),
					 &redirect_tuple->sip,
					 sizeof(redirect_tuple->sip));
		if (ret)
			return ret;
		ret = bpf_skb_load_bytes(skb,
					 ETH_HLEN + offsetof(struct ipv6hdr, saddr),
					 &redirect_tuple->dip,
					 sizeof(redirect_tuple->dip));
		if (ret)
			return ret;
		return 0;
	}
	return 1;
}

static __always_inline int
load_redirect_tuple(struct __sk_buff *skb,
		    struct redirect_tuple *redirect_tuple)
{
	int ret = load_redirect_tuple_fast(skb, redirect_tuple);

	if (ret == LOAD_REDIRECT_TUPLE_FALLBACK)
		return load_redirect_tuple_slow(skb, redirect_tuple);
	return ret;
}

/* reply_publisher_matches reports whether the reply packet in flight was sent
 * by the host/mac pair the stored binary binding belongs to: the reply's L2
 * source is the mac the binding routes back to, and its L2 destination is the
 * peer it was published for. This mirrors the publisher test the forward path
 * applies (publish_redirect_track_for_packet compares ifindex / from_wan /
 * smac); the reply path has no forward ifindex to compare against, because
 * every reply arrives on the same daer0 ingress hook.
 *
 * An unreadable L2 header is reported as "not the publisher" on purpose: the
 * conservative failure of this test is to stop refreshing the entry, which
 * lets the userspace janitor expire it, whereas the optimistic failure would
 * hand a frozen binding an unlimited lease and make the 2s window
  * unrecoverable .
 */
static __always_inline bool
reply_publisher_matches(struct __sk_buff *skb,
			const struct redirect_entry *redirect_entry)
{
	struct ethhdr eth;

	/* Read the L2 header with bpf_skb_load_bytes rather than through
	 * skb->data: the header is at L2 offset 0 on this hook, and this way the
	 * test is independent of both the read being preceded by a pull and of
	 * how skb->data is interpreted for the packet's protocol. */
	if (bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth)))
		return false;
	return mac6_equal(redirect_entry->smac, eth.h_source) &&
	       mac6_equal(redirect_entry->dmac, eth.h_dest);
}

SEC("classifier/daer0_ingress")
int tproxy_daer0_ingress(struct __sk_buff *skb)
{
	struct redirect_tuple redirect_tuple = {};
	int ret;

	ret = load_redirect_tuple(skb, &redirect_tuple);
	if (ret)
		return DAER_TC_PASS;
	struct redirect_entry *redirect_entry =
		bpf_map_lookup_elem(&redirect_track, &redirect_tuple);

	if (!redirect_entry)
		return DAER_TC_PASS;

	/* Only the publisher of the binding may extend its lease. Refreshing
	 * last_seen_ns for every packet that matched the tuple let a rejected
	 * competitor keep its victim's binding frozen forever: the rejection on
	 * the forward path deliberately does not refresh, but the competitor's
	 * own replies did, so the staleness window that is supposed to release
	 * the binding never elapsed and the flow stayed on the winner's path
	 * for good. Keeping the refresh tied to the publisher is what makes the
	 * window mean "the winner has been silent for that long", which is
	 * exactly when the competitor is allowed to take over. */
	if (reply_publisher_matches(skb, redirect_entry))
		redirect_entry->last_seen_ns = bpf_ktime_get_ns();

	bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_source),
			    redirect_entry->dmac, sizeof(redirect_entry->dmac),
			    0);
	bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_dest),
			    redirect_entry->smac, sizeof(redirect_entry->smac),
			    0);
	__u32 type = redirect_entry->from_wan ? PACKET_HOST : PACKET_OTHERHOST;

	bpf_skb_change_type(skb, type);
	__u64 flags = redirect_entry->from_wan ? BPF_F_INGRESS : 0;

	return bpf_redirect(redirect_entry->ifindex, flags);
}


