// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
//
// Part of the datapath translation unit. See ADR-0024 for why the split is by
// map ownership and attach domain rather than by directory convention.

/* The L4 protocol rides in the high nibble of cb[0] as well as in cb[1].
 * The redirect path on some kernels preserves cb[0] but clobbers cb[1], and
 * losing the protocol makes the peer-ingress hook skip assign_listener. */
static __always_inline void set_tproxy_cb(struct __sk_buff *skb, __u8 l4proto)
{
	// 1 = TCP, 2 = UDP. IPPROTO_UDP is 17 and does not fit in the nibble, so
	// the tag carries the listener *kind*, not the raw protocol number.
	__u32 kind = l4proto == IPPROTO_TCP ? 1 : (l4proto == IPPROTO_UDP ? 2 : 0);
	skb->cb[0] = TPROXY_MARK | (kind << 28);
	skb->cb[1] = l4proto;
}

static __always_inline int assign_listener(struct __sk_buff *skb, __u8 l4proto)
{


	struct bpf_sock *sk;
	const __u32 *key = &one_key;

	if (l4proto == IPPROTO_TCP)
		key = skb->protocol == bpf_htons(ETH_P_IPV6) ? &two_key : &zero_key;

	sk = bpf_map_lookup_elem(&listen_socket_map, key);

	if (!sk) {
		bump_stat(BPF_STATS_LISTENER_ASSIGN_FAILED);
		return -1;
	}

	int ret = bpf_sk_assign(skb, sk, 0);

	bpf_sk_release(sk);
	if (ret)
		bump_stat(BPF_STATS_LISTENER_ASSIGN_FAILED);
	return ret;
}

/* get_daer0_ifindex returns the current daer0 ifindex, preferring the
 * runtime-updatable map over the frozen rodata constant. This allows
 * transparent recovery when daer0 is recreated with a new ifindex.
 */
static __always_inline __u32 get_daer0_ifindex(void)
{
	__u32 key = 0;
	__u32 *val = bpf_map_lookup_elem(&daer_ifindex_map, &key);

	// zero is not a valid interface index: it is the map's default before the loader
	// publishes the real one, so treat it as absent and use the parameter fallback.
	if (val && *val)
		return *val;
	return PARAM.device_ifindex;
}

static __always_inline int redirect_to_control_plane_ingress(void)
{
	__u32 ifindex = get_daer0_ifindex();
	// bpf_redirect_peer requires the CVE-2025-37959 fix (mainline >= 6.14.7
	// or official stable backports); the loader only sets
	// PARAM.use_redirect_peer on kernels known to contain it.
	if (PARAM.use_redirect_peer)
		return bpf_redirect_peer(ifindex, 0);
	return bpf_redirect(ifindex, 0);
}

static __always_inline int redirect_to_control_plane_egress(void)
{
	__u32 ifindex = get_daer0_ifindex();
	// bpf_redirect_peer is NOT supported in egress direction.
	// Only use it for ingress hooks.
	return bpf_redirect(ifindex, 0);
}

static __always_inline bool
wan_egress_needs_control_plane(__u8 outbound, __u32 mark)
{
	return !(outbound == OUTBOUND_DIRECT && mark == 0);
}

static __always_inline void
fill_routing_result(struct routing_result *dst,
		    __u32 mark, __u8 must, __u8 outbound,
		    const __u8 mac[6], __u8 dscp,
		    const char *pname, __u32 pid,
		    __u8 routing_epoch_slot, __u16 datapath_generation)
{
	__builtin_memset(dst, 0, sizeof(*dst));
	dst->mark = mark;
	dst->must = must;
	dst->outbound = outbound;
	dst->pid = pid;
	dst->dscp = dscp;
	dst->routing_epoch_slot =
		routing_epoch_slot_sanitize(routing_epoch_slot);
	dst->datapath_generation = datapath_generation;
	if (mac)
		__builtin_memcpy(dst->mac, mac, sizeof(dst->mac));
	if (pname)
		__builtin_memcpy(dst->pname, pname, TASK_COMM_LEN);
}

static __always_inline int
publish_routing_handoff(const struct tuples_key *tuples,
			const struct routing_result *result)
{
	struct routing_handoff_entry handoff = {};
	long ret;

	handoff.last_seen_ns = bpf_ktime_get_ns();
	handoff.result = *result;
	ret = bpf_map_update_elem(&routing_handoff_map, tuples, &handoff, BPF_ANY);
	/* The failure is returned to the caller, which decides whether to drop the
	 * packet; a debug print here used to be compiled out in release builds. */
	return (int)ret;
}

static __always_inline void
fill_redirect_tuple_from_forward_packet(const struct __sk_buff *skb,
					const struct tuples *tuples,
					struct redirect_tuple *redirect_tuple)
{
	__builtin_memset(redirect_tuple, 0, sizeof(*redirect_tuple));
	if (skb->protocol == bpf_htons(ETH_P_IP)) {
		redirect_tuple->sip.u6_addr32[2] = bpf_htonl(0x0000ffff);
		redirect_tuple->sip.u6_addr32[3] = tuples->five.sip.u6_addr32[3];
		redirect_tuple->dip.u6_addr32[2] = bpf_htonl(0x0000ffff);
		redirect_tuple->dip.u6_addr32[3] = tuples->five.dip.u6_addr32[3];
	} else {
		__builtin_memcpy(&redirect_tuple->sip, &tuples->five.sip,
				 IPV6_BYTE_LENGTH);
		__builtin_memcpy(&redirect_tuple->dip, &tuples->five.dip,
				 IPV6_BYTE_LENGTH);
	}
}

static __always_inline void
fill_redirect_entry_from_forward_packet(__u32 ifindex, __u32 link_h_len,
					const struct ethhdr *ethh, __u8 from_wan,
					struct redirect_entry *redirect_entry)
{
	__builtin_memset(redirect_entry, 0, sizeof(*redirect_entry));
	redirect_entry->ifindex = ifindex;
	redirect_entry->from_wan = from_wan;
	redirect_entry->last_seen_ns = bpf_ktime_get_ns();
	if (link_h_len == ETH_HLEN && ethh) {
		__builtin_memcpy(redirect_entry->smac, ethh->h_source, 6);
		__builtin_memcpy(redirect_entry->dmac, ethh->h_dest, 6);
	}
}

static __always_inline bool mac6_equal(const __u8 *a, const __u8 *b)
{
	for (int i = 0; i < 6; i++)
		if (a[i] != b[i])
			return false;
	return true;
}

/* publish_redirect_track_for_packet stores the reply-path binding of a
 * redirected flow.
 *
  *: the entry is keyed by the forward tuple and carries the
 * interface/MAC to send replies to. Updating it unconditionally on every
 * redirected packet let a competing writer (e.g. a spoofer reusing the
 * victim's tuple) hand the victim's replies to itself for as long as it kept
 * sending. The entry is single-writer now:
 *   - same publisher (ifindex / from_wan / smac): refresh liveness in place;
 *   - different publisher on a fresh entry: keep the existing binding, count
 *     it and emit a rate-limited event;
 *   - different publisher on a stale entry: allow the rebind. A real LAN
 *     client that roams (Wi-Fi roam, VM migration) is silent for a while
 *     before it reappears on a new interface, so the window must stay short
 *     enough to recover the flow yet long enough to defeat a competing writer.
 * Every path that keeps an entry must refresh last_seen_ns: the userspace
 * janitor expires entries idle for redirectTrackTimeout, so skipping the
 * refresh would turn a live flow's reply path into a black hole.
 */
static __always_inline int
publish_redirect_track_for_packet(struct __sk_buff *skb, __u32 link_h_len,
				  const struct tuples *tuples,
				  const struct ethhdr *ethh, __u8 from_wan)
{
	struct redirect_tuple redirect_tuple = {};
	struct redirect_entry redirect_entry = {};
	struct redirect_entry *existing;
	long map_ret;

	fill_redirect_tuple_from_forward_packet(skb, tuples, &redirect_tuple);
	fill_redirect_entry_from_forward_packet(skb->ifindex, link_h_len, ethh,
						from_wan, &redirect_entry);

	existing = bpf_map_lookup_elem(&redirect_track, &redirect_tuple);
	if (existing) {
		bool same_publisher =
			existing->ifindex == redirect_entry.ifindex &&
			existing->from_wan == redirect_entry.from_wan &&
			mac6_equal(existing->smac, redirect_entry.smac);

		if (same_publisher) {
			existing->last_seen_ns = redirect_entry.last_seen_ns;
			return 0;
		}
		if (existing->last_seen_ns <= redirect_entry.last_seen_ns &&
		    redirect_entry.last_seen_ns - existing->last_seen_ns <
			    EVENT_RATE.redirect_rebind_stale_ns) {
			bump_stat(BPF_STATS_REDIRECT_REBIND_REJECTED);
			send_anomaly_event(EVENT_RATE.redirect_rebind_key,
					   DAER_EVENT_REDIRECT_REBIND_REJECTED,
					   tuples->five.l4proto, &tuples->five);
			return 0;
		}
	}

	map_ret = bpf_map_update_elem(&redirect_track, &redirect_tuple,
				      &redirect_entry, BPF_ANY);
	if (map_ret) {
		/* A saturated redirect_track used to lose the reply path
		 * silently: the failure was reported with `bpf_printk`, which the
		 * release build compiles to nothing. Count it instead (userspace
		 * sizes the map from these keys) and emit a rate-limited event. */
		if (map_ret == -E2BIG || map_ret == -ENOSPC)
			bump_stat(BPF_STATS_REDIRECT_OVERFLOW);
		else
			bump_stat(BPF_STATS_REDIRECT_UPDATE_FAILED);
		send_anomaly_event(EVENT_RATE.overflow_key,
				   DAER_EVENT_REDIRECT_UPDATE_FAILED,
				   tuples->five.l4proto, &tuples->five);
		return (int)map_ret;
	}
	return 0;
}

static __always_inline int
rewrite_packet_for_control_plane(struct __sk_buff *skb, __u32 link_h_len,
				 __u8 from_wan)
{
	bool use_redirect_peer = PARAM.use_redirect_peer && !from_wan;
	int ret;

	if (!use_redirect_peer) {
		if (!link_h_len) {
			__u16 l3proto = skb->protocol;
			__u8 zero_mac[6] = {0};

			ret = bpf_skb_change_head(skb, sizeof(struct ethhdr), 0);
			if (ret) {
				return ret;
			}
			ret = bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_proto),
						  &l3proto, sizeof(l3proto), 0);
			if (ret)
				return ret;
			ret = bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_source),
						  zero_mac, sizeof(zero_mac), 0);
			if (ret)
				return ret;
		}

		ret = bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_dest),
					  (void *)&PARAM.peer_mac, 6, 0);
		if (ret)
			return ret;
	}
	return 0;
}

static __noinline int prep_redirect_to_control_plane(
	struct __sk_buff *skb, __u32 link_h_len, struct tuples *tuples,
	struct ethhdr *ethh, __u8 from_wan)
{
	int ret = rewrite_packet_for_control_plane(skb, link_h_len, from_wan);

	if (ret)
		return ret;
	return publish_redirect_track_for_packet(skb, link_h_len, tuples, ethh,
						 from_wan);
}


