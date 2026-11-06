// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
//
// Part of the datapath translation unit. See ADR-0024 for why the split is by
// map ownership and attach domain rather than by directory convention.

static __always_inline void copy_reversed_tuples(struct tuples_key *key,
						 struct tuples_key *dst)
{
	__builtin_memset(dst, 0, sizeof(*dst));
	dst->dip = key->sip;
	dst->sip = key->dip;
	dst->sport = key->dport;
	dst->dport = key->sport;
	dst->l4proto = key->l4proto;
}

static __always_inline bool is_short_lived_udp_traffic(struct tuples_key *key)
{
	return key->l4proto == IPPROTO_UDP &&
	       (key->dport == bpf_htons(53) || key->sport == bpf_htons(53));
}

// mark_udp_seen: update/create UDP conn state with optional routing metadata.
// Expired entries are pruned on lookup. Map overflow increments bpf_stats_map.
// UDP_CONN_STATE_TIMEOUT_NS is overridable so test builds can shorten the
// backstop: with the 300-second value the expired-state path is unreachable on
// a host whose uptime is below it, because a seeded past timestamp wraps and
// udp_conn_state_expired() then treats the entry as live.
#ifndef UDP_CONN_STATE_TIMEOUT_NS
#define UDP_CONN_STATE_TIMEOUT_NS 300000000000ULL        // 300-second backstop, aligned with QuicNatTimeout; userspace endpoint teardown is the primary owner
#endif
#define UDP_CONN_STATE_UPDATE_INTERVAL_NS 1000000000ULL  // 1 second

enum udp_conn_state_status {
	UDP_CONN_STATE_STATUS_UNAVAILABLE = 0,
	UDP_CONN_STATE_STATUS_MISSING,
	UDP_CONN_STATE_STATUS_EXPIRED,
	UDP_CONN_STATE_STATUS_EXISTING,
	UDP_CONN_STATE_STATUS_CREATED,
	UDP_CONN_STATE_STATUS_OVERFLOW,
};

static __always_inline bool
udp_conn_state_expired(const struct conn_state *state, __u64 now)
{
	if (!state)
		return false;
	/* Guard against a timestamp in the future (clock slew, seeded state):
	 * without this, now - last_seen_ns underflows and live entries expire. */
	__u64 last_seen_ns = state->last_seen_ns;

	return now > last_seen_ns &&
	       now - last_seen_ns > UDP_CONN_STATE_TIMEOUT_NS;
}

static __always_inline bool
conntrack_args_are_empty(__u8 *outbound, __u32 *mark, __u8 *must, __u8 *mac,
			 __u8 dscp, const char *pname, __u32 pid,
			 __u8 routing_epoch_slot)
{
	return !outbound && !mark && !must && !mac && dscp == 0 && !pname &&
	       pid == 0 && routing_epoch_slot == ROUTING_EPOCH_SLOT_UNKNOWN;
}

static __noinline struct conn_state *
__mark_udp_seen(struct tuples_key *key, bool is_wan_ingress_direction,
		const struct conntrack_args *args, __u8 *status)
{
	struct conntrack_args empty_args = {};

	if (!args)
		args = &empty_args;
	if (status)
		*status = UDP_CONN_STATE_STATUS_MISSING;

	__u64 now = bpf_ktime_get_ns();
	struct conn_state *state =
		bpf_map_lookup_elem(&conn_state_map, key);

	if (udp_conn_state_expired(state, now)) {
		bpf_map_delete_elem(&conn_state_map, key);
		state = NULL;
		if (status)
			*status = UDP_CONN_STATE_STATUS_EXPIRED;
	}

	if (state) {
		if (status)
			*status = UDP_CONN_STATE_STATUS_EXISTING;
		// Fast path: lazy timestamp update (only if interval > 1 second)
		if (now - state->last_seen_ns > UDP_CONN_STATE_UPDATE_INTERVAL_NS)
			state->last_seen_ns = now;

		// Update routing if provided (e.g., routing decision changed)
		if (args->flags & CT_ARGS_HAS_ROUTING) {
			union routing_meta meta =
				build_routing_meta(args->outbound, args->mark,
						   args->must, args->dscp);

			if (args->flags & CT_ARGS_HAS_MAC)
				__builtin_memcpy(state->mac, args->mac, 6);
			if (args->flags & CT_ARGS_HAS_PNAME)
				__builtin_memcpy(state->pname, args->pname,
						 TASK_COMM_LEN);
			state->pid = args->pid;
			state->routing_epoch_slot = args->routing_epoch_slot;
			state->datapath_generation = PARAM.datapath_generation;
			publish_routing_meta(&state->meta, meta);
		}
		return state;
	}

	// Slow path: create new entry (either no entry or expired one was deleted)
	bool has_rt = !!(args->flags & CT_ARGS_HAS_ROUTING);
	struct conn_state new_state = {};

	new_state.is_wan_ingress_direction = is_wan_ingress_direction;
	new_state.last_seen_ns = now;
	new_state.meta.data.dscp = args->dscp;
	new_state.pid = args->pid;

	if (has_rt) {
		new_state.meta = build_routing_meta(args->outbound, args->mark,
						    args->must, args->dscp);
		if (args->flags & CT_ARGS_HAS_MAC)
			__builtin_memcpy(new_state.mac, args->mac, 6);
		if (args->flags & CT_ARGS_HAS_PNAME)
			__builtin_memcpy(new_state.pname, args->pname,
					 TASK_COMM_LEN);
		new_state.routing_epoch_slot = args->routing_epoch_slot;
		new_state.datapath_generation = PARAM.datapath_generation;
	}

	int ret = bpf_map_update_elem(&conn_state_map, key,
				      &new_state, BPF_ANY);

	if (unlikely(ret)) {
		if (status)
			*status = UDP_CONN_STATE_STATUS_OVERFLOW;
		/* Map full or other error: the per-packet counter always advances
		 * (userspace reads it to size the map), while the ringbuf event is
		 * rate-limited: a full map would otherwise emit one event per
		 * packet and starve the other event types. */
		__u32 stats_key = BPF_STATS_UDP_CONN_OVERFLOW;
		__u64 *overflow_count =
			bpf_map_lookup_elem(&bpf_stats_map, &stats_key);

		if (overflow_count)
			__sync_fetch_and_add(overflow_count, 1);
		if (!blocked_event_rate_limited(EVENT_RATE.overflow_key))
			send_daer_event(DAER_EVENT_UDP_CONN_OVERFLOW, args->pid,
				       (const char *)args->pname,
				       (args->flags & CT_ARGS_HAS_PNAME) != 0, 0,
				       key->l4proto, key->sip.u6_addr32,
				       key->dip.u6_addr32, key->sport,
				       key->dport);
		return NULL;
	}

	if (status)
		*status = UDP_CONN_STATE_STATUS_CREATED;
	return bpf_map_lookup_elem(&conn_state_map, key);
}

// mark_udp_seen_with_status is the shared wrapper for state updates that also
// exposes whether the key was already live to the caller.
static __always_inline struct conn_state *
mark_udp_seen_with_status(struct tuples_key *key, bool is_wan_ingress_direction,
			  __u8 *outbound, __u32 *mark, __u8 *must, __u8 *mac,
			  __u8 dscp, const char *pname, __u32 pid,
			  __u8 routing_epoch_slot, __u8 *status)
{
	if (conntrack_args_are_empty(outbound, mark, must, mac, dscp, pname, pid,
				     routing_epoch_slot))
		return __mark_udp_seen(key, is_wan_ingress_direction, NULL, status);

	__u32 zero = 0;
	struct conntrack_args *args =
		bpf_map_lookup_elem(&conntrack_args_map, &zero);

	if (unlikely(!args)) {
		if (status)
			*status = UDP_CONN_STATE_STATUS_UNAVAILABLE;
		return NULL;
	}
	conntrack_args_set(args, outbound, mark, must, mac, dscp, pname, pid,
			   routing_epoch_slot);
	return __mark_udp_seen(key, is_wan_ingress_direction, args, status);
}

static __always_inline struct conn_state *
mark_udp_seen(struct tuples_key *key, bool is_wan_ingress_direction,
	      __u8 *outbound, __u32 *mark, __u8 *must, __u8 *mac,
	      __u8 dscp, const char *pname, __u32 pid,
	      __u8 routing_epoch_slot)
{
	return mark_udp_seen_with_status(key, is_wan_ingress_direction, outbound,
					 mark, must, mac, dscp, pname, pid,
					 routing_epoch_slot, NULL);
}

// mark_tcp_seen: update/create TCP conn state with optional routing metadata.
// SYN starts new lifecycle; FIN/RST transitions to CLOSING.
#define TCP_CONN_STATE_CLOSING_TIMEOUT_NS 10000000000ULL       // 10 seconds
#define TCP_CONN_STATE_UPDATE_INTERVAL_NS 1000000000ULL  // 1 second

static __always_inline bool
tcp_conn_state_expired(const struct conn_state *state, __u64 now)
{
	/* ACTIVE entries may belong to process-owned sessions across reloads.
	 * Userspace owns their idle expiry because it can distinguish a live,
	 * pinned session from stale kernel state. */
	if (!state || state->state != TCP_STATE_CLOSING)
		return false;
	/* Same future-timestamp guard as the UDP expiry path: a last_seen_ns
	 * in the future would underflow and reap a live CLOSING entry early. */
	return now > state->last_seen_ns &&
	       now - state->last_seen_ns > TCP_CONN_STATE_CLOSING_TIMEOUT_NS;
}

/* routing_generation_matches reports whether a live flow's cached routing was
 * decided under the generation this packet belongs to.
 *
 * args->routing_epoch_slot is the epoch the packet was routed with: every SYN
 * path supplies the value route() packed into its result together with the
 * decision, and the paths that only refresh an entry pass UNKNOWN. A packet
 * that cannot name its epoch is not evidence of equality, so it never inherits
 * a live flow's cached routing.
 *
 * The routing epoch identifies the rule set: a slot's rules and routing metadata
 * are staged before the selector is published, and the selector only ever moves
 * to the slot prepared for the new generation, so "same slot" implies "same
 * rules". Equivalence between two generations is decided by the reload's staged
 * handoff; nothing here re-derives it, and a flow re-routed onto an equivalent
 * rule set simply lands on a byte-identical decision.
 *
 * A datapath generation marks the datapath that wrote an entry. It is frozen in
 * PARAM at load time, so an entry can only disagree with it when the pinned
 * conn_state_map outlived the datapath that created it (a pinned reload or an
 * in-place upgrade reusing the pin directory), and such an entry must not be
 * inherited either.
 */
static __always_inline bool
routing_generation_matches(const struct conn_state *state,
			   const struct conntrack_args *args)
{
	__u8 decision_slot = routing_epoch_slot_sanitize(args->routing_epoch_slot);
	__u8 entry_slot =
		routing_epoch_slot_sanitize(state->routing_epoch_slot);

	if (decision_slot == ROUTING_EPOCH_SLOT_UNKNOWN ||
	    entry_slot == ROUTING_EPOCH_SLOT_UNKNOWN)
		return false;
	if (decision_slot != entry_slot)
		return false;
	return state->datapath_generation == PARAM.datapath_generation;
}

// __mark_tcp_seen: noinline core. tcp_flags: bit 0 = SYN && !ACK (new
// connection), bit 1 = FIN || RST.
static __noinline struct conn_state *
__mark_tcp_seen(struct tuples_key *key, bool is_wan_ingress_direction,
		__u8 tcp_flags, struct conntrack_args *args)
{
	struct conntrack_args empty_args = {};

	if (!args)
		args = &empty_args;

	__u64 now = bpf_ktime_get_ns();
	struct conn_state *state =
		bpf_map_lookup_elem(&conn_state_map, key);
	bool new_conn_syn = tcp_flags & 1;
	bool is_fin_rst   = tcp_flags & 2;

	/*
	 * A pure SYN normally starts a fresh TCP lifecycle. If an older entry still
	 * exists under the same 4-tuple (for example because only the reverse-side
	 * FIN/RST was observed previously), drop it now so the new connection does
	 * not inherit stale routing metadata.
	 *
	 * Exception: an ACTIVE entry that carries a routing decision
	 * belongs to a live flow, and a same-tuple pure SYN is then an illegal
	 * mid-stream SYN that the kernel answers with a challenge ACK instead of
	 * opening a connection. Deleting the entry there let a single spoofed SYN
	 * re-route everything the flow sends afterwards — including its reply
	 * binding — for the rest of the flow's life, because an ACTIVE entry with
	 * routing metadata has no TTL to heal it. Refuse the rewrite instead:
	 * keep the entry, lock the rebind, count it and emit a rate-limited event.
	 *
	 * That protection is bound to the generation it was decided under. A
	 * connection that outlives a reload — the staged handoff let it drain
	 * instead of cutting it — still carries the old routing, while the
	 * rule the flow must follow is the current one: "after the rules changed,
	 * every new connection uses the new rules". The lock is therefore only
	 * granted while the decision's epoch (and the datapath that wrote it)
	 * still matches; otherwise the entry is dropped and re-created from the
	 * current generation. Equivalence is not re-derived here: reload decides
	 * it, and an equivalent re-route lands on a byte-identical decision.
	 */
	if (state && new_conn_syn) {
		if (state->state == TCP_STATE_ACTIVE &&
		    state->meta.data.has_routing &&
		    routing_generation_matches(state, args)) {
			/* Same generation: the flow keeps its routing. */
			args->flags |= CT_ARGS_REBIND_LOCKED;
			bump_stat(BPF_STATS_SYN_REBIND_REJECTED);
			send_anomaly_event(EVENT_RATE.syn_rebind_key,
					   DAER_EVENT_SYN_REBIND_REJECTED,
					   key->l4proto, key);
		} else {
			/* Either the entry carries no routing decision to
			 * inherit, or it carries one from another generation:
			 * drop it so the SYN below re-creates it from the
			 * current rules. Only the second case replaces a
			 * decision, so only it advances the re-route counter
			 * (the first is the plain stale-SYN path). */
			if (state->state == TCP_STATE_ACTIVE &&
			    state->meta.data.has_routing) {
				bump_stat(BPF_STATS_REBIND_REROUTED_AFTER_EPOCH_CHANGE);
				send_anomaly_event(
					EVENT_RATE.syn_rebind_key,
					DAER_EVENT_SYN_REBIND_REROUTED,
					key->l4proto, key);
			}
			bpf_map_delete_elem(&conn_state_map, key);
			state = NULL;
		}
	} else if (tcp_conn_state_expired(state, now)) {
		bpf_map_delete_elem(&conn_state_map, key);
		state = NULL;
	}

	if (state) {
		// Fast path: lazy timestamp update (only if interval > 1 second).
		// This must happen even for a locked rebind: an entry whose
		// last_seen_ns stopped advancing would be deleted by the userspace
		// janitor while the flow is still live, turning the reply path
		// into a black hole.
		if (now - state->last_seen_ns > TCP_CONN_STATE_UPDATE_INTERVAL_NS)
			state->last_seen_ns = now;

		// Check for connection close signals (FIN or RST)
		if (is_fin_rst)
			state->state = TCP_STATE_CLOSING;

		// Update routing if provided (rare: routing decision changed). A
		// locked rebind keeps both the routing decision and the side
		// fields that belong to the live flow.
		if (!(args->flags & CT_ARGS_REBIND_LOCKED) &&
		    (args->flags & CT_ARGS_HAS_ROUTING)) {
			union routing_meta meta =
				build_routing_meta(args->outbound, args->mark,
						   args->must, args->dscp);

			if (args->flags & CT_ARGS_HAS_MAC)
				__builtin_memcpy(state->mac, args->mac, 6);
			if (args->flags & CT_ARGS_HAS_PNAME)
				__builtin_memcpy(state->pname, args->pname,
						 TASK_COMM_LEN);
			state->pid = args->pid;
			state->routing_epoch_slot = args->routing_epoch_slot;
			state->datapath_generation = PARAM.datapath_generation;
			publish_routing_meta(&state->meta, meta);
		}

		return state;
	}

	// Only create new entry on SYN (new connection)
	if (new_conn_syn) {
		bool has_rt = !!(args->flags & CT_ARGS_HAS_ROUTING);
		struct conn_state new_state = {};

		new_state.is_wan_ingress_direction = is_wan_ingress_direction;
		new_state.state = TCP_STATE_ACTIVE;
		new_state.last_seen_ns = now;
		new_state.meta.data.dscp = args->dscp;
		new_state.pid = args->pid;

		if (has_rt) {
			new_state.meta = build_routing_meta(args->outbound,
							    args->mark,
							    args->must,
							    args->dscp);
			if (args->flags & CT_ARGS_HAS_MAC)
				__builtin_memcpy(new_state.mac, args->mac, 6);
			if (args->flags & CT_ARGS_HAS_PNAME)
				__builtin_memcpy(new_state.pname, args->pname,
						 TASK_COMM_LEN);
			new_state.routing_epoch_slot = args->routing_epoch_slot;
			new_state.datapath_generation = PARAM.datapath_generation;
		}

		int ret = bpf_map_update_elem(&conn_state_map, key,
					      &new_state, BPF_ANY);

		if (unlikely(ret)) {
			/* Per-packet counter + rate-limited event; see the UDP
			 * path above for why the event is throttled. */
			__u32 stats_key = BPF_STATS_TCP_CONN_OVERFLOW;
			__u64 *overflow_count =
				bpf_map_lookup_elem(&bpf_stats_map, &stats_key);

			if (overflow_count)
				__sync_fetch_and_add(overflow_count, 1);
			if (!blocked_event_rate_limited(EVENT_RATE.overflow_key))
				send_daer_event(DAER_EVENT_TCP_CONN_OVERFLOW,
					       args->pid,
					       (const char *)args->pname,
					       (args->flags &
						CT_ARGS_HAS_PNAME) != 0,
					       0, key->l4proto,
					       key->sip.u6_addr32,
					       key->dip.u6_addr32, key->sport,
					       key->dport);
			return NULL;
		}

		return bpf_map_lookup_elem(&conn_state_map, key);
	}

	// Non-SYN packets without existing state must never allocate new state.
	return NULL;
}

// mark_tcp_seen: thin inline wrapper that populates per-CPU scratch args once
// and then delegates to the single-copy __mark_tcp_seen body.
static __always_inline struct conn_state *
mark_tcp_seen(struct tuples_key *key, const struct tcphdr *tcph,
	      bool is_wan_ingress_direction,
	      __u8 *outbound, __u32 *mark, __u8 *must, __u8 *mac,
	      __u8 dscp, const char *pname, __u32 pid,
	      __u8 routing_epoch_slot)
{
	if (conntrack_args_are_empty(outbound, mark, must, mac, dscp, pname, pid,
				     routing_epoch_slot)) {
		__u8 tcp_flags = 0;
		__u8 flags = tcph_flags(tcph);

		if ((flags & TCPH_SYN) && !(flags & TCPH_ACK))
			tcp_flags |= 1;
		if (flags & (TCPH_FIN | TCPH_RST))
			tcp_flags |= 2;
		return __mark_tcp_seen(key, is_wan_ingress_direction, tcp_flags,
				       NULL);
	}

	__u32 zero = 0;
	struct conntrack_args *args =
		bpf_map_lookup_elem(&conntrack_args_map, &zero);

	if (unlikely(!args))
		return NULL;
	conntrack_args_set(args, outbound, mark, must, mac, dscp, pname, pid,
			   routing_epoch_slot);

	__u8 tcp_flags = 0;
	__u8 flags = tcph_flags(tcph);

	if ((flags & TCPH_SYN) && !(flags & TCPH_ACK))
		tcp_flags |= 1;
	if (flags & (TCPH_FIN | TCPH_RST))
		tcp_flags |= 2;
	return __mark_tcp_seen(key, is_wan_ingress_direction, tcp_flags, args);
}

static __always_inline bool is_new_tcp_connection(const struct tcphdr *tcph)
{
	__u8 flags = tcph_flags(tcph);

	return (flags & TCPH_SYN) && !(flags & TCPH_ACK);
}

// Reverse-direction conntrack refresh shared by standalone and combined LAN
// egress roles after a single packet parse.
static __always_inline int
tproxy_lan_egress_refresh(struct tuples *tuples, const struct tcphdr *tcph,
			  const struct udphdr *udph, __u8 l4proto)
{
	if (l4proto == IPPROTO_TCP) {
		struct tuples_key reversed_tuples_key;

		copy_reversed_tuples(&tuples->five, &reversed_tuples_key);
		// Reverse-side TCP packets should refresh the forward conn-state and
		// surface FIN/RST so the lifecycle does not remain ACTIVE until the
		// janitor backstop expires.
		mark_tcp_seen(&reversed_tuples_key, tcph, true,
			      NULL, NULL, NULL, NULL,
			      0, NULL, 0, ROUTING_EPOCH_SLOT_UNKNOWN);
	} else if (l4proto == IPPROTO_UDP) {
		if (udph->source == bpf_htons(53) || udph->dest == bpf_htons(53))
			return DAE_TC_CONTINUE;

		struct tuples_key reversed_tuples_key;

		copy_reversed_tuples(&tuples->five, &reversed_tuples_key);
		mark_udp_seen(&reversed_tuples_key, true,
			      NULL, NULL, NULL, NULL,
			      0, NULL, 0, ROUTING_EPOCH_SLOT_UNKNOWN);
	}

	return DAE_TC_CONTINUE;
}


