// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
//
// Part of the datapath translation unit. See ADR-0024 for why the split is by
// map ownership and attach domain rather than by directory convention.

// Functions:

/* Reserves the ringbuf record instead of building it on the BPF stack: the
 * 72-byte event would otherwise be charged to every caller's frame, and the
 * datapath call chains must stay inside the 512-byte combined stack budget.
 * Fields that have no source are zeroed explicitly (a reserved record is not
 * pre-zeroed), and a failed reservation drops the event exactly like the
 * previous bpf_ringbuf_output() on a full ring. */
static __always_inline int
send_daer_event(__u32 type, __u32 pid, const char *pname, bool pname_valid,
	       __u8 outbound, __u8 l4proto, const __u32 *sip,
	       const __u32 *dip, __u16 sport, __u16 dport)
{
	struct daer_event *e = bpf_ringbuf_reserve(&event_ringbuf, sizeof(*e), 0);

	if (!e) {
		/* The ringbuf is full. The event is lost either way (this is
		 * what bpf_ringbuf_output() did before), but the loss must be
		 * countable: userspace raises this to the operator. */
		bump_stat(BPF_STATS_EVENT_DROP);
		return -1;
	}

	e->timestamp = bpf_ktime_get_ns();
	e->type = type;
	e->pid = pid;
	e->outbound = outbound;
	e->l4proto = l4proto;
	e->sport = sport;
	e->dport = dport;
	__builtin_memset(e->pname, 0, sizeof(e->pname));
	__builtin_memset(e->sip, 0, sizeof(e->sip));
	__builtin_memset(e->dip, 0, sizeof(e->dip));

	/* The copy is guarded by a scalar flag, not by `pname != NULL`: clang
	 * 15/16/17 lower a select of a pointer and NULL (`c ? p : NULL`) into a
	 * bitwise AND on a pointer register, which the verifier rejects with
	 * "bitwise operator &= on pointer prohibited". Passing a pointer that is
	 * always valid (the conntrack args slot) plus this flag keeps the select
	 * on a scalar. */
	if (pname_valid)
		__builtin_memcpy(e->pname, pname, 16);

	if (sip)
		__builtin_memcpy(e->sip, sip, 16);

	if (dip)
		__builtin_memcpy(e->dip, dip, 16);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

// blocked_event_rate_limited reports whether an emission for rate key
// is allowed (at most once per second per key across CPUs). The clock is
// sampled AFTER the previous-emission read so now >= old always holds for
// the value compared: sampling first lets a concurrent CPU claim the slot
// with a newer timestamp between the sample and the read, and the unsigned
// subtraction then underflows past the 1s window. CAS claims the slot
// atomically: when several CPUs observe an expired window concurrently,
// only the CAS winner emits and the others are rate-limited, keeping the
// per-key budget strict instead of merely best-effort.
static __always_inline bool
blocked_event_rate_limited(__u32 key)
{
	__u64 *last = bpf_map_lookup_elem(&alive_block_rate_map, &key);

	if (!last)
		return true;

	__u64 old = *last;
	__u64 now = bpf_ktime_get_ns();

	if (now - old < EVENT_RATE.window_ns)
		return true;
	if (__sync_val_compare_and_swap(last, old, now) != old)
		return true;
	return false;
}

// send_blocked_alive_event emits DAER_EVENT_BLOCKED_ALIVE at most once per
// second per outbound. The rate limit keeps a dead outbound from flooding the
// ringbuf with one event per blocked packet while the periodic health check is
// still recovering it. Returns true when an event was actually emitted.
static __always_inline bool
send_blocked_alive_event(__u8 outbound, __u8 l4proto, const __u32 *sip,
			 const __u32 *dip, __u16 sport, __u16 dport)
{
	if (blocked_event_rate_limited((__u32)outbound))
		return false;

	send_daer_event(DAER_EVENT_BLOCKED_ALIVE, 0, NULL, false, outbound, l4proto,
		       sip, dip, sport, dport);
	return true;
}

// send_blocked_event emits DAER_EVENT_BLOCKED (type 0) at most once per
// second. The event has no userspace consumer today, and an unthrottled
// blocked-flow flood (e.g. an attacker hitting a block rule at line rate)
// would occupy ringbuf space that the consumed event types (1/2/3) need.
static __always_inline void
send_blocked_event(__u8 outbound, __u8 l4proto, const __u32 *sip,
		   const __u32 *dip, __u16 sport, __u16 dport)
{
	if (blocked_event_rate_limited(EVENT_RATE.blocked_key))
		return;

	send_daer_event(DAER_EVENT_BLOCKED, 0, NULL, false, outbound, l4proto, sip,
		       dip, sport, dport);
}

// send_anomaly_event emits a datapath anomaly at most once per second per
// reserved rate key. The bpf_stats_map counter for the same condition always
// advances per occurrence; this call only bounds the ringbuf cost of a flood.
// key may be NULL when the packet was never classified (e.g. a non-IP frame).
//
// The rate key is per event type, not per flow: every flow of the type shares
// one 1s budget, so this bounds the emission rate but says nothing about how
// many flows are affected, and the tuple it reports is one arbitrary sample.
// Only use it for a genuine anomaly. A path that is the normal steady state
// (established TCP without cached routing after a restart, a forwarded
// fragment tail) must count per packet with bump_stat instead and let
// userspace summarise the counter's interval delta, or the log carries one
// warning per second for as long as the state lasts.
static __always_inline void
send_anomaly_event(__u32 rate_key, __u32 type, __u8 l4proto,
		   const struct tuples_key *key)
{
	if (blocked_event_rate_limited(rate_key))
		return;

	if (key)
		send_daer_event(type, 0, NULL, false, 0, l4proto, key->sip.u6_addr32,
			       key->dip.u6_addr32, key->sport, key->dport);
	else
		send_daer_event(type, 0, NULL, false, 0, l4proto, NULL, NULL, 0, 0);
}


