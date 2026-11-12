// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2022-2026, daer contributors
//
// Part of the datapath translation unit. See ADR-0024 for why the split is by
// map ownership and attach domain rather than by directory convention.

#include "include/tcp_offload.h"

// tcp_offload_redirect is the stream-verdict (RX path) program for the
// fast_sock SOCKHASH. When a socket registered by the Go control plane
// receives data, this program redirects it to the peer relay socket's egress
// path (i.e. the peer socket transmits it), splicing the pair in-kernel.
//
// The upstream sockmap fast redirect used an sk_msg program with
// BPF_F_INGRESS (delivering written data into the peer receive queue), which
// never transmits bytes for a local<->remote relay pair; this sk_skb +
// egress-redirect design matches kernel selftest semantics instead.
//
// bpf_sk_redirect_hash returns SK_DROP when the key is not found, so a miss
// must be turned into SK_PASS before calling the helper or the packet would
// be silently dropped.
SEC("sk_skb/stream_verdict")
int tcp_offload_redirect(struct __sk_buff *skb)
{
	struct tuples_key peer_key = {};

	// Key layout must match Go's makeTuplesKey(remote, local, TCP):
	// sip=remote, dip=local, sport=remote_port(BE), dport=local_port(BE).
	// __sk_buff.remote_port carries the network-order port in the high 16
	// bits on little-endian targets (convert_skb_access LSH 16);
	// local_port is host byte order.
	peer_key.l4proto = IPPROTO_TCP;
	peer_key.sport = tcp_offload_remote_port(skb->remote_port);
	peer_key.dport = bpf_htons((__u16)skb->local_port);
	if (skb->family == AF_INET) {
		peer_key.sip.u6_addr32[2] = bpf_htonl(0x0000ffff);
		peer_key.sip.u6_addr32[3] = skb->remote_ip4;
		peer_key.dip.u6_addr32[2] = bpf_htonl(0x0000ffff);
		peer_key.dip.u6_addr32[3] = skb->local_ip4;
	} else if (skb->family == AF_INET6) {
		__builtin_memcpy(&peer_key.sip, skb->remote_ip6,
				 IPV6_BYTE_LENGTH);
		__builtin_memcpy(&peer_key.dip, skb->local_ip6, IPV6_BYTE_LENGTH);
	} else {
		return SK_PASS;
	}

	// Backlog fuse: a paused key passes data through to the userspace
	// fallback. The fast_sock entry stays registered so the kernel keeps
	// draining already-redirected skbs from the peer's egress retry queue.
	if (bpf_map_lookup_elem(&tcp_offload_pause, &peer_key))
		return SK_PASS;

	// Pre-check: bpf_sk_redirect_hash returns SK_DROP when the key is not
	// found, which would silently discard the packet. Pass instead. The
	// lookup returns a referenced socket that must be released before the
	// program exits (the redirect helper itself does not take a reference).
	{
		struct bpf_sock *peer =
			bpf_map_lookup_elem(&fast_sock, &peer_key);
		if (!peer)
			return SK_PASS;
		bpf_sk_release(peer);
	}

	// flags == 0 selects the egress path: the peer socket sends the data.
	// The helper returns SK_DROP when the key vanished between the pre-check
	// lookup above and this call (userspace teardown deletes keys after
	// pausing), or on any other redirect failure. Dropping the skb would
	// lose the packet, so translate every outcome into SK_PASS: a successful
	// redirect has already marked the skb, and a failed one is handed to
	// the userspace fallback path. No further reference accounting is
	// involved here: the helper resolves the redirect target from the map
	// and records it in the skb (validated later under RCU when the verdict
	// runs), so the pre-check's released reference stays balanced.
	bpf_sk_redirect_hash(skb, &fast_sock, &peer_key, 0);
	return SK_PASS;
}

/* tcp_offload_sent_account records, per reversed four-tuple, the bytes that
 * skb_send_sock pushes into a peer socket's send path. The key layout
 * must match tcp_offload_redirect's peer_key so the Go session can look up
 * both directions with its registered keys. Userspace picks the attach
 * site per kernel (see tcp_offload_hook.go): fentry on the outer wrapper
 * when only it is verified, or the kprobe variant on the shared inner
 * __skb_send_sock when LTO can bypass the wrapper.
 *
 * NOTE: the hook must sit on skb_send_sock, not skb_send_sock_locked.
 * The sockmap verdict egress path is sk_psock_verdict_apply ->
 * sk_psock_skb_redirect -> sk_psock_handle_skb -> skb_send_sock
 * (net/core/skmsg.c); skb_send_sock_locked's only caller in the whole
 * kernel is net/xfrm/espintcp.c, so a hook placed there never fires on
 * our redirect path and the sent counters stay empty (verified against
 * v6.12 and v6.17 sources). Both functions are identical one-line
 * tail-call wrappers into __skb_send_sock with the same first four
 * arguments, so the BPF_PROG signature below is unchanged.
 *
 * A successful attach does not prove this wrapper executes. LTO kernels
 * can bypass it and call __skb_send_sock directly; the E2E sent/inflow
 * assertions must still pass before relying on accounting on that kernel.
 *
 * An earlier EBUSY when attaching to skb_send_sock on 6.12/6.17/6.18 was
 * an attachment-conflict signal, not a function-shape artifact: the
 * kernel-side EBUSY conditions for fentry link_create are an EXT/freplace
 * program on the target, the same prog linked twice, or an existing
 * direct call on the target function (a trampoline with a different key,
 * or any other ftrace direct-call user); see kernel/bpf/trampoline.c
 * __bpf_trampoline_link_prog and kernel/trace/ftrace.c
 * register_ftrace_direct. The actual conflict was the reload-leftover
 * fentry link, fixed at the root by the per-bpfObjects link registry
 * (reuse across reload generations), so re-attaching to skb_send_sock
 * should now succeed.
 *
 * Accounting caveat: fentry fires on function entry, so skbs requeued via
 * the EAGAIN retry path in sk_psock_handle_skb (!sock_writeable) are
 * counted once per attempt. Under congestion this over-estimates "sent"
 * and delays fuse engagement slightly — the conservative direction
 * relative to a dead counter, accepted deliberately.
 *
 * KPROBE FALLBACK: on kernels without CONFIG_DYNAMIC_FTRACE (trimmed
 * router builds such as ImmortalWrt), functions carry no mcount NOP
 * entry, so fentry attach goes through bpf_arch_text_poke, which requires
 * the entry to be a 5-byte NOP and returns EBUSY for tail-call wrappers
 * whose entry is `jmp`. The kprobe variant attaches at any instruction
 * boundary and is selected by the Go side when the fentry attach fails. */
static __always_inline void
tcp_offload_sent_account_body(struct sk_buff *skb, int len)
{
	struct tuples_key key = {};
	__u64 *v;

	if (!tcp_offload_skb_key(skb, &key))
		return;

	v = bpf_map_lookup_elem(&tcp_offload_sent, &key);
	if (v) {
		__sync_fetch_and_add(v, len);
	} else {
		__u64 init = len;

		bpf_map_update_elem(&tcp_offload_sent, &key, &init, BPF_ANY);
	}
}

SEC("fentry/skb_send_sock")
int BPF_PROG(tcp_offload_sent_account, struct sock *sk, struct sk_buff *skb,
	     int offset, int len)
{
	tcp_offload_sent_account_body(skb, len);
	return 0;
}

SEC("kprobe/skb_send_sock")
int BPF_KPROBE(tcp_offload_sent_account_kprobe, struct sock *sk,
	       struct sk_buff *skb, int offset, int len)
{
	tcp_offload_sent_account_body(skb, len);
	return 0;
}

/* The layout assertions for every struct `ebpf/abi.toml` declares. They come last because
 * they assert properties of the structs declared above, and `cargo xtask abi` regenerates
 * them — `cargo xtask abi --check` fails the build when they drift (ADR-0021). */
#include "daer_abi_assertions.h"
