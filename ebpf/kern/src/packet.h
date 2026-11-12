// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2022-2026, daer contributors
//
// Part of the datapath translation unit. See ADR-0024 for why the split is by
// map ownership and attach domain rather than by directory convention.

static __always_inline __u8 ipv4_get_dscp(const struct iphdr *iph)
{
	return (iph->tos & 0xfc) >> 2;
}

/* Raw-byte accessors for the UAPI header bitfields.
 *
 * struct iphdr/struct tcphdr declare ihl/version and doff/fin/syn/rst/... as
 * bitfields whose allocation order follows the target's endianness, not the
 * wire format: on a big-endian build `iph->ihl` reads the version nibble and
 * `tcph->syn` reads a different bit than the wire SYN bit, so every packet
 * classification below would be wrong (IPv4 dropped as malformed, IPv6 TCP
 * policy bypassed). Reading the header bytes directly keeps the datapath
 * identical on little- and big-endian builds, exactly like ipv6_get_dscp
 * above. The TCP flag masks are the wire-format values, which coincide with
 * the little-endian bitfield layout.
 */
static __always_inline __u8 iphdr_ihl(const void *p)
{
	return ((const __u8 *)p)[0] & 0x0f;
}

static __always_inline __u8 iphdr_version(const void *p)
{
	return ((const __u8 *)p)[0] >> 4;
}

static __always_inline __u8 tcph_doff(const void *p)
{
	return ((const __u8 *)p)[12] >> 4;
}

static __always_inline __u8 tcph_flags(const void *p)
{
	return ((const __u8 *)p)[13];
}

#define TCPH_FIN 0x01
#define TCPH_SYN 0x02
#define TCPH_RST 0x04
#define TCPH_ACK 0x10

static __always_inline __u8 ipv6_get_dscp(const struct ipv6hdr *ipv6h)
{
	const __u8 *version_and_tc = (const __u8 *)ipv6h;

	/* Read DSCP from raw bytes to avoid bitfield layout variability. */
	return ((version_and_tc[0] & 0x0f) << 2) | (version_and_tc[1] >> 6);
}

static __always_inline void
get_tuples(const struct __sk_buff *skb, struct tuples *tuples,
	   const struct iphdr *iph, const struct ipv6hdr *ipv6h,
	   const struct tcphdr *tcph, const struct udphdr *udph, __u8 l4proto)
{
	__builtin_memset(tuples, 0, sizeof(*tuples));
	tuples->five.l4proto = l4proto;

	// Read the version/ihl byte raw, then classify; iph is a stack copy of
	// the header and both branches below use raw-byte helpers.
	if (iphdr_version(iph) == 4) {
		tuples->five.sip.u6_addr32[2] = bpf_htonl(0x0000ffff);
		tuples->five.sip.u6_addr32[3] = iph->saddr;

		tuples->five.dip.u6_addr32[2] = bpf_htonl(0x0000ffff);
		tuples->five.dip.u6_addr32[3] = iph->daddr;

		tuples->dscp = ipv4_get_dscp(iph);

	} else {
		// IPv6
		__builtin_memcpy(&tuples->five.dip, &ipv6h->daddr,
				 IPV6_BYTE_LENGTH);
		__builtin_memcpy(&tuples->five.sip, &ipv6h->saddr,
				 IPV6_BYTE_LENGTH);

		tuples->dscp = ipv6_get_dscp(ipv6h);
	}
	if (l4proto == IPPROTO_TCP && tcph) {
		tuples->five.sport = tcph->source;
		tuples->five.dport = tcph->dest;
	} else if (udph) {
		tuples->five.sport = udph->source;
		tuples->five.dport = udph->dest;
	}
}

static __always_inline bool equal16(const __be32 x[4], const __be32 y[4])
{
	return ((__be64 *)x)[0] == ((__be64 *)y)[0] &&
	       ((__be64 *)x)[1] == ((__be64 *)y)[1];
}

static __always_inline bool is_extension_header(__u8 nexthdr)
{
	switch (nexthdr) {
	case IPPROTO_HOPOPTS:
	case IPPROTO_ROUTING:
	case IPPROTO_FRAGMENT:
	case IPPROTO_DSTOPTS:
	case IPPROTO_AH:
	case IPPROTO_MH:
		return true;
	default:
		return false;
	}
}

/* Total length in bytes of a walkable IPv6 extension header. AH (RFC 4302)
 * encodes its length in 4-octet units excluding the first 8 octets:
 * (payload_len + 2) * 4. Every other extension header (incl. MH) uses
 * 8-octet units, which is what ipv6_optlen computes.
 */
static __always_inline __u32 ipv6_exthdr_len(__u8 nexthdr, __u8 len_field)
{
	if (nexthdr == IPPROTO_AH)
		return (__u32)(len_field + 2) * 4;
	return ipv6_optlen(len_field);
}

/* Parser return codes. Positive values mean "not classifiable here" and are
 * forwarded unchanged by every caller; negative values are malformed packets.
 * PARSE_UNSUPPORTED_L4 and PARSE_UNSUPPORTED_ETH are deliberately distinct so
 * the consumers can tell "the IP header parsed but the L4 protocol is not
 * routed" (counted as BPF_STATS_PARSE_UNSUPPORTED_L4) from "this frame is not
 * IP at all" without changing the forwarding decision.
 */
#define PARSE_FRAGMENT 2
#define PARSE_UNSUPPORTED_L4 3
#define PARSE_UNSUPPORTED_ETH 4

static __always_inline __u8
tcp_listener_l4proto(const struct tcphdr *tcph)
{
	__u8 flags;

	if (!tcph)
		return 0;
	flags = tcph_flags(tcph);
	return (flags & TCPH_SYN) && !(flags & TCPH_ACK) ? IPPROTO_TCP : 0;
}

// report_parse_passthrough accounts for a packet the parser could not
// classify, right before the caller forwards it unchanged. The forwarding
// decision itself is intentionally untouched here: dropping non-initial
// fragments or non-TCP/UDP traffic is a policy decision tracked apart from
// this visibility work.
static __always_inline void
report_parse_passthrough(int ret)
{
	if (ret == PARSE_FRAGMENT) {
		/* Forwarding a non-initial fragment is the intended policy,
		 * not an anomaly: only the counter is advanced here. The
		 * per-event warning this used to emit shared one 1s budget
		 * across every fragmenting flow in the datapath, so a
		 * steadily fragmenting path logged one line per second
		 * forever, while the tuple it carried said nothing the
		 * operator could act on. Userspace reports the counter's
		 * interval delta instead (see reportDatapathPassthroughSummary
		 * in control/control_plane.go). */
		bump_stat(BPF_STATS_FRAG_TAIL_PASSED);
	} else if (ret == PARSE_UNSUPPORTED_L4) {
		bump_stat(BPF_STATS_PARSE_UNSUPPORTED_L4);
	}
}

// Fast-path packet parsing via bpf_skb_pull_data + direct access.
// Returns 0 on success, -1 for slow-path fallback, -EFAULT for malformed.
static __always_inline int
parse_transport_fast(struct __sk_buff *skb, __u32 link_h_len,
		     struct parse_transport_ctx *ctx)
{
	struct ethhdr *ethh = &ctx->ethh;
	struct iphdr *iph = &ctx->iph;
	struct ipv6hdr *ipv6h = &ctx->ipv6h;
	struct icmp6hdr *icmp6h = &ctx->icmp6h;
	struct tcphdr *tcph = &ctx->tcph;
	struct udphdr *udph = &ctx->udph;
	__u8 *ihl = &ctx->ihl;
	__u8 *l4proto = &ctx->l4proto;
	__u8 *listener_l4proto = &ctx->listener_l4proto;

	void *data, *data_end;
	__u32 offset = 0;

	*ihl = 0;
	*l4proto = 0;
	*listener_l4proto = 0;
	__builtin_memset(ethh, 0, sizeof(struct ethhdr));
	__builtin_memset(iph, 0, sizeof(struct iphdr));
	__builtin_memset(ipv6h, 0, sizeof(struct ipv6hdr));
	__builtin_memset(icmp6h, 0, sizeof(struct icmp6hdr));
	__builtin_memset(tcph, 0, sizeof(struct tcphdr));
	__builtin_memset(udph, 0, sizeof(struct udphdr));

	// Pull 128 bytes: eth(14)+IP(20)+TCP(20)+options. Larger sizes hurt verifier.
#define HEADER_PULL_SIZE 128
	if (bpf_skb_pull_data(skb, HEADER_PULL_SIZE))
		return -1;

	data = (void *)(long)skb->data;
	data_end = (void *)(long)skb->data_end;

	// Parse Ethernet header (or L3-only)
	if (link_h_len == ETH_HLEN) {
		struct ethhdr *eth_ptr = data;

		if ((void *)(eth_ptr + 1) > data_end)
			return -1;

		ethh->h_proto = eth_ptr->h_proto;
		ethh->h_dest[0] = eth_ptr->h_dest[0];
		ethh->h_dest[1] = eth_ptr->h_dest[1];
		ethh->h_dest[2] = eth_ptr->h_dest[2];
		ethh->h_dest[3] = eth_ptr->h_dest[3];
		ethh->h_dest[4] = eth_ptr->h_dest[4];
		ethh->h_dest[5] = eth_ptr->h_dest[5];
		ethh->h_source[0] = eth_ptr->h_source[0];
		ethh->h_source[1] = eth_ptr->h_source[1];
		ethh->h_source[2] = eth_ptr->h_source[2];
		ethh->h_source[3] = eth_ptr->h_source[3];
		ethh->h_source[4] = eth_ptr->h_source[4];
		ethh->h_source[5] = eth_ptr->h_source[5];
		offset += sizeof(struct ethhdr);
	} else {
		ethh->h_proto = skb->protocol;
	}

	// Parse IP header
	if (ethh->h_proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *iph_ptr = data + offset;

		if ((void *)(iph_ptr + 1) > data_end)
			return -1;
		// Malformed IP header: ihl < 5 is invalid, no point falling back
		if (iphdr_ihl(iph_ptr) < 5)
			return -EFAULT;

		// Copy saddr/daddr early so get_tuples works for PARSE_FRAGMENT.
		// The version/ihl byte is copied raw: the UAPI bitfields cannot be
		// trusted on big-endian targets.
		((__u8 *)iph)[0] = ((const __u8 *)iph_ptr)[0];
		iph->tos = iph_ptr->tos;
		iph->protocol = iph_ptr->protocol;
		iph->saddr = iph_ptr->saddr;
		iph->daddr = iph_ptr->daddr;
		*ihl = iphdr_ihl(iph_ptr);
		*l4proto = iph_ptr->protocol;

		__u32 ip_hdr_len = iphdr_ihl(iph_ptr) * 4;
		__u32 l4_offset = offset + ip_hdr_len;

		// First fragment carries L4 header; non-initial fragments fall back.
		__u16 frag_off = bpf_ntohs(iph_ptr->frag_off);

		if ((frag_off & 0x1FFF) != 0)
			return PARSE_FRAGMENT;

		switch (iph->protocol) {
		case IPPROTO_TCP: {
			struct tcphdr *tcph_ptr = data + l4_offset;

			if ((void *)(tcph_ptr + 1) > data_end)
				return -1;
			tcph->source = tcph_ptr->source;
			tcph->dest = tcph_ptr->dest;
			tcph->seq = tcph_ptr->seq;
			tcph->ack_seq = tcph_ptr->ack_seq;
			// Data offset + flags, read through the raw accessors for
			// the same reason as the IP version/ihl byte above. The
			// reserved nibble is zero in a valid header and is not read
			// by any consumer of the copied struct.
			((__u8 *)tcph)[12] = tcph_doff(tcph_ptr) << 4;
			((__u8 *)tcph)[13] = tcph_flags(tcph_ptr);
			tcph->window = tcph_ptr->window;
			*listener_l4proto = tcp_listener_l4proto(tcph_ptr);
			return 0;
		}
		case IPPROTO_UDP: {
			struct udphdr *udph_ptr = data + l4_offset;

			if ((void *)(udph_ptr + 1) > data_end)
				return -1;
			udph->source = udph_ptr->source;
			udph->dest = udph_ptr->dest;
			udph->len = udph_ptr->len;
			udph->check = udph_ptr->check;
			*listener_l4proto = IPPROTO_UDP;
			return 0;
		}
		default:
			return PARSE_UNSUPPORTED_L4;
		}
	}

	if (ethh->h_proto == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ipv6h_ptr = data + offset;

		if ((void *)(ipv6h_ptr + 1) > data_end)
			return -1;

		/* Preserve version, traffic class, and flow label for DSCP extraction. */
		__builtin_memcpy(ipv6h, ipv6h_ptr, 4);
		ipv6h->nexthdr = ipv6h_ptr->nexthdr;
		ipv6h->payload_len = ipv6h_ptr->payload_len;
		__u32 *saddr_dst = (__u32 *)ipv6h->saddr.in6_u.u6_addr32;
		const __u32 *saddr_src = (const __u32 *)ipv6h_ptr->saddr.in6_u.u6_addr32;

		saddr_dst[0] = saddr_src[0];
		saddr_dst[1] = saddr_src[1];
		saddr_dst[2] = saddr_src[2];
		saddr_dst[3] = saddr_src[3];
		__u32 *daddr_dst = (__u32 *)ipv6h->daddr.in6_u.u6_addr32;
		const __u32 *daddr_src = (const __u32 *)ipv6h_ptr->daddr.in6_u.u6_addr32;

		daddr_dst[0] = daddr_src[0];
		daddr_dst[1] = daddr_src[1];
		daddr_dst[2] = daddr_src[2];
		daddr_dst[3] = daddr_src[3];

		*l4proto = ipv6h_ptr->nexthdr;
		*ihl = sizeof(struct ipv6hdr) / 4;
		offset += sizeof(struct ipv6hdr);

		__u8 nexthdr = ipv6h_ptr->nexthdr;
		const __u8 *ext_hdr;

		for (int i = 0; i < IPV6_MAX_EXTENSIONS; i++) {
			if (nexthdr == IPPROTO_NONE)
				return -EFAULT;
			if (nexthdr == IPPROTO_FRAGMENT) {
				// First fragment still has L4; non-initial falls back.
				struct frag_hdr *fragh = data + offset;

				if ((void *)(fragh + 1) > data_end)
					return -1;
				__u16 frag_off = bpf_ntohs(fragh->frag_off);

				nexthdr = fragh->nexthdr;
				*l4proto = nexthdr;
				offset += sizeof(*fragh);
				if ((frag_off & 0xFFF8) != 0)
					return PARSE_FRAGMENT;
				continue;
			}
			if (!is_extension_header(nexthdr))
				break;

			ext_hdr = data + offset;
			if ((void *)(ext_hdr + 2) > data_end)
				return -1;

			__u8 cur_hdr = nexthdr;

			nexthdr = ext_hdr[0];
			offset += ipv6_exthdr_len(cur_hdr, ext_hdr[1]);
			*l4proto = nexthdr;
		}

		if (is_extension_header(nexthdr))
			return -EFAULT;

		// L4 parsing for IPv6
		switch (nexthdr) {
		case IPPROTO_TCP: {
			struct tcphdr *tcph_ptr = data + offset;

			if ((void *)(tcph_ptr + 1) > data_end)
				return -1;
			tcph->source = tcph_ptr->source;
			tcph->dest = tcph_ptr->dest;
			tcph->seq = tcph_ptr->seq;
			tcph->ack_seq = tcph_ptr->ack_seq;
			// Data offset + flags, read through the raw accessors for
			// the same reason as the IP version/ihl byte above. The
			// reserved nibble is zero in a valid header and is not read
			// by any consumer of the copied struct.
			((__u8 *)tcph)[12] = tcph_doff(tcph_ptr) << 4;
			((__u8 *)tcph)[13] = tcph_flags(tcph_ptr);
			tcph->window = tcph_ptr->window;
			*listener_l4proto = tcp_listener_l4proto(tcph_ptr);
			return 0;
		}
		case IPPROTO_UDP: {
			struct udphdr *udph_ptr = data + offset;

			if ((void *)(udph_ptr + 1) > data_end)
				return -1;
			udph->source = udph_ptr->source;
			udph->dest = udph_ptr->dest;
			udph->len = udph_ptr->len;
			udph->check = udph_ptr->check;
			*listener_l4proto = IPPROTO_UDP;
			return 0;
		}
		case IPPROTO_ICMPV6: {
			struct icmp6hdr *icmp6h_ptr = data + offset;

			if ((void *)(icmp6h_ptr + 1) > data_end)
				return -1;
			icmp6h->icmp6_type = icmp6h_ptr->icmp6_type;
			icmp6h->icmp6_code = icmp6h_ptr->icmp6_code;
			return 0;
		}
		default:
			return PARSE_UNSUPPORTED_L4;
		}
	}

	return PARSE_UNSUPPORTED_ETH;
}

// Slow-path fallback using bpf_skb_load_bytes.
static __always_inline int
parse_transport_slow(struct __sk_buff *skb, __u32 link_h_len,
		     struct parse_transport_ctx *ctx)
{
	struct ethhdr *ethh = &ctx->ethh;
	struct iphdr *iph = &ctx->iph;
	struct ipv6hdr *ipv6h = &ctx->ipv6h;
	struct icmp6hdr *icmp6h = &ctx->icmp6h;
	struct tcphdr *tcph = &ctx->tcph;
	struct udphdr *udph = &ctx->udph;
	__u8 *ihl = &ctx->ihl;
	__u8 *l4proto = &ctx->l4proto;
	__u8 *listener_l4proto = &ctx->listener_l4proto;

	__u32 offset = 0;
	int ret;

	if (link_h_len == ETH_HLEN) {
		ret = bpf_skb_load_bytes(skb, offset, ethh,
					 sizeof(struct ethhdr));
		if (ret)
			return PARSE_UNSUPPORTED_ETH;
		offset += sizeof(struct ethhdr);
	} else {
		__builtin_memset(ethh, 0, sizeof(struct ethhdr));
		ethh->h_proto = skb->protocol;
	}

	*ihl = 0;
	*l4proto = 0;
	*listener_l4proto = 0;
	__builtin_memset(iph, 0, sizeof(struct iphdr));
	__builtin_memset(ipv6h, 0, sizeof(struct ipv6hdr));
	__builtin_memset(icmp6h, 0, sizeof(struct icmp6hdr));
	__builtin_memset(tcph, 0, sizeof(struct tcphdr));
	__builtin_memset(udph, 0, sizeof(struct udphdr));

	if (ethh->h_proto == bpf_htons(ETH_P_IP)) {
		ret = bpf_skb_load_bytes(skb, offset, iph,
					 sizeof(struct iphdr));
		if (ret)
			return -EFAULT;
		if (iphdr_ihl(iph) < 5)
			return -EFAULT;
		*ihl = iphdr_ihl(iph);
		*l4proto = iph->protocol;

		// First fragment carries L4; non-initial falls back.
		__u16 frag_off = bpf_ntohs(iph->frag_off);

		if ((frag_off & 0x1FFF) != 0)
			return PARSE_FRAGMENT;

		offset += iphdr_ihl(iph) * 4;

		switch (iph->protocol) {
		case IPPROTO_TCP:
			ret = bpf_skb_load_bytes(skb, offset, tcph,
						 sizeof(struct tcphdr));
			if (ret)
				return -EFAULT;
			*listener_l4proto = tcp_listener_l4proto(tcph);
			break;
		case IPPROTO_UDP:
			ret = bpf_skb_load_bytes(skb, offset, udph,
						 sizeof(struct udphdr));
			if (ret)
				return -EFAULT;
			*listener_l4proto = IPPROTO_UDP;
			break;
		default:
			return PARSE_UNSUPPORTED_L4;
		}
		return 0;
	}

	if (ethh->h_proto == bpf_htons(ETH_P_IPV6)) {
		ret = bpf_skb_load_bytes(skb, offset, ipv6h,
					 sizeof(struct ipv6hdr));
		if (ret)
			return -EFAULT;

		offset += sizeof(struct ipv6hdr);
		*ihl = sizeof(struct ipv6hdr) / 4;
		__u8 nexthdr = ipv6h->nexthdr;

		// Skip extension headers using bpf_skb_load_bytes
		for (int i = 0; i < IPV6_MAX_EXTENSIONS; i++) {
			if (nexthdr == IPPROTO_NONE)
				return -EFAULT;
			if (nexthdr == IPPROTO_FRAGMENT) {
				// First fragment still has L4; non-initial falls back.
				struct frag_hdr fragh = {};

				ret = bpf_skb_load_bytes(skb, offset, &fragh,
							 sizeof(fragh));
				if (ret)
					return -EFAULT;
				nexthdr = fragh.nexthdr;
				*l4proto = nexthdr;
				offset += sizeof(fragh);
				if ((bpf_ntohs(fragh.frag_off) & 0xFFF8) != 0)
					return PARSE_FRAGMENT;
				continue;
			}

			if (!is_extension_header(nexthdr))
				break;

			__u8 cur_hdr = nexthdr;

			ret = bpf_skb_load_bytes(skb, offset, &nexthdr, 1);
			if (ret)
				return -EFAULT;

			__u8 hdr_ext_len = 0;

			ret = bpf_skb_load_bytes(skb, offset + 1, &hdr_ext_len,
						 sizeof(hdr_ext_len));
			if (ret)
				return -EFAULT;

			__u32 ext_len = ipv6_exthdr_len(cur_hdr, hdr_ext_len);

			offset += ext_len;
		}

		if (is_extension_header(nexthdr))
			return -EFAULT;

		*l4proto = nexthdr;
		switch (nexthdr) {
		case IPPROTO_TCP:
			ret = bpf_skb_load_bytes(skb, offset, tcph,
						 sizeof(struct tcphdr));
			if (ret)
				return -EFAULT;
			*listener_l4proto = tcp_listener_l4proto(tcph);
			break;
		case IPPROTO_UDP:
			ret = bpf_skb_load_bytes(skb, offset, udph,
						 sizeof(struct udphdr));
			if (ret)
				return -EFAULT;
			*listener_l4proto = IPPROTO_UDP;
			break;
		case IPPROTO_ICMPV6:
			ret = bpf_skb_load_bytes(skb, offset, icmp6h,
						 sizeof(struct icmp6hdr));
			if (ret)
				return -EFAULT;
			break;
		default:
			return PARSE_UNSUPPORTED_L4;
		}
		return 0;
	}

	return PARSE_UNSUPPORTED_ETH;
}

// Try fast path first; fall back to slow path on -1.
static __always_inline int
parse_transport(struct __sk_buff *skb, __u32 link_h_len,
		struct parse_transport_ctx *ctx)
{
	int ret = parse_transport_fast(skb, link_h_len, ctx);

	if (ret == -1)
		return parse_transport_slow(skb, link_h_len, ctx);
	return ret;
}

struct parsed_packet {
	struct ethhdr ethh;
	struct tuples tuples;
	struct tcphdr tcph;
	struct udphdr udph;
	__u8 l4proto;
	__u8 listener_l4proto;
	__u8 handoff_required;
	__u16 datapath_generation;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct parsed_packet);
	__uint(max_entries, 1);
} pkt_scratch_map SEC(".maps");

static __always_inline void
populate_parsed_packet(struct __sk_buff *skb, struct parse_transport_ctx *ctx,
		       struct parsed_packet *out)
{
	__builtin_memset(out, 0, sizeof(*out));
	out->ethh = ctx->ethh;
	out->tcph = ctx->tcph;
	out->udph = ctx->udph;
	out->l4proto = ctx->l4proto;
	out->listener_l4proto = ctx->listener_l4proto;
	get_tuples(skb, &out->tuples, &ctx->iph, &ctx->ipv6h, &ctx->tcph,
		   &ctx->udph, ctx->l4proto);
}

static __always_inline int
parse_packet(struct __sk_buff *skb, __u32 link_h_len,
	     struct parsed_packet *out)
{
	__u32 scratch_key = 0;
	struct parse_transport_ctx *ctx =
		bpf_map_lookup_elem(&parse_ctx_scratch_map, &scratch_key);

	if (!ctx)
		return -EFAULT;

	int ret = parse_transport(skb, link_h_len, ctx);

	if (ret < 0)
		return ret;
	/* ICMPv6 is classified, but it is not proxied: report it through the
	 * same "L4 not routed" code so consumers count it uniformly. */
	if (ctx->l4proto == IPPROTO_ICMPV6)
		return PARSE_UNSUPPORTED_L4;

	// PARSE_FRAGMENT still populates the IP tuple for callers.
	populate_parsed_packet(skb, ctx, out);
	return ret;
}


