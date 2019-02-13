/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright (c) 2019, Joyent, Inc.
 * Copyright 2025 Oxide Computer Company
 */

/*
 * This file implements general TCP large receive offload (LRO).
 *
 * XXX Expand
 */

#include <sys/types.h>
#include <sys/strsubr.h>
#include <sys/strsun.h>
#include <sys/pattr.h>
#include <sys/kmem.h>
#include <sys/mac_impl.h>
#include <inet/tcp_impl.h>
#include <sys/sdt.h>

typedef enum mac_lro_flags {
	MLF_VALID	= 1 << 0,
	MLF_IPV4	= 1 << 1,
	MLF_TS_VALID	= 1 << 2,
} mac_lro_flags_t;

struct mac_lro_state_s {
	/*
	 * These fields track relevant state.
	 */
	mblk_t		*mls_head;
	mblk_t		*mls_tail;
	tcpha_t		*mls_tcp;

	/*
	 * These fields are kept in network endianness and (with the exception
	 * of TCP flags) are not modified from the packet.
	 */
	in6_addr_t	mls_src;
	in6_addr_t	mls_dst;
	uint16_t	mls_lport;
	uint16_t	mls_fport;
	uint32_t	mls_ip_ecn;
	uint32_t	mls_tcp_ack;
	uint16_t	mls_tcp_window;
	uint8_t		mls_tcp_flags;

	/*
	 * These fields are kept in host endianness.
	 */
	mac_lro_flags_t	mls_flags;
	uint_t		mls_len;
	uint_t		mls_count;
	uint32_t	mls_exp_seq;
	uint32_t	mls_tsval;
	uint32_t	mls_tsecr;
};

/*
 * Number of LRO entries to allocate for a soft ring.
 */
uint_t mac_lro_cache_size = 8;

/*
 * Rough statistics. We don't try and serialize these across CPUs, so they will
 * be lossy.
 */
uint_t mac_lro_slot_misses;

void
mac_lro_free(mac_lro_state_t *lrop, uint_t count)
{
	kmem_free(lrop, sizeof (mac_lro_state_t) * count);
}

void
mac_lro_alloc(mac_lro_state_t **lropp, uint_t *countp)
{
	*countp = mac_lro_cache_size;
	*lropp = kmem_zalloc(sizeof (mac_lro_state_t) * *countp,
	    KM_SLEEP);
}

static void
mac_lro_append_bnext(mblk_t *mp, mblk_t **head, mblk_t **tail)
{
	ASSERT3P(mp->b_next, ==, NULL);

	if (*head == NULL) {
		*head = mp;
	}

	if (*tail != NULL) {
		(*tail)->b_next = mp;
	}

	*tail = mp;
}

static inline void
mac_lro_append_bcont(mblk_t *mp, mblk_t **head, mblk_t **tail)
{
	if (*head == NULL) {
		*head = mp;
	}

	if (*tail != NULL) {
		(*tail)->b_cont = mp;
	}

	while (mp->b_cont != NULL) {
		mp = mp->b_cont;
	}
	ASSERT3P(mp, !=, NULL);
	*tail = mp;
}

static mac_lro_state_t *
mac_lro_find_free_slot(mac_lro_state_t *lrop, uint_t count)
{
	uint_t i;

	for (i = 0; i < count; i++, lrop++) {
		if ((lrop->mls_flags & MLF_VALID) == 0)
			return (lrop);
	}

	return (NULL);
}

static void
mac_lro_commit(mac_lro_state_t *lro, mblk_t **headp, mblk_t **tailp)
{
	tcpha_t *tcp;

	ASSERT3S((lro->mls_flags & MLF_VALID), !=, 0);
	ASSERT3U(lro->mls_count, >, 0);
	if (lro->mls_count == 1) {
		goto done;
	}

	/*
	 * We've joined multiple segments. This means that we need to update the
	 * following fields:
	 *
	 *  o IP Payload
	 *  o IP Checksum (zero)
	 *  o TCP ACK
	 *  o TCP Window Size
	 *  o TCP Checksum (zero)
	 *  o Timestamp
	 *  o TCP flags
	 */
	tcp = lro->mls_tcp;
	ASSERT3U(lro->mls_len, <=, IP_MAXPACKET);
	if ((lro->mls_flags & MLF_IPV4) != 0) {
		ipha_t *ip = (ipha_t *)lro->mls_head->b_rptr;
		ip->ipha_length = htons((uint16_t)lro->mls_len);
		ip->ipha_hdr_checksum = 0;
	} else {
		ip6_t *ip = (ip6_t *)lro->mls_head->b_rptr;
		ip->ip6_plen = htons((uint16_t)lro->mls_len);
	}
	tcp->tha_ack = lro->mls_tcp_ack;
	tcp->tha_win = lro->mls_tcp_window;
	tcp->tha_sum = 0;
	if ((lro->mls_flags & MLF_TS_VALID) != 0) {
		uint32_t *ts = (uint32_t *)(tcp + 1);
		ts[1] = htonl(lro->mls_tsval);
		ts[2] = htonl(lro->mls_tsecr);
	}
	tcp->tha_flags = lro->mls_tcp_flags;

done:
	DTRACE_PROBE3(mac__lro__commit, mblk_t *, lro->mls_head,
	    mac_lro_state_t *, lro, tcpha_t *, tcp);
	mac_lro_append_bnext(lro->mls_head, headp, tailp);
	ASSERT3P(*tailp, ==, lro->mls_head);
	ASSERT3P(lro->mls_tail->b_cont, ==, NULL);
	ASSERT3P(lro->mls_tail->b_next, ==, NULL);
	bzero(lro, sizeof (*lro));
}

#ifdef DEBUG
static void
mac_lro_verify_chain(mblk_t **head, mblk_t **tail)
{
	mblk_t *mp = *head;

	if (mp == NULL) {
		VERIFY3P(*tail, ==, NULL);
		return;
	}

	while (mp != NULL) {
		mblk_t *cont;

		cont = mp->b_cont;
		while (cont != NULL) {
			VERIFY3P(cont->b_next, ==, NULL);
			cont = cont->b_cont;
		}

		if (mp->b_next == NULL) {
			VERIFY3P(mp, ==, *tail);
		}
		mp = mp->b_next;
	}

	VERIFY3P((*tail)->b_next, ==, NULL);
	mp = *tail;
	while (mp->b_cont != NULL) {
		mp = mp->b_cont;
		VERIFY3P(mp->b_next, ==, NULL);
	}

	mp = *head;
	while (mp != NULL) {
		if (mp == *tail)
			break;
		mp = mp->b_next;
	}
	VERIFY3P(mp, !=, NULL);
}
#endif

typedef enum mac_lro_suitable {
	MLS_OK = 0,
	MLS_L3_PROTO,
	MLS_L4_PROTO,
	MLS_FRAGMENT,
	MLS_MBLK_LAYOUT,
	MLS_IPV4_OPTS,
	MLS_IPV6_EH,
	MLS_CKSUM,
	MLS_TCP_OPTS,

} mac_lro_suitable_t;

static mac_lro_suitable_t
mac_sw_lro_is_suitable(const mblk_t *mp, const mac_ether_offload_info_t *meoi,
    uint32_t hck_flags)
{
	/* Must be IPv4 or IPv6 and TCP */
	if ((meoi->meoi_flags & MEOI_L3INFO_SET) == 0 ||
	    (meoi->meoi_flags & MEOI_L4INFO_SET) == 0) {
		return (MLS_L3_PROTO);
	}
	if (meoi->meoi_l3proto != ETHERTYPE_IP &&
	    meoi->meoi_l3proto != ETHERTYPE_IPV6) {
		return (MLS_L3_PROTO);
	}
	if (meoi->meoi_l4proto != IPPROTO_TCP) {
		return (MLS_L4_PROTO);
	}

	/* Cannot be fragmented */
	if ((meoi->meoi_flags & MEOI_L3_FRAGMENT) != 0) {
		return (MLS_FRAGMENT);
	}

	/* First mblk does not contain all headers */
	const uint_t hdr_size =
	    (meoi->meoi_l2hlen + meoi->meoi_l3hlen + meoi->meoi_l4hlen);
	if (MBLKL(mp) < hdr_size) {
		return (MLS_MBLK_LAYOUT);
	}

	/* IPv4 must not carry options, and must contain a valid L3 cksum */
	if (meoi->meoi_l3proto == ETHERTYPE_IP) {
		if (meoi->meoi_l3hlen != IP_SIMPLE_HDR_LENGTH) {
			return (MLS_IPV4_OPTS);
		}
		if ((hck_flags & HCK_IPV4_HDRCKSUM_OK) == 0) {
			return (MLS_CKSUM);
		}
	}

	/* IPv6 must not carry extension headers */
	if (meoi->meoi_l3proto == ETHERTYPE_IPV6 &&
	    meoi->meoi_l3hlen != IPV6_HDR_LEN) {
		return (MLS_IPV6_EH);
	}

	/* The L4 cksum must be valid */
	if ((hck_flags & HCK_FULLCKSUM_OK) == 0) {
		return (MLS_CKSUM);
	}

	/* The only TCP option permitted for now is timestamp */
	const uint_t tcp_ts_len = (TCP_MIN_HEADER_LENGTH + TCPOPT_REAL_TS_LEN);
	if (meoi->meoi_l4hlen > tcp_ts_len) {
		return (MLS_TCP_OPTS);
	} else if (meoi->meoi_l4hlen == tcp_ts_len) {
		const uint32_t *tsp = (const uint32_t *)(mp->b_rptr +
		    meoi->meoi_l2hlen + meoi->meoi_l3hlen + sizeof (tcpha_t));
		if (*tsp != TCPOPT_NOP_NOP_TSTAMP) {
			return (MLS_TCP_OPTS);
		}
	}

	return (MLS_OK);
}

static boolean_t
mac_sw_lro_extract_tcp_ts(const tcpha_t *tcpha,
    const mac_ether_offload_info_t *meoi, uint32_t *tsval, uint32_t *tsecr)
{
	ASSERT(meoi->meoi_flags & MEOI_L4INFO_SET);
	ASSERT3U(meoi->meoi_l4proto, ==, IPPROTO_TCP);

	if (meoi->meoi_l4hlen == TCP_MIN_HEADER_LENGTH) {
		return (B_FALSE);
	}

	const uint32_t *tsp = (const uint32_t *)(tcpha + 1);

	/*
	 * mac_sw_lro_is_suitable() should have already rejected any packets
	 * which had options other than timestamp.
	 */
	ASSERT3U(*tsp, ==, TCPOPT_NOP_NOP_TSTAMP);
	ASSERT3U(meoi->meoi_l4hlen, ==,
	    TCP_MIN_HEADER_LENGTH + TCPOPT_REAL_TS_LEN);

	*tsval = ntohl(tsp[1]);
	*tsecr = ntohl(tsp[2]);
	return (B_TRUE);
}

/*
 * Perform software LRO on a stream of message blocks that exist in a chain.
 * This is commonly called from soft ring processing after fanout has occurred
 * to a protocol ring. We make the following assumptions only about the message
 * blocks:
 *
 *  o The packet has an IP + L4 header in the first message block. This property
 *    is currently maintained by all callers today.
 *
 *  o The L2 header has already been consumed by the mac_rx path and so the
 *    message blocks b_rptr starts at the IP header.
 *
 *  o We do _not_ assume that we will only encounter TCP data. While callers
 *    today make sure that we have TCP, we should assume that UDP or other types
 *    of IP packets may show up.
 *
 *  o We are given some number of LRO state structures to use.
 *
 * We will join TCP packets together under the following circumstances:
 *
 *  o The packet is TCP
 *  o The TCP packet checksummed has been confirmed by hardware
 *  o The IP checksum, if IPv4, has been confirmed by hardware
 *  o There are no IP options or extensions
 *  o The packets have the same 4-tuple
 *  o We have not already joined more than 64k of data.
 *  o No TCP flags other than ACK are present or PUSH are present.
 *  o TCP Sequence numbers match
 *  o If TCP options are present, the TCP option is the timestamp and we only
 *    see timestamps that are larger than the current. The previous packet must
 *    match the current packet with respect to options.
 *  o The TCP packet isn't an empty ack.
 *  o There is no urgent window set.
 *
 * The combined message block has the following properties in its headers:
 *
 *  o The IP Packet Length value is updated
 *  o The IP Checksum header is zeroed
 *  o The TCP header ACK is set to the last ACK seen
 *  o The TCP header flags are set to the combination of seen ACK/PUSH flags.
 *  o The TCP window is set to the last seen TCP window
 *  o If a TCP timestamp is present, the last timestamp is used.
 *
 * Finally, we will store a number of in-use LRO states based upon the passed in
 * state. Because this is occurring after protocol fanout (in most cases where
 * we'd care to multiple software rings), we assume that the likelihood of this
 * being a higher hit rate and therefore will traverse the lro state linearly.
 */
void
mac_sw_lro(mac_lro_state_t *lrop, uint_t lrocnt, mblk_t **mp_chain,
    mblk_t **tailp, int *cntp, size_t *sizep)
{
	mblk_t *mp;
	mblk_t *head = NULL, *tail = NULL;
	mblk_t *free_head = NULL, *free_tail = NULL;

	if (lrop == NULL || lrocnt == 0) {
		return;
	}

	for (uint_t i = 0; i < lrocnt; i++) {
		lrop[i].mls_flags = 0;
	}

	mp = *mp_chain;
	while (mp != NULL) {
		mblk_t *next = mp->b_next;
		mp->b_next = NULL;

		/* Gather header info from packet */
		mac_ether_offload_info_t meoi = { 0 };
		uint32_t flags;
		if (MBLKL(mp) == 0) {
			goto skip;
		}
		switch (IPH_HDR_VERSION(mp->b_rptr)) {
		case IP_VERSION:
			meoi.meoi_l3proto = ETHERTYPE_IP;
			meoi.meoi_flags |= MEOI_L2INFO_SET;
			break;
		case IPV6_VERSION:
			meoi.meoi_l3proto = ETHERTYPE_IPV6;
			meoi.meoi_flags |= MEOI_L2INFO_SET;
			break;
		default:
			break;
		}
		mac_hcksum_get(mp, NULL, NULL, NULL, NULL, &flags);
		mac_partial_offload_info(mp, 0, &meoi);
		meoi.meoi_len = msgsize(mp);

		const mac_lro_suitable_t suitable =
		    mac_sw_lro_is_suitable(mp, &meoi, flags);
		if (suitable != MLS_OK) {
			DTRACE_PROBE3(mac__lro__unsuitable, mblk_t *,
			    mp, mac_ether_offload_info_t *, &meoi,
			    mac_lro_suitable_t, suitable);
			goto skip;
		}

		const boolean_t is_ipv4 = meoi.meoi_l3proto == ETHERTYPE_IP;
		ipha_t *ip4 = NULL;
		ip6_t *ip6 = NULL;
		uint32_t ip_ecn;
		if (is_ipv4) {
			ip4 = (ipha_t *)(mp->b_rptr + meoi.meoi_l2hlen);
			ip_ecn = ip4->ipha_type_of_service;
		} else {
			ip6 = (ip6_t *)(mp->b_rptr + meoi.meoi_l2hlen);
			ip_ecn = ip6->ip6_vcf;
		}
		tcpha_t *tcp = (tcpha_t *)
		    (mp->b_rptr + meoi.meoi_l2hlen + meoi.meoi_l3hlen);
		const uint_t hdr_len =
		    meoi.meoi_l2hlen + meoi.meoi_l3hlen + meoi.meoi_l4hlen;
		const uint_t data_len = meoi.meoi_len - hdr_len;

		boolean_t force_commit = B_FALSE;
		if ((tcp->tha_flags & ~(TH_ACK | TH_PUSH)) != 0 ||
		    tcp->tha_urp != 0) {
			force_commit = B_TRUE;
		} else if (data_len == 0) {
			goto skip;
		}

		uint32_t tsval, tsecr;
		const boolean_t ts_valid =
		    mac_sw_lro_extract_tcp_ts(tcp, &meoi, &tsval, &tsecr);

		/*
		 * At this point, we have a TCP segment which may or may not be
		 * valid. We can't just skip this and instead have to see if
		 * there's already a record of its flow. There are a few
		 * different cases to consider from here:
		 *
		 * 1) There is no record of the flow. In this case, if its
		 * valid, we'll open a new flow record, otherwise, we'll just
		 * append it as is ('skip' label).
		 *
		 * 2) There is a record for this flow and this packet is invalid
		 * for LRO or there is a mismatch in the sequence numbers or
		 * timestamp data. In that case we need to commit the current
		 * flow's packets, append the committed data to the output
		 * chain, and then append this as is.
		 *
		 * 3) There is a record for this flow and this packet would push
		 * us beyond 64k of payload data. We will commit the current
		 * flow's data and then start a new flow.
		 *
		 * 4) There is a record for this flow and this packet fits in
		 * the current bounds, so append it to the current state.
		 */

		mac_lro_state_t *matched = NULL;
		for (uint_t i = 0; i < lrocnt; i++) {
			mac_lro_state_t *l = &lrop[i];

			if ((l->mls_flags & MLF_VALID) == 0) {
				continue;
			}

			if (((l->mls_flags & MLF_IPV4) != 0) != is_ipv4) {
				DTRACE_PROBE2(mac__lro__mismatch__proto,
				    mblk_t *, mp, mac_lro_state_t *, l);
				continue;
			}
			if (l->mls_lport != tcp->tha_lport ||
			    l->mls_fport != tcp->tha_fport) {
				DTRACE_PROBE2(mac__lro__mismatch__port,
				    mblk_t *, mp, mac_lro_state_t *, l);
				continue;
			}
			if (is_ipv4 &&
			    (ip4->ipha_src != V4_PART_OF_V6(l->mls_src) ||
			    ip4->ipha_dst != V4_PART_OF_V6(l->mls_dst))) {
				DTRACE_PROBE2(mac__lro__mismatch__addr__v4,
				    mblk_t *, mp, mac_lro_state_t *, l);
				continue;
			}
			if (!is_ipv4 &&
			    (!IN6_ARE_ADDR_EQUAL(&ip6->ip6_src, &l->mls_src) ||
			    !IN6_ARE_ADDR_EQUAL(&ip6->ip6_dst, &l->mls_dst))) {
				DTRACE_PROBE2(mac__lro__mismatch__addr__v6,
				    mblk_t *, mp, mac_lro_state_t *, l);
				continue;
			}

			const uint32_t seq = ntohl(tcp->tha_seq);
			const boolean_t ent_ts_valid =
			    (l->mls_flags & MLF_TS_VALID) != 0;

			if (force_commit ||
			    data_len > IP_MAXPACKET - l->mls_len ||
			    seq != l->mls_exp_seq ||
			    ts_valid != ent_ts_valid ||
			    (ts_valid && l->mls_tsval > tsval) ||
			    ip_ecn != l->mls_ip_ecn) {
				DTRACE_PROBE5(mac__lro__force__commit,
				    mblk_t *, mp, mac_lro_state_t *, l,
				    tcpha_t *, tcp, uint_t, data_len,
				    uint16_t, ip_ecn);
				/*
				 * In some cases it could make sense to try and
				 * use this new packet to start a new sequence,
				 * but for the time being, we'll just append
				 * this directly.
				 */
				mac_lro_commit(l, &head, &tail);
				goto skip;
			}

			DTRACE_PROBE4(mac__lro__append, mblk_t *, mp,
			    mac_lro_state_t *, l, tcpha_t *, tcp,
			    uint_t, data_len);
			l->mls_tcp_ack = tcp->tha_ack;
			l->mls_tcp_window = tcp->tha_win;
			l->mls_len += data_len;
			l->mls_count++;
			l->mls_exp_seq += data_len;
			if (ts_valid) {
				l->mls_tsval = tsval;
				l->mls_tsecr = tsecr;
			}
			l->mls_tcp_flags |= tcp->tha_flags;

			/*
			 * XXX Consider something with a b_cont as not being fit
			 * for inclusion rather than this
			 */
			mp->b_rptr += hdr_len;
			if (MBLKL(mp) == 0) {
				mblk_t *tmp = mp;
				mp = tmp->b_cont;
				VERIFY3P(mp, !=, NULL);
				tmp->b_cont = NULL;
				mac_lro_append_bnext(tmp, &free_head,
				    &free_tail);
			}
			ASSERT3P(mp->b_next, ==, NULL);
			mac_lro_append_bcont(mp, &l->mls_head, &l->mls_tail);
			(*cntp)--;
			ASSERT3S(*cntp, >=, 1);
			/*
			 * sizep may be zero if we're not under bandwidth
			 * control
			 */
			if (*sizep != 0) {
				ASSERT3S(*sizep, >, hdr_len);
				(*sizep) -= hdr_len;
			}
			matched = l;
			break;
		}

		if (matched != NULL) {
			DTRACE_PROBE2(mac__lro__hit, mblk_t *, mp,
			    mac_lro_state_t *, matched);
			/* Processed above */
			mp = next;
			continue;
		} else {
			mac_lro_state_t *l;

			DTRACE_PROBE1(mac__lro__miss, mblk_t *, mp);
			l = mac_lro_find_free_slot(lrop, lrocnt);
			if (l == NULL) {
				mac_lro_slot_misses++;
				goto skip;
			}

			l->mls_flags = MLF_VALID |
			    (is_ipv4 ? MLF_IPV4 : 0) |
			    (ts_valid ? MLF_TS_VALID : 0);
			mac_lro_append_bcont(mp, &l->mls_head, &l->mls_tail);
			l->mls_tcp = tcp;

			if (is_ipv4) {
				V6_SET_ZERO(l->mls_src);
				V4_PART_OF_V6(l->mls_src) = ip4->ipha_src;
				V6_SET_ZERO(l->mls_dst);
				V4_PART_OF_V6(l->mls_dst) = ip4->ipha_dst;
			} else {
				l->mls_src = ip6->ip6_src;
				l->mls_dst = ip6->ip6_dst;
			}
			l->mls_lport = tcp->tha_lport;
			l->mls_fport = tcp->tha_fport;

			l->mls_len = hdr_len + data_len;
			l->mls_count = 1;
			l->mls_exp_seq = ntohl(tcp->tha_seq) + data_len;
			l->mls_tcp_ack = tcp->tha_ack;
			l->mls_tcp_window = tcp->tha_win;
			l->mls_ip_ecn = ip_ecn;
			l->mls_tsval = tsval;
			l->mls_tsecr = tsecr;
			l->mls_tcp_flags = tcp->tha_flags;

			DTRACE_PROBE3(mac__lro__create, mblk_t *, mp,
			    mac_lro_state_t *, l, tcpha_t *, tcp);

			mp = next;
			continue;
		}

skip:
		DTRACE_PROBE2(mac__lro__skip, mblk_t *, mp,
		    mac_ether_offload_info_t *, &meoi);
		mac_lro_append_bnext(mp, &head, &tail);
		mp = next;
	}

	for (uint_t i = 0; i < lrocnt; i++) {
		if ((lrop[i].mls_flags & MLF_VALID) != 0) {
			mac_lro_commit(&lrop[i], &head, &tail);
		}
	}

#ifdef DEBUG
	mac_lro_verify_chain(&head, &tail);
#endif
	*mp_chain = head;
	*tailp = tail;
	freemsgchain(free_head);
}
