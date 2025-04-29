
#include <time.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <sys/socket.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "lib/ip.h"

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__type(key, __u32);
	__type(value, __u32);
} xsks_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_DEVMAP);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1);
} ip_frag_out_dev SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} ip_frag_signal SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, 10000);
	__type(key, union ipfrag_key);
	__type(value, struct ipfrag_rule);
} ip_frag SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, PKT_STAT_MAX);
	__type(key, __u32);
	__type(value, __u64);
} pkt_stats SEC(".maps");



/***********/

static inline void stats_inc(int key)
{
	__u64 *val = bpf_map_lookup_elem(&pkt_stats, &key);
	if (val != NULL)
		++*val;
}


/***********/
/* ipfrag, should go into a "library" */

/*
 * add ipfrag_key as metadata, then redirect packet
 */
static inline int
ipfrag_queue_packet(struct xdp_md *ctx, const union ipfrag_key *fkey)
{
	union ipfrag_key *mk;
	void *data;
	int err;

	/* Reserve space in-front of data pointer for our meta info */
	err = bpf_xdp_adjust_meta(ctx, -(int)sizeof(*mk));
	if (err)
		return -1;

	data = (void *)(unsigned long)ctx->data;
	mk = (void *)(unsigned long)ctx->data_meta;
	if ((void *)(mk + 1) > data) /* Verify meta area is accessible */
		return -1;

	*mk = *fkey;

	/* redirect packet on af_xdp socket, of rx queue index */
	int index = ctx->rx_queue_index;
	if (bpf_map_lookup_elem(&xsks_map, &index)) {
		bpf_printk("meta %d added, redirect to xsks index %d",
			   sizeof (*mk), index);
		if (bpf_redirect_map(&xsks_map, index, 0) == XDP_REDIRECT)
			return 0;
	}
	return -1;
}

static int
ipfrag_timer_fired(void *map, int *key, struct ipfrag_rule *r)
{
	if (!(r->flags & IPFRAG_FL_RULE_SET))
		stats_inc(PKT_STAT_FRAG_NOMATCH_DROP);
	bpf_map_delete_elem(map, key);
	return 0;
}

static int
ipfrag_insert_rule(const union ipfrag_key *fkey, struct ipfrag_rule *r)
{
	int ret = 0;

	if (bpf_map_update_elem(&ip_frag, fkey, r, BPF_NOEXIST) < 0)
		return -1;

	/* timer needs to be reload from map */
	r = bpf_map_lookup_elem(&ip_frag, fkey);
	if (r == NULL)
		return -1;

	/* register expire timer for this entry */
	ret = bpf_timer_init(&r->timer, &ip_frag, CLOCK_MONOTONIC);
	if (ret != 0) {
		bpf_map_delete_elem(&ip_frag, fkey);
		return -1;
	}

	/* fragment tracking lifetime is 500ms */
	bpf_timer_set_callback(&r->timer, ipfrag_timer_fired);
	bpf_timer_start(&r->timer, 500000000, 0);

	return 0;
}

/*
 * first segment of a fragmented ip packet
 * return:
 *   -1: error, drop
 *    0: ok, let it pass
 */
static int
ipfrag_handle_first_frag_seg(struct xdp_md *ctx, struct iphdr *iph,
			     struct ipfrag_rule *rule)
{
	union ipfrag_key fkey = {
		.v4.family = AF_INET,
		.v4.proto = iph->protocol,
		.v4.packet_id = iph->id,
		.v4.src = iph->saddr,
		.v4.dst = iph->daddr,
		.v4.pad = {},
	};

	struct ipfrag_rule *r = bpf_map_lookup_elem(&ip_frag, &fkey);
	if (r != NULL && !(r->flags & IPFRAG_FL_RULE_SET)) {
		/*  xxx: save rule into r. *r = *rule won't work */
		r->flags |= IPFRAG_FL_RULE_SET;

		/* we received and queued fragment(s) of this packet */
		bpf_printk("first segment, we saw other seg for this pkt, signal");
		bpf_perf_event_output(ctx, &ip_frag_signal, BPF_F_CURRENT_CPU,
				      &fkey, sizeof(fkey));

		// xxx: better count at XDP-TX, to have the number of frag.
		stats_inc(PKT_STAT_FRAG_REORDER);

	} else if (r != NULL) {
		/* most probably a duplicated/re-sent packet */
		bpf_printk("first segment, duplicate?");

	} else {
		/* got 1st packet in an ordered way: save rule */
		rule->flags |= IPFRAG_FL_RULE_SET;
		bpf_printk("save ref, fkey={%d:%d:%d:0x%08x:0x%08x}",
			   fkey.v4.family, fkey.v4.proto, fkey.v4.packet_id,
			   fkey.v4.src, fkey.v4.dst);

		if (ipfrag_insert_rule(&fkey, rule) < 0)
			return -1;
	}

	stats_inc(PKT_STAT_FRAG_FWD);
	return 0;
}

/*
 * subsequent segment of a fragmented packet.
 * return:
 *  -1: error, drop
 *   0: no/empty rule, packet sent to AF_XDP, return XDP_REDIRECT
 *   1: have translation rule
 */
static int
ipfrag_handle_following_frag_seg(struct xdp_md *ctx, struct iphdr *iph,
				 struct ipfrag_rule **out_rule)
{
	union ipfrag_key fkey = {
		.v4.family = AF_INET,
		.v4.proto = iph->protocol,
		.v4.packet_id = iph->id,
		.v4.src = iph->saddr,
		.v4.dst = iph->daddr,
		.v4.pad = {},
	};

	__u32 offset = bpf_htons(iph->frag_off);
	offset &= IP_OFFMASK;
	offset <<= 3;

	bpf_printk("got subsq off: %d fkey={%d:%d:%d:0x%08x:0x%08x}",
		   offset, fkey.v4.family, fkey.v4.proto, fkey.v4.packet_id,
		   fkey.v4.src, fkey.v4.dst);

	struct ipfrag_rule *ipf_r = bpf_map_lookup_elem(&ip_frag, &fkey);
	if (ipf_r == NULL) {
		/* no rule. create an empty one and queue packet */
		bpf_printk("no rule, queue paquet");
		struct ipfrag_rule empty_rule = { };
		if (ipfrag_insert_rule(&fkey, &empty_rule) < 0)
			return -1;
		return ipfrag_queue_packet(ctx, &fkey);

	} else if (!(ipf_r->flags & IPFRAG_FL_RULE_SET)) {
		/* empty rule, another unordered frag hit us before.
		 * queue packet */
		bpf_printk("empty rule, queue paquet");
		return ipfrag_queue_packet(ctx, &fkey);

	} else {
		/* order fragments, fetch the rule (common case) */
		*out_rule = ipf_r;
		return 1;
	}
}

/***********/

/* packet rewrite */
static inline void swap_src_dst_mac(struct ethhdr *eth)
{
	__u8 h_tmp[ETH_ALEN];
	__builtin_memcpy(h_tmp, eth->h_source, ETH_ALEN);
	__builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
	__builtin_memcpy(eth->h_dest, h_tmp, ETH_ALEN);
}

static inline void swap_src_dst_ip(struct iphdr *iph)
{
	__u32 tmp = iph->daddr;
	iph->daddr = iph->saddr;
	iph->saddr = tmp;
}



/***********/


SEC("xdp")
int xdp_entry(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	struct iphdr *iph = (struct iphdr *)(eth + 1);
	struct icmphdr *icmph;
	struct ipfrag_rule *rule;
	int ret;

	/* let it goes if not IP packet */
	if ((void *)eth + sizeof(*eth) + sizeof(*iph) > data_end)
		return XDP_ABORTED;
	if (eth->h_proto != __constant_htons(ETH_P_IP))
		return XDP_PASS;

	/* subsequent frag segments: early handle & return */
	if (iph->frag_off & bpf_htons(IP_OFFMASK)) {
		ret = ipfrag_handle_following_frag_seg(ctx, iph, &rule);
		if (ret == 1)
			goto apply_rule;
		if (ret == 0)
			return XDP_REDIRECT;
		return XDP_DROP;
	}

	/* xxx: do the work, traverse layers, lookup maps, retrieve translation
	 * teid, cgn port, ... whatever the program want to do */
	struct ipfrag_rule r = {};
	//r.teid = 33333;
	rule = &r;

	/* example: reply to echo */
	icmph = (struct icmphdr *)(iph + 1);
	if ((void *)icmph + sizeof(*icmph) > data_end)
		return XDP_ABORTED;
	if (icmph->type == ICMP_ECHO) {
		icmph->type = ICMP_ECHOREPLY;
		icmph->checksum = icmph->checksum + 8;
	}

	/* first fragment, save translation rule */
	if (iph->frag_off & bpf_htons(IP_MF)) {
		ret = ipfrag_handle_first_frag_seg(ctx, iph, rule);
		if (ret < 0)
			return XDP_DROP;
	}

 apply_rule:
	/* xxx: apply translation wrt rule (modify packet here),
	 * then send this segment (probably XDP_TX) */
	//gtp->teid = rule->teid;

	swap_src_dst_ip(iph);
	swap_src_dst_mac(eth);

	return XDP_TX;
}


/*
 * entry point for out-of-order fragmented packets that got a rule.
 * attached to veth 'ipfrag-out', created by ipfrag userland program.
 */
SEC("xdp")
int xdp_ipfrag_entry(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	union ipfrag_key *fkey = data;

	/* retrieve 'metadata': ipfrag_key.
	 * see comment in src/ipfrag.c:read_pkt_cb() */
	if ((void *)fkey + sizeof (*fkey) > data_end)
		return XDP_ABORTED;

	/* check if ipfrag entry still in map */
	bpf_printk("got late frag: fkey={%d:%d:%d:0x%08x:0x%08x}",
		   fkey->v4.family, fkey->v4.proto, fkey->v4.packet_id,
		   fkey->v4.src, fkey->v4.dst);

	struct ipfrag_rule *ipf_r = bpf_map_lookup_elem(&ip_frag, fkey);
	if (ipf_r == NULL || !(ipf_r->flags & IPFRAG_FL_RULE_SET)) {
		bpf_printk("no rule, drop %p", ipf_r);
		return XDP_DROP;
	}

	/* restore packet */
	if (bpf_xdp_adjust_head(ctx, sizeof(*fkey)) < 0)
		return XDP_ABORTED;


	/* xxx: now we can use ipf_r to rewrite packet */

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	struct ethhdr *eth = data;
	struct iphdr *iph = (struct iphdr *)(eth + 1);

	if (data + sizeof (*eth) + sizeof (*iph) > data_end)
		return XDP_ABORTED;

	swap_src_dst_ip(iph);
	swap_src_dst_mac(eth);

	/* XDP_REDIRECT on "main" device (where xdp_entry is attached) */
	return bpf_redirect_map(&ip_frag_out_dev, 0, 0);
}


char _license[] SEC("license") = "GPL";
