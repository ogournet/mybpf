/* SPDX-License-Identifier: AGPL-3.0-or-later */

#include <linux/if_ether.h>

#include "lib/ip6fw.h"


SEC("xdp")
int xdp_entry(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	struct ipv6hdr *ip6h;
	struct icmp6hdr *icmp6;
	__u8 nh;
	int ret;

	if ((void *)(eth + 1) > data_end)
		return XDP_ABORTED;
	if (eth->h_proto != __constant_htons(ETH_P_IPV6))
		return XDP_PASS;

	ip6h = (struct ipv6hdr *)(eth + 1);
	if ((void *)(ip6h + 1) > data_end)
		return 1;

	/* let icmpv6 ND pass */
	icmp6 = ipv6_skip_exthdr(ctx, ip6h, &nh);
	if (icmp6 != NULL && nh == IPPROTO_ICMPV6 && (void *)(icmp6 + 1) <= data_end &&
	    icmp6->icmp6_type >= 133 && icmp6->icmp6_type <= 137)
		return XDP_PASS;

	ret = ip6fw_pkt_handle(ctx, (void *)(eth + 1), eth->h_dest[5]);
	if (ret)
		return XDP_DROP;
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
