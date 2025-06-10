/* SPDX-License-Identifier: AGPL-3.0-or-later */

#include <linux/if_ether.h>

#include "lib/cgn.h"


/*
 * test flow/block lookup/allocation, without real ip packet data.
 */
SEC("xdp")
int xdp_test_alloc(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct cgn_packet *cp = data;
	int ret;

	if (data + sizeof (*cp) > data_end)
		return XDP_ABORTED;

	if (cp->from_priv)
		ret = cgn_flow_handle_priv(cp);
	else
		ret = cgn_flow_handle_pub(cp);
	if (hit_bug) {
		hit_bug = 0;
		return -1;
	}
	return ret;
}


/*
 * attach to interface, get l2 packet
 */
SEC("xdp")
int xdp_entry(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	int ret;

	if ((void *)(eth + 1) > data_end)
		return XDP_ABORTED;
	if (eth->h_proto != __constant_htons(ETH_P_IP))
		return XDP_PASS;

	if ((void *)((struct iphdr *)(eth + 1) + 1) > data_end)
		return 1;

	ret = cgn_pkt_handle(ctx, (void *)(eth + 1), eth->h_dest[5]);
	if (hit_bug || ret < 0) {
		hit_bug = 0;
		return XDP_ABORTED;
	}
	if (ret > 0)
		return XDP_DROP;
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
