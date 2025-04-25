/* SPDX-License-Identifier: AGPL-3.0-or-later */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>


SEC("xdp")
int xdp_entry_mac(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;

	if ((void *)eth + sizeof(*eth) > data_end)
		return XDP_ABORTED;

	/* if (eth->h_proto == bpf_htons(ETH_P_IP)) { */
	/* 	__u8 h_tmp[ETH_ALEN]; */
	/* 	__builtin_memcpy(h_tmp, eth->h_source, ETH_ALEN); */
	/* 	__builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN); */
	/* 	__builtin_memcpy(eth->h_dest, h_tmp, ETH_ALEN); */
	/* } */

	bpf_printk("pkt pass! size: %d", data_end - data);
	bpf_printk("src_mac: %02x:%02x:%02x:%02x:%02x:%02x",
		   eth->h_source[0], eth->h_source[1], eth->h_source[2],
		   eth->h_source[3], eth->h_source[4], eth->h_source[5]);
	bpf_printk("dst_mac: %02x:%02x:%02x:%02x:%02x:%02x",
		   eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
		   eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
	return XDP_PASS;
}


SEC("xdp")
int xdp_entry(struct xdp_md *ctx)
{
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
