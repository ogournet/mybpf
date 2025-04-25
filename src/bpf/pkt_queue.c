
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "lib/test_shared.h"


struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__type(key, __u32);
	__type(value, __u32);
} xsks_map SEC(".maps");


SEC("xdp")
int xdp_entry(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;

	// let arp pass
	if ((void *)eth + sizeof(*eth) > data_end)
		return XDP_ABORTED;
	if (eth->h_proto == bpf_htons(ETH_P_ARP))
		return XDP_PASS;

	/* redirect packet on af_xdp socket, of rx queue index */
	int index = ctx->rx_queue_index;
	if (bpf_map_lookup_elem(&xsks_map, &index)) {
		int action = bpf_redirect_map(&xsks_map, index, 0);
		bpf_printk("redirect to xsks index %d, ret=%d", index, action);
		return action;
	}

	bpf_printk("cannot find xsks entry :/");
	return XDP_PASS;
}


char _license[] SEC("license") = "GPL";
