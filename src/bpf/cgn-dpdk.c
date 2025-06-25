/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "lib/ip.h"

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
	__uint(max_entries, 64);
} xsks_map SEC(".maps");


/*
 * filter only part of trafic for dpdk-app
 */
SEC("xdp")
int xdp_dpdk_prosthesis(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *ethh = data;
	struct vlan_hdr *vlanh;
	struct iphdr *ip4h;
	struct udphdr *udp;
	struct tcphdr *tcp;
	struct icmphdr *icmp;
	void *payload;
	__u16 eth_type, vlan = 0;
	int ret;

	if ((void *)(ethh + 1) > data_end)
		return XDP_PASS;

	eth_type = ethh->h_proto;

	/* handle outer VLAN tag */
	if (eth_type == __constant_htons(ETH_P_8021Q) ||
	    eth_type == __constant_htons(ETH_P_8021AD)) {
		vlanh = (struct vlan_hdr *)(ethh + 1);
		if ((void *)(vlanh + 1) > data_end)
			return XDP_PASS;
		vlan = bpf_ntohs(vlanh->vlan_tci) & 0x0fff;
		eth_type = vlanh->next_proto;
		ip4h = (struct iphdr *)(vlanh + 1);
	} else {
		ip4h = (struct iphdr *)(ethh + 1);
	}

	if (eth_type != __constant_htons((ETH_P_IP)))
		return XDP_PASS;

	if ((void *)(ip4h + 1) > data_end)
		return XDP_PASS;
	if (ip4h->version != 4)
		return XDP_PASS;

	payload = (void *)ip4h + ip4h->ihl * 4;

	/* inspect l4 layer */
	switch (ip4h->protocol) {
	case IPPROTO_UDP:
		udp = payload;
		if ((void *)(udp + 1) > data_end)
			return XDP_PASS;
		if (bpf_ntohs(udp->dest) < 1024)
			return XDP_PASS;
		break;

	case IPPROTO_TCP:
		tcp = payload;
		if ((void *)(tcp + 1) > data_end)
			return XDP_PASS;
		if (bpf_ntohs(tcp->dest) < 1024)
			return XDP_PASS;
		break;

	case IPPROTO_ICMP:
		icmp = payload;
		if ((void *)(icmp + 1) > data_end)
			return XDP_PASS;
		switch (icmp->type) {
		case ICMP_ECHO:
		case ICMP_ECHOREPLY:
			return XDP_PASS; // XXX should pass to dpdk
		case ICMP_DEST_UNREACH:
		case ICMP_TIME_EXCEEDED:
			break;
		default:
			return XDP_PASS;
		}

	case IPPROTO_GRE:
		break;

	default:
		return XDP_PASS;
	}

	return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, XDP_PASS);
}

char _license[] SEC("license") = "GPL";
