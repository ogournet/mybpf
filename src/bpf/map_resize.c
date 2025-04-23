/* SPDX-License-Identifier: AGPL-3.0-or-later */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <string.h>

#include "lib/test_shared.h"

/* stats array, percpu, nothing exiting */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 64);
} xdp_stats_map SEC(".maps");

/*
 * test hash table that will be resized on startup, to fit our configuration needs.
 * sizeof(basic) is 32, but we will allocate for tab[16], so value_size = 160
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, struct basic);
	/* __uint(value_size, 64); */	/* another way to declare size */
	__uint(max_entries, 20);	/* will be changed on program load */
} resize_hash_map SEC(".maps");



SEC("xdp")
int xdp_entry(struct xdp_md *ctx)
{
	int index = ctx->rx_queue_index;
	__u32 *pkt_count;

	// usual way to do stats
	pkt_count = bpf_map_lookup_elem(&xdp_stats_map, &index);
	if (pkt_count)
		++*pkt_count;

	// test map of type hash
	int idx = 669;
	struct basic *toto = bpf_map_lookup_elem(&resize_hash_map, &idx);
	if (toto == NULL) {
		/* yes 160b is hardcoded, but this kind of table will be
		 * created/filled from userspace anyway */
		__u8 data[160] = {};
		bpf_map_update_elem(&resize_hash_map, &idx, data, BPF_ANY);
		toto = (struct basic *)data;
	}
	toto->a1++;
	toto->a2 += 10;
	toto->a3 += 2000;
	toto->tab[15]++;	/* verifier accept */
	//toto->tab[16]++;	/* verifier disallow */

	return XDP_PASS;
}


SEC("xdp")
int xdp_pass(struct xdp_md *ctx)
{
	return XDP_PASS;
}


SEC("xdp")
int xdp_drop(struct xdp_md *ctx)
{
	return XDP_DROP;
}



char _license[] SEC("license") = "GPL";
