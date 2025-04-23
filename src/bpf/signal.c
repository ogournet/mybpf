/* SPDX-License-Identifier: AGPL-3.0-or-later */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "lib/test_shared.h"

/*
 * a 'signal' (event) is sent from bpf to userspace on each received packet,
 * with arbitrary data included. it uses perf bpf helpers.
 *
 * data is defined in struct mysignal, which is shared between bpf and userspace.
 */

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events SEC(".maps");


static void send_event(struct xdp_md *ctx)
{
	struct mysignal s = {
		.a1 = 333,
		.a2 = 222,
		.a5 = 666,
	};
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &s, sizeof(s));
}

SEC("xdp")
int xdp_entry(struct xdp_md *ctx)
{
	send_event(ctx);

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
