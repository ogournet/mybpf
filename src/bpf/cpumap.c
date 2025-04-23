/* SPDX-License-Identifier: AGPL-3.0-or-later */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/*
 * redirect packet to wanted cpu (here, everything on cpu 3)
 *
 * logs can be seen with:
 * sudo cat /sys/kernel/debug/tracing/trace_pipe
 *
 * cpu_map.max_entries is set from userspace, from libbpf_num_possible_cpus()
 */

struct {
	__uint(type, BPF_MAP_TYPE_CPUMAP);
	__type(key, __u32);
	__type(value, struct bpf_cpumap_val);
} cpu_map SEC(".maps");


SEC("xdp")
int xdp_entry(struct xdp_md *ctx)
{
	if (bpf_get_smp_processor_id() != 3) {
		bpf_printk(" from: %d redirect to %d\n", bpf_get_smp_processor_id(), 3);
		return bpf_redirect_map(&cpu_map, 3, 0);
	} else {
		bpf_printk(" already on cpu %d\n", bpf_get_smp_processor_id());
	}

	return XDP_PASS;
}


char _license[] SEC("license") = "GPL";
