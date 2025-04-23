
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/*
 * constant values are modified by userspace before startup.
 */

const volatile __u64 cst64;
const volatile int my_constant;
const volatile __u8 array_constant[64];


SEC("xdp")
int xdp_entry(struct xdp_md *ctx)
{
	bpf_printk("my_constant: %d", my_constant);

	return XDP_PASS;
}


char _license[] SEC("license") = "GPL";
