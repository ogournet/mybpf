/* SPDX-License-Identifier: AGPL-3.0-or-later */


#include "lib/cgn.h"

/*
 * return:
 *   -1: internal error
 *    0: ok
 *    1: no flow match (from pub only)
 *    2: user alloc error (from priv only)
 *    3: flow alloc error (from priv only)
 */
static int
handle_flow(const struct cgn_parsed_packet *pp, struct cgn_parsed_packet *out)
{
	struct cgn_user *u;

	if (pp->from_priv) {
		/*
		 * packet from private: may create user/flow
		 */
		u = _user_v4_lookup(pp->src_addr);
		if (u == NULL) {
			/* XXX redirect with cpumap to a single cpu to allocate */
			u = _user_v4_alloc(pp->src_addr);
			if (u == NULL)
				return 2;
		}

		struct cgn_v4_flow_priv *f;
		f = _flow_v4_lookup_priv(pp);
		if (f == NULL) {
			f = _flow_alloc(u, pp);
			if (f == NULL)
				return 3;
		}
		/* XXX may apply policy or sorts of things on user */

		out->src_addr = f->cgn_addr;
		out->src_port = f->cgn_port;

	} else {
		/*
		 * packet from public: check if a flow exists,
		 *  if so rewrite dst addr/port,
		 *  if not, drop packet.
		 */
		struct cgn_v4_flow_pub *f;
		f = _flow_v4_lookup_pub(pp);
		if (f == NULL) {
			/* no match, drop */
			return 1;
		}

		u = _user_v4_lookup(f->priv_addr);
		if (f == NULL) {
			/* bug */
			return -1;
		}
		/* XXX may apply policy or sorts of things on user */

		out->dst_addr = f->priv_addr;
		out->dst_port = f->priv_port;
	}

	return 0;
}


SEC("xdp")
int xdp_entry(struct xdp_md *ctx)
{
	return XDP_PASS;
}

SEC("xdp")
int xdp_test_alloc(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct cgn_parsed_packet *pp = data;
	struct cgn_parsed_packet pp_out;
	int ret;

	if (data + sizeof (*pp) > data_end)
		return XDP_ABORTED;

	ret = handle_flow(pp, &pp_out);
	if (hit_bug) {
		hit_bug = 0;
		return -1;
	}
	return ret;
}


char _license[] SEC("license") = "GPL";
