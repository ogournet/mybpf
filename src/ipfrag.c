/* SPDX-License-Identifier: AGPL-3.0-or-later */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include <bpf/libbpf.h>

#include "lib/hlist.h"
#include "lib/jhash.h"
#include "mybpf-priv.h"
#include "bpf/lib/ip.h"

#define HFRAGLIST_SIZE		2000

/* locals */
static struct pq_ctx *pq_ctx;
static struct hlist_head hfraglist[HFRAGLIST_SIZE];


struct ipfrag_pkt_data
{
	struct hlist_node hlist;
	union ipfrag_key key;
};

static inline
int fragdata_hash(const union ipfrag_key *fkey, uint32_t *out_keylen)
{
	switch (fkey->family) {
	case AF_INET:
		*out_keylen = 12;
		return jhash_3words(fkey->_u4.data[0], fkey->_u4.data[1],
				    fkey->_u4.data[2], 0x654657)
			% HFRAGLIST_SIZE;

	case AF_INET6:
		*out_keylen = 44;
		return 0;
	default:
		return -1;
	}
}


/*
 * receive packet from AF_XDP. metadata is right before 'pkt->data'.
 * we know it's of size 'union ipfrag_key', still userland and bpf program
 * needs to always be aligned during upgrade. maybe add a 'magic/cookie' field ?
 *
 * AF_XDP-Interaction does is by using/checking BTF data
 * https://github.com/xdp-project/bpf-examples/blob/main/AF_XDP-interaction/
 * but it add too much complexity (without a skeleton) for our needs.
 *
 * so, hash packet data using this key.
 */
static void
read_pkt_cb(struct pq_ctx */* ctx */, void */* uctx */, struct pq_desc *pkt)
{
	union ipfrag_key *fkey = (union ipfrag_key *)(pkt->data) - 1;
	struct ipfrag_pkt_data *pd = (struct ipfrag_pkt_data *)pkt->user_data;
	uint32_t klen;
	int h = fragdata_hash(fkey, &klen);

	if (h == -1) {
		printf("af_xdp: wrong pkt metadata: %d / "
		       "sizeof=%ld data=%p fkey=%p\n",
		       fkey->family, sizeof(union ipfrag_key), pkt->data, fkey);
		INIT_HLIST_NODE(&pd->hlist);
		return;
	}

	/*
	 * here we adjust packet by including metadata. why ?
	 *
	 * on xsk, RX metadata is added by nic card, or may also be set by
	 * bpf xdp program to arbitrary data. we use this second case to set
	 * ipfrag_key.
	 *
	 * on xsk, TX metadata is somewhat 'hardcoded' to few hw nic operations
	 * (hwcsum and timestamping), and kernel xsk will check it and won't let
	 * use send anything.
	 *
	 * in our case, we will TX on veth, with our bpf program on the other side.
	 * and we need to transfer ipfrag_key again so bpf prog can access map data.
	 *
	 * we may try to bypass kernel xsk checks with the right flags, instead
	 * we choose to add metdata in packet, then adjust in RX bpf program.
	 */
	pkt->len += sizeof (*fkey);
	pkt->data -= sizeof (*fkey);

	/* add to our htable, in order to quickly get it when signal
	 * will be fired (1st pkt rcvd) */
	pd->key = *fkey;
	hlist_add_head(&pd->hlist, &hfraglist[h]);
}

static void
timeout_pkt_cb(struct pq_ctx */* ctx */, void */* uctx */, struct pq_desc *pkt)
{
	struct ipfrag_pkt_data *pd = (struct ipfrag_pkt_data *)pkt->user_data;

	printf("timeout xdp frame at %p of %d!!!\n", pkt->data, pkt->len);

	hlist_del(&pd->hlist);
}

/*
 * got signal from bpf program: time to send queued segments.
 */
static void
signal_cb(struct pq_ctx *ctx, void */* uctx */,
	  void *data, uint32_t /* data_size */)
{
	union ipfrag_key *fkey = data;
	struct ipfrag_pkt_data *pd;
	struct pq_desc *pkt;
	uint32_t klen;
	int h = fragdata_hash(fkey, &klen);

	if (h == -1) {
		printf("signal: wrong pkt metadata\n");
		return;
	}

	hlist_for_each_entry(pd, &hfraglist[h], hlist) {
		if (!memcmp(fkey, &pd->key, klen)) {
			pkt = (struct pq_desc *)(pd) - 1;

			pq_tx(ctx, 0, pkt);
			// XXX free elem
			return;
		}
	}
	printf("signal: no data found for this key\n");
}


int
ipfrag_init(const char *iface, struct bpf_object *oprg)
{
	/* create veth, will tx packets from umem to ipfrag-in */
	if (veth_create("ipfrag-in", "ipfrag-out") < 0)
		return -1;

	struct pq_cfg phc = {
		.xsks_map = "xsks_map",
		.signal_map = "ip_frag_signal",
		.timeout_ms = 1500,
		.read_pkt_cb = read_pkt_cb,
		.timeout_pkt_cb = timeout_pkt_cb,
		.signal_cb = signal_cb,
		.pkt_cb_user_size = sizeof (struct ipfrag_pkt_data),
	};
	strcpy(phc.rx_iface, iface);
	strcpy(phc.tx_iface, "ipfrag-in");
	pq_ctx = pq_ctx_create(&phc, oprg);
	if (pq_ctx == NULL)
		return 1;

	return 0;
}

int
ipfrag_load(struct bpf_object *oprg)
{
	struct bpf_program *prg;
	struct bpf_link *link;
	struct bpf_map *m;
	const struct pq_cfg *cfg = pq_cfg(pq_ctx);

	if (pq_ctx_load(pq_ctx) < 0)
		return -1;

	/* fill 'ip_frag_out_dev' with the ifindex of our output device  */
	m = bpf_object__find_map_by_name(oprg, "ip_frag_out_dev");
	if (m == NULL) {
		printf("cannot find map 'ip_frag_out_dev'\n");
		return -1;
	}
	uint32_t key = 0;
	int iface_idx = if_nametoindex(cfg->rx_iface);
	bpf_map__update_elem(m, &key, sizeof (key),
			     &iface_idx, sizeof (iface_idx), 0);

	/* load the same bpf program on ipfrag-out */
	prg = bpf_object__find_program_by_name(oprg, "xdp_ipfrag_entry");
	if (prg == NULL) {
		printf("cannot find function 'xdp_ipfrag_entry'\n");
		return -1;
	}
	iface_idx = if_nametoindex("ipfrag-out");
	link = bpf_program__attach_xdp(prg, iface_idx);
	if (link == NULL) {
		printf("failed to attach program\n");
		return -1;
	}

	return 0;
}

void
ipfrag_release(void)
{
	pq_ctx_release(pq_ctx);
}
