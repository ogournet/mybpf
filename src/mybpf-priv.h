/* SPDX-License-Identifier: AGPL-3.0-or-later */

#pragma once

#include <stdint.h>

#ifndef min
# define min(A, B) ((A) > (B) ? (B) : (A))
#endif
#ifndef max
# define max(A, B) ((A) > (B) ? (A) : (B))
#endif

/*
 * container_of - cast a member of a structure out to the containing structure
 *
 * @ptr:	the pointer to the member.
 * @type:	the type of the container struct this is embedded in.
 * @member:	the name of the member within the struct.
 *
 */
#ifndef container_of
# define container_of(ptr, type, member) ({			\
	const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
	(type *)( (char *)__mptr - offsetof(type,member) );})
#endif
#ifndef const_container_of
# define const_container_of(ptr, type, member) ({			\
	const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
	(const type *)( (char *)__mptr - offsetof(type,member) );})
#endif


struct bpf_object;
struct gp_xsk_umem;
struct gp_xsk_socket;
struct pq_ctx;

/* a packet descriptor, hold in AF_XDP's umem */
struct pq_desc {
	uint8_t *data;		// pointer to umem
	uint32_t len;		// packet len
	time_t alloc_time;	// in seconds
	uint8_t user_data[];	// of pkt_cb_user_size
};

struct pq_cfg
{
	char rx_iface[128];
	char tx_iface[128];	// can be unset or the same as rx_iface
	char xsks_map[32];
	char signal_map[32];
	time_t timeout_ms;

	void (*read_pkt_cb)(struct pq_ctx *ctx, void *uctx, struct pq_desc *pkt);
	void (*timeout_pkt_cb)(struct pq_ctx *ctx, void *uctx, struct pq_desc *pkt);
	void (*signal_cb)(struct pq_ctx *ctx, void *uctx, void *data, uint32_t data_size);
	void *uctx;
	uint32_t pkt_cb_user_size;
};


/* global */
extern struct ev_loop *loop;

/* pkthold.c */
void pq_tx(struct pq_ctx *ctx, int queue_idx, const struct pq_desc *pkt);
struct pq_ctx *pq_ctx_create(struct pq_cfg *cfg, struct bpf_object *oprg);
int pq_ctx_load(struct pq_ctx *ctx);
void pq_ctx_release(struct pq_ctx *ctx);

/* ipfrag.c */
int ipfrag_init(const char *iface, struct bpf_object *oprg);
int ipfrag_load(void);
void ipfrag_release(void);

/* ethtool.c */
int xsk_get_cur_queues(const char *ifname, uint32_t *rx, uint32_t *tx);
