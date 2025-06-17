/* SPDX-License-Identifier: AGPL-3.0-or-later */

#pragma once

#include <time.h>
#include <linux/bpf.h>
#include <linux/errno.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "flow.h"
#include "cgn-def.h"


/* cfg set from userspace */
const volatile __u32 ipbl_n = 1;	/* # of ip in pool */
const volatile __u32 bl_n = 2;		/* # of blocks per ip */
const volatile __u32 port_count = 3;	/* # ports per block */
const volatile __u32 bl_flow_max = 4;	/* # of allocatable flow per block  */

/* locals */
int hit_bug;


/*
 * user
 */

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct cgn_user_key);
	__type(value, struct cgn_user);
	__uint(max_entries, 120000);
} users SEC(".maps");


static struct cgn_user *
_user_v4_lookup(__u32 addr)
{
	struct cgn_user_key uk = {
		.addr.ip4 = addr,
		.flags = 0,
	};

	return bpf_map_lookup_elem(&users, &uk);
}

static struct cgn_user *
_user_v4_alloc(__u32 addr)
{
	struct cgn_user_key uk = {
		.addr.ip4 = addr,
		.flags = 0,
	};
	struct cgn_user u = {
		.addr.ip4 = addr,
		.flags = 0,
	};
	int ret;

	ret = bpf_map_update_elem(&users, &uk, &u, BPF_NOEXIST);
	if (ret < 0) {
		if (ret == -EEXIST)
			return _user_v4_lookup(addr);
		bpf_printk("cannot allocate user: %d", ret);
		return NULL;
	}

	return _user_v4_lookup(addr);
}

static void
_user_v4_release(struct cgn_user *u)
{
	struct cgn_user_key uk = {
		.addr.ip4 = u->addr.ip4,
		.flags = 0,
	};

	/* bpf_printk("release user %x", u->addr.ip4); */
	bpf_map_delete_elem(&users, &uk);
}


/*
 * ipv4 block
 */

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct cgn_v4_block_lock);
	__uint(max_entries, 1);
} v4_block_lock SEC(".maps");

/* ipv4 allocatable blocks
 * value size and max entries set on startup */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct cgn_v4_ipblock);
} v4_blocks SEC(".maps");

/* store free blocks, as index in 'blocks' map */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
} v4_free_blocks SEC(".maps");


static inline int
_block_lookup(struct cgn_user_allocated_blocks ub,
	      struct cgn_v4_ipblock **out_ipbl,
	      struct cgn_v4_block **out_bl)
{
	struct cgn_v4_ipblock *ipbl;

	ipbl = bpf_map_lookup_elem(&v4_blocks, &ub.ipbl_idx);
	if (ipbl == NULL)
		return -1;

	if (ub.bl_idx >= bl_n)
		return -1;
	*out_ipbl = ipbl;
	*out_bl = &ipbl->b[ub.bl_idx];
	return 0;
}


static inline int
_block_alloc_sub(struct cgn_user *u, __u32 *frd_from, __u32 *frd_to,
		 struct cgn_v4_ipblock **out_ipbl, struct cgn_v4_block **out_bl)
{
	struct cgn_v4_ipblock *ipbl;
	struct cgn_v4_block *bl;
	__u32 ipblock_idx;
	__u32 *fdata;
	__u32 idx, i;

	idx = 0;
	struct bpf_spin_lock *lock = bpf_map_lookup_elem(&v4_block_lock, &idx);
	if (lock == NULL)
		goto bug;

	bpf_spin_lock(lock);

	/* re-check if not empty, under lock */
	if (frd_from[0] == frd_from[1]) {
		bpf_spin_unlock(lock);
		return 1;
	}

	/* move from v4_free_block[i]... (inc begin index) */
	if (frd_from[0] > ipbl_n)
		goto bug_unlock;
	ipblock_idx = frd_from[frd_from[0] + 2];
	if (++frd_from[0] == ipbl_n + 1)
		frd_from[0] = 0;

	/* ... to v4_free_block[i + 1] (inc end index) */
	if (frd_to[1] > ipbl_n)
		goto bug_unlock;
	frd_to[frd_to[1] + 2] = ipblock_idx;
	if (++frd_to[1] == ipbl_n + 1)
		frd_to[1] = 0;

	bpf_spin_unlock(lock);

	/* get a block from this ipblock */
	ipbl = bpf_map_lookup_elem(&v4_blocks, &ipblock_idx);
	if (ipbl == NULL)
		goto bug;
	idx = ipbl->next;
	for (int i = 0; i < bl_n; i++) {
		if (idx >= bl_n)
			goto bug;
		bl = &ipbl->b[idx];
		if (!bl->refcnt)
			break;
		++idx;
		idx %= bl_n;
	}

	/* assign to user */
	__u32 block_n = u->block_n;
	if (block_n >= CGN_USER_BLOCKS_MAX)
		goto bug;
	u->block[block_n].ipbl_idx = ipblock_idx;
	u->block[block_n].bl_idx = idx;
	++u->block_n;

	++idx;
	idx %= bl_n;
	ipbl->next = idx;
	ipbl->used++;

	*out_ipbl = ipbl;
	*out_bl = bl;

	return 0;

 bug_unlock:
	bpf_spin_unlock(lock);
 bug:
	bpf_printk("_block_alloc_sub bug!");
	hit_bug = 1;
	return -2;
}


static inline int
_block_alloc(struct cgn_user *u, struct cgn_v4_ipblock **out_ipbl,
	     struct cgn_v4_block **out_bl)
{
	__u32 *frd_from, *frd_to;
	__u32 idx, i;
	int ret;

	if (u->block_n >= CGN_USER_BLOCKS_MAX)
		return -1;

	idx = 0;
	frd_from = bpf_map_lookup_elem(&v4_free_blocks, &idx);
	if (frd_from == NULL)
		goto bug;

	/* get the least used ipblock */
	for (i = 0; i < bl_n; i++) {
		idx = i + 1;
		frd_to = bpf_map_lookup_elem(&v4_free_blocks, &idx);
		if (frd_to == NULL)
			goto bug;
		if (frd_from[0] != frd_from[1]) {
			ret = _block_alloc_sub(u, frd_from, frd_to, out_ipbl, out_bl);
			if (ret <= 0)
				return ret;
		}

		frd_from = frd_to;
	}

	/* nothing left... */
	return -1;

 bug:
	bpf_printk("_block_alloc bug!");
	hit_bug = 1;
	return -2;
}

static inline void
_block_release(struct cgn_user *u, struct cgn_v4_ipblock *ipbl, struct cgn_v4_block *bl)
{
	__u32 i, idx, block_n;
	__u32 *frd_from, *frd_to;
	__u32 idx_to_move = ~0, ipbl_fr_idx;
	__u32 l_ipbl_n;

	idx = ipbl->used;
	frd_from = bpf_map_lookup_elem(&v4_free_blocks, &idx);
	--idx;
	frd_to = bpf_map_lookup_elem(&v4_free_blocks, &idx);
	if (frd_from == NULL || frd_to == NULL)
		goto bug;

	l_ipbl_n = ipbl_n;

	/* take lock to update v4_free_block */
	idx = 0;
	struct bpf_spin_lock *lock = bpf_map_lookup_elem(&v4_block_lock, &idx);
	if (lock == NULL)
		goto bug;

	bpf_spin_lock(lock);

	/* move us from v4_free_block[i] ... */
	if (ipbl->fr_idx != frd_from[0]) {
		if (frd_from[0] > l_ipbl_n || ipbl->fr_idx > l_ipbl_n)
			goto bug_unlock;
		idx_to_move = frd_from[frd_from[0] + 2];
		ipbl_fr_idx = ipbl->fr_idx;
		frd_from[ipbl->fr_idx + 2] = idx_to_move;
	}
	if (++frd_from[0] == l_ipbl_n + 1)
		frd_from[0] = 0;

	/* ... to v4_free_block[i - 1] */
	--ipbl->used;
	ipbl->fr_idx = frd_to[1];
	if (frd_to[1] > l_ipbl_n)
		goto bug_unlock;
	frd_to[frd_to[1] + 2] = bl->ipbl_idx;
	if (++frd_to[1] == l_ipbl_n + 1)
		frd_to[1] = 0;

	bpf_spin_unlock(lock);

	if (idx_to_move != ~0) {
		struct cgn_v4_ipblock *ipbl_to_move;
		ipbl_to_move = bpf_map_lookup_elem(&v4_blocks, &idx_to_move);
		if (ipbl_to_move == NULL)
			goto bug;
		if (ipbl_fr_idx == ipbl_to_move->fr_idx)
			ipbl_to_move->fr_idx = ipbl->fr_idx;
	}

	/* release in user's allocated block */
	block_n = u->block_n;
	if (block_n < 1 || block_n > CGN_USER_BLOCKS_MAX)
		goto bug;
	for (i = 0 ; i < block_n - 1; i++) {
		if (u->block[i].ipbl_idx == ipbl->ipbl_idx &&
		    u->block[i].bl_idx == bl->bl_idx)
			break;
	}
	for ( ; i < block_n - 1; i++)
		u->block[i] = u->block[i + 1];
	--u->block_n;

	if (!u->block_n && !u->v6flow_n)
		_user_v4_release(u);

	return;

 bug_unlock:
	bpf_spin_unlock(lock);
 bug:
	bpf_printk("_block_release bug");
	hit_bug = 1;
}


/*
 * ipv4 flows
 */

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct cgn_v4_flow_priv_key);
	__type(value, struct cgn_v4_flow_priv);
	__uint(max_entries, 1000000);
} v4_priv_flows SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct cgn_v4_flow_pub_key);
	__type(value, struct cgn_v4_flow_pub);
	__uint(max_entries, 1000000);
} v4_pub_flows SEC(".maps");



static inline void
_flow_release(struct cgn_v4_flow_priv_key *priv_k, struct cgn_v4_flow_priv *f)
{
	struct cgn_v4_ipblock *ipbl;
	struct cgn_v4_block *bl;
	struct cgn_user *u;
	__u32 idx;

	idx = f->ipbl_idx;
	ipbl = bpf_map_lookup_elem(&v4_blocks, &idx);
	if (ipbl == NULL)
		goto bug;

	idx = f->bl_idx;
	if (idx >= bl_n)
		goto bug;
	bl = &ipbl->b[idx];
	if (!--bl->refcnt) {
		struct cgn_user_key u_k = {
			.addr.ip4 = priv_k->priv_addr,
			.flags = 0,
		};
		u = bpf_map_lookup_elem(&users, &u_k);
		if (u == NULL)
			goto bug;
		_block_release(u, ipbl, bl);
	}

	bpf_map_delete_elem(&v4_priv_flows, priv_k);

	struct cgn_v4_flow_pub_key pub_k = {
		.cgn_addr = f->cgn_addr,
		.pub_addr = priv_k->pub_addr,
		.cgn_port = f->cgn_port,
		.pub_port = priv_k->pub_port,
		.proto = priv_k->proto,
	};
	bpf_map_delete_elem(&v4_pub_flows, &pub_k);

	return;

 bug:
	bpf_printk("_flow_release bug, idx: %d", idx);
	hit_bug = 1;
}

static int
_flow_timer_cb(void *_map, struct cgn_v4_flow_priv_key *key,
	       struct cgn_v4_flow_priv *f)
{
	/* bpf_printk("flow_timer_cb"); */
	_flow_release(key, f);
	return 0;
}

/* get next cgn port */
static inline __u16
_block_get_next_port(struct cgn_v4_block *bl)
{
	if (__sync_fetch_and_add(&bl->refcnt, 1) >= bl_flow_max) {
		__sync_fetch_and_sub(&bl->refcnt, 1);
		return 0;
	}
	__u16 port = __sync_fetch_and_add(&bl->cgn_port_next, 1);
	return bl->cgn_port_start + (port % port_count);
}

static inline struct cgn_v4_flow_priv *
_flow_alloc(struct cgn_user *u, const struct cgn_packet *pp)
{
	struct cgn_v4_ipblock *ipbl;
	struct cgn_v4_block *bl;
	__u8 block_n = u->block_n;
	__u16 cgn_port = 0;
	int ret, i;

	if (block_n > 0) {
		if (block_n >= CGN_USER_BLOCKS_MAX)
			block_n = CGN_USER_BLOCKS_MAX;
		/* XXX check hairpin */

		/* try with lastest block used to allocate block first */
		if (_block_lookup(u->block[block_n - 1], &ipbl, &bl) < 0)
			return NULL;
		cgn_port = _block_get_next_port(bl);

		/* if no space left, check in other allocated blocks */
		for (i = 0; !cgn_port && i < block_n - 1; i++) {
			if (_block_lookup(u->block[i], &ipbl, &bl) < 0)
				return NULL;
			cgn_port = _block_get_next_port(bl);
			if (cgn_port) {
				/* got port. move this block to the last
				 * place, so next alloc will use it first */
				for ( ; i < block_n - 1; i++) {
					struct cgn_user_allocated_blocks tmp;
					tmp = u->block[i];
					u->block[i] = u->block[i + 1];
					u->block[i + 1] = tmp;
				}
			}
		}
	}

	/* last resort, allocate a new block */
	if (!cgn_port) {
		if (_block_alloc(u, &ipbl, &bl) < 0)
			return NULL;
		cgn_port = _block_get_next_port(bl);
		if (!cgn_port)
			return NULL;
	}
	/* bpf_printk("%d: user 0x%x get port: %d newrefc: %d ", */
	/* 	   bpf_get_smp_processor_id(), bpf_ntohl(u->addr.ip4), */
	/* 	   cgn_port, bl->refcnt); */

	/* add pub entry */
	struct cgn_v4_flow_pub_key pub_k = {
		.cgn_addr = ipbl->cgn_addr,
		.pub_addr = pp->dst_addr,
		.cgn_port = cgn_port,
		.pub_port = pp->dst_port,
		.proto = pp->proto,
	};
	struct cgn_v4_flow_pub pf = {
		.priv_addr = pp->src_addr,
		.cgn_addr = ipbl->cgn_addr,
		.priv_port = pp->src_port,
		.cgn_port = cgn_port,
	};
	ret = bpf_map_update_elem(&v4_pub_flows, &pub_k, &pf, BPF_NOEXIST);
	if (ret) {
		bpf_printk("cannot insert in v4_pub_flows: %d", ret);
		return NULL;
	}

	/* add priv entry */
	struct cgn_v4_flow_priv_key priv_k = {
		.priv_addr = pp->src_addr,
		.pub_addr = pp->dst_addr,
		.priv_port = pp->src_port,
		.pub_port = pp->dst_port,
		.proto = pp->proto,
	};
	struct cgn_v4_flow_priv ppf = {
		.created = bpf_ktime_get_ns(),
		.cgn_addr = ipbl->cgn_addr,
		.cgn_port = cgn_port,
		.bl_idx = bl->bl_idx,
		.ipbl_idx = ipbl->ipbl_idx,
	};
	ret = bpf_map_update_elem(&v4_priv_flows, &priv_k, &ppf, BPF_NOEXIST);
	if (ret) {
		bpf_printk("cannot insert in v4_priv_flows: %d", ret);
	}

	/* need to retrieve it from map to initialize bpf timer */
	struct cgn_v4_flow_priv *f = bpf_map_lookup_elem(&v4_priv_flows, &priv_k);
	if (f == NULL) {
		bpf_printk("bug: unable to retrieve just inserted v4_priv_flows");
		goto err;
	}

	ret = bpf_timer_init(&f->timer, &v4_priv_flows, CLOCK_MONOTONIC);
	if (ret) {
		bpf_printk("bug: cannot init timer: %d", ret);
		goto err;
	}
	ret = bpf_timer_set_callback(&f->timer, _flow_timer_cb);
	if (ret)
		goto err;

	return f;

 err:
	bpf_printk("error setting up flow");
	bpf_map_delete_elem(&v4_priv_flows, &priv_k);
	bpf_map_delete_elem(&v4_pub_flows, &pub_k);
	return NULL;
}


static struct cgn_v4_flow_pub *
_flow_v4_lookup_pub(const struct cgn_packet *pp)
{
	struct cgn_v4_flow_pub_key pub_k = {
		.cgn_addr = pp->dst_addr,
		.pub_addr = pp->src_addr,
		.cgn_port = pp->dst_port,
		.pub_port = pp->src_port,
		.proto = pp->proto,
	};

	return bpf_map_lookup_elem(&v4_pub_flows, &pub_k);
}

static struct cgn_v4_flow_priv *
_flow_v4_lookup_priv(const struct cgn_packet *pp)
{
	struct cgn_v4_flow_priv_key priv_k = {
		.priv_addr = pp->src_addr,
		.pub_addr = pp->dst_addr,
		.priv_port = pp->src_port,
		.pub_port = pp->dst_port,
		.proto = pp->proto,
	};

	return bpf_map_lookup_elem(&v4_priv_flows, &priv_k);
}



/*
 * packet from private: may create user/flow,
 * and update src addr/port.
 *
 * return:
 *    0: ok
 *   10: no associated flow
 *   11: user alloc error
 *   12: flow alloc error
 */
static inline __attribute__((always_inline)) int
cgn_flow_handle_priv(struct cgn_packet *cp)
{
	struct cgn_user *u;
	struct cgn_v4_flow_priv *f;
	int ret;

	u = _user_v4_lookup(cp->src_addr);
	if (u == NULL) {
		if (cp->icmp_err != NULL)
			return 10;
		u = _user_v4_alloc(cp->src_addr);
		if (u == NULL)
			return 11;
	}

	f = _flow_v4_lookup_priv(cp);
	if (f == NULL) {
		if (cp->icmp_err != NULL)
			return 10;
		f = _flow_alloc(u, cp);
		if (f == NULL)
			return 12;

	} else if (cp->proto == IPPROTO_TCP) {
		if (flow_update_priv_tcp_state(cp->tcp_flags, &f->proto_state)) {
			struct cgn_v4_flow_pub_key pub_k = {
				.cgn_addr = f->cgn_addr,
				.pub_addr = cp->dst_addr,
				.cgn_port = f->cgn_port,
				.pub_port = cp->dst_port,
				.proto = cp->proto,
			};
			struct cgn_v4_flow_pub *pub_f;
			pub_f = bpf_map_lookup_elem(&v4_pub_flows, &pub_k);
			if (pub_f != NULL) {
				pub_f->proto_state = f->proto_state;
			}
		}
	}
	/* XXX may apply policy or sorts of things on user */

	cp->src_addr = f->cgn_addr;
	cp->src_port = f->cgn_port;

	/* start or refresh flow timeout */
	__u64 to = flow_timeout_ns(cp->proto, cp->dst_port, f->proto_state);
	ret = bpf_timer_start(&f->timer, to, 0);
	if (ret) {
		bpf_printk("cannot (re)start timer??? (val=%ld)", to);
		struct cgn_v4_flow_priv_key priv_k = {
			.priv_addr = cp->src_addr,
			.pub_addr = cp->dst_addr,
			.priv_port = cp->src_port,
			.pub_port = cp->dst_port,
			.proto = cp->proto,
		};
		_flow_release(&priv_k, f);
		return 12;
	}

	return 0;
}

/*
 * packet from public: check if a flow exists;
 *  if there is, update dst addr/port,
 *  if not, drop packet.
 *
 * return:
 *     0: ok
 *    10: no associated flow
 */
static inline __attribute__((always_inline)) int
cgn_flow_handle_pub(struct cgn_packet *cp)
{
	struct cgn_user *u;
	struct cgn_v4_flow_pub *f;

	f = _flow_v4_lookup_pub(cp);
	if (f == NULL)
		return 10;

	if (cp->proto == IPPROTO_TCP) {
		if (flow_update_pub_tcp_state(cp->tcp_flags, &f->proto_state)) {
			struct cgn_v4_flow_priv_key priv_k = {
				.priv_addr = f->priv_addr,
				.pub_addr = cp->src_addr,
				.priv_port = f->priv_port,
				.pub_port = cp->src_port,
				.proto = cp->proto,
			};
			struct cgn_v4_flow_priv *priv_f;
			priv_f = bpf_map_lookup_elem(&v4_priv_flows, &priv_k);
			if (priv_f != NULL)
				priv_f->proto_state = f->proto_state;
		}
	}

	u = _user_v4_lookup(f->priv_addr);
	if (f == NULL) {
		/* is a bug */
		return 10;
	}
	/* XXX may apply policy or sorts of things on user */

	cp->dst_addr = f->priv_addr;
	cp->dst_port = f->priv_port;

	return 0;
}



/*
 * ipv4 packet manipulation
 */


static int
cgn_pkt_rewrite_src(struct cgn_packet *cp, struct iphdr *ip4h, struct udphdr *udp,
		    __u32 addr, __u16 port)
{
	struct tcphdr *tcp;
	struct icmphdr *icmp;
	__u32 sum;

	addr = bpf_htonl(addr);
	port = bpf_htons(port);

	/* update l4 checksum */
	switch (cp->proto) {
	case IPPROTO_UDP:
		if (udp->check) {
			sum = csum_diff32(0, ip4h->saddr, addr);
			sum = csum_diff16(sum, udp->source, port);
			__u16 nsum = csum_replace(udp->check, sum);
			if (nsum == 0)
				nsum = 0xffff;
			udp->check = nsum;
		}
		udp->source = port;
		break;

	case IPPROTO_TCP:
		tcp = (struct tcphdr *)udp;
		if ((void *)(tcp + 1) > cp->data_end)
			return 1;
		sum = csum_diff32(0, ip4h->saddr, addr);
		sum = csum_diff16(sum, tcp->source, port);
		tcp->check = csum_replace(tcp->check, sum);
		tcp->source = port;
		break;

	case IPPROTO_ICMP:
		icmp = (struct icmphdr *)udp;
		sum = csum_diff16(0, icmp->un.echo.id, port);
		icmp->checksum = csum_replace(icmp->checksum, sum);
		icmp->un.echo.id = port;
		break;
	}

	/* decrement ttl and update l3 checksum */
	sum = csum_diff32(0, ip4h->saddr, addr);
	ip4h->saddr = addr;
	if (cp->icmp_err == NULL) {
		--sum;
		--ip4h->ttl;
		ip4h->check = csum_replace(ip4h->check, sum);
	} else {
		__u16 old_ip4h_csum = ip4h->check;
		ip4h->check = csum_replace(ip4h->check, sum);
		if (cp->proto != IPPROTO_ICMP) {
			sum = csum_diff16(0, old_ip4h_csum, ip4h->check);
			cp->icmp_err->checksum = csum_replace(cp->icmp_err->checksum, sum);
		}
	}

	return 0;
}


static int
cgn_pkt_rewrite_dst(struct cgn_packet *cp, struct iphdr *ip4h, struct udphdr *udp,
		    __u32 addr, __u16 port)
{
	struct tcphdr *tcp;
	struct icmphdr *icmp;
	__u32 sum;

	addr = bpf_htonl(addr);
	port = bpf_htons(port);

	/* update l4 checksum */
	switch (cp->proto) {
	case IPPROTO_UDP:
		if (udp->check) {
			sum = csum_diff32(0, ip4h->daddr, addr);
			sum = csum_diff16(sum, udp->dest, port);
			__u16 nsum = csum_replace(udp->check, sum);
			if (nsum == 0)
				nsum = 0xffff;
			udp->check = nsum;
		}
		udp->dest = port;
		break;

	case IPPROTO_TCP:
		tcp = (struct tcphdr *)udp;
		if ((void *)(tcp + 1) > cp->data_end)
			return 1;
		sum = csum_diff32(0, ip4h->daddr, addr);
		sum = csum_diff16(sum, tcp->dest, port);
		tcp->check = csum_replace(tcp->check, sum);
		tcp->dest = port;
		break;

	case IPPROTO_ICMP:
		icmp = (struct icmphdr *)udp;
		sum = csum_diff16(0, icmp->un.echo.id, port);
		icmp->checksum = csum_replace(icmp->checksum, sum);
		icmp->un.echo.id = port;
		break;
	}

	/* decrement ttl and update l3 checksum */
	sum = csum_diff32(0, ip4h->daddr, addr);
	ip4h->daddr = addr;
	if (cp->icmp_err == NULL) {
		--sum;
		--ip4h->ttl;
		ip4h->check = csum_replace(ip4h->check, sum);
	} else {
		__u16 old_ip4h_csum = ip4h->check;
		ip4h->check = csum_replace(ip4h->check, sum);
		if (cp->proto != IPPROTO_ICMP) {
			sum = csum_diff16(0, old_ip4h_csum, ip4h->check);
			cp->icmp_err->checksum = csum_replace(cp->icmp_err->checksum, sum);
		}
	}

	return 0;
}


/*
 * process icmp error's inner ip header
 */
static inline int
_handle_pkt_icmp_error(struct xdp_md *ctx, struct iphdr *outer_ip4h,
		       struct icmphdr *outer_icmp, struct iphdr *ip4h,
		       __u8 from_priv)
{
	void *data_end = (void *)(long)ctx->data_end;
	struct udphdr *udp;
	struct icmphdr *icmp;
	__u32 sum, addr;
	int ret;

	if ((void *)(ip4h + 1) > data_end || ip4h->version != 4)
		return 1;

	/* parse packet with swapped src/dst, in order to be able
	 * to lookup flow */
	struct cgn_packet cp = {
		.data_end = data_end,
		.icmp_err = outer_icmp,
		.proto = ip4h->protocol,
		.src_addr = bpf_ntohl(ip4h->daddr),
		.dst_addr = bpf_ntohl(ip4h->saddr),
	};

	udp = (void *)(ip4h) + ip4h->ihl * 4;
	if ((void *)(udp + 1) > data_end)
		return 1;

	switch (ip4h->protocol) {
	case IPPROTO_UDP:
	case IPPROTO_TCP:
		cp.dst_port = bpf_ntohs(udp->source);
		cp.src_port = bpf_ntohs(udp->dest);
		break;
	case IPPROTO_ICMP:
		icmp = (struct icmphdr *)udp;
		switch (icmp->type) {
		case ICMP_ECHO:
			cp.dst_port = bpf_ntohs(icmp->un.echo.id);
			cp.src_port = 0;
			break;
		case ICMP_ECHOREPLY:
			cp.dst_port = 0;
			cp.src_port = bpf_ntohs(icmp->un.echo.id);
			break;
		default:
			return 2;
		}
		break;
	default:
		return 2;
	}

	/* lookup and process flow, then rewrite inner l3/l4 and outer l3 */
	if (from_priv) {
		ret = cgn_flow_handle_priv(&cp);
		if (ret)
			return ret;
		ret = cgn_pkt_rewrite_dst(&cp, ip4h, udp, cp.src_addr, cp.src_port);
		if (ret)
			return ret;

		addr = bpf_htonl(cp.src_addr);
		sum = csum_diff32(0, outer_ip4h->saddr, addr);
		outer_ip4h->saddr = addr;

	} else {
		ret = cgn_flow_handle_pub(&cp);
		if (ret)
			return ret;
		ret = cgn_pkt_rewrite_src(&cp, ip4h, udp, cp.dst_addr, cp.dst_port);
		if (ret)
			return ret;

		addr = bpf_htonl(cp.dst_addr);
		sum = csum_diff32(0, outer_ip4h->daddr, addr);
		outer_ip4h->daddr = addr;
	}

	--sum;
	--outer_ip4h->ttl;
	outer_ip4h->check = csum_replace(outer_ip4h->check, sum);

	return 0;
}

/*
 * main cgn entry function.
 * parameters:
 *  - ip4h: must already be checked (ihl, version, ttl > 0), and cannot be a fragment
 *  - from_priv: 1 if packet is coming from 'private' side, else 0
 *
 * returns:
 *    0: ok. packet modified
 *    1: invalid packet
 *    2: unsupported protocol/operation
 *   10: no associated flow
 *   11: user alloc error
 *   12: flow alloc error
 */
static int
cgn_pkt_handle(struct xdp_md *ctx, struct iphdr *ip4h, __u8 from_priv)
{
	void *data_end = (void *)(long)ctx->data_end;
	struct udphdr *udp;
	struct tcphdr *tcp;
	struct icmphdr *icmp;
	void *payload;
	int ret;

	struct cgn_packet cp = {
		.data_end = data_end,
		.proto = ip4h->protocol,
		.from_priv = from_priv,
		.src_addr = bpf_ntohl(ip4h->saddr),
		.dst_addr = bpf_ntohl(ip4h->daddr)
	};
	payload = (void *)ip4h + ip4h->ihl * 4;

	/* bpf_printk("priv:%d parse proto: %d dst: %x ihl %d/%d", from_priv, */
	/* 	   cp.proto, ip4h->daddr, ip4h->ihl, ip4h->version); */

	switch (cp.proto) {
	case IPPROTO_UDP:
		udp = payload;
		if ((void *)(udp + 1) > data_end)
			return 1;
		cp.src_port = bpf_ntohs(udp->source);
		cp.dst_port = bpf_ntohs(udp->dest);
		break;
	case IPPROTO_TCP:
		tcp = payload;
		if ((void *)(tcp + 1) > data_end)
			return 1;
		cp.src_port = bpf_ntohs(tcp->source);
		cp.dst_port = bpf_ntohs(tcp->dest);
		cp.tcp_flags = ((union tcp_word_hdr *)(tcp))->words[3];
		break;
	case IPPROTO_ICMP:
		icmp = payload;
		if ((void *)(icmp + 1) > data_end)
			return 1;
		switch (icmp->type) {
		case ICMP_ECHO:
			cp.src_port = bpf_ntohs(icmp->un.echo.id);
			cp.dst_port = 0;
			break;
		case ICMP_ECHOREPLY:
			cp.src_port = 0;
			cp.dst_port = bpf_ntohs(icmp->un.echo.id);
			break;
		case ICMP_DEST_UNREACH:
		case ICMP_TIME_EXCEEDED:
			return _handle_pkt_icmp_error(ctx, ip4h, icmp,
						      (struct iphdr *)(icmp + 1),
						      from_priv);
		default:
			return 2;
		}
		break;
	default:
		return 2;
	}

	if (from_priv) {
		ret = cgn_flow_handle_priv(&cp);
		if (ret)
			return ret;
		ret = cgn_pkt_rewrite_src(&cp, ip4h, udp, cp.src_addr, cp.src_port);
	} else {
		ret = cgn_flow_handle_pub(&cp);
		if (ret)
			return ret;
		ret = cgn_pkt_rewrite_dst(&cp, ip4h, udp, cp.dst_addr, cp.dst_port);
	}
	return ret;
}
