/* SPDX-License-Identifier: AGPL-3.0-or-later */

#pragma once

#include "ip.h"

/*
 * ipv4 block allocation.
 * filled by userspace on startup, then exclusively managed by bpf program
 */
struct cgn_v4_block {
	__u64			refcnt;		/* used flow */
	__u64			cgn_port_next;
	__u32			ipbl_idx;	/* idx in map 'blocks' */
	__u16			bl_idx;		/* ipbl->b[@idx] */
	__u16			cgn_port_start;	/* fixed */
} __attribute__((packed));

struct cgn_v4_ipblock {
	__u32			ipbl_idx;
	__u32			fr_idx;		/* idx in map 'v4_free_blocks'  */
	__u32			cgn_addr;	/* cpu order */
	__u32			used;
	__u32			total;
	__u32			next;
	struct cgn_v4_block	b[];		/* 'total' blocks follow */
} __attribute__((packed));


/* global lock for ipv4 block allocation */
struct cgn_v4_block_lock
{
	struct bpf_spin_lock l;
};


/*
 * ipv4 flow
 */
struct cgn_v4_flow_pub_key {
	__u32			cgn_addr;
	__u32			pub_addr;
	__u16			cgn_port;
	__u16			pub_port;
	__u8			proto;
	__u8			_pad[3];
};

struct cgn_v4_flow_pub {
	__u32			priv_addr;
	__u32			cgn_addr;
	__u16			priv_port;
	__u16			cgn_port;
};


struct cgn_v4_flow_priv_key {
	__u32			priv_addr;
	__u32			pub_addr;
	__u16			priv_port;
	__u16			pub_port;
	__u8			proto;
	__u8			_pad[3];
};

struct cgn_v4_flow_priv {
	struct bpf_timer	timer;		/* flow expiration */
	__u64			created;
	__u32			cgn_addr;
	__u16			cgn_port;
	__u16			bl_idx;
	__u32			ipbl_idx;
};

/* todo */
struct cgn_v4_flow_priv_hairpin_key {
	__u32			priv_addr;
	__u16			priv_port;
	__u8			proto;
} __attribute__((packed));

struct cgn_v4_flow_priv_hairpin {
	__u16			cgn_port;
} __attribute__((packed));



/*
 * user, on priv side. ipv4 or ipv6.
 */
#define CGN_USER_IS_V6		0x01

struct cgn_user_key {
	union v4v6addr		addr;
	__u8			flags;
} __attribute__((packed));


struct cgn_user_allocated_blocks {
	__u32			ipbl_idx;
	__u32			bl_idx;
} __attribute__((packed));

#define CGN_USER_BLOCKS_MAX	4

struct cgn_user {
	union v4v6addr		addr;
	struct cgn_user_allocated_blocks block[CGN_USER_BLOCKS_MAX];
	__u8			block_n;
	__u8			block_cur;
	__u16			v6flow_n;
	__u8			flags;
	__u8			_pad[3];
} __attribute__((packed));


/* all address/port in cpu order */
struct cgn_parsed_packet
{
	__u32	src_addr;
	__u32	dst_addr;
	__u16	src_port;
	__u16	dst_port;
	__u8	from_priv;
	__u8	proto;
} __attribute__((packed));
