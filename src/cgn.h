/* SPDX-License-Identifier: AGPL-3.0-or-later */

#pragma once

#include "lib/addr.h"

/* public ip address ranges to allocate */
struct block_addr_cfg
{
	union addr		a;
	uint32_t		netmask;
};

struct cgn_cfg
{
	struct block_addr_cfg   addr[16];
	uint16_t		port_start;
	uint16_t		port_end;
	uint32_t		block_size;		/* # of port per block */
	uint32_t		bflow_size;		/* # of flow per block */
};


/* block.c */
struct cgn_ctx *cgn_ctx_create(const struct cgn_cfg *bc, struct bpf_object *oprg);
int cgn_ctx_load(const struct cgn_ctx *ctx);
void cgn_ctx_dump(const struct cgn_ctx *ctx, int full);
void cgn_test_init(int test, struct bpf_object *obj);
int cgn_test_start(int test, struct bpf_object *obj);
