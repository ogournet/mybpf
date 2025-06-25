/* SPDX-License-Identifier: AGPL-3.0-or-later */

#define _GNU_SOURCE

#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/btf.h>
#include <linux/btf.h>

#include "mybpf-priv.h"
#include "cgn.h"
#include "bpf/lib/cgn-def.h"
#include "bpf/lib/flow-def.h"


struct cgn_ctx
{
	struct cgn_cfg c;
	struct bpf_map *block_map;
	struct bpf_map *free_block_map;
	struct bpf_map *user_map;
	struct bpf_map *flow_map;
	uint32_t ipblock_n;
	uint32_t block_count;
	uint32_t block_size;
	int bcpu_n;
	int block_msize;
};


struct init_var_set
{
	const char *name;
	uint8_t type;		/* 1:u32, 2:u64 */
	const void *value;
};

static void
_set_const_var(struct bpf_object *obj, const struct init_var_set *consts)
{
	struct bpf_map *map;
	void *rodata;
	struct btf *btf;
	const struct btf_type *sec;
	struct btf_var_secinfo *secinfo;
	int sec_id, i, j;
	int set = 0, to_be_set = 0;

	/* this open() subskeleton is only here to retrieve map's mmap address
	 * libbpf doesn't provide other way to get this address */
	struct bpf_map_skeleton ms[1] = { {
		.name = ".rodata",
		.map = &map,
		.mmaped = &rodata,
	} };
	struct bpf_object_subskeleton ss = {
		.sz = sizeof (struct bpf_object_subskeleton),
		.obj = obj,
		.map_cnt = 1,
		.map_skel_sz = sizeof (struct bpf_map_skeleton),
		.maps = ms,
	};
	if (bpf_object__open_subskeleton(&ss) < 0) {
		printf("cannot open subskeleton!!!\n");
		return;
	}

	/* now use btf info to find this variable */
	btf = bpf_object__btf(obj);
	if (btf == NULL)
		return;

	/* get secdata id */
	sec_id = btf__find_by_name(btf, ".rodata");
	if (sec_id < 0)
		return;

	/* get the actual BTF type from the ID */
	sec = btf__type_by_id(btf, sec_id);
	if (sec == NULL)
		return;

	/* Get all secinfos, each of which will be a global variable */
	secinfo = btf_var_secinfos(sec);
	for (i = 0; i < btf_vlen(sec); i++) {
		const struct btf_type *t = btf__type_by_id(btf, secinfo[i].type);
		const char *name = btf__name_by_offset(btf, t->name_off);
		for (j = 0; consts[j].name != NULL; j++) {
			if (strcmp(name, consts[j].name))
				continue;
			switch (consts[j].type) {
			case 1:
				*((uint32_t *)(rodata + secinfo[i].offset)) =
					*(uint32_t *)consts[j].value;
				++set;
				break;
			case 2:
				*((uint64_t *)(rodata + secinfo[i].offset)) =
					*(uint64_t *)consts[j].value;
				++set;
				break;
			}
		}
		to_be_set = j;
	}

	if (set < to_be_set - 1)
		printf("warn: not all .rodata var set!!! (%d/%d)\n", set, to_be_set);
}


struct cgn_ctx *
cgn_ctx_create(const struct cgn_cfg *bc, struct bpf_object *obj)
{
	struct cgn_ctx *ctx;
	uint64_t icmp_to;
	int i;

	if (!bc->block_size || bc->port_end <= bc->port_start) {
		printf("invalid block_size/port_start/port_end config\n");
		return NULL;
	}

	ctx = calloc(1, sizeof (*ctx));
	ctx->c = *bc;
	ctx->block_count = (bc->port_end - bc->port_start) / bc->block_size;
	if (!ctx->block_count) {
		printf("invalid block_count\n");
		goto err;
	}
	ctx->block_size = bc->block_size;

	/* count number of ip */
	for (i = 0; i < (int)ARRAY_SIZE(bc->addr); i++) {
		if (!addr_len(&bc->addr[i].a))
			break;
		ctx->ipblock_n += 1 << (32 - bc->addr[i].netmask);
	}

	printf("set const var ipbl_n: %d bl_n: %d bl_size: %d flow_max: %d\n",
	       ctx->ipblock_n, ctx->block_count, bc->block_size, bc->flow_max);
	icmp_to = bc->timeout_icmp * 1000000000ULL;
	struct init_var_set consts_var[] = {
		{ .name = "ipbl_n", .type = 1, .value = &ctx->ipblock_n },
		{ .name = "bl_n", .type = 1, .value = &ctx->block_count },
		{ .name = "port_count", .type = 1, .value = &bc->block_size },
		{ .name = "bl_flow_max", .type = 1, .value = &bc->flow_max },
		{ .name = "icmp_timeout", .type = 2, .value = &icmp_to },
		{ NULL },
	};
	_set_const_var(obj, consts_var);

	/* 'allocate' bpf maps */
	ctx->block_map = bpf_object__find_map_by_name(obj, "v4_blocks");
	if (ctx->block_map == NULL)
		goto err;
	if (bpf_map__set_max_entries(ctx->block_map, ctx->ipblock_n) != 0) {
		printf("set v4_blocks.max_entries failed\n");
		goto err;
	}
	ctx->block_msize = sizeof (struct cgn_v4_ipblock) +
		sizeof (struct cgn_v4_block) * ctx->block_count;
	if (bpf_map__set_value_size(ctx->block_map, ctx->block_msize) != 0) {
		printf("set v4_blocks.value_size = %d failed\n", ctx->block_msize);
		goto err;
	}

	ctx->free_block_map = bpf_object__find_map_by_name(obj, "v4_free_blocks");
	if (ctx->free_block_map == NULL)
		goto err;
	if (bpf_map__set_max_entries(ctx->free_block_map, ctx->block_count + 1) != 0) {
		printf("set free_blocks_cnt.max_entries failed\n");
		goto err;
	}
	if (bpf_map__set_value_size(ctx->free_block_map,
				    (ctx->ipblock_n + 3) * sizeof (int)) != 0) {
		printf("set free_blocks_cnt.value_size failed\n");
		goto err;
	}

	ctx->user_map = bpf_object__find_map_by_name(obj, "users");
	ctx->flow_map = bpf_object__find_map_by_name(obj, "flow_port_timeouts");
	if (ctx->flow_map == NULL) {
		printf("cannot find map flow_port_timeouts\n");
		goto err;
	}

	return ctx;

 err:
	free(ctx);
	return NULL;
}


int
cgn_ctx_load(const struct cgn_ctx *ctx)
{
	struct cgn_v4_ipblock *ipbl;
	const size_t fmsize = (ctx->ipblock_n + 3) * sizeof (int);
	int j, k, ip_n;
	uint32_t i, l, ip_addr;
	void *d, *area, *free_area;
	int *free_cnt;

	/* prepare memory to be copied to maps */
	area = calloc(ctx->ipblock_n, ctx->block_msize);
	free_cnt = free_area = malloc(fmsize);

	/* fill blocks */
	for (i = 0, k = 0; i < (int)ARRAY_SIZE(ctx->c.addr); i++) {
		if (!addr_len(&ctx->c.addr[i].a))
			break;

		d = area;
		ip_n = 1 << (32 - ctx->c.addr[i].netmask);
		ip_addr = ntohl(ctx->c.addr[i].a.sin.sin_addr.s_addr);
		for (j = 0; j < ip_n; j++) {
			ipbl = d;
			ipbl->ipbl_idx = k;
			ipbl->fr_idx = k;
			ipbl->cgn_addr = ip_addr;
			ipbl->total = ctx->block_count;
			for (l = 0; l < ctx->block_count; l++) {
				ipbl->b[l].ipbl_idx = k;
				ipbl->b[l].bl_idx = l;
				ipbl->b[l].cgn_port_start =
					ctx->c.port_start + l * ctx->block_size;
				ipbl->b[l].cgn_port_next = ipbl->b[l].cgn_port_start;
			}
			++ip_addr;
			free_cnt[2 + k] = k;
			++k;
			d += ctx->block_msize;
		}
	}
	free_cnt[0] = 0;
	free_cnt[1] = k;

	/* then copy to bpf maps */
	d = area;
	for (i = 0; i < ctx->ipblock_n; i++) {
		bpf_map__update_elem(ctx->block_map, &i, sizeof (i),
				     d, ctx->block_msize, 0);
		d += ctx->block_msize;
	}
	free(area);

	/* on startup, all blocks are unused, so only the first line contains
	 * indexes. */
	i = 0;
	bpf_map__update_elem(ctx->free_block_map, &i, sizeof (i),
			     free_area, fmsize, 0);
	free(free_area);

	/* set flow port timeout */
	for (i = 0; i < 1 << 16; i++) {
		union flow_timeout_config val;

		k = i;
		val.udp = ctx->c.timeout_by_port[i].udp ?: ctx->c.timeout.udp;
		bpf_map__update_elem(ctx->flow_map, &k, sizeof (k), &val, sizeof (val), 0);

		k = (1 << 16) | i;
		val.tcp_synfin = ctx->c.timeout_by_port[i].tcp_synfin ?:
			ctx->c.timeout.tcp_synfin;
		val.tcp_est = ctx->c.timeout_by_port[i].tcp_est ?: ctx->c.timeout.tcp_est;
		bpf_map__update_elem(ctx->flow_map, &k, sizeof (k), &val, sizeof (val), 0);
	}

	return 0;
}


void
cgn_ctx_dump(const struct cgn_ctx *ctx, int /* full */)
{
	size_t bmsize = ctx->block_msize;
	const size_t fmsize = (ctx->ipblock_n + 3) * sizeof (int);
	struct cgn_v4_ipblock *ipbl;
	uint8_t data[bmsize];
	uint32_t fdata[fmsize], *fp;
	char buf[128];
	uint32_t i, j;
	int ret;

	printf("ipblocks (%d):\n", ctx->ipblock_n);
	for (i = 0; i < ctx->ipblock_n; i++) {
		bpf_map__lookup_elem(ctx->block_map, &i, sizeof (i),
				     data, bmsize, 0);
		ipbl = (struct cgn_v4_ipblock *)(data);
		if (!ipbl->used && ipbl->total > 4)
			continue;

		uint32_t ip = htonl(ipbl->cgn_addr);
		printf("  %s: alloc %d/%d next %d\n",
		       inet_ntop(AF_INET, &ip, buf, 128),
		       ipbl->used, ipbl->total, ipbl->next);
	}

	printf("free indexes:\n");
	for (i = 0; i < ctx->block_count + 1; i++) {
		bpf_map__lookup_elem(ctx->free_block_map, &i, sizeof (i),
				     fdata, fmsize, 0);
		fp = fdata;
		if (fp[0] == fp[1])
			continue;

		printf("    [%d] {%d,%d}", i, fp[0], fp[1]);
		for (j = fp[0]; j != fp[1];
		     j = (j + 1) % (ctx->ipblock_n + 1)) {
			printf(" %d", fp[j + 2]);
		}
		printf("\n");
	}

	printf("users:\n");
	struct cgn_user_key *uk = NULL, nuk;
	struct cgn_user u;
	while (!bpf_map__get_next_key(ctx->user_map, uk, &nuk, sizeof (*uk))) {
		uk = &nuk;
		ret = bpf_map__lookup_elem(ctx->user_map, uk, sizeof (*uk),
					   &u, sizeof (u), 0);
		if (ret) {
			printf("lookup err: %d\n", ret);
			break;
		}
		uint32_t addr = ntohl(u.addr.ip4);
		printf("  %s: blocks: %d/%d\n",
		       inet_ntop(AF_INET, &addr, buf, sizeof (buf)),
		       u.block_cur, u.block_n);
	}
}

/*************************************/
/* self-tests */

#include <bpf/bpf.h>
#include <errno.h>
#include <assert.h>

static struct cgn_ctx *test_bctx;


static void
_test1(int fd, struct bpf_test_run_opts *rcfg)
{
	struct cgn_packet *pp = (struct cgn_packet *)rcfg->data_in;
	int i, k;

	/* 4 users */
	for (k = 0; k < 4; k++) {
		/* alloc 4 * 20 = 80 ports */
		for (i = 0; i < 80; i++) {
			pp->src_port++;
			printf("alloc at user[%d]=0x%x port[%d]=%d\n",
			       k, pp->src_addr, i, pp->src_port);
			assert(!bpf_prog_test_run_opts(fd, rcfg));
			if (rcfg->retval) {
				printf("ret %d at user=%d port=%d\n",
				       rcfg->retval, k, i);
				abort();
			}
			printf("allocated port = %d\n", pp->src_port);
		}

		/* cannot alloc more flow */
		pp->src_port++;
		assert(!bpf_prog_test_run_opts(fd, rcfg));
		assert(rcfg->retval == 12);

		pp->src_addr++;
		pp->src_port = 32000;
	}

	/* no more block for 5th user */
	assert(!bpf_prog_test_run_opts(fd, rcfg));
	assert(rcfg->retval == 12);
}

static void
_test2(int fd, struct bpf_test_run_opts *rcfg)
{
	struct cgn_packet *pp = (struct cgn_packet *)rcfg->data_in;
	int i, k;

	/* alloc for 100k users */
	for (k = 0; k < 100000; k++) {
		if (k % 1000 == 0)
			printf("done %d users\n", k);
		/* alloc 40 ports each */
		for (i = 0; i < 40; i++) {
			pp->src_port++;
			assert(!bpf_prog_test_run_opts(fd, rcfg));
			if (rcfg->retval != 0) {
				printf("fails at user %d port %d\n", k, i);
				return;
			}
		}

		pp->src_addr++;
		pp->src_port = 32000;
	}
}

struct test3_arg
{
	int id;
	int fd;
};

static void *
_test3(void *varg)
{
	struct test3_arg *arg = varg;
	struct cgn_packet pp;
	struct xdp_md ctx_in = {
		.data_end = sizeof (pp),
	};
	LIBBPF_OPTS(bpf_test_run_opts, rcfg,
		    .data_in = &pp,
		    .data_size_in = sizeof (pp),
		    .ctx_in = &ctx_in,
		    .ctx_size_in = sizeof (ctx_in),
		    .repeat = 1);
	int i, k;

	printf("start test3: %d\n", arg->id);

	pp.src_addr = 0x0100000a;
	pp.dst_addr = 0x04040408;
	pp.src_port = 13555;
	pp.dst_port = 80;
	pp.from_priv = 1;
	pp.proto = IPPROTO_TCP;
	pp.src_port = 10000 + arg->id * 1000;

	/* alloc for 20k users */
	for (k = 0; k < 2000; k++) {
		if (k % 500 == 0)
			printf("%d: done %d users\n", arg->id, k);
		/* alloc 20 ports each */
		for (i = 0; i < 20; i++) {
			pp.src_port++;
			assert(!bpf_prog_test_run_opts(arg->fd, &rcfg));
			if (rcfg.retval != 0) {
				printf("fails at user %d port %d\n", k, i);
				return NULL;
			}
		}

		pp.src_addr++;
		pp.src_port = 10000 + arg->id * 1000;
	}

	printf("done test3: %d\n", arg->id);

	return NULL;
}


void
cgn_test_init(int test, struct bpf_object *obj)
{
	struct cgn_cfg cfg = {
		.port_start = 1000,
		.port_end = 65535,
		.block_size = 1000,
		.flow_max = 2000,
		.timeout_icmp = 120,
		.timeout.udp = 120,
		.timeout.tcp_synfin = 20,
		.timeout.tcp_est = 600,
	};

	switch (test) {
	case 1:
		cfg.port_start = 30000;
		cfg.port_end = 30320;
		cfg.block_size = 20;
		cfg.flow_max = 20;
		addr_parse_ip("37.127.0.1/32", &cfg.addr[0].a,
			      &cfg.addr[0].netmask, NULL, 1);
		break;

	case 2:
		addr_parse_ip("37.139.0.0/18", &cfg.addr[0].a,
			      &cfg.addr[0].netmask, NULL, 1);
		break;

	case 3:
	case 10:
		addr_parse_ip("37.141.0.0/24", &cfg.addr[0].a,
			      &cfg.addr[0].netmask, NULL, 1);
		break;
	}

	test_bctx = cgn_ctx_create(&cfg, obj);
	assert(test_bctx != NULL);
}

int
cgn_test_start(int test, struct bpf_object *obj)
{
	const char *prgname;
	const int cpu_n = libbpf_num_possible_cpus();
	struct bpf_program *prg;
	uint8_t data_in[2000], data_out[2000];
	struct cgn_packet *pp = (struct cgn_packet *)data_in;
	struct xdp_md ctx_in = {
		.data_end = sizeof (*pp),
	};
	int prg_fd;
	pthread_t pth[cpu_n];
	int i;

	if (cgn_ctx_load(test_bctx) < 0)
		return -1;

	switch (test) {
	case 1 ... 3:
		prgname = "xdp_test_alloc";
		break;
	case 10:
		prgname = "xdp_entry";
		break;
	default:
		printf("test %d not implemented\n", test);
		return -1;
	}

	prg = bpf_object__find_program_by_name(obj, prgname);
	if (prg == NULL) {
		printf("cannot find function '%s'\n", prgname);
		return -1;
	}
	prg_fd = bpf_program__fd(prg);

	pp->src_addr = 0x0100000a;
	pp->dst_addr = 0x08080808;
	pp->src_port = 13555;
	pp->dst_port = 80;
	pp->from_priv = 1;
	pp->proto = IPPROTO_TCP;
	pp->data_end = NULL;
	pp->icmp_err = NULL;

	LIBBPF_OPTS(bpf_test_run_opts, rcfg,
		    .data_in = data_in,
		    .data_out = data_out,
		    .data_size_in = sizeof (*pp),
		    .data_size_out = sizeof (data_out),
		    .ctx_in = &ctx_in,
		    .ctx_size_in = sizeof (ctx_in),
		    .repeat = 1);

	switch (test) {
	default:
	case 1:
		_test1(prg_fd, &rcfg);
		cgn_ctx_dump(test_bctx, 0);
		sleep(2);
		cgn_ctx_dump(test_bctx, 0);
		break;
	case 2:
		_test2(prg_fd, &rcfg);
		break;
	case 3:
		for (i = 0; i < cpu_n; i++) {
			struct test3_arg *a = malloc(sizeof (struct test3_arg));
			a->id = i;
			a->fd = prg_fd;
			pthread_create(&pth[i], NULL, _test3, a);

			cpu_set_t cpuset;
			CPU_ZERO(&cpuset);
			CPU_SET(i, &cpuset);
			pthread_setaffinity_np(pth[i], sizeof(cpu_set_t), &cpuset);
		}

		for (i = 0; i < cpu_n; i++)
			pthread_join(pth[i], NULL);
		break;

	case 10:
		/* nothing here, run the main loop */
		return 1;
	}

	return 0;
}
