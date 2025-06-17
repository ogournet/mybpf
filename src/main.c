/* SPDX-License-Identifier: AGPL-3.0-or-later */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/resource.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <errno.h>
#include <ev.h>
#include <net/ethernet.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/btf.h>
#include <linux/btf.h>

#include "bpf/lib/test_shared.h"

#include "lib/addr.h"
#include "cgn.h"
#include "mybpf-priv.h"


enum prg_type {
	PRG_PASS,
	PRG_MAP_RESIZE,
	PRG_CPUMAP,
	PRG_BPF_VAR,
	PRG_SIGNAL,
	PRG_PKT_QUEUE,
	PRG_IPFRAG,
	PRG_CGN_TEST,
	PRG_IP6FW_TEST,

	PRG_MAX,
};

/* globals */
struct ev_loop *loop;

/* locals */
static int debug;
static struct ev_signal ev_sigint;
static int sigint;
static struct bpf_object *bo;
static struct pq_ctx *pq_ctx;

/*
 * change current network namespace for this process.
 * assume iproute2 did create namespaces, with file in /run/netns
 */
static void
change_network_ns(const char *nsname)
{
	char nspath[64];
	int fd;

	snprintf(nspath, sizeof(nspath), "/run/netns/%s", nsname);

	if (unshare(CLONE_NEWNET) < 0) {
		perror("unshare");
		return;
	}

	fd = open(nspath, O_RDONLY, 0);
	if (fd < 0) {
		printf("nspath: %m\n");
	} else {
		if (setns(fd, CLONE_NEWNET) < 0)
			printf("setns{%s}: %m", nspath);
	}
	close(fd);
}


static void
sigint_hdl(struct ev_loop *, struct ev_signal *, int)
{
	if (++sigint > 2) {
		fprintf(stderr, "ctrl-C pressed too much, dying hard\n");
		exit(1);
	}

	if (sigint == 1) {
		fprintf(stderr, "shutting down\n");
		ev_break(loop, EVBREAK_ONE);
	}
}


static int
libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (debug || level != LIBBPF_DEBUG)
		return vfprintf(stderr, format, args);
	return 0;
}


/*************************************/
/* 'map_resize' program */

/* timer that trigger every second */
static void
poll_cb(struct ev_loop *, struct ev_timer *, int /* revents */)
{
	uint32_t n_cpu = libbpf_num_possible_cpus();
	uint64_t val[n_cpu];
	struct bpf_map *m;

	m = bpf_object__find_map_by_name(bo, "xdp_stats_map");
	if (m == NULL)
		return;

	for (uint32_t j = 0; j < bpf_map__max_entries(m); j++) {
		bpf_map__lookup_elem(m, &j, sizeof (j), val, sizeof (val), 0);
		for (uint32_t i = 0; i < n_cpu; i++) {
			if (val[i])
				printf(" cpu %d queue %d: %ld pkt\n", i, j, val[i]);
		}
	}

	uint8_t data[160];
	uint32_t idx = 669;
	m = bpf_object__find_map_by_name(bo, "resize_hash_map");
	int r = bpf_map__lookup_elem(m, &idx, sizeof (idx), data, sizeof (data), 0);
	if (!r) {
		struct basic *bb = (struct basic *)data;
		printf("a1: %lld a2: %lld a3: %lld tab[15]: %lld\n",
		       bb->a1, bb->a2, bb->a3, bb->tab[15]);
	}
}


/*************************************/
/* 'bpf_var' program */


/*
 * this is an example of how to modify constants in .rodata section,
 * without using generated skeleton from libbpf.
 *
 * they can be modified *only* before program is loaded into kernel.
 * it should be the same for variables in .data or .bss sections.
 */
static void
modify_variable_in_rodata(struct bpf_object *obj)
{
	struct bpf_map *map;
	void *rodata;

	/* this open() subskeleton is only here to retrieve map's mmap address
	 * libbpf doesn't provide other way to get this address */
	struct bpf_map_skeleton ms[1] = { {
		.name = "bpf_var.rodata",
		.map = &map,
		.mmaped = &rodata,
	} };
	struct bpf_object_subskeleton ss = {
		.sz = sizeof (struct bpf_object_subskeleton),
		.obj = bo,
		.map_cnt = 1,
		.map_skel_sz = sizeof (struct bpf_map_skeleton),
		.maps = ms,
	};
	if (bpf_object__open_subskeleton(&ss) < 0) {
		printf("cannot open subskeleton!!!\n");
		return;
	}

	/* now use btf info to find this variable */
	struct btf *btf;
	const struct btf_type *sec;
	struct btf_var_secinfo *secinfo;
	int sec_id, i;

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
		printf("name: %s off:%d size:%d\n", name, secinfo[i].offset, secinfo[i].size);

		if (!strcmp(name, "my_constant")) {
			*((uint32_t *)(rodata + secinfo[i].offset)) = 42;
		}
	}
}


/*************************************/
/* 'signal' program */

static void
signal_cb(struct pq_ctx */* ctx */, void */* uctx */, void *data, uint32_t data_size)
{
	struct mysignal *s = data;

	printf("dsize: %d | a1: %lld a2: %lld a3: %lld a4: %lld a5: %lld\n",
	       data_size, s->a1, s->a2, s->a3, s->a4, s->a5);
}

/*************************************/
/* 'pkt_queue' program */


/*
 * test case: ping on veth1, xdp prog rx on veth2, redirect to AF_XDP,
 * store in umem, then on timeout tx it on veth2.
 *
 * schema:
 *      veth1       <------>      veth2 (in netns)
 *
 * 1.  ping   (TX)   ------>      (RX) xdp prg (bpf_redirect)  --\
 * 2.     /------<     [umem] <-----       AF_XDP           <----/
 * 3.  timeout ---> modify packet, reply to icmp er, swap mac --\
 * 4.     /-- (RX)    <------       (TX)                     <--/
 * 5.  shown on tcpdump
 */

static void
read_pkt_cb(struct pq_ctx */* ctx */, void */* uctx */, struct pq_desc *pkt)
{
	printf("reading xdp frame at %p of %d!!!\n", pkt->data, pkt->len);
}

static void
timeout_pkt_cb(struct pq_ctx *ctx, void */* uctx */, struct pq_desc *pkt)
{
	struct ether_header *eth;
	struct iphdr *ip;
	struct icmphdr *icmp;
	uint8_t buf[ETH_ALEN];
	uint32_t tmp;

	printf("timeout xdp frame at %p of %d!!!\n", pkt->data, pkt->len);
	eth = (struct ether_header *)pkt->data;
	memcpy(buf, eth->ether_dhost, ETH_ALEN);
	memcpy(eth->ether_dhost, eth->ether_shost, ETH_ALEN);
	memcpy(eth->ether_shost, buf, ETH_ALEN);
	ip = (struct iphdr *)(eth + 1);
	tmp = ip->saddr;
	ip->saddr = ip->daddr;
	ip->daddr = tmp;
	icmp = (struct icmphdr *)(ip + 1);
	icmp->type = ICMP_ECHOREPLY;
	icmp->checksum += ICMP_ECHO;

	pq_tx(ctx, 0, pkt);
}

/*************************************/
/* main */

static char iface[4][128] = { "lo", "", "", "" };


static const char *prglist[PRG_MAX] = {
	[PRG_PASS] = "pass",
	[PRG_MAP_RESIZE] = "map_resize",
	[PRG_CPUMAP] = "cpumap",
	[PRG_BPF_VAR] = "bpf_var",
	[PRG_SIGNAL] = "signal",
	[PRG_PKT_QUEUE] = "pkt_queue",
	[PRG_IPFRAG] = "ipfrag",
	[PRG_CGN_TEST] = "cgn_test",
	[PRG_IP6FW_TEST] = "ip6fw_test",
};

static const struct option long_options[] = {
	{ "help", 0, NULL, 'h' },
	{ "debug", 0, NULL, 'd' },
	{ "iface", 1, NULL, 'i' },
	{ "test-id", 1, NULL, 't' },
	{ NULL, 0, NULL, 0 },
};

static void
usage(const char *prgname)
{
	int i;

	printf("usage: %s [options] <program>\n", prgname);
	printf("options are:\n"
	       "  -h  --help            display this help\n"
	       "  -i  --iface           use this/these interface(s) [lo]\n"
	       "  -d  --debug           print more information\n"
	       "  -t  --test-id         start this test-id [1]\n");
	printf("program can be:\n");
	for (i = 0; i < PRG_MAX; i++)
		printf("  %s\n", prglist[i]);

	exit(1);
}

int main(int argc, char **argv)
{
	char filename[128];
	struct bpf_program *prg;
	struct bpf_link *link;
	struct bpf_map *map;
	enum prg_type prgtype;
	ev_timer poll_timer;
	int ret = 9;
	int test_id = 1;
	unsigned iface_idx = 0, i;

	while (1) {
		int c = getopt_long(argc, argv, "hdi:t:", long_options, NULL);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			usage(argv[0]);
			break;
		case 'd':
			debug = 1;
			break;
		case 'i':
			if (iface_idx < ARRAY_SIZE(iface))
				strcpy(iface[iface_idx++], optarg);
			break;
		case 't':
			test_id = atoi(optarg);
			break;
		}
	}

	argc -= optind;
	argv += optind;
	const char *prgname = argc > 0 ? argv[0] : "";

	/* program to load */
	for (prgtype = 0; prgtype < PRG_MAX; prgtype++) {
		if (!strcmp(prglist[prgtype], prgname))
			break;
	}
	if (prgtype == PRG_MAX) {
		printf("cannot find program '%s'\n", prgname);
		return 1;
	}

	printf("running libbpf %s, num cpu: %d, program: %s\n",
	       libbpf_version_string(),
	       libbpf_num_possible_cpus(),
	       prglist[prgtype]);
	libbpf_set_print(libbpf_print_fn);

	/* load bpf program from file to userspace */
	sprintf(filename, "%s.bpf", prglist[prgtype]);
	bo = bpf_object__open_file(filename, NULL);
	if (bo == NULL && errno == ENOENT) {
		sprintf(filename, "build/src/bpf/%s.bpf", prglist[prgtype]);
		bo = bpf_object__open_file(filename, NULL);
	}
	if (bo == NULL) {
		printf("cannot load %s: %m\n", filename);
		return 1;
	}

	printf("%s loaded, contains:\n", filename);
	bpf_object__for_each_program(prg, bo) {
		printf("  - %s\n", bpf_program__name(prg));
	}

	loop = ev_default_loop(0);

	/* bpf loaded, some setup before it goes into kernel */
	switch (prgtype) {
	case PRG_MAP_RESIZE:
		/* resize map before attaching program to kernel */
		map = bpf_object__find_map_by_name(bo, "resize_hash_map");
		if (bpf_map__set_max_entries(map, 4096) != 0)
			printf("set max entries failed\n");
		if (bpf_map__set_value_size(map, 160) != 0)
			printf("set value size failed\n");
		break;

	case PRG_CPUMAP:
		map = bpf_object__find_map_by_name(bo, "cpu_map");
		if (bpf_map__set_max_entries(map, libbpf_num_possible_cpus()) != 0)
			printf("set cpu_map.max_entries failed\n");
		break;

	case PRG_BPF_VAR:
		modify_variable_in_rodata(bo);
		break;

	case PRG_SIGNAL:
		{
			/* test pkt_queue's signal implementation */
			struct pq_cfg phc = {
				.signal_map = "events",
				.signal_cb = signal_cb,
			};
			strcpy(phc.rx_iface, iface[0]);
			pq_ctx = pq_ctx_create(&phc, bo);
		}
		break;

	case PRG_PKT_QUEUE:
		{
			/* test pkt_queue implementation */
			struct pq_cfg phc = {
				.xsks_map = "xsks_map",
				.timeout_ms = 2000,
				.read_pkt_cb = read_pkt_cb,
				.timeout_pkt_cb = timeout_pkt_cb,
			};
			strcpy(phc.rx_iface, iface[0]);
			strcpy(phc.tx_iface, iface[1]);
			*iface[1] = 0;  /* do not run bpf prog on it */
			pq_ctx = pq_ctx_create(&phc, bo);
		}
		break;

	case PRG_IPFRAG:
		if (ipfrag_init(iface[0], bo) < 0)
			goto err;
		break;

	case PRG_CGN_TEST:
		cgn_test_init(test_id, bo);
		break;

	default:
		break;
	}

	printf("maps:\n");
	bpf_object__for_each_map(map, bo) {
		printf("  - %s; type=%s max_e=%d numa=%d size=k:%d v:%d\n",
		       bpf_map__name(map),
		       libbpf_bpf_map_type_str(bpf_map__type(map)),
		       bpf_map__max_entries(map),
		       bpf_map__numa_node(map),
		       bpf_map__key_size(map),
		       bpf_map__value_size(map));
	}

	/* load bpf into kernel (create maps, verifier, ...) */
	if (bpf_object__load(bo) < 0)
		goto err;

	/* action to make after loading into kernel, but before attaching
	 * (starting) program */
	switch (prgtype) {
	case PRG_CPUMAP:
		/* now that map is initialized, set queue size for cpu_map on all entries */
		map = bpf_object__find_map_by_name(bo, "cpu_map");
		if (map != NULL) {
			struct bpf_cpumap_val v = { .qsize = 100 }; /* queue size */
			for (int i = 0; i < libbpf_num_possible_cpus(); i++ ) {
				bpf_map__update_elem(map, &i, sizeof (i),
						     &v, sizeof (v), 0);
			}
		}
		break;

	case PRG_SIGNAL:
	case PRG_PKT_QUEUE:
		pq_ctx_load(pq_ctx);
		break;

	case PRG_IPFRAG:
		if (ipfrag_load(bo) < 0)
			goto err;
		break;

	case PRG_CGN_TEST:
		if ((ret = cgn_test_start(test_id, bo)) <= 0)
			goto err;
		break;

	default:
		break;
	}

	/* now start bpf program */
	prg = bpf_object__find_program_by_name(bo, "xdp_entry");
	if (prg == NULL) {
		printf("cannot find function 'xdp_entry'\n");
		goto err;
	}
	for (i = 0; i < ARRAY_SIZE(iface) && *iface[i]; i++) {
		char ifn[128], *ns;

		strcpy(ifn, iface[i]);
		if ((ns = strchr(ifn, '@')) != NULL) {
			*ns++ = 0;
			change_network_ns(ns);
		}

		iface_idx = if_nametoindex(ifn);
		if (!iface_idx) {
			printf("iface '%s' in netns %s: %m\n", ifn, ns);
			goto err;
		}
		link = bpf_program__attach_xdp(prg, iface_idx);
		if (link == NULL) {
			printf("failed to attach program\n");
			goto err;
		}
	}

	if (isatty(STDIN_FILENO)) {
		ev_signal_init(&ev_sigint, &sigint_hdl, SIGINT);
		ev_signal_start(loop, &ev_sigint);
	}

	/* after starting, run main loop */
	switch (prgtype) {
	case PRG_MAP_RESIZE:
		ev_timer_init(&poll_timer, poll_cb, 1., 1.);
		ev_timer_start(loop, &poll_timer);
		break;
	default:
	}

	ev_run(loop, 0);
	ret = 0;

 err:
	bpf_link__destroy(link);
	bpf_object__close(bo);

	return ret;
}
