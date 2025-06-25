/* SPDX-License-Identifier: AGPL-3.0-or-later */

#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "lib/util.h"
#include "bpf/lib/cgn-def.h"

#pragma GCC diagnostic ignored "-Wunused-parameter"

static const char *
proto_to_str(uint8_t proto)
{
	switch (proto) {
	case IPPROTO_ICMP:
		return "icmp";
	case IPPROTO_TCP:
		return "tcp";
	case IPPROTO_UDP:
		return "udp";
	case IPPROTO_ICMPV6:
		return "icmp6";
	default:
		return "???";
	}
}

static int
_open_pinned_map(struct bpf_map_info *info)
{
	char path[1024];
	uint32_t s = sizeof (*info);
	int fd;

	snprintf(path, sizeof (path), "/sys/fs/bpf/mybpf/%s", info->name);

	fd = bpf_obj_get(path);
	if (fd < 0) {
		printf("obj_get(%s): %m\n", path);
		return -1;
	}

	uint32_t expect_key_size = info->key_size;
	uint32_t expect_val_size = info->value_size;

	if (bpf_map_get_info_by_fd(fd, info, &s) < 0) {
		printf("map_get_info(%s): %m\n", path);
		close(fd);
		return -1;
	}

	if (expect_key_size && expect_key_size != info->key_size) {
		printf("%s: inconsistent key size, expected:%d loaded_prog:%d\n",
		       info->name, expect_key_size, info->key_size);
		close(fd);
		return -1;
	}
	if (expect_val_size && expect_val_size != info->value_size) {
		printf("%s: inconsistent value size, expected:%d loaded_prog:%d\n",
		       info->name, expect_val_size, info->value_size);
		close(fd);
		return -1;
	}

	return fd;
}

static void
user_list(int argc, char **argv)
{
	struct bpf_map_info mi = {
		.name = "users",
		.key_size = sizeof (struct cgn_user_key),
		.value_size = sizeof (struct cgn_user),
	};

	int fd = _open_pinned_map(&mi);
	if (fd < 0)
		return;

	struct cgn_user_key k = {}, nk;
	struct cgn_user u;
	char buf[64];
	while (!bpf_map_get_next_key(fd, &k, &nk)) {
		k = nk;
		bpf_map_lookup_elem(fd, &k, &u);
		uint32_t addr = u.addr.ip4;
		printf("  %s: blocks: %d/%d\n",
		       inet_ntop(AF_INET, &addr, buf, sizeof (buf)),
		       u.block_cur, u.block_n);
	}

	printf("done\n");
}

static void
block_list(int argc, char **argv)
{
	struct bpf_map_info mi = {
		.name = "v4_blocks",
		.key_size = sizeof (uint32_t),
	};
	struct bpf_map_info mif = {
		.name = "v4_free_blocks",
		.key_size = sizeof (uint32_t),
	};

	int fd = _open_pinned_map(&mi);
	if (fd < 0)
		return;
	int ipbl_s = mi.max_entries;
	int bl_s = mi.value_size - sizeof (struct cgn_v4_ipblock);
	if (bl_s < 0 || bl_s % sizeof (struct cgn_v4_block)) {
		printf("unexpected v4_blocks value size (%d)\n", mi.value_size);
		return;
	}
	bl_s /= sizeof (struct cgn_v4_block);

	uint32_t k = -1, nk;
	char data[mi.value_size];
	struct cgn_v4_ipblock *b;
	char buf[64];
	while (!bpf_map_get_next_key(fd, &k, &nk)) {
		k = nk;
		if (bpf_map_lookup_elem(fd, &k, data) < 0)
			break;
		b = (struct cgn_v4_ipblock *)data;
		uint32_t addr = ntohl(b->cgn_addr);
		printf("  %s: blocks: %d/%d (next idx:%d)\n",
		       inet_ntop(AF_INET, &addr, buf, sizeof (buf)),
		       b->used, b->total, b->next);
	}
	close(fd);

	fd = _open_pinned_map(&mif);
	if (fd < 0)
		return;

	char fdata[mif.value_size];
	uint32_t *fp, i, j;
	printf("free indexes: (%d)\n", mif.max_entries);
	for (i = 0; i < mif.max_entries; i++) {
		bpf_map_lookup_elem(fd, &i, fdata);

		fp = (uint32_t *)fdata;
		if (fp[0] == fp[1])
			continue;

		printf("    [%d] {%d,%d}", i, fp[0], fp[1]);
		for (j = fp[0]; j != fp[1];
		     j = (j + 1) % (ipbl_s + 1)) {
			printf(" %d", fp[j + 2]);
		}
		printf("\n");
	}
}

static void
flow4_list_priv(int argc, char **argv)
{
	struct bpf_map_info mi = {
		.name = "v4_priv_flows",
		.key_size = sizeof (struct cgn_v4_flow_priv_key),
		.value_size = sizeof (struct cgn_v4_flow_priv),
	};
	char buf[64000];
	int s = sizeof (buf);
	int k = 0;

	int fd = _open_pinned_map(&mi);
	if (fd < 0)
		return;

	k += scnprintf(buf + k, s - k, "   prot  tim     "
		       "priv                    cgn      "
		       "        ext_pub\n");

	struct cgn_v4_flow_priv_key fk = {}, nk;
	struct cgn_v4_flow_priv f;
	char spriv[64], scgn[64], sext[64];
	uint32_t ip;
	while (!bpf_map_get_next_key(fd, &fk, &nk)) {
		fk = nk;
		if (bpf_map_lookup_elem(fd, &fk, &f) < 0) {
			printf("lookup v4_priv_flow: %m\n");
			break;
		}

		ip = htonl(fk.priv_addr);
		inet_ntop(AF_INET, &ip, spriv, sizeof (spriv));
		ip = htonl(f.cgn_addr);
		inet_ntop(AF_INET, &ip, scgn, sizeof (scgn));
		ip = htonl(fk.pub_addr);
		inet_ntop(AF_INET, &ip, sext, sizeof (sext));

		k += scnprintf(buf + k, s - k, "   %4s  %4d  ",
			       proto_to_str(fk.proto), 0);
		k += scnprintf(buf + k, s - k,
			       "%s:%-5d  %s:%-5d  %s:%d\n",
			       spriv, fk.priv_port, scgn, f.cgn_port,
			       sext, fk.pub_port);
	}

	printf("%s", buf);
}


int
cgn_ctl_process_cmd(int argc, char **argv)
{
	if (argc < 2)
		return 1;

	if (!strcmp(argv[0], "user")) {
		if (!strcmp(argv[1], "list"))
			user_list(argc - 2, argv + 2);

	} else if (!strcmp(argv[0], "conf")) {

	} else if (!strcmp(argv[0], "block")) {
		if (!strcmp(argv[1], "list"))
			block_list(argc - 2, argv + 2);

	} else if (!strcmp(argv[0], "flow4")) {
		if (!strcmp(argv[1], "list_priv"))
			flow4_list_priv(argc - 2, argv + 2);

	}

	return 0;
}
