/* SPDX-License-Identifier: AGPL-3.0-or-later */

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <linux/if.h>
#include <linux/if_link.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>

#include "mybpf-priv.h"



#define MAX_DEV_QUEUE_PATH_LEN 64

static void xsk_get_queues_from_sysfs(const char* ifname, uint32_t *rx, uint32_t *tx)
{
	char buf[MAX_DEV_QUEUE_PATH_LEN];
	struct dirent *entry;
	DIR *dir;

	snprintf(buf, MAX_DEV_QUEUE_PATH_LEN,
		 "/sys/class/net/%s/queues/", ifname);

	dir = opendir(buf);
	if (dir == NULL)
		return;

	while ((entry = readdir(dir))) {
		if (!strncmp(entry->d_name, "rx", 2))
			++*rx;

		if (!strncmp(entry->d_name, "tx", 2))
			++*tx;
	}

	closedir(dir);
}

/*
 * get configured number of rx/tx queues for requested iface,
 * from kernel ethtool
 */
int
xsk_get_cur_queues(const char *ifname, uint32_t *rx, uint32_t *tx)
{
	struct ethtool_channels channels = { .cmd = ETHTOOL_GCHANNELS };
	struct ifreq ifr = {};
	int fd, err;

	fd = socket(AF_LOCAL, SOCK_DGRAM, 0);
	if (fd < 0)
		return -errno;

	ifr.ifr_data = (void *)&channels;
	memcpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
	ifr.ifr_name[IFNAMSIZ - 1] = '\0';
	err = ioctl(fd, SIOCETHTOOL, &ifr);
	if (err && errno != EOPNOTSUPP) {
		close(fd);
		return -errno;
	}

	if (err) {
		/* If the device says it has no channels,
		 * try to get rx tx from sysfs, otherwise all traffic
		 * is sent to a single stream, so max queues = 1.
		 */
		xsk_get_queues_from_sysfs(ifr.ifr_name, rx, tx);
	} else {
		/* Take the max of rx, tx, combined. Drivers return
		 * the number of channels in different ways.
		 */
		*rx = channels.rx_count;
		*tx = channels.tx_count;
		if (!*rx)
			*rx = channels.combined_count;
		if (!*tx)
			*tx = channels.combined_count;
	}

	close(fd);

	return *rx > 0 && *tx > 0 ? 0 : -1;
}
