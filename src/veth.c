/* SPDX-License-Identifier: AGPL-3.0-or-later */

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <libmnl/libmnl.h>
#include <linux/if.h>
#include <linux/if_link.h>
#include <linux/veth.h>
#include <linux/rtnetlink.h>


/* locals */
static struct mnl_socket *nl;
uint32_t nl_seq;


static int
nl_read_ack(const char *op, int errno_allow)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct nlmsgerr *nle;
	int ret = 1;

	while (ret > 0 || (ret == -1 && errno == EINTR)) {
		ret = mnl_socket_recvfrom(nl, buf, sizeof (buf));
		if (ret < 0)
			continue;

		nlh = (struct nlmsghdr*)buf;
		if (nlh->nlmsg_seq != nl_seq) {
			printf("libmnl ack, bad seq recv %d, expected %d\n",
			       nlh->nlmsg_seq, nl_seq);
			continue;
		}
		if (nlh->nlmsg_type == NLMSG_ERROR) {
			nle = (struct nlmsgerr *)(nlh + 1);
			if (nle->error) {
				if (-errno_allow == nle->error)
					return 1;
				printf("libmnl error on \"%s\": %s\n",
				       op, strerror(-nle->error));
			}
			return 0;
		}
	}

	if (ret == -1) {
		printf("error while retrieving ack: %m\n");
		return -1;
	}

	return 0;
}

/*
 * ip link add dev 'name' type veth peer name 'peer_name'
 */
static int
create_veth(const char *name, const char *peer_name)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifm, *peer_ifm;
	struct nlattr *attr_li, *attr_id, *attr_peer;
	int ret;

	/* create veth */
	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type	= RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK;
	nlh->nlmsg_seq = ++nl_seq;
	ifm = mnl_nlmsg_put_extra_header(nlh, sizeof (*ifm));
	ifm->ifi_family = AF_UNSPEC;
	mnl_attr_put_str(nlh, IFLA_IFNAME, name);

	attr_li = mnl_attr_nest_start(nlh, IFLA_LINKINFO);
	mnl_attr_put_str(nlh, IFLA_INFO_KIND, "veth");
	attr_id = mnl_attr_nest_start(nlh, IFLA_INFO_DATA);
	attr_peer = mnl_attr_nest_start(nlh, VETH_INFO_PEER);
	peer_ifm = mnl_nlmsg_put_extra_header(nlh, sizeof (*peer_ifm));
	peer_ifm->ifi_family = AF_UNSPEC;
	mnl_attr_put_str(nlh, IFLA_IFNAME, peer_name);
	mnl_attr_nest_end(nlh, attr_peer);
	mnl_attr_nest_end(nlh, attr_id);
	mnl_attr_nest_end(nlh, attr_li);

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
		printf("mnl_socket_send: %m\n");
		return -1;
	}

	ret = nl_read_ack("ip link add veth", EEXIST);
	if (ret < 0)
		return -1;
	/* already exists */
	if (ret == 1)
		return 0;

	/* set link up */
	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type	= RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq = ++nl_seq;
	ifm = mnl_nlmsg_put_extra_header(nlh, sizeof (*ifm));
	ifm->ifi_family = AF_UNSPEC;
	ifm->ifi_type = 0;
	ifm->ifi_change = IFF_UP;
	ifm->ifi_flags = IFF_UP;
	mnl_attr_put_str(nlh, IFLA_IFNAME, name);

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
		printf("mnl_socket_send: %m\n");
		return -1;
	}

	if (nl_read_ack("ip link veth up1", 0) < 0)
		return -1;

	/* set link up */
	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type	= RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq = ++nl_seq;
	ifm = mnl_nlmsg_put_extra_header(nlh, sizeof (*ifm));
	ifm->ifi_family = AF_UNSPEC;
	ifm->ifi_type = 0;
	ifm->ifi_change = IFF_UP;
	ifm->ifi_flags = IFF_UP;
	mnl_attr_put_str(nlh, IFLA_IFNAME, peer_name);

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
		printf("mnl_socket_send: %m\n");
		return -1;
	}

	if (nl_read_ack("ip link veth up2", 0) < 0)
		return -1;

	return 0;
}


int
veth_create(const char *name, const char *peer_name)
{
	int ret;

	nl = mnl_socket_open(NETLINK_ROUTE);
	if (nl == NULL) {
		printf("mnl_socket_open: %m\n");
		return -1;
	}
	if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
		printf("mnl_socket_bind: %m\n");
		return -1;
	}

	nl_seq = 669;

	ret = create_veth(name, peer_name);

	mnl_socket_close(nl);

	return ret;
}
