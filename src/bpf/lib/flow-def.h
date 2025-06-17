/* SPDX-License-Identifier: AGPL-3.0-or-later */

#pragma once

union flow_timeout_config
{
	__u16 udp;
	struct {
		__u16 tcp_synfin;
		__u16 tcp_est;
	};
} __attribute__((packed));
