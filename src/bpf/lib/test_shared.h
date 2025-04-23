/* SPDX-License-Identifier: AGPL-3.0-or-later */

#pragma once

/*
 * this header will be included from bpf programs AND userspace programs
 */

struct basic {
	__u64 a1;
	__u64 a2;
	__u64 a3;
	__u64 a4;
	__u64 tab[];
} __attribute__((packed));


struct mysignal {
	__u64 a1;
	__u64 a2;
	__u64 a3;
	__u64 a4;
	__u64 a5;
} __attribute__((packed));
