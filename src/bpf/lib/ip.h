
#pragma once

#define	IP_MF 0x2000			/* more fragments flag */
#define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */


typedef __u32 v4addr_t;

union v6addr
{
	struct {
		__u32 p1;
		__u32 p2;
		__u32 p3;
		__u32 p4;
	};
	struct {
		__u64 d1;
		__u64 d2;
	};
	__u8 addr[16];
} __attribute__((packed));

union v4v6addr
{
	struct {
		v4addr_t	ip4;
		__u32		pad[3];
	};
	union v6addr		ip6;
} __attribute__((packed));

/* ipfrag key. used as metadata */
union ipfrag_key
{
	__u8	family;

	struct {
		__u8		family;
		__u8		proto;
		__u16		packet_id;
		__u32		src;		/* net order */
		__u32		dst;		/* net order */
		__u32		pad[7];
	} v4;

	struct {
		__u8		family;
		__u8		proto;
		__u8		pad[2];
		__u32		packet_id;
		union v6addr	src;
		union v6addr	dst;
	} v6;

	struct {
		__u32		data[10];
	} _u4;

} __attribute__((aligned(4))) __attribute__((packed));

#define IPFRAG_FL_RULE_SET	0x01

struct ipfrag_rule
{
	struct bpf_timer timer;
	__u8 flags;
};

/* Program statistics */
enum pkt_stats_type {
	PKT_STAT_FRAG_FWD = 0,
	PKT_STAT_FRAG_REORDER,
	PKT_STAT_FRAG_NOMATCH_DROP,
	PKT_STAT_MAX,
};

