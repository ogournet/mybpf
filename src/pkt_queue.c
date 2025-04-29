/* SPDX-License-Identifier: AGPL-3.0-or-later */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <assert.h>
#include <sys/mman.h>
#include <ev.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/if_link.h>
#include <bpf/libbpf.h>
#include <xdp/xsk.h>
#include <bpf/btf.h>

#include "lib/hlist.h"
#include "mybpf-priv.h"

/*
 * packet queueing using AF_XDP.
 *
 * packets data/metadata are read from xsk, stay on umem,
 * and are freed on timeout or when user TX them on xsk.
 *
 * moreover, there's a signal channel using perf_buffer that can be used
 * to trigger TX on queued packets.
 *
 * packets can be RX/TX on the same iface, or RX from one iface (nic) and
 * TX to another (veth). last option allow triggering xdp program on TX
 * (RX on the other veth side).
 *    RX: one xsk socket will be created for each rx queue.
 *    TX: one xsk socket will be created for each tx queue.
 */

struct pq_ctx
{
	struct pq_cfg		c;

	struct pq_xsk_umem	*umem;
	struct pq_xsk_socket	**rx_sock;
	struct pq_xsk_socket	**tx_sock;
	uint32_t		rx_sock_n;
	uint32_t		tx_sock_n;
	bool			rxtx_combined;

	struct bpf_map		*xsks_map;

	/* when defined, perf_buffer map used as signaling channel */
	struct bpf_map		*signal_map;
	struct perf_buffer	*pb;
	struct perfb_ev		**apev;

	/* single timer to timeout hold packets */
	struct ev_timer		timer;
};


/*************************************************************************/
/* implements AF_XDP sockets through libxdp */


// wrap xsk_umem with data we need
struct pq_xsk_umem {
	struct xsk_ring_prod fq;	// fill ring
	struct xsk_ring_cons cq;	// completion ring
	struct xsk_umem *umem;
	uint32_t desc_n;		// number of descriptors in buffer
	size_t buffer_size;		// desc_n * frame_size
	void *buffer;
	struct pq_desc *desc_pending;
	uint64_t *desc_free;
	uint32_t desc_pending_b;
	uint32_t desc_pending_e;
	uint32_t desc_free_n;
};

// wrap xsk_socket with data we need
struct pq_xsk_socket {
	ev_io io;
	struct pq_ctx *ctx;
	struct pq_xsk_umem *umem;
	struct xsk_ring_prod tx;
	struct xsk_ring_cons rx;
	struct xsk_ring_prod fq;
	struct xsk_ring_cons cq;
	struct xsk_socket *xsk;
	uint32_t outstanding_tx;
};


static inline struct pq_desc *
_get_pending_desc(struct pq_ctx *ctx, uint32_t idx)
{
	return (struct pq_desc *)((uint8_t *)ctx->umem->desc_pending +
				       idx * (sizeof (struct pq_desc) +
					      ctx->c.pkt_cb_user_size));
}

static inline void
complete_tx(struct pq_xsk_socket *xs)
{
	struct pq_xsk_umem *u = xs->umem;
	uint32_t i, n, idx_cq = 0;
 	int ret;

	if (!xs->outstanding_tx)
		return;

	/* kick tx */
	ret = sendto(xsk_socket__fd(xs->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
	if (ret < 0 && (errno != EAGAIN && errno != EBUSY && errno != ENETDOWN))
		printf("kick_tx sento: %m\n");

	/* reclaim descriptors for finished TX operations, add them to our
	 * free list */
	n = min(64, xs->outstanding_tx);
	n = xsk_ring_cons__peek(&u->cq, n, &idx_cq);
	if (n > 0) {
		for (i = 0; i < n; i++)
			u->desc_free[u->desc_free_n++] =
				*xsk_ring_cons__comp_addr(&u->cq, idx_cq + i);
		xsk_ring_cons__release(&u->cq, n);
		xs->outstanding_tx -= n;
	}
}


void
pq_tx(struct pq_ctx *ctx, int queue_idx, const struct pq_desc *pkt)
{
	struct pq_xsk_socket *xs = ctx->tx_sock[queue_idx];
	uint32_t idx;

	if (!xsk_ring_prod__reserve(&xs->tx, 1, &idx)) {
		complete_tx(xs);
		if (!xsk_ring_prod__reserve(&xs->tx, 1, &idx)) {
			printf("TX ring buffer is full\n");
			return;
		}
	}

	struct xdp_desc *tx_desc = xsk_ring_prod__tx_desc(&xs->tx, idx);

	tx_desc->addr = (void *)pkt->data - xs->umem->buffer;
	tx_desc->len = pkt->len;
	tx_desc->options = 0;

	xsk_ring_prod__submit(&xs->tx, 1);
	++xs->outstanding_tx;

	complete_tx(xs);
}


/*
 * read callback
 */
static void
xsk_cb(struct ev_loop *, struct ev_io *w, int /* revents */)
{
	struct pq_xsk_socket *xs = (struct pq_xsk_socket *)w;
	struct pq_xsk_umem *u = xs->umem;
	struct pq_desc *pkt;
	uint32_t rcvd, i;
	uint32_t idx_rx = 0, idx_fq = 0;

	rcvd = xsk_ring_cons__peek(&xs->rx, 64, &idx_rx);
	if (!rcvd)
		return;

	// read packets
	for (i = 0; i < rcvd; i++) {
		const struct xdp_desc *desc = xsk_ring_cons__rx_desc(&xs->rx, idx_rx++);
		if (desc->options & XDP_PKT_CONTD) {
			printf("I AM fragmented :/\n");
		}

		// add this packet to pending list
		pkt = _get_pending_desc(xs->ctx, u->desc_pending_e);
		pkt->data = xsk_umem__get_data(u->buffer, desc->addr);
		pkt->len = desc->len;
		pkt->alloc_time = time(NULL);
		++u->desc_pending_e;

		if (xs->ctx->c.read_pkt_cb != NULL)
			xs->ctx->c.read_pkt_cb(xs->ctx, xs->ctx->c.uctx, pkt);
	}

	// acke'd, we read them
	xsk_ring_cons__release(&xs->rx, rcvd);

	// now we give back to kernel the same number of descriptors,
	// so it won't run out.
	if (u->desc_free_n < rcvd) {
		printf("ooops, running out of RX descriptors :/\n");
		return;
	}
	if (xsk_ring_prod__reserve(&xs->umem->fq, rcvd, &idx_fq) == 0) {
		printf("cannot write into fill queue, what the kernel is doing ?\n");
		return;
	}
	for (i = 0; i < rcvd; i++)
		*xsk_ring_prod__fill_addr(&xs->umem->fq, idx_fq++) = u->desc_free[--u->desc_free_n];
	xsk_ring_prod__submit(&xs->umem->fq, rcvd);

}


/*
 * umem is the memory shared between us and the kernel, where packets will be stored.
 *
 * each packet (== descriptor) must fit in a 4KB page.
 * real packet data could be about 3.5KB because XDP use space at beginning and end.
 * ip packet could be fragmented into multiple descriptors.
 *
 * only ONE umem is created, and will be shared with ALL AF_XDP sockets.
 * one AF_XDP will be created per queue_id.
 *
 * packet memory should hold at least (fill ring size + completion ring size) buffers,
 * and may hold more, if we intend to hold (queue) RX packets for a few time before TX them.
 */
static struct pq_xsk_umem *
_setup_umem(struct pq_ctx *ctx)
{
	struct pq_xsk_umem *u;
	uint32_t i;

	u = calloc(1, sizeof (*u));

	/* enough descriptors to fit all fill+completion rings, plus
	 * 16k of 'buffered' packets */
	u->desc_n = (8 + ctx->rx_sock_n * 2) * XSK_RING_PROD__DEFAULT_NUM_DESCS;

	// create the 'big buffer' that will hold packets data.
	//   20k packets of 4k size each => 80 MB  (for one rx queue)
	u->buffer_size = u->desc_n * XSK_UMEM__DEFAULT_FRAME_SIZE;
	u->buffer = mmap(NULL, u->buffer_size,
			 PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (u->buffer == MAP_FAILED) {
		printf("ERROR: mmap failed: %m\n");
		goto out;
	}

	LIBBPF_OPTS(xsk_umem_opts, umem_cfg,
		    .size = u->buffer_size,
		    .fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
		    .comp_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
		    .frame_size = XSK_UMEM__DEFAULT_FRAME_SIZE,
		    /* leave space before packet data on rx, if we wanna add encap. */
		    .frame_headroom = 256,
		    .flags = 0,
		    .tx_metadata_len = 0,
	);

	/* create umem. umem fill/completion queues will not be used, as we
	 * will allocate one for each sockets.
	 * but it is mandatory to have them here. */
	u->umem = xsk_umem__create_opts(u->buffer, &u->fq, &u->cq, &umem_cfg);
	if (u->umem == NULL) {
		printf("cannot create xsk umem\n");
		goto out;
	}

	// add all descriptors into free array
	u->desc_free = calloc(u->desc_n, sizeof (*u->desc_free));
	for (i = 0; i < u->desc_n; i++) {
		u->desc_free[u->desc_free_n++] = i * XSK_UMEM__DEFAULT_FRAME_SIZE;
	}

	u->desc_pending = calloc(u->desc_n * 2,
				 sizeof (struct pq_desc) +
				 ctx->c.pkt_cb_user_size);

	return u;

 out:
	if (u->umem != NULL)
		(void)xsk_umem__delete(u->umem);
	if (u != NULL && u->buffer != MAP_FAILED)
		munmap(u->buffer, u->buffer_size);
	free(u);
	return NULL;
}

/*
 * setup AF_XDP sockets (xsk), one per rx queue.
 * socket is bind() on a specific queue_id and will only receive from it,
 * so there have to be one socket per rx queue.
 *
 * it will use polling (with libev). no busy poll.
 * if real performance is needed, we may start one thread per socket.
 *
 * it also configure 4 rings:
 *   - tx ring
 *   - rx ring
 *   - fill ring: gives back buffers to kernel, so it can use them for RX
 *   - completion ring: kernel gives buffers to us, so we can use them again for TX.
 * these 4 rings will be mmap'ed by libxdp
 *
 * we *may* create a set of sockets for one netdev/queue_id (like SO_REUSEPORT),
 * in this case fill/completion ring *may* be shared. it is not the use-case here.
 */
static struct pq_xsk_socket *
_setup_socket(struct pq_ctx *ctx, const char *ifname, int queue_id, bool w_rx, bool w_tx)
{
	struct pq_xsk_umem *u = ctx->umem;
	int xsks_map_fd = bpf_map__fd(ctx->xsks_map);
	struct pq_xsk_socket *xs;
	uint32_t idx, i;
	int ret;

	printf(" initialize xsk on iface:%s/%d, mode:%s%s\n",
	       ifname, queue_id, w_rx ? " RX" : "", w_tx ? " TX" : "");

	xs = calloc(1, sizeof (*xs));
	xs->ctx = ctx;
	xs->umem = u;
	LIBBPF_OPTS(xsk_socket_opts, xsd_cfg,
		    .fill = &xs->fq,
		    .comp = &xs->cq,
		    .libxdp_flags = XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD,
		    .xdp_flags = XDP_FLAGS_DRV_MODE,
		    .bind_flags = XDP_USE_NEED_WAKEUP | XDP_COPY,
	);
	if (w_rx) {
		xsd_cfg.rx = &xs->rx;
		xsd_cfg.rx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
	}
	if (w_tx) {
		xsd_cfg.tx = &xs->tx;
		xsd_cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
	}

	xs->xsk = xsk_socket__create_opts(ifname, queue_id, u->umem, &xsd_cfg);
	if (xs->xsk == NULL) {
		printf("cannot create xsk socket: %m\n");
		free(xs);
		return NULL;
	}

	// remaining is only for RX sockets
	if (!w_rx)
		return xs;

	// give kernel some descriptors for RX, by writting into fill ring
	ret = xsk_ring_prod__reserve(&xs->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS, &idx);
	assert(ret == XSK_RING_PROD__DEFAULT_NUM_DESCS);
	for (i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i++)
		*xsk_ring_prod__fill_addr(&xs->fq, idx++) = u->desc_free[--u->desc_free_n];
	xsk_ring_prod__submit(&xs->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS);

	// use libev to poll() sockets
	ev_io_init(&xs->io, xsk_cb, xsk_socket__fd(xs->xsk), EV_READ);
	ev_io_start(loop, &xs->io);

	// insert this fd into bpf's map BPF_MAP_TYPE_XSKMAP
	ret = xsk_socket__update_xskmap(xs->xsk, xsks_map_fd);
	if (ret) {
		fprintf(stderr, "ERROR: xsk_socket__update_xskmap: %m\n");
		xsk_socket__delete(xs->xsk);
		free(xs);
		return NULL;
	}

	return xs;
}

static int
pq_xsk_load(struct pq_ctx *ctx)
{
	uint32_t i;

	ctx->umem = _setup_umem(ctx);
	if (ctx->umem == NULL)
		return -1;

	ctx->rx_sock = calloc(ctx->rx_sock_n, sizeof (*ctx->rx_sock));
	ctx->tx_sock = calloc(ctx->tx_sock_n, sizeof (*ctx->tx_sock));

	/* initialize rx (or trx) sockets */
	for (i = 0; i < ctx->rx_sock_n; i++) {
		ctx->rx_sock[i] = _setup_socket(ctx, ctx->c.rx_iface,
						i, true, ctx->rxtx_combined);
		if (ctx->rx_sock[i] == NULL)
			return -1;
	}

	/* initialize tx sockets */
	for (i = 0; i < ctx->tx_sock_n; i++) {
		if (ctx->rxtx_combined && i <= ctx->rx_sock_n)
			ctx->tx_sock[i] = ctx->rx_sock[i];
		else
			ctx->tx_sock[i] = _setup_socket(ctx, ctx->c.tx_iface,
							i, false, true);
	}

	return 0;
}

static void
pq_xsk_release(struct pq_ctx *ctx)
{
	uint32_t i;

	if (ctx->rx_sock != NULL) {
		for (i = 0; i < ctx->rx_sock_n; i++)
			xsk_socket__delete(ctx->rx_sock[i]->xsk);
		for (i = ctx->rxtx_combined ? i : 0; i < ctx->tx_sock_n; i++)
			xsk_socket__delete(ctx->tx_sock[i]->xsk);
	}
	free(ctx->rx_sock);
	free(ctx->tx_sock);
	if (ctx->umem != NULL) {
		(void)xsk_umem__delete(ctx->umem->umem);
		munmap(ctx->umem->buffer, ctx->umem->buffer_size);
		free(ctx->umem);
	}
}


/*************************************************************************/
/* implements signal from kernel to userland, using map perf_event_array */


#define PERF_BUFFER_PAGES		8

struct perfb_ev
{
	struct ev_io io;
	struct perf_buffer *pb;
	uint64_t cpu;
};


static void
handle_event(void *uctx, int cpu, void *data, __u32 data_size)
{
	struct pq_ctx *ctx = uctx;

	fprintf(stderr, "got perf event cpu: %d data: %p, size: %d\n", cpu, data, data_size);

	if (ctx->c.signal_cb != NULL)
		ctx->c.signal_cb(ctx, ctx->c.uctx, data, data_size);

}

static void
handle_missed_events(void *, int cpu, __u64 lost_cnt)
{
	fprintf(stderr, "Lost %llu events on CPU %d\n", lost_cnt, cpu);
}

/*
 * callback called by libev, when there is something to read on perf buffer's fd.
 * libbpf will handle data and then will call handle_event.
 */
static void
perfb_io_read(struct ev_loop * /* loop */, struct ev_io *io, int /* revents */)
{
	struct perfb_ev *pev = (struct perfb_ev *)io;
	int err;

	err = perf_buffer__consume_buffer(pev->pb, pev->cpu);
	if (err) {
		fprintf(stderr, "perf comsume buffer: %m\n");
	}
}



static int
pq_signal_load(struct pq_ctx *ctx)
{
	struct perfb_ev *pev;
	uint64_t cpu;
	int map_fd = bpf_map__fd(ctx->signal_map);
	int fd;

	ctx->pb = perf_buffer__new(map_fd, PERF_BUFFER_PAGES, handle_event, handle_missed_events, ctx, NULL);
	if (ctx->pb == NULL) {
		fprintf(stderr, "Failed to open perf buffer: %m\n");
		return -errno;
	}

	ctx->apev = calloc(perf_buffer__buffer_cnt(ctx->pb), sizeof (*ctx->apev));
	for (cpu = 0; cpu < perf_buffer__buffer_cnt(ctx->pb); cpu++) {
		fd = perf_buffer__buffer_fd(ctx->pb, cpu);
		if (fd < 0)
			return fd;

		pev = calloc(1, sizeof (*pev));
		pev->pb = ctx->pb;
		pev->cpu = cpu;
		ev_io_init(&pev->io, perfb_io_read, fd, EV_READ);
		ev_io_start(loop, &pev->io);
		ctx->apev[cpu] = pev;
	}

	return 0;
}

static void
pq_signal_release(struct pq_ctx *ctx)
{
	struct perfb_ev *pev;
	size_t cpu;

	if (ctx == NULL)
		return;

	for (cpu = 0; cpu < perf_buffer__buffer_cnt(ctx->pb); cpu++) {
		pev = ctx->apev[cpu];
		ev_io_stop(loop, &pev->io);
		free(pev);
	}
	free(ctx->apev);
	perf_buffer__free(ctx->pb);
}


/*************************************************************************/
/* context creation */

static void
timeout_cb(struct ev_loop * /* loop */, struct ev_timer *t, int /* revents */)
{
	struct pq_ctx *ctx = container_of(t, struct pq_ctx, timer);
	struct pq_xsk_umem *u = ctx->umem;
	struct pq_desc *pkt;
	uint32_t i;

	for (i = u->desc_pending_b; i < u->desc_pending_e; i++) {
		pkt = _get_pending_desc(ctx, i);
		if (pkt->alloc_time + ctx->c.timeout_ms / 1000 > time(NULL))
			break;
		printf("free pkt %p pending: [%d-%d]\n", pkt->data,
		       u->desc_pending_b, u->desc_pending_e);
		if (ctx->c.timeout_pkt_cb != NULL)
			ctx->c.timeout_pkt_cb(ctx, ctx->c.uctx, pkt);
	}
	u->desc_pending_b = i;

	if (u->desc_pending_b > u->desc_n) {
		memmove(u->desc_pending, _get_pending_desc(ctx, u->desc_pending_b),
			(u->desc_pending_e - u->desc_pending_b) *
			(sizeof (struct pq_desc) + ctx->c.pkt_cb_user_size));
		u->desc_pending_e -= u->desc_pending_b;
		u->desc_pending_b = 0;
	}
}

/* to be called after loading from file (bpf_object__open()),
 * but before loading program into kernel (bpf_object__load()) */
struct pq_ctx *
pq_ctx_create(struct pq_cfg *cfg, struct bpf_object *oprg)
{
	struct pq_ctx *ctx;
	uint32_t tmp;
	int ret;

	ctx = calloc(1, sizeof (*ctx));
	ctx->c = *cfg;

	if (!*cfg->tx_iface)
		strcpy(cfg->tx_iface, cfg->rx_iface);

	if (strcmp(cfg->rx_iface, cfg->tx_iface)) {
		/* different interfaces for RX and TX */
		ret = xsk_get_cur_queues(cfg->rx_iface, &ctx->rx_sock_n, &tmp);
		if (!ret)
			ret = xsk_get_cur_queues(cfg->tx_iface, &tmp, &ctx->tx_sock_n);
		if (ret < 0) {
			printf("cannot get cur_queues on %s/%s: %m\n",
			       cfg->rx_iface, cfg->tx_iface);
			free(ctx);
			return NULL;
		}
		ctx->rxtx_combined = false;
		printf("we have %d rx queues on %s and %d tx queues on %s\n",
		       ctx->rx_sock_n, cfg->rx_iface, ctx->tx_sock_n, cfg->tx_iface);
	} else {
		/* same interface for RX/TX */
		ret = xsk_get_cur_queues(cfg->rx_iface, &ctx->rx_sock_n, &ctx->tx_sock_n);
		if (ret < 0) {
			printf("cannot get cur_queues on %s: %m\n", cfg->rx_iface);
			free(ctx);
			return NULL;
		}
		ctx->rxtx_combined = true;
		printf("we have %d rx and %d tx queues on iface %s\n",
		       ctx->rx_sock_n, ctx->tx_sock_n, cfg->rx_iface);
	}

	ctx->xsks_map = bpf_object__find_map_by_name(oprg, cfg->xsks_map);
	if (ctx->xsks_map != NULL) {
		if (bpf_map__set_max_entries(ctx->xsks_map, ctx->rx_sock_n) != 0) {
			printf("set %s.max_entries failed: %m\n", cfg->xsks_map);
			free(ctx);
			return NULL;
		}
	} else if (*cfg->xsks_map) {
		printf("cannot find table %s, do not load pkt_queue af_xdp\n",
		       cfg->xsks_map);
	}

	ctx->signal_map = bpf_object__find_map_by_name(oprg, cfg->signal_map);

	return ctx;
}


/* to be called after loading program into kernel, before running it */
int
pq_ctx_load(struct pq_ctx *ctx)
{
	if (ctx->signal_map != NULL) {
		if (pq_signal_load(ctx))
			return -1;
	}

	if (ctx->xsks_map != NULL) {
		if (pq_xsk_load(ctx))
			return -1;
		ev_timer_init(&ctx->timer, timeout_cb, 1., 1.);
		ev_timer_start(loop, &ctx->timer);
	}

	return 0;
}

void
pq_ctx_release(struct pq_ctx *ctx)
{
	if (ctx != NULL) {
		pq_signal_release(ctx);
		pq_xsk_release(ctx);
		free(ctx);
	}
}

const struct pq_cfg *
pq_cfg(struct pq_ctx *ctx)
{
	return &ctx->c;
}
