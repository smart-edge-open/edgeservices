/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

/**
 * @file nis_io.c
 * @brief Implementation of nis i/o
 */

#include <rte_config.h>
#include <rte_mbuf.h>
#include "nes_common.h"
#include "nts/nts_lookup.h"
#include "nes_ring.h"
#include "nes_ring_lookup.h"
#include "nts/nts_route.h"
#include "libnes_queue.h"
#include "nis/nis_io.h"
#include "nis/nis_param.h"
#include "nis/nis_acl.h"
#include "libnes_acl.h"
#include "ctrl/nes_ctrl.h"
#include "io/nes_io.h"
#include "io/nes_dev_addons.h"

#ifdef UNIT_TESTS
	#include "nis_io_decl.h"
#endif

static nes_queue_t nis_io_rings;

__attribute__((constructor))
static void nis_io_early_init(void)
{
	nes_queue_ctor(&nis_io_rings);
}

enum rx_rings_id
{
	NIS_UPSTR_RNIS = 0,
	NIS_UPSTR_SCTP,
	NIS_UPSTR_GTPUC,
	NIS_UPSTR_GTPC,
	NIS_DWSTR_RNIS,
	NIS_DWSTR_SCTP,
	NIS_DWSTR_GTPUC,
	NIS_DWSTR_GTPC,
	NIS_RX_RINGS_CNT
};

static nes_ring_t *rx_rings[NIS_RX_RINGS_CNT];

NES_STATIC int nis_io_init_traffic_rings(void)
{
	if (nes_ring_find(&rx_rings[NIS_UPSTR_RNIS],  "NIS_UPSTR_RNIS")  ||
			nes_ring_find(&rx_rings[NIS_UPSTR_SCTP],  "NIS_UPSTR_SCTP")  ||
			nes_ring_find(&rx_rings[NIS_UPSTR_GTPUC], "NIS_UPSTR_GTPUC") ||
			nes_ring_find(&rx_rings[NIS_UPSTR_GTPC],  "NIS_UPSTR_GTPC")  ||
			nes_ring_find(&rx_rings[NIS_DWSTR_RNIS],  "NIS_DWSTR_RNIS")  ||
			nes_ring_find(&rx_rings[NIS_DWSTR_SCTP],  "NIS_DWSTR_SCTP")  ||
			nes_ring_find(&rx_rings[NIS_DWSTR_GTPUC], "NIS_DWSTR_GTPUC") ||
			nes_ring_find(&rx_rings[NIS_DWSTR_GTPC],  "NIS_DWSTR_GTPC")) {
		/* if statement body */
		NES_LOG(ERR, "NIS IO: Unable to find all RX rings\n");
		return NES_FAIL;
	}

	int rxi;
	for (rxi = 0; rxi < NIS_RX_RINGS_CNT; rxi++) {
		if (NES_SUCCESS != nes_queue_enqueue(&nis_io_rings, rx_rings[rxi])) {
			NES_LOG(ERR, "Unable to enqueue RX ring pointer\n");
			return NES_FAIL;
		}
	}
	return NES_SUCCESS;
}

static int nis_io_dwstr_flow(__attribute__((unused)) nes_ring_t *self, void **buf, int rx_cnt)
{
	struct ether_hdr *eth_hdr;
	int i;

	for (i = 0; i < rx_cnt; i++) {
		eth_hdr = rte_pktmbuf_mtod((struct rte_mbuf *)buf[i], struct ether_hdr *);

		if (unlikely(NULL == eth_hdr)) {
			rte_pktmbuf_free(buf[i]);
			continue;
		}
		/* check if VLAN tag is present */
		if (eth_hdr->ether_type == rte_cpu_to_be_16(ETHER_TYPE_VLAN))
			eth_hdr = (struct ether_hdr *)((uint8_t*)eth_hdr + sizeof(struct vlan_hdr));

		if (unlikely(eth_hdr->ether_type != rte_cpu_to_be_16(ETHER_TYPE_IPv4))) {
			rte_pktmbuf_free(buf[i]);
			continue;
		}

		nes_ring_t *ring = nes_dev_get_egressring_from_port_idx(
				((struct rte_mbuf *)buf[i])->port);

		if (likely(NULL != ring))
			ring->enq(ring, buf[i]);
		else {
			rte_pktmbuf_free(buf[i]);
			NES_STATS_RING_UPDATE(1, self->ring_stats->stats.drp_cnt_2);
		}
	}
	return NES_SUCCESS;
}

static int nis_io_upstr_flow(__attribute__((unused)) nes_ring_t *self, void **buf, int rx_cnt)
{
	struct ether_hdr *eth_hdr;
	int i;

	for (i = 0; i < rx_cnt; i++) {

		eth_hdr = rte_pktmbuf_mtod((struct rte_mbuf *)buf[i], struct ether_hdr *);

		if (unlikely(NULL == eth_hdr)) {
			rte_pktmbuf_free(buf[i]);
			continue;
		}
		/* check if VLAN tag is present */
		if (eth_hdr->ether_type == rte_cpu_to_be_16(ETHER_TYPE_VLAN))
			eth_hdr = (struct ether_hdr *)((uint8_t*)eth_hdr + sizeof(struct vlan_hdr));

		if (unlikely(eth_hdr->ether_type != rte_cpu_to_be_16(ETHER_TYPE_IPv4))) {
			rte_pktmbuf_free(buf[i]);
			continue;
		}

		nes_ring_t *ring =  nes_dev_get_egressring_from_port_idx(
				((struct rte_mbuf *)buf[i])->port);
		if (likely(NULL != ring))
			ring->enq(ring, buf[i]);
		else
			rte_pktmbuf_free(buf[i]);
	}
	return NES_SUCCESS;
}

#define NIS_DWSTR_PREFIX "NIS_DWSTR"
#define NIS_UPSTR_PREFIX "NIS_UPSTR"

static int
nis_io_ring_flow_set(nes_ring_t *ring) {
	char *ring_name = nes_ring_name(ring);

	if (0 == strncmp(ring_name, NIS_DWSTR_PREFIX, sizeof(NIS_DWSTR_PREFIX) - 1))
		ring->flow = nis_io_dwstr_flow;
	else if (0 == strncmp(ring_name, NIS_UPSTR_PREFIX, sizeof(NIS_UPSTR_PREFIX) - 1))
		ring->flow = nis_io_upstr_flow;

	return NULL == ring->flow ? NES_FAIL : NES_SUCCESS;
}

NES_STATIC int
nis_io_init_flows(void) {
	int rxi;
	for (rxi = 0 ; rxi < NIS_RX_RINGS_CNT ; rxi++) {
		if (NES_SUCCESS != nis_io_ring_flow_set(rx_rings[rxi]))
			return NES_FAIL;
	}
	return NES_SUCCESS;
}

NES_STATIC int nis_io_init(void)
{
	return nis_io_init_traffic_rings() || nis_io_init_flows();
}

int nis_io_main(__attribute__((unused))void *arg)
{
	if (NES_SUCCESS != nis_io_init()) {
		NES_LOG(ERR,"NIS IO thread init failed\n");
		return NES_FAIL;
	}

	NES_LOG(INFO, "NIS_IO started\n");

	rte_atomic32_add(&threads_started, THREAD_NIS_IO_ID);
	for (NES_FOREVER_LOOP) {
		nes_queue_node_t *node;
		NES_QUEUE_FOREACH(node, &nis_io_rings) {
			struct rte_mbuf *buf[MAX_BURST_SIZE];
			int rx_cnt;
			nes_ring_t *in_ring = node->data;

			if (likely(NULL != in_ring->deq_burst))
				rx_cnt = in_ring->deq_burst(in_ring, (void **)buf, MAX_BURST_SIZE);
			else {
				NES_LOG(INFO, "Undefined method deq_burst for ring %s.\n",
					nes_ring_name(in_ring));
				rx_cnt = 0;
			}

			if (likely(NULL != in_ring->flow)) {
				if (likely(rx_cnt > 0))
					in_ring->flow(in_ring, (void **)buf, rx_cnt);
			} else {
				NES_LOG(INFO, "NIS Undefined method flow for ring %s.\n",
					nes_ring_name(in_ring));
				continue;
			}

		}
		usleep(1);	/* WORKAROUND for 100% CPU usage */
	}

	return NES_SUCCESS;
}
