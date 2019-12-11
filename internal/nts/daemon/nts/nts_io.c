/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

/**
 * @file nts_io.c
 * @brief Implementation of nts i/o
 */

#include <rte_config.h>
#include <rte_log.h>
#include <rte_mbuf.h>
#include <rte_memcpy.h>
#include <rte_ip.h>

#include "nes_main.h"
#include "nes_common.h"
#include "nes_ring.h"
#include "nts/nts_io.h"
#include "nts/nts_edit.h"
#include "nts/nts_lookup.h"
#include "ctrl/nes_ctrl.h"
#include "nes_ring_lookup.h"
#include "io/nes_io.h"

#include "libnes_queue.h"
#include "libnes_lookup.h"
#include "libnes_cfgfile.h"

#ifdef UNIT_TESTS
	#include "nts_io_decl.h"
#endif

static nes_queue_t nts_io_rings;

NES_STATIC nts_lookup_tables_t nts_io_lookup_tables;

__attribute__((constructor))
static void nts_io_early_init(void)
{
	nes_queue_ctor(&nts_io_rings);
}

void nts_io_ring_queue_get(nes_queue_t **queue)
{
	*queue = &nts_io_rings;
}

nts_lookup_tables_t *nts_io_routing_tables_get(void)
{
	return &nts_io_lookup_tables;
}

NES_STATIC int nts_io_init(void)
{
	return nts_lookup_init(&nts_io_lookup_tables) || nts_edit_init();
}

int nts_io_main(__attribute__((unused))void *arg)
{
	if (NES_SUCCESS != nts_io_init()) {
		NES_LOG(ERR, "NTS_IO init failed\n");
		return NES_FAIL;
	}

	NES_LOG(INFO, "NTS_IO started\n");

	rte_atomic32_add(&threads_started, THREAD_NTS_IO_ID);
	for (NES_FOREVER_LOOP) {
		nes_queue_node_t *node, *removed_node;
		NES_QUEUE_FOREACH(node, &nts_io_rings) {
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
				NES_LOG(INFO, "NTS Undefined method flow for ring %s.\n",
					nes_ring_name(in_ring));
				continue;
			}
			if (unlikely(in_ring->remove)) {
				nes_queue_node_unlock(node);
				if ((removed_node = nes_queue_remove(
						&nts_io_rings, node)) != NULL) {
					in_ring->remove = 0;
					rte_free(removed_node);
				}
				break;
			}
		}
	}
	return NES_SUCCESS;
}
