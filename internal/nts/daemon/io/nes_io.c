/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

/**
 * @file nes_io.c
 * @brief Implementation of nes i/o
 */

#include <rte_config.h>
#include <rte_log.h>
#include <rte_cycles.h>
#include <rte_malloc.h>
#include "nes_common.h"
#include "libnes_queue.h"
#include "libnes_cfgfile.h"
#include "io/nes_dev.h"
#include "io/nes_io.h"
#include "io/nes_mac_lookup.h"

static nes_queue_t nes_io_devices;
rte_atomic32_t threads_started = RTE_ATOMIC32_INIT(0);

__attribute__((constructor))
static void nes_io_early_init(void)
{
	nes_queue_ctor(&nes_io_devices);
}

void nes_io_dev_queue_get(nes_queue_t **queue)
{
	*queue = &nes_io_devices;
}

static int nes_io_init(void)
{
	return nes_mac_lookup_init();
}

int nes_io_main(__attribute__((unused))void *arg)
{
	if (NES_SUCCESS != nes_io_init()) {
		NES_LOG(EMERG,"NES:IO_THREAD init failed.\n");
		return NES_FAIL;
	}

	while (THREADS_MASK != rte_atomic32_read(&threads_started))
		usleep(1);

	NES_LOG(INFO, "NES_IO started\n");
	for (NES_FOREVER_LOOP) {
		nes_dev_t *device;
		nes_queue_node_t *node, *removed_node;
		/* Receive, scatter and send*/
		NES_QUEUE_FOREACH(node, &nes_io_devices) {
			device = node->data;
			if (device->recv)
				device->recv(device,NULL);
			if (device->scatter)
				device->scatter(device,NULL);
			if (device->send)
				device->send(device,NULL);
			if (unlikely(device->remove)) {
				nes_queue_node_unlock(node);
				if ((removed_node = nes_queue_remove(&nes_io_devices,
						node)) != NULL) {
					/*rte_free(device);*/
					rte_free(removed_node);
				}
				break;
			}

		} /* end for all devices nodes */
	} /* end for(;;) */

	return NES_SUCCESS;

}
