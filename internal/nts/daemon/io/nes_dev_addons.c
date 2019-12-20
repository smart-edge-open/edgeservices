/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

/**
 * @file nes_dev_addons.c
 * @brief Implementation of tabq
 */

#include <rte_config.h>
#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_ip.h>
#include <rte_log.h>
#include <rte_udp.h>
#include <rte_alarm.h>
#include <rte_malloc.h>
#include "ctrl/nes_ctrl.h"
#include "nes_common.h"
#include "nes_dev_addons.h"
#include "nes_io.h"

nes_tabq_t devices_tab[NES_TABQ_MAX_ELEMENTS];
static nes_queue_t * nes_io_devices;

int nes_dev_tabq_init(void)
{
	memset(devices_tab, 0, sizeof(nes_tabq_t)*NES_TABQ_MAX_ELEMENTS);
	nes_io_dev_queue_get(&nes_io_devices);
	return NES_SUCCESS;
}

nes_dev_t *nes_dev_get_device_by_idx(int idx)
{
	if (NES_TABQ_MAX_ELEMENTS <= idx)
		return NULL;
	return (nes_dev_t *)devices_tab[idx].device;
}

nes_dev_t *nes_dev_get_device_by_tx_ring(const nes_ring_t *ring_ptr)
{
	int i;
	if (NULL == ring_ptr)
		return NULL;
	for (i = 0; i < NES_TABQ_MAX_ELEMENTS; i++) {
		if (NULL != devices_tab[i].device)
			if (devices_tab[i].device->tx_ring == ring_ptr)
				return (nes_dev_t *)devices_tab[i].device;
	}
	return NULL;
}

int nes_dev_add_device(nes_dev_t *device)
{
	if (ETH == device->dev_type) {
		int port_id = device->dev.eth.port_id;
		if (NES_TABQ_MAX_ELEMENTS <= port_id)
			return NES_FAIL;

		devices_tab[port_id].device = device;
		int i;
		/* get next valid device */
		for (i = port_id + 1; i < NES_TABQ_MAX_ELEMENTS; i++) {
			if (NULL != devices_tab[i].device) {
				devices_tab[port_id].next_idx = i;
				break;
			}
		}
		for (i = port_id - 1; i >= 0; i--) {
			devices_tab[i].next_idx = port_id;
			if (NULL != devices_tab[i].device)
				break;
		}
	}
	nes_ctrl_add_device(device, device->name);
	nes_queue_enqueue(nes_io_devices, device);
	return NES_SUCCESS;
}

int nes_dev_del_device(nes_dev_t *device)
{
	int port_id = device->dev.eth.port_id;
	nes_ctrl_del_device(device);
	if (ETH == device->dev_type) {
		if (NES_TABQ_MAX_ELEMENTS <= port_id)
			return NES_FAIL;
		int i;
		devices_tab[port_id].device = NULL;
		/* get next valid device */
		for (i = port_id + 1; i < NES_TABQ_MAX_ELEMENTS; i++) {
			if (NULL != devices_tab[i].device)
				break;
		}
		if (NES_TABQ_MAX_ELEMENTS != i) {
			for (; port_id >= 0; port_id--) {
				devices_tab[port_id].next_idx = i;
				if (NULL != devices_tab[port_id].device)
					break;
			}
		}
	}
	return NES_SUCCESS;
}
