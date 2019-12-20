/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

/**
 * @file nes_dev_addons.h
 * @brief Header file for nes addons.
 */

#ifndef _NES_DEV_ADDONS_H_
#define _NES_DEV_ADDONS_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_pci.h>
#include <rte_ether.h>

#include "nes_dev.h"
#include "nes_ring.h"

#define NES_TABQ_MAX_ELEMENTS 16

typedef struct nes_tabq_s
{
	nes_dev_t   *device;
	int         next_idx;
} nes_tabq_t;

extern nes_tabq_t devices_tab[NES_TABQ_MAX_ELEMENTS];
static inline nes_ring_t *nes_dev_get_egressring_from_port_idx(int idx)
{
	if (NES_TABQ_MAX_ELEMENTS <= idx)
		return NULL;
	if (unlikely(NULL == devices_tab[idx].device))
		return NULL;
	return (nes_ring_t *)devices_tab[idx].device->rx_default_ring;
}

int nes_dev_tabq_init(void);
nes_dev_t *nes_dev_get_device_by_idx(int idx);
int nes_dev_add_device(nes_dev_t *device);
int nes_dev_del_device(nes_dev_t *device);
nes_dev_t *nes_dev_get_device_by_tx_ring(const nes_ring_t *ring_ptr);

#ifdef __cplusplus
}
#endif /* extern "C" */

#endif /* _NES_DEV_ADDONS_H_ */
