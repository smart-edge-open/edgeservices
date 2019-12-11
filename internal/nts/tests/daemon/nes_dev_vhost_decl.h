/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

#ifndef NES_DEV_VHOST_DECL_H_
#define NES_DEV_VHOST_DECL_H_

int nes_dev_vhost_mempool_init(void);
int create_vm_rings(nes_dev_t *self);
int nes_dev_vhost_new_device(int vm_id);
void nes_dev_vhost_destroy_device(int vm_id);
int dtor_vhost(nes_dev_t *self, __attribute__((unused)) void *data);
int ctor_vhost(nes_dev_t *self, __attribute__((unused)) void *data);
int mac_authorized(struct nes_dev_s *self, struct rte_mbuf **m, int pkt_count);
int send_vhost_unauthorized(__attribute__((unused)) struct nes_dev_s *self,
	__attribute__((unused)) void *data);

#ifndef FILE_NAME
	#define FILE_NAME nes_dev_vhost
#endif
#include "mock.h"

int rte_vhost_enable_guest_notification(int dev, uint16_t queue_id, int enable);
uint16_t rte_vhost_dequeue_burst(int vid, uint16_t queue_id,
	struct rte_mempool *mbuf_pool, struct rte_mbuf **pkts, uint16_t count);

MOCK_DECL(rte_vhost_enable_guest_notification);
#define rte_vhost_enable_guest_notification MOCK_NAME(mocked_rte_vhost_enable_guest_notification)

MOCK_DECL(rte_vhost_dequeue_burst);
#define rte_vhost_dequeue_burst MOCK_NAME(mocked_rte_vhost_dequeue_burst)

#endif
