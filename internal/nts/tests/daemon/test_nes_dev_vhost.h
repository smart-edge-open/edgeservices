/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

#ifndef TEST_NES_DEV_VHOST_H_
#define TEST_NES_DEV_VHOST_H_

#include <CUnit/CUnit.h>

int init_suite_nes_dev_vhost(void);
int cleanup_suite_nes_dev_vhost(void);

int rte_vhost_enable_guest_notification_stub(int, uint16_t, int);
void *destroy_thread_start(void *arg);

void add_nes_dev_vhost_suite_to_registry(void);

#endif /* TEST_NES_DEV_VHOST_H_ */
