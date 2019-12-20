/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

#ifndef TEST_NES_DEV_PORT_H_
#define TEST_NES_DEV_PORT_H_

#include <CUnit/CUnit.h>

int init_suite_nes_dev_port(void);
int cleanup_suite_nes_dev_port(void);

void test_nes_dev_port_new_device(void);
void test_get_port_rings(void);
void test_scatter_port(void);
void test_scatter_eth_lbp(void);
void test_ctor_eth_port(void);
void test_add_ring_to_ntsqueue(void);
void test_dtor_port(void);

void add_nes_dev_port_suite_to_registry(void);

#endif /* TEST_NES_DEV_PORT_H_ */
