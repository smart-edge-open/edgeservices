/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

#ifndef TEST_NES_DEV_ETH_H_
#define TEST_NES_DEV_ETH_H_

#include <CUnit/CUnit.h>

int init_suite_nes_dev_eth(void);
int cleanup_suite_nes_dev_eth(void);

void test_nes_dev_eth_pci_addr_get(void);
void test_nes_dev_eth_mac_addr_get(void);
void test_check_eth_port_link_status(void);
void test_init_eth_port(void);
void test_send_eth(void);
void test_recv_eth(void);

void add_nes_dev_eth_suite_to_registry(void);

#endif /* TEST_NES_DEV_ETH_H_ */
