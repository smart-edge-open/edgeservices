/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

#ifndef TEST_NES_ARP_H_
#define TEST_NES_ARP_H_

#include <CUnit/CUnit.h>

int init_suite_nes_arp(void);
int cleanup_suite_nes_arp(void);

void add_nes_arp_suite_to_registry(void);

#endif /* TEST_NES_ARP_H_ */

