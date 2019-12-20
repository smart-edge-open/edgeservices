/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

#ifndef TEST_NES_MAC_LOOKUP_H_
#define TEST_NES_MAC_LOOKUP_H_

#include <CUnit/CUnit.h>

int init_suite_nes_mac_lookup(void);
int cleanup_suite_nes_mac_lookup(void);

void add_nes_mac_lookup_suite_to_registry(void);

#endif /* TEST_NES_MAC_LOOKUP_H_ */
