/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

#ifndef TEST_NES_DNS_H
#define	TEST_NES_DNS_H

#include <CUnit/CUnit.h>

int init_suite_nes_dns(void);
int cleanup_suite_nes_dns(void);

void add_nes_dns_suite_to_registry(void);

#endif	/* TEST_NES_DNS_H */
