/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

#ifndef TEST_NTS_LOOKUP_H
#define	TEST_NTS_LOOKUP_H

#include <CUnit/CUnit.h>

int init_suite_nts_lookup(void);
int cleanup_suite_nts_lookup(void);

void add_nts_lookup_suite_to_registry(void);

#endif	/* TEST_NTS_LOOKUP_H */
