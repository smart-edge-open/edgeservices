/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

#ifndef TEST_NTS_IO_H_
#define TEST_NTS_IO_H_

#include <CUnit/CUnit.h>

extern CU_TestInfo tests_suite_nts_io[];

int init_suite_nts_io(void);
int cleanup_suite_nts_io(void);

void nts_io_init_test(void);
void nts_io_main_test(void);

void add_nts_io_suite_to_registry(void);

#endif /* TEST_NTS_IO_H_ */
