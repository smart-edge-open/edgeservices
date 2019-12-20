/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

#ifndef TEST_NIS_IO_H_
#define TEST_NIS_IO_H_

#include <CUnit/CUnit.h>

int init_suite_nis_io(void);
int cleanup_suite_nis_io(void);

void add_nis_io_suite_to_registry(void);

#endif /* TEST_NIS_IO_H_ */
