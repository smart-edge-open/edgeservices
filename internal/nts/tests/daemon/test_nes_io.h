/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

#ifndef TEST_NES_IO_H_
#define TEST_NES_IO_H_

#include <CUnit/CUnit.h>

int init_suite_nes_io(void);
int cleanup_suite_nes_io(void);

void add_nes_io_suite_to_registry(void);

#endif /* TEST_NES_IO_H_ */
