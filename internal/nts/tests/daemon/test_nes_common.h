/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

#ifndef TEST_NES_COMMON_H_
#define TEST_NES_COMMON_H_

#include <CUnit/CUnit.h>

int init_suite_nes_common(void);
int cleanup_suite_nes_common(void);

void add_nes_common_suite_to_registry(void);

#endif /* TEST_NES_COMMON_H_ */

