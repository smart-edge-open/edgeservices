/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

#ifndef TEST_NES_MAIN_H_
#define TEST_NES_MAIN_H_

#include <CUnit/CUnit.h>

int init_suite_nes_main(void);
int cleanup_suite_nes_main(void);

void add_nes_main_suite_to_registry(void);

#endif
