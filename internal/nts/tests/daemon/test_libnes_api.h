/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

#ifndef TEST_LIBNES_API_H_
#define TEST_LIBNES_API_H_

#include <CUnit/CUnit.h>

int init_suite_libnes_api(void);
int cleanup_suite_libnes_api(void);

void add_nes_libnes_api_suite_to_registry(void);

#endif /* TEST_LIBNES_API_H_ */
