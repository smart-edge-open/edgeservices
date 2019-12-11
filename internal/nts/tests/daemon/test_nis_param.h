/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

#ifndef TEST_NIS_PARAM_H_
#define TEST_NIS_PARAM_H_

#include <CUnit/CUnit.h>

int init_suite_nis_param(void);
int cleanup_suite_nis_param(void);

void add_nis_param_suite_to_registry(void);

#endif /* TEST_NIS_PARAM_H_ */
