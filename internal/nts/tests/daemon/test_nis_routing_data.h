/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

#ifndef TEST_NIS_ROUTING_DATA_H_
#define TEST_NIS_ROUTING_DATA_H_

#include <CUnit/CUnit.h>

int init_suite_nis_routing_data(void);
int cleanup_suite_nis_routing_data(void);

void add_nis_routing_data_suite_to_registry(void);

#endif /* TEST_NIS_ROUTING_DATA_H_ */
