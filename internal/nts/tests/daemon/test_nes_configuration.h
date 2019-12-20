/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

#ifndef TEST_NES_CONFIGURATION_H_
#define TEST_NES_CONFIGURATION_H_

#include <CUnit/CUnit.h>
#include "ctrl/nes_configuration.h"

int init_suite_nes_configuration(void);
int cleanup_suite_nes_configuration(void);

void add_nes_configuration_suite_to_registry(void);

#endif /* TEST_NES_CONFIGURATION_H_ */
