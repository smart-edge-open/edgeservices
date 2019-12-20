/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

#ifndef TEST_NES_RING_H_
#define TEST_NES_RING_H_

#include <CUnit/CUnit.h>
#include "nes_ring.h"

int init_suite_nes_ring(void);
int cleanup_suite_nes_ring(void);

void add_nes_ring_suite_to_registry(void);

#endif /* TEST_NES_RING_H_ */

