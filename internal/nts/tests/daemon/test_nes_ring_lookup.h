/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

#ifndef TEST_NES_RING_LOOKUP_H_
#define TEST_NES_RING_LOOKUP_H_

#include <CUnit/CUnit.h>
#include "nes_ring_lookup.h"

int init_suite_nes_ring_lookup(void);
int cleanup_suite_nes_ring_lookup(void);

void nes_ring_add(const char *name, nes_ring_t *entry);
void nes_ring_del(const char *name);

struct nes_rings_bak_s {
	const char *name;
	nes_ring_t *ring;
};

void add_nes_ring_lookup_suite_to_registry(void);

#endif /* TEST_NES_RING_LOOKUP_H_ */

