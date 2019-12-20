/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

/**
 * @file nes_ring_lookup.h
 * @brief Prototypes for NES ring lookup functions
 */

#ifndef _NES_RING_LOOKUP_H_
#define _NES_RING_LOOKUP_H_

#ifdef __cpluplus
extern "C" {
#endif

#include "nes_ring.h"

	int nes_ring_lookup_init(void);
	int nes_ring_find(nes_ring_t **, const char *);
	int nes_ring_lookup_entry_get(const char *,  nes_ring_t **);

#ifdef __cpluplus
}
#endif
#endif /* _NES_RING_LOOKUP_H_ */
