/*******************************************************************************
* Copyright 2019 Intel Corporation. All rights reserved.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*******************************************************************************/

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
