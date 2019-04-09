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
* @file nes_dev_egressport.h
* @brief Header file for egress port inline functions.
*/

#ifndef NES_DEV_EGRESSPORT_H
#define NES_DEV_EGRESSPORT_H

#ifdef __cplusplus
extern "C" {
#endif

#include "nes_ring.h"
#include "io/nes_dev.h"

typedef struct egress_port_s
{
	struct src {
		nes_ring_t  *ring;
		/* determine if this ring could be overwritten by learning */
		int         from_config;
	} src;
	struct dst {
		nes_ring_t  *ring;
	} dst;
	nes_dev_traffic_dir  direction;
} egress_port_t;

static inline nes_ring_t *get_egress_ring_from_src_ip(uint32_t src_ip)
{
	egress_port_t *remote;
	assert(NULL != egress_port_table);

	if (NES_SUCCESS == nes_lookup_entry_find(egress_port_table, &src_ip, (void**)&remote))
		return remote->src.ring;

	return NULL;
}

static inline nes_ring_t *get_egress_ring_from_dst_ip(uint32_t dst_ip)
{
	egress_port_t *remote;
	assert(NULL != egress_port_table);

	if (NES_SUCCESS == nes_lookup_entry_find(egress_port_table, &dst_ip, (void**)&remote))
		return remote->dst.ring;

	return NULL;
}

static inline nes_ring_t *get_egress_ring_from_ips(uint32_t src_ip, uint32_t dst_ip)
{
	assert(NULL != egress_port_table);

	nes_ring_t *ring = get_egress_ring_from_dst_ip(dst_ip);
	if (NULL != ring)
		return ring;

	return get_egress_ring_from_src_ip(src_ip);
}

#ifdef __cplusplus
}
#endif

#endif /* NES_DEV_EGRESSPORT_H */
