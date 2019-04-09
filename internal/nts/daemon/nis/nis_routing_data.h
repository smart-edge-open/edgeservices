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
* @file nis_routing_data.h
* @brief Header file for nis_routing_data
*/

#ifndef NIS_ROUTE_DATA_H
#define	NIS_ROUTE_DATA_H

#ifdef	__cplusplus
extern "C" {
#endif

#include "ctrl/nes_ctrl.h"

typedef struct nis_routing_data_s {
	uint8_t qci;
	uint8_t spid;
} nis_routing_data_t;

typedef struct nis_routing_data_key_s {
	uint32_t teid;
	uint32_t enb_ip;
	nes_direction_t direction;
} __attribute__((__packed__)) nis_routing_data_key_t;

int nis_routing_data_get(const nis_routing_data_key_t *key, nis_routing_data_t **data);

int nis_routing_data_init(void);

int nis_routing_data_add(const nis_routing_data_key_t *key, nis_routing_data_t *data);

int nis_routing_data_del(const nis_routing_data_key_t *key);

void nis_routing_data_dtor(void);

#ifdef	__cplusplus
}
#endif

#endif	/* NIS_ROUTE_DATA_H */
