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

#ifndef NIS_PARAM_H_
#define NIS_PARAM_H_

#include "libnes_acl.h"

typedef struct nis_param_rab_s {
	uint32_t teid;
	uint8_t qci;
	uint8_t spid;
} nis_param_rab_t;

typedef struct nis_param_pkt_flow_s {
	uint8_t proto;
	uint32_t inner_src_ip;
	uint32_t inner_src_ip_mask;
	uint32_t inner_dst_ip;
	uint32_t inner_dst_ip_mask;
	uint16_t inner_src_port;
	uint16_t inner_src_port_max;
	uint16_t inner_dst_port;
	uint16_t inner_dst_port_max;
	uint8_t tos;
	uint8_t tos_mask;
} nis_param_pkt_flow_t;

int nis_param_init(nes_acl_ctx_t *ctx);

void nis_param_ctx_dtor(nes_acl_ctx_t *ctx);

int nis_param_rab_set(nes_acl_ctx_t *ctx, nis_param_pkt_flow_t *flow, nis_param_rab_t *rab_params);

int nis_param_rab_get(nes_acl_ctx_t *ctx, nis_param_pkt_flow_t *flow,
	nis_param_rab_t ** rab_params);

int nis_param_rab_del(nes_acl_ctx_t *ctx, nis_param_pkt_flow_t *flow);

#endif /*NIS_PARAM_H_*/
