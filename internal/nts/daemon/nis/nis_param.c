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

#include "nis/nis_param.h"
#include "nis/nis_acl.h"
#include "nes_common.h"

int nis_param_init(nes_acl_ctx_t *ctx)
{
	return nis_acl_lookup_init(ctx);
}

void nis_param_ctx_dtor(nes_acl_ctx_t *ctx)
{
	nis_acl_lookup_dtor(ctx);
}

int nis_param_rab_set(nes_acl_ctx_t *ctx, nis_param_pkt_flow_t *flow, nis_param_rab_t *rab_params)
{
	return nis_acl_lookup_add(ctx, flow, rab_params);
}

int nis_param_rab_get(nes_acl_ctx_t *ctx, nis_param_pkt_flow_t *flow, nis_param_rab_t ** param_rab)
{
	return nis_acl_lookup_find(ctx, flow, param_rab);
}

int nis_param_rab_del(nes_acl_ctx_t *ctx, nis_param_pkt_flow_t *flow)
{
	return nis_acl_lookup_del(ctx, flow);
}
