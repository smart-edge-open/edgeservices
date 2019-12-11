/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

#include <rte_acl.h>
#include "nes_capacity.h"
#include "nis/nis_acl.h"
#include "nes_common.h"
#include "libnes_acl.h"
#include "nis_routing_data.h"
#ifdef UNIT_TESTS
	#include "nis_acl_decl.h"
#endif

#define NIS_ACL_NAME "NIS_ACL_LOOKUP"
#define NIS_ACL_CFG_DEFAULT_CATEGORY 1
#define NIS_ACL_CFG_DEFAULT_PRIO 1

static struct rte_acl_field_def nis_acl_lookup_fields[NIS_FIELD_NUMS_IPV4] = {
	{
		.type = RTE_ACL_FIELD_TYPE_BITMASK,
		.size = sizeof (uint8_t),
		.field_index = NIS_FIELD_PROTO_IPV4,
		.input_index = NIS_ACL_PROTO,
		.offset = 0,
	},
	{
		.type = RTE_ACL_FIELD_TYPE_MASK,
		.size = sizeof (uint32_t),
		.field_index = NIS_FIELD_INNER_SRC_IPV4,
		.input_index = NIS_ACL_INNER_SRC_IP,
		.offset = offsetof(nis_acl_tuple_t, inner_ip_src),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_MASK,
		.size = sizeof (uint32_t),
		.field_index = NIS_FIELD_INNER_DST_IPV4,
		.input_index = NIS_ACL_INNER_DST_IP,
		.offset = offsetof(nis_acl_tuple_t, inner_ip_dst),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_RANGE,
		.size = sizeof (uint16_t),
		.field_index = NIS_FIELD_INNER_SRC_PORT_IPV4,
		.input_index = NIS_ACL_PORTS,
		.offset = offsetof(nis_acl_tuple_t, inner_port_src),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_RANGE,
		.size = sizeof (uint16_t),
		.field_index = NIS_FIELD_INNER_DST_PORT_IPV4,
		.input_index = NIS_ACL_PORTS,
		.offset = offsetof(nis_acl_tuple_t, inner_port_dst),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_BITMASK,
		.size = sizeof (uint8_t),
		.field_index = NIS_FIELD_TOS_IPV4,
		.input_index = NIS_ACL_TOS,
		.offset = offsetof(nis_acl_tuple_t, tos),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_BITMASK,
		.size = sizeof (uint8_t),
		.field_index = NIS_FIELD_PADDING1_IPV4,
		.input_index = NIS_ACL_TOS,
		.offset = offsetof(nis_acl_tuple_t, _padding1),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_BITMASK,
		.size = sizeof (uint16_t),
		.field_index = NIS_FIELD_PADDING2_IPV4,
		.input_index = NIS_ACL_TOS,
		.offset = offsetof(nis_acl_tuple_t, _padding2),
	},
};

int nis_acl_rule_prepare(struct nis_acl_lookup_field *lookup, nis_param_pkt_flow_t* tft_param)
{
	if (NULL == lookup || NULL == tft_param)
		return NES_FAIL;

	lookup->data = (struct rte_acl_rule_data) {
		.userdata = 1,
		.category_mask = NIS_ACL_CFG_DEFAULT_CATEGORY,
		.priority = NIS_ACL_CFG_DEFAULT_PRIO
	};
	lookup->field[NIS_FIELD_PROTO_IPV4].value.u8 = tft_param->proto;
	lookup->field[NIS_FIELD_PROTO_IPV4].mask_range.u8 = 0xff;
	lookup->field[NIS_FIELD_INNER_SRC_IPV4].value.u32 = tft_param->inner_src_ip;
	lookup->field[NIS_FIELD_INNER_SRC_IPV4].mask_range.u32 = tft_param->inner_src_ip_mask;
	lookup->field[NIS_FIELD_INNER_DST_IPV4].value.u32 = tft_param->inner_dst_ip;
	lookup->field[NIS_FIELD_INNER_DST_IPV4].mask_range.u32 = tft_param->inner_dst_ip_mask;
	lookup->field[NIS_FIELD_INNER_SRC_PORT_IPV4].value.u16 = tft_param->inner_src_port;
	lookup->field[NIS_FIELD_INNER_SRC_PORT_IPV4].mask_range.u16 = tft_param->inner_src_port_max;
	lookup->field[NIS_FIELD_INNER_DST_PORT_IPV4].value.u16 = tft_param->inner_dst_port;
	lookup->field[NIS_FIELD_INNER_DST_PORT_IPV4].mask_range.u16 = tft_param->inner_dst_port_max;
	lookup->field[NIS_FIELD_TOS_IPV4].value.u8 = tft_param->tos;
	lookup->field[NIS_FIELD_TOS_IPV4].mask_range.u8 = tft_param->tos_mask;

	NES_LOG(INFO, "Field proto: %"PRIu8"/%"PRIu8"\n",
		lookup->field[NIS_FIELD_PROTO_IPV4].value.u8,
		lookup->field[NIS_FIELD_PROTO_IPV4].mask_range.u8);
	NES_LOG(INFO, "Field ip src: %"PRIu32"/%"PRIu32"\n",
		lookup->field[NIS_FIELD_INNER_SRC_IPV4].value.u32,
		lookup->field[NIS_FIELD_INNER_SRC_IPV4].mask_range.u32);
	NES_LOG(INFO, "Field ip dst: %"PRIu32"/%"PRIu32"\n",
		lookup->field[NIS_FIELD_INNER_DST_IPV4].value.u32,
		lookup->field[NIS_FIELD_INNER_DST_IPV4].mask_range.u32);
	NES_LOG(INFO, "Field port src: %"PRIu16"-%"PRIu16"\n",
		lookup->field[NIS_FIELD_INNER_SRC_PORT_IPV4].value.u16,
		lookup->field[NIS_FIELD_INNER_SRC_PORT_IPV4].mask_range.u16);
	NES_LOG(INFO, "Field port dst: %"PRIu16"-%"PRIu16"\n",
		lookup->field[NIS_FIELD_INNER_DST_PORT_IPV4].value.u16,
		lookup->field[NIS_FIELD_INNER_DST_PORT_IPV4].mask_range.u16);
	NES_LOG(INFO, "Field tos: %"PRIu8"/%"PRIu8"\n",
		lookup->field[NIS_FIELD_TOS_IPV4].value.u8,
		lookup->field[NIS_FIELD_TOS_IPV4].mask_range.u8);
	return NES_SUCCESS;
}

int
nis_acl_lookup_init(nes_acl_ctx_t* lookup_ctx)
{
	assert(lookup_ctx);

	if (NES_SUCCESS != nes_acl_ctor(lookup_ctx, NIS_ACL_NAME, sizeof (nis_param_rab_t),
			NES_MAX_RB, nis_acl_lookup_fields, RTE_DIM(nis_acl_lookup_fields))) {
		NES_LOG(ERR, "nes_acl constructor failed\n");
		return NES_FAIL;
	}
	return nis_routing_data_init();
}

int
nis_acl_lookup_add(nes_acl_ctx_t* lookup_ctx, nis_param_pkt_flow_t* flow_ptr,
	nis_param_rab_t* rab_params)
{
	assert(lookup_ctx);

	struct nis_acl_lookup_field rule;
	struct nis_acl_lookup_field *rule_ptr;
	nis_param_rab_t * entry_ptr;


	if (NULL == flow_ptr || NULL == rab_params) {
		NES_LOG(ERR, "Flow parameters pointer is NULL\n");
		return NES_FAIL;
	}

	rule_ptr = &rule;
	memset(rule_ptr, 0, sizeof (struct nis_acl_lookup_field));
	nis_acl_rule_prepare(rule_ptr, flow_ptr);

	entry_ptr = rab_params;
	NES_LOG(INFO, "rab params: TEID: %"PRIu32", SPID: %"PRIu8", QCI: %"PRIu8".\n",
		rab_params->teid, rab_params->spid, rab_params->qci);

	if (NES_SUCCESS != nes_acl_add_entries(lookup_ctx, (void**) &entry_ptr,
			(struct rte_acl_rule**) &rule_ptr, 1)) {
		NES_LOG(ERR, "Could not add flow rule");
		return NES_FAIL;
	}

	return NES_SUCCESS;
}

int
nis_acl_lookup_find(nes_acl_ctx_t* lookup_ctx, nis_param_pkt_flow_t* flow_ptr,
	nis_param_rab_t** entries)
{
	assert(lookup_ctx);

	struct nis_acl_lookup_field lookup_field;
	int i;

	if (NULL == flow_ptr) {
		NES_LOG(ERR, "Flow parameters pointer is NULL\n");
		return NES_FAIL;
	}

	memset(&lookup_field, 0, sizeof (struct nis_acl_lookup_field));

	nis_acl_rule_prepare(&lookup_field, flow_ptr);

	i = nes_acl_find_rule_id(lookup_ctx, (struct rte_acl_rule*)&lookup_field);
	if (i < 0)
		return NES_FAIL;

	i = lookup_ctx->rules[i]->data.userdata - USER_DATA_OFFSET;

	*entries = lookup_ctx->entries[i];
	return NES_SUCCESS;
}

int nis_acl_lookup_del(nes_acl_ctx_t *lookup_ctx, nis_param_pkt_flow_t *flow_ptr)
{
	assert(lookup_ctx);

	struct nis_acl_lookup_field lookup_field;

	if (NULL == flow_ptr) {
		NES_LOG(ERR, "Flow parameters pointer is NULL\n");
		return NES_FAIL;
	}

	memset(&lookup_field, 0, sizeof (struct nis_acl_lookup_field));

	nis_acl_rule_prepare(&lookup_field, flow_ptr);

	if (NES_SUCCESS != nes_acl_del_entry(lookup_ctx,(struct rte_acl_rule *) &lookup_field))
		return NES_FAIL;

	return NES_SUCCESS;
}

void
nis_acl_lookup_dtor(nes_acl_ctx_t* lookup_ctx) {

	assert(lookup_ctx);

	nes_acl_dtor(lookup_ctx);
	nis_routing_data_dtor();
}
