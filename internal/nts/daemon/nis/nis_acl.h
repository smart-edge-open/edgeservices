/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

#ifndef NIS_ACL_H_
#define NIS_ACL_H_


#include "libnes_acl.h"
#include <rte_acl.h>
#include "nis/nis_param.h"

typedef struct nis_acl_flow_entry_s {
	uint32_t teid;
	uint8_t qci;
	uint8_t spid;
} nis_acl_flow_entry_t;

typedef struct nis_acl_tuple_s {
	uint8_t proto;
	uint32_t inner_ip_src;
	uint32_t inner_ip_dst;
	uint16_t inner_port_src;
	uint16_t inner_port_dst;
	uint8_t tos;
	uint8_t _padding1;
	uint16_t _padding2; // multiples of 32bits for performance rte_acl reasons
} __attribute__((__packed__)) nis_acl_tuple_t;

enum {
	NIS_FIELD_PROTO_IPV4,
	NIS_FIELD_INNER_SRC_IPV4,
	NIS_FIELD_INNER_DST_IPV4,
	NIS_FIELD_INNER_SRC_PORT_IPV4,
	NIS_FIELD_INNER_DST_PORT_IPV4,
	NIS_FIELD_TOS_IPV4,
	NIS_FIELD_PADDING1_IPV4,
	NIS_FIELD_PADDING2_IPV4,
	NIS_FIELD_NUMS_IPV4
};

enum {
	NIS_ACL_PROTO,
	NIS_ACL_INNER_SRC_IP,
	NIS_ACL_INNER_DST_IP,
	NIS_ACL_PORTS,
	NIS_ACL_TOS,
	NIS_ACL_NUM
};

RTE_ACL_RULE_DEF(nis_acl_lookup_field, NIS_FIELD_NUMS_IPV4);

int nis_acl_rule_prepare(struct nis_acl_lookup_field *lookup, nis_param_pkt_flow_t*);

int
nis_acl_lookup_init(nes_acl_ctx_t* lookup_ctx);

int nis_acl_lookup_add(nes_acl_ctx_t* lookup_ctx, nis_param_pkt_flow_t* flow_ptr,
	nis_param_rab_t* rab_params);

int nis_acl_lookup_find(nes_acl_ctx_t* lookup_ctx, nis_param_pkt_flow_t* flow_ptr,
	nis_param_rab_t ** param_rab);

int nis_acl_lookup_del(nes_acl_ctx_t* lookup_ctx, nis_param_pkt_flow_t* flow_ptr);

void
nis_acl_lookup_dtor(nes_acl_ctx_t* lookup_ctx);
#endif /*NIS_ACL_H_*/
