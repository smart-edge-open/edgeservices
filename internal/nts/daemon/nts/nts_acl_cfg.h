/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

/**
 * @file nts_acl_cfg.h
 * @brief Header file for nts_acl_cfg
 */

#ifndef NTS_ACL_CFG
#define NTS_ACL_CFG

#ifdef	__cplusplus
extern "C" {
#endif

#include <rte_acl.h>
#include <rte_ether.h>
#include <rte_spinlock.h>

#include "nts/nts_route.h"
#include "nes_common.h"
#include "nts/nts_lookup.h"
#include "libnes_sq.h"
#include "libnes_acl.h"


#define NTS_ACL_VM_NAME_LENGTH 20
#define NTS_ACL_CFG_ENTRY_NAME "route"
#define NTS_ACL_CFG_ENTRY_MIRROR_NAME "route-mirror"

typedef struct nts_acl_tuple_s {
	uint8_t encap_flag;
	uint8_t qci;
	uint8_t spid;
	uint16_t _padding;
	uint32_t teid;
	uint32_t outer_ip_src;
	uint32_t outer_ip_dst;
	uint32_t inner_ip_src;
	uint32_t inner_ip_dst;
	uint16_t inner_port_src;
	uint16_t inner_port_dst;
} __attribute__((__packed__)) nts_acl_tuple_t;

enum {
	FIELD_ENCAP_PROTO_IPV4,
	FIELD_QCI,
	FIELD_SPID,
	FIELD_PADDING,
	FIELD_TEID,
	FIELD_OUTER_SRC_IPV4,
	FIELD_OUTER_DST_IPV4,
	FIELD_INNER_SRC_IPV4,
	FIELD_INNER_DST_IPV4,
	FIELD_INNER_SRC_PORT_IPV4,
	FIELD_INNER_DST_PORT_IPV4,
	FIELD_NUMS_IPV4
};

enum {
	ACL_ENCAP_PROTO,
	ACL_QCI_SPID_PAD,
	ACL_TEID,
	ACL_OUTER_SRC_IP,
	ACL_OUTER_DST_IP,
	ACL_INNER_SRC_IP,
	ACL_INNER_DST_IP,
	ACL_INNER_PORTS,
	ACL_NUM
};

enum {
	PRI_IDX_QCI,
	PRI_IDX_SPID,
	PRI_IDX_TEID,
	PRI_IDX_OUTER_IP,
	PRI_IDX_INNER_IP,
	PRI_IDX_INNER_PORT,
	PRI_IDX_NUM
};

enum {
	NTS_ACL_LOOKUPS_MATCH,
	NTS_ACL_LOOKUPS_DIFFER,
	NTS_ACL_LOOKUPS_OVERLAP
};

RTE_ACL_RULE_DEF(nts_acl_lookup_field, FIELD_NUMS_IPV4);



int nts_acl_cfg_init_vm_rings_names(void);

void nts_acl_cfg_free_vm_rings_names(void);

const char* nts_acl_cfg_tx_ring_name_get(int vm_num);

int nts_acl_cfg_lookup_prepare(struct nts_acl_lookup_field *lookup,
	struct nts_acl_lookup_field *reverse_lookup, const char* lookup_str);

int nts_acl_cfg_route_entry_prepare(const char* ring_name, struct ether_addr mac_addr,
	nts_route_entry_t *route_entry, nts_edit_modes_t edit_mode);

int nts_acl_cfg_overlaps(nes_acl_ctx_t* lookup_ctx, struct nts_acl_lookup_field *lookup);

int nes_acl_ether_aton(const char *mac, struct ether_addr *ether_address);

int nts_acl_get_field_from_lookup(const struct nts_acl_lookup_field *lookup,
	const char *field_name, void *value, void* mask, size_t size);

#ifdef	__cplusplus
}
#endif

#endif	/* NTS_ACL_CFG */
