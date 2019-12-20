/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

/**
 * @file nts_acl_cfg.c
 * @brief Implementation of nts acl config loading
 */

#include <assert.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include <rte_ip.h>
#include <rte_ether.h>

#include "nts/nts_acl_cfg.h"
#include "nes_ring.h"
#include "nts/nts_route.h"
#include "libnes_cfgfile.h"
#include "nes_ring_lookup.h"
#include "nts/nts_edit.h"
#include "io/nes_mac_lookup.h"

static int nts_acl_cfg_vm_max;
static char **nts_acl_cfg_tx_ring_names;

#define NTS_ACL_CFG_DEFAULT_RANGE_SEP '-'
#define NTS_ACL_CFG_MAX_LOOKUP_STR_LEN 256
#define NTS_ACL_CFG_FIELD_PRIO 255
#define NTS_ACL_CFG_DEFAULT_CATEGORY 1
#define NTS_ACL_CFG_VM_ID_OFFSET 1
#define NTS_ACL_CFG_MAX_IPV4_MASK 32


#define PARSE_VAL_RANGE(IN, VAL, LIMIT_VAL, RANGE, LIMIT_RANGE, SEP) \
	do { \
		uint32_t res_val, res_range; \
		char *end; \
		const char *buffer = strchr((IN), (SEP)); \
		if (NULL != buffer) { \
			res_range = strtoul(buffer + 1, &end, 0); \
			if (*end != 0) \
				return NES_FAIL; \
			res_val = strtoul((IN), &end, 0); \
			if (*end != (SEP)) \
				return NES_FAIL; \
		} else { \
			res_val = res_range = strtoul((IN), &end, 0); \
			if (*end != 0) \
				return NES_FAIL; \
		} \
		if ((res_val > (LIMIT_VAL) && (LIMIT_VAL) > 0) || \
				(res_range > (LIMIT_RANGE) && (LIMIT_RANGE) > 0)) { \
			NES_LOG(ERR, "Invalid value-range in %s\n", (IN)); \
			return NES_FAIL; \
		} \
		if ((VAL)) \
			*(VAL) = res_val; \
		if ((RANGE)) \
			*(RANGE) = res_range; \
		return NES_SUCCESS; \
	} while(0)

int
nts_acl_cfg_init_vm_rings_names(void) {
	int i, j;
	const char *buffer;
	if (NES_SUCCESS != nes_cfgfile_entry("VM common", "max", &buffer)) {
		NES_LOG(ERR, "Missing: section %s, entry %s, in config file.\n",
			"VM common", "max");
		return NES_FAIL;
	}
	nts_acl_cfg_vm_max = atoi(buffer);

	nts_acl_cfg_tx_ring_names = rte_malloc(
		"Ring names table",
		nts_acl_cfg_vm_max * sizeof (char*),
		0);

	if (NULL == nts_acl_cfg_tx_ring_names) {
		NES_LOG(ERR, "Could not allocate table for VM ring names.\n");
		return NES_FAIL;
	}
	for (i = 0; i < nts_acl_cfg_vm_max; i++) {
		nts_acl_cfg_tx_ring_names[i] = rte_malloc(
			"Ring name",
			NES_RING_NAME_LEN,
			0);
		if (NULL == nts_acl_cfg_tx_ring_names[i]) {
			NES_LOG(ERR, "Ring name allocation failed");
			break;
		}
	}
	if (i < nts_acl_cfg_vm_max) {
		for (j = 0; j < i; j++)
			rte_free(nts_acl_cfg_tx_ring_names[j]);

		return NES_FAIL;
	}

	for (i = 0; i < nts_acl_cfg_vm_max; i++) {
		snprintf(
			nts_acl_cfg_tx_ring_names[i],
			NES_RING_NAME_LEN,
			"IO_VM%d_ANY",
			i);
	}
	return NES_SUCCESS;
}

void
nts_acl_cfg_free_vm_rings_names(void) {
	int i;
	for (i = 0; i < nts_acl_cfg_vm_max; i++)
		rte_free(nts_acl_cfg_tx_ring_names[i]);

	rte_free(nts_acl_cfg_tx_ring_names);

}

const char*
nts_acl_cfg_tx_ring_name_get(int vm_num) {
	if (0 > vm_num || vm_num >= nts_acl_cfg_vm_max)
		return NULL;

	if (NULL == nts_acl_cfg_tx_ring_names)
		return NULL;

	return nts_acl_cfg_tx_ring_names[vm_num];
}

int
nes_acl_ether_aton(const char *mac, struct ether_addr *ether_address) {
	int i;
	char *end;
	unsigned long data[ETHER_ADDR_LEN];

	i = 0;
	do {
		errno = 0;
		data[i] = strtoul(mac, &end, 16);
		if (errno != 0 || end == mac || (end[0] != ':' && end[0] != 0))
			return NES_FAIL;
		mac = end + 1;
	} while (++i != sizeof (data) / sizeof (data[0]) && end[0] != 0);

	if (end[0] != 0)
		return NES_FAIL;

	/* format XX:XX:XX:XX:XX:XX */
	if (i == ETHER_ADDR_LEN) {
		while (i-- != 0) {
			if (data[i] > UINT8_MAX)
				return NES_FAIL;
			ether_address->addr_bytes[i] = (uint8_t) data[i];
		}
	}
	return NES_SUCCESS;
}

static uint32_t
gen_bit_mask(uint8_t mask_len) {
	if (32 == mask_len)
		return UINT32_MAX;
	return ((1 << mask_len) - 1) << (32 - mask_len);
}

static inline int
nts_acl_cfg_parse_u8_val_range(const char *in, uint8_t *val, uint8_t *range) {
	PARSE_VAL_RANGE(in, val, UINT8_MAX, range, UINT8_MAX, NTS_ACL_CFG_DEFAULT_RANGE_SEP);
}

static inline int
nts_acl_cfg_parse_u16_val_range(const char *in, uint16_t *val, uint16_t *range) {
	PARSE_VAL_RANGE(in, val, UINT16_MAX, range, UINT16_MAX, NTS_ACL_CFG_DEFAULT_RANGE_SEP);
}

static inline int
nts_acl_cfg_parse_u32_val_range(const char *in, uint32_t *val, uint32_t *range) {
	PARSE_VAL_RANGE(in, val, UINT32_MAX, range, UINT32_MAX, NTS_ACL_CFG_DEFAULT_RANGE_SEP);
}

static inline int
nts_acl_cfg_parse_prio_val(const char *in, int32_t *out) {
	char* end;
	if (NULL == in)
		return NES_FAIL;

	errno = 0;
	long val = strtol(in, &end, 0);
	if (end == in || *end != 0)
		return NES_FAIL;

	if (val < RTE_ACL_MIN_PRIORITY || val > RTE_ACL_MAX_PRIORITY)
		return NES_FAIL;

	*out = (int32_t) val;
	return NES_SUCCESS;
}

static int
nts_acl_cfg_parse_ipv4_addr(char *in, uint32_t *addr, uint32_t *mask_len) {
	struct in_addr retval;
	uint32_t res_mask;
	char *end;
	char *buffer = strchr(in, '/');
	if (NULL != buffer) {
		res_mask = strtoul(buffer + 1, &end, 0);
		if (*end != 0)
			return NES_FAIL;
		*buffer = 0;
	} else
		res_mask = NTS_ACL_CFG_MAX_IPV4_MASK;

	if (0 == inet_aton(in, &retval) || res_mask > NTS_ACL_CFG_MAX_IPV4_MASK) {
		NES_LOG(ERR, "Invalid IP address %s\n", in);
		return NES_FAIL;
	}
	if (buffer)
		*buffer = '/';

	*addr = ntohl(retval.s_addr);
	*mask_len = res_mask;
	return NES_SUCCESS;
}

#define PROTO_FIELD_GTPU_NAME    "gtpu"
#define PROTO_FIELD_NOENCAP_NAME "noencap"

static int
nts_acl_cfg_parse_encap_proto(char *in, uint8_t *value) {
	uint8_t ret = 0;

	if (0 == strncmp(in, PROTO_FIELD_GTPU_NAME, sizeof(PROTO_FIELD_GTPU_NAME)))
		ret = NTS_ENCAP_GTPU_FLAG;
	else if (0 == strncmp(in, PROTO_FIELD_NOENCAP_NAME, sizeof(PROTO_FIELD_NOENCAP_NAME)))
		ret &=~ NTS_ENCAP_GTPU_FLAG;
	else
		return NES_FAIL;

	*value = ret;
	return NES_SUCCESS;
}

#define COL_L "15"
#define BUFF_LEN 1024

static int
nts_acl_cfg_get_lookup_field_id(const char* field_name) {
	int ret = -1;
	if (strcmp("prio", field_name) == 0)
		ret = NTS_ACL_CFG_FIELD_PRIO;
	else if (strcmp("qci", field_name) == 0)
		ret = FIELD_QCI;
	else if (strcmp("spid", field_name) == 0)
		ret = FIELD_SPID;
	else if (strcmp("teid", field_name) == 0)
		ret = FIELD_TEID;
	else if (strcmp("enb_ip", field_name) == 0)
		ret = FIELD_OUTER_SRC_IPV4;
	else if (strcmp("epc_ip", field_name) == 0)
		ret = FIELD_OUTER_DST_IPV4;
	else if (strcmp("ue_ip", field_name) == 0)
		ret = FIELD_INNER_SRC_IPV4;
	else if (strcmp("srv_ip", field_name) == 0)
		ret = FIELD_INNER_DST_IPV4;
	else if (strcmp("ue_port", field_name) == 0)
		ret = FIELD_INNER_SRC_PORT_IPV4;
	else if (strcmp("srv_port", field_name) == 0)
		ret = FIELD_INNER_DST_PORT_IPV4;
	else if (strcmp("encap_proto", field_name) == 0)
		ret = FIELD_ENCAP_PROTO_IPV4;

	return ret;
}

int
nts_acl_get_field_from_lookup(const struct nts_acl_lookup_field *lookup,
	const char *field_name, void *value, void* mask, size_t size)
{
	int field_id;

	if (NULL == lookup || NULL == field_name || NULL == value) {
		NES_LOG(ERR, "Invalid parameters\n");
		return NES_FAIL;
	}

	field_id = nts_acl_cfg_get_lookup_field_id(field_name);
	if (field_id < 0 || field_id >= FIELD_NUMS_IPV4) {
		NES_LOG(ERR, "Unknown field %s\n", field_name);
		return NES_FAIL;
	}

	switch (size) {
	case sizeof(uint8_t):
		*(uint8_t*)value = lookup->field[field_id].value.u8;
		if (mask)
			*(uint8_t*)mask = lookup->field[field_id].mask_range.u8;
		break;
	case sizeof(uint16_t):
		*(uint16_t*)value = lookup->field[field_id].value.u16;
		if (mask)
			*(uint16_t*)mask = lookup->field[field_id].mask_range.u16;
		break;
	case sizeof(uint32_t):
		*(uint32_t*)value = lookup->field[field_id].value.u32;
		if (mask)
			*(uint32_t*)mask = lookup->field[field_id].mask_range.u32;
		break;
	default:
		NES_LOG(ERR, "Wrong field[%s] size %lu\n", field_name, size);
		return NES_FAIL;
	}
	return NES_SUCCESS;
}

int
nts_acl_cfg_route_entry_prepare(const char* ring_name, struct ether_addr mac_addr,
	nts_route_entry_t *route_entry, nts_edit_modes_t edit_mode) {

	struct mac_entry *mac_data;
	if (NULL == route_entry)
		return NES_FAIL;

	memset(route_entry, 0, sizeof (nts_route_entry_t));

	route_entry->mac_addr = mac_addr;

	if (NULL != ring_name) {
		route_entry->ring_name = ring_name;

		if (NES_FAIL == nes_ring_find(&route_entry->dst_ring, ring_name))
			NES_LOG(INFO, "Could not find ring %s.\n", ring_name);
	} else if (NES_SUCCESS == nes_mac_lookup_entry_find(&mac_addr, &mac_data)) {
		route_entry->ring_name = mac_data->ring_name;
		route_entry->dst_ring = mac_data->ring;
	} else {
		route_entry->ring_name = NULL;
		route_entry->dst_ring = NULL;
	}

	nts_route_entry_edit_set(route_entry, edit_mode);
	return NES_SUCCESS;
}

static void
nts_acl_cfg_init_lookup(struct nts_acl_lookup_field *lookup) {
	assert(lookup);
	memset(lookup, 0, sizeof (struct nts_acl_lookup_field));
	lookup->field[FIELD_ENCAP_PROTO_IPV4].value.u8 = NTS_ENCAP_GTPU_FLAG;
	lookup->field[FIELD_ENCAP_PROTO_IPV4].mask_range.u8 = NTS_ENCAP_GTPU_FLAG;
	lookup->field[FIELD_QCI].value.u8 = 0;
	lookup->field[FIELD_QCI].mask_range.u8 = UINT8_MAX;
	lookup->field[FIELD_SPID].value.u8 = 0;
	lookup->field[FIELD_SPID].mask_range.u8 = UINT8_MAX;
	lookup->field[FIELD_TEID].value.u32 = 0;
	lookup->field[FIELD_TEID].mask_range.u32 = UINT32_MAX;
	// IP Addresses have mask set to 0 which is wildcard
	lookup->field[FIELD_INNER_SRC_PORT_IPV4].value.u16 = 0;
	lookup->field[FIELD_INNER_SRC_PORT_IPV4].mask_range.u16 = UINT16_MAX;
	lookup->field[FIELD_INNER_DST_PORT_IPV4].value.u16 = 0;
	lookup->field[FIELD_INNER_DST_PORT_IPV4].mask_range.u16 = UINT16_MAX;
}

int
nts_acl_cfg_lookup_prepare(struct nts_acl_lookup_field *lookup,
	struct nts_acl_lookup_field *reverse_lookup,
	const char* lookup_str)
{
	assert(lookup);
	assert(lookup_str);
	assert(reverse_lookup);
	struct cfg_lookup_entry cfg_lookup_entries[MAX_LOOKUP_ENTRIES];
	int lookup_entries, i, pure_ip = 0, encap_proto_present = 0;

	nts_acl_cfg_init_lookup(lookup);
	nts_acl_cfg_init_lookup(reverse_lookup);
	if (strlen(lookup_str) > NTS_ACL_CFG_MAX_LOOKUP_STR_LEN) {
		NES_LOG(ERR, "Lookup entry is too long %s", lookup_str);
		return NES_FAIL;
	}

	lookup_entries = nes_cfgfile_num_lookup_entries(lookup_str);
	if (lookup_entries < 2 ||
			NES_SUCCESS != nes_cfgfile_get_lookup_entries(lookup_str,
				cfg_lookup_entries, MAX_LOOKUP_ENTRIES)) {
		NES_LOG(ERR, "Failed parsing lookup %s\n", lookup_str);
		return NES_FAIL;
	}

	/* check if this is a PURE IP routing first */
	for (i = 0; i < lookup_entries; i++) {
		int id = nts_acl_cfg_get_lookup_field_id(cfg_lookup_entries[i].name);
		if (FIELD_ENCAP_PROTO_IPV4 == id) {

			uint8_t val;
			encap_proto_present = 1;
			if (NES_SUCCESS != nts_acl_cfg_parse_encap_proto(
					cfg_lookup_entries[i].value, &val))
				return NES_FAIL;
			if (NTS_ENCAP_GTPU_FLAG & val) {
				lookup->field[id].value.u8 = NTS_ENCAP_GTPU_FLAG;
				lookup->field[id].mask_range.u8 = NTS_ENCAP_GTPU_FLAG;
				reverse_lookup->field[id].value.u8 = NTS_ENCAP_GTPU_FLAG;
				reverse_lookup->field[id].mask_range.u8 = NTS_ENCAP_GTPU_FLAG;
			} else {
				pure_ip = 1;
				lookup->field[id].value.u8 = 0;
				lookup->field[id].mask_range.u8 = NTS_ENCAP_GTPU_FLAG;
				reverse_lookup->field[id].value.u8 = 0;
				reverse_lookup->field[id].mask_range.u8 = NTS_ENCAP_GTPU_FLAG;
			}
			break;

		}
	}

	if (2 > (lookup_entries - encap_proto_present)) {
		NES_LOG(ERR, "Not enough lookup keys in %s\n", lookup_str);
		return NES_FAIL;
	}

	for (i = 0; i < lookup_entries; i++) {

		int id = nts_acl_cfg_get_lookup_field_id(cfg_lookup_entries[i].name);

		switch (id) {
		case NTS_ACL_CFG_FIELD_PRIO:
		{
			int32_t prio;
			if (NES_SUCCESS != nts_acl_cfg_parse_prio_val(
					cfg_lookup_entries[i].value, &prio)) {
				NES_LOG(ERR, "Bad lookup priority :%s\n",
					cfg_lookup_entries[i].value);
				return NES_FAIL;
			}
			lookup->data.category_mask = NTS_ACL_CFG_DEFAULT_CATEGORY;
			reverse_lookup->data.category_mask = NTS_ACL_CFG_DEFAULT_CATEGORY;
			lookup->data.priority = reverse_lookup->data.priority = prio;
			break;
		}
		case FIELD_ENCAP_PROTO_IPV4:
			break;
		case FIELD_QCI:
		case FIELD_SPID:
		{
			uint8_t val, range;
			if (1 == pure_ip)
				break;

			if (NES_SUCCESS != nts_acl_cfg_parse_u8_val_range(
					cfg_lookup_entries[i].value, &val, &range))
				return NES_FAIL;
			lookup->field[id].value.u8 = val;
			lookup->field[id].mask_range.u8 = range;
			reverse_lookup->field[id].value.u8 = val;
			reverse_lookup->field[id].mask_range.u8 = range;
			break;
		}
		case FIELD_TEID:
		{
			uint32_t val, range;
			if (1 == pure_ip)
				break;

			if (NES_SUCCESS != nts_acl_cfg_parse_u32_val_range(
					cfg_lookup_entries[i].value, &val, &range))
				return NES_FAIL;
			lookup->field[id].value.u32 = val;
			lookup->field[id].mask_range.u32 = range;
			reverse_lookup->field[id].value.u32 = val;
			reverse_lookup->field[id].mask_range.u32 = range;
			// TODO: Determine what should reversed teid be,
			// how to set it from config if its not the same for UL and DL
			break;
		}
		case FIELD_OUTER_SRC_IPV4:
		case FIELD_OUTER_DST_IPV4:
			if (1 == pure_ip)
				break;

		case FIELD_INNER_SRC_IPV4:
		case FIELD_INNER_DST_IPV4:
		{
			uint32_t ip, mask;
			if (NES_SUCCESS != nts_acl_cfg_parse_ipv4_addr(
					cfg_lookup_entries[i].value, &ip, &mask)) {
				NES_LOG(ERR, "Failed parsing ip\n");
				return NES_FAIL;
			}
			lookup->field[id].value.u32 = ip;
			lookup->field[id].mask_range.u32 = mask;
			id += (FIELD_OUTER_SRC_IPV4 == id || FIELD_INNER_SRC_IPV4 == id) ? 1 : -1;
			reverse_lookup->field[id].value.u32 = ip;
			reverse_lookup->field[id].mask_range.u32 = mask;
			break;
		}
		case FIELD_INNER_SRC_PORT_IPV4:
		case FIELD_INNER_DST_PORT_IPV4:
		{
			uint16_t port, range;
			if (NES_SUCCESS != nts_acl_cfg_parse_u16_val_range(
					cfg_lookup_entries[i].value, &port, &range))
				return NES_FAIL;
			lookup->field[id].value.u16 = port;
			lookup->field[id].mask_range.u16 = range;

			id = FIELD_INNER_SRC_PORT_IPV4 == id ?
				FIELD_INNER_DST_PORT_IPV4 : FIELD_INNER_SRC_PORT_IPV4;
			reverse_lookup->field[id].value.u16 = port;
			reverse_lookup->field[id].mask_range.u16 = range;

			break;
		}
		default:
		{
			NES_LOG(ERR, "Unknown lookup field %s\n", cfg_lookup_entries[i].name);
			return NES_FAIL;
		}
		}
	}
	return NES_SUCCESS;
}

static inline int
nts_acl_cfg_pair_overlaps(struct nts_acl_lookup_field *lookup_a,
	struct nts_acl_lookup_field *lookup_b) {
	if (NULL == lookup_a || NULL == lookup_b)
		return NTS_ACL_LOOKUPS_DIFFER;

	int i;
	if (0 == memcmp(lookup_a, lookup_b, sizeof (struct nts_acl_lookup_field)))
		return NTS_ACL_LOOKUPS_MATCH;

	for (i = 0; i < FIELD_NUMS_IPV4; i++) {
		switch (i) {
		case FIELD_OUTER_SRC_IPV4:
		case FIELD_OUTER_DST_IPV4:
		case FIELD_INNER_SRC_IPV4:
		case FIELD_INNER_DST_IPV4:
		{
			uint32_t shorter_mask =
				lookup_a->field[i].mask_range.u32 >
				lookup_b->field[i].mask_range.u32 ?
				lookup_b->field[i].mask_range.u32 :
				lookup_a->field[i].mask_range.u32;
			if ((lookup_a->field[i].value.u32 & gen_bit_mask(shorter_mask)) !=
					(lookup_b->field[i].value.u32 &
					gen_bit_mask(shorter_mask)))
				return NTS_ACL_LOOKUPS_DIFFER;
			break;
		}
		case FIELD_SPID:
		case FIELD_QCI:
		{
			if (!(lookup_a->field[i].value.u8 <= lookup_b->field[i].mask_range.u8 &&
					lookup_b->field[i].value.u8 <=
					lookup_a->field[i].mask_range.u8))
				return NTS_ACL_LOOKUPS_DIFFER;
			break;
		}
		case FIELD_INNER_SRC_PORT_IPV4:
		case FIELD_INNER_DST_PORT_IPV4:
		{
			if (!(lookup_a->field[i].value.u16 <= lookup_b->field[i].mask_range.u16 &&
					lookup_b->field[i].value.u16 <=
					lookup_a->field[i].mask_range.u16))
				return NTS_ACL_LOOKUPS_DIFFER;
			break;
		}
		case FIELD_TEID:
		{
			if (!(lookup_a->field[i].value.u32 <= lookup_b->field[i].mask_range.u32 &&
					lookup_b->field[i].value.u32 <=
					lookup_a->field[i].mask_range.u32))
				return NTS_ACL_LOOKUPS_DIFFER;
			break;
		}
		case FIELD_ENCAP_PROTO_IPV4:
		{
			if (lookup_a->field[i].value.u8 && lookup_a->field[i].mask_range.u8 !=
					lookup_b->field[i].value.u8 &&
					lookup_b->field[i].mask_range.u8)
				return NTS_ACL_LOOKUPS_DIFFER;
			break;
		}
		default:
		{
			break;
		}
		}
	}
	return NTS_ACL_LOOKUPS_OVERLAP;
}

int
nts_acl_cfg_overlaps(nes_acl_ctx_t* lookup_ctx, struct nts_acl_lookup_field *lookup) {
	int ret;
	uint32_t z;
	for (z = 0; z < lookup_ctx->max_entries; z++) {
		ret = nts_acl_cfg_pair_overlaps(
			(struct nts_acl_lookup_field*) lookup_ctx->rules[z], lookup);

		if (ret != NTS_ACL_LOOKUPS_DIFFER)
			return ret;
	}
	return NTS_ACL_LOOKUPS_DIFFER;
}
