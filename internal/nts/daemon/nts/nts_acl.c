/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

/**
 * @file nts_acl.c
 * @brief implementation of lookups using libnes_acl
 */

#include <assert.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include <rte_acl.h>
#include <rte_ip.h>
#include <rte_ether.h>

#include "nes_capacity.h"
#include "nts/nts_acl.h"
#include "nes_common.h"
#include "nts/nts_route.h"
#include "nes_ring_lookup.h"
#include "nts/nts_acl_cfg.h"
#include "libnes_cfgfile.h"
#include "libnes_sq.h"
#include "nts_edit.h"
#include "dns/nes_dns_config.h"
#include "dns/nes_dns.h"

#ifdef UNIT_TESTS
	#include "nts_acl_decl.h"
#endif

#define NTS_ACL_NAME "NTS_ACL_LOOKUP"

static struct rte_acl_field_def nts_acl_lookup_fields[FIELD_NUMS_IPV4] = {
	{
		.type = RTE_ACL_FIELD_TYPE_BITMASK,
		.size = sizeof (uint8_t),
		.field_index = FIELD_ENCAP_PROTO_IPV4,
		.input_index = ACL_ENCAP_PROTO,
		.offset = offsetof(nts_acl_tuple_t, encap_flag),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_RANGE,
		.size = sizeof (uint8_t),
		.field_index = FIELD_QCI,
		.input_index = ACL_QCI_SPID_PAD,
		.offset = offsetof(nts_acl_tuple_t, qci),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_RANGE,
		.size = sizeof (uint8_t),
		.field_index = FIELD_SPID,
		.input_index = ACL_QCI_SPID_PAD,
		.offset = offsetof(nts_acl_tuple_t, spid),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_BITMASK,
		.size = sizeof (uint16_t),
		.field_index = FIELD_PADDING,
		.input_index = ACL_QCI_SPID_PAD,
		.offset = offsetof(nts_acl_tuple_t, _padding),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_RANGE,
		.size = sizeof (uint32_t),
		.field_index = FIELD_TEID,
		.input_index = ACL_TEID,
		.offset = offsetof(nts_acl_tuple_t, teid),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_MASK,
		.size = sizeof (uint32_t),
		.field_index = FIELD_OUTER_SRC_IPV4,
		.input_index = ACL_OUTER_SRC_IP,
		.offset = offsetof(nts_acl_tuple_t, outer_ip_src),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_MASK,
		.size = sizeof (uint32_t),
		.field_index = FIELD_OUTER_DST_IPV4,
		.input_index = ACL_OUTER_DST_IP,
		.offset = offsetof(nts_acl_tuple_t, outer_ip_dst),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_MASK,
		.size = sizeof (uint32_t),
		.field_index = FIELD_INNER_SRC_IPV4,
		.input_index = ACL_INNER_SRC_IP,
		.offset = offsetof(nts_acl_tuple_t, inner_ip_src),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_MASK,
		.size = sizeof (uint32_t),
		.field_index = FIELD_INNER_DST_IPV4,
		.input_index = ACL_INNER_DST_IP,
		.offset = offsetof(nts_acl_tuple_t, inner_ip_dst),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_RANGE,
		.size = sizeof (uint16_t),
		.field_index = FIELD_INNER_SRC_PORT_IPV4,
		.input_index = ACL_INNER_PORTS,
		.offset = offsetof(nts_acl_tuple_t, inner_port_src),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_RANGE,
		.size = sizeof (uint16_t),
		.field_index = FIELD_INNER_DST_PORT_IPV4,
		.input_index = ACL_INNER_PORTS,
		.offset = offsetof(nts_acl_tuple_t, inner_port_dst),
	}
};

int
nts_acl_lookup_init(nes_acl_ctx_t* lookup_ctx) {
	assert(lookup_ctx);

	if (NES_SUCCESS != nes_acl_ctor(lookup_ctx, NTS_ACL_NAME, sizeof (nes_sq_t),
			NES_MAX_ROUTING_RULES, nts_acl_lookup_fields,
			RTE_DIM(nts_acl_lookup_fields))) {
		NES_LOG(ERR, "nes_acl constructor failed\n");
		return NES_FAIL;
	}

	if (NES_SUCCESS != is_avp_enabled()) {
		if (NES_SUCCESS != nts_acl_cfg_init_vm_rings_names()) {
			NES_LOG(ERR, "Failed to initialize lookup rings names.\n");
			return NES_FAIL;
		}
	}

	if (NES_SUCCESS != nts_acl_add_dataplane_entries(lookup_ctx)) {
		NES_LOG(ERR, "Failed to add dataplane rules.\n");
		return NES_FAIL;
	}

	if (NES_SUCCESS != is_lbp_enabled())
		NES_LOG(INFO, "LBP is disabled\n");


	return NES_SUCCESS;
}

NES_STATIC int
nes_acl_add_entry(nes_sq_t *queue, nts_route_entry_t *entry) {

	nts_route_entry_t *route = NULL;
#ifdef MIRROR
	nes_sq_node_t *item = NULL, *prev_item = NULL;
	if (nts_route_entry_edit_get(entry) == NTS_EDIT_MIRROR) {
		// add mirror
		if (0 == queue->cnt) {
			nts_route_entry_edit_set(entry, NTS_EDIT_MIRROR_LAST);
			if (NES_SUCCESS != nes_sq_enq(queue, entry)) {
				rte_free(entry);
				return NES_FAIL;
			}
			return NES_SUCCESS;
		} else {
			// add a new one as last NTS_EDIT_MIRROR
			NES_SQ_FOREACH(item, queue) {
				route = nes_sq_data(item);
				if (nts_route_entry_edit_get(route) == NTS_EDIT_MIRROR) {
					prev_item = item;
					continue;
				}
			}
			nes_sq_node_t *newnode = rte_malloc(NULL,sizeof(*newnode),0);
			if (NULL == newnode)
				return NES_FAIL;

			newnode->data = entry;

			if (NULL != prev_item) {
				newnode->next = prev_item->next;
				prev_item->next = newnode;
			} else {
				newnode->next = queue->head;
				queue->head = newnode;
			}

			queue->cnt++;
			return NES_SUCCESS;
		}
	} else {
#endif
		// add decap
		if (0 == queue->cnt) {
			if (NES_SUCCESS != nes_sq_enq(queue, entry)) {
				rte_free(entry);
				return NES_FAIL;
			}
			return NES_SUCCESS;
		} else {
			route = nes_sq_data(queue->tail);
			if (nts_route_entry_edit_get(route) == NTS_EDIT_MIRROR_LAST)
				nts_route_entry_edit_set(route, NTS_EDIT_MIRROR);
			else {
				// There is a routing already or some bad mirror
				NES_LOG(ERR, "Route already exists\n");
				rte_free(entry);
				return NES_FAIL;
			}
			if (NES_SUCCESS != nes_sq_enq(queue, entry)) {
				rte_free(entry);
				return NES_FAIL;
			}
			return NES_SUCCESS;
		}
#ifdef MIRROR
	}
#endif
	return NES_FAIL;
}

NES_STATIC int
nts_acl_lookup_add_impl(nes_acl_ctx_t* lookup_ctx, char* lookup_str, const char* ring_name,
	struct ether_addr mac_addr, nts_edit_modes_t edit_mode) {
	assert(lookup_ctx);

	struct nts_acl_lookup_field upstream_rule, downstream_rule;
	struct nts_acl_lookup_field *rule_ptr;
	nts_route_entry_t *upstream_route = NULL, *downstream_route = NULL;
	nes_sq_t *upstream_entry = NULL, *downstream_entry = NULL;
	int rule_id, rules_differ;

#ifndef MIRROR
	if (edit_mode == NTS_EDIT_MIRROR) {
		NES_LOG(ERR, "Mirroring is disabled! failed to add an entry\n");
		return NES_FAIL;
	}
#endif

	if (NULL == lookup_str) {
		NES_LOG(ERR, "Lookup string is empty\n");
		return NES_FAIL;
	}

	if ((upstream_route = rte_malloc("route entry", sizeof (nts_route_entry_t), 0)) == NULL ||
			(downstream_route = rte_malloc("route entry",
				sizeof (nts_route_entry_t), 0)) == NULL) {
		rte_free(upstream_route);
		NES_LOG(ERR, "Unable to allocate new route entries\n");
		return NES_FAIL;
	}

	if (NES_SUCCESS != nts_acl_cfg_lookup_prepare(&upstream_rule, &downstream_rule,
			lookup_str)) {
		NES_LOG(ERR, "Failed parsing: %s\n", lookup_str);
		rte_free(upstream_route);
		rte_free(downstream_route);
		return NES_FAIL;
	}
	rules_differ = memcmp(&upstream_rule, &downstream_rule, sizeof (downstream_rule));
	if (NTS_ACL_LOOKUPS_DIFFER != nts_acl_cfg_overlaps(lookup_ctx, &upstream_rule) ||
			NTS_ACL_LOOKUPS_DIFFER != nts_acl_cfg_overlaps(lookup_ctx,
				&downstream_rule))
		NES_LOG(WARNING, "Overlapping rule: %s\n", lookup_str);

	if (NES_SUCCESS != nts_acl_cfg_route_entry_prepare(ring_name, mac_addr,
			upstream_route, edit_mode)) {
		if (NULL == ring_name)
			NES_LOG(ERR, "Failed to add route entry\n");
		else
			NES_LOG(ERR, "Failed to add route entry for %s\n", ring_name);
		return NES_FAIL;
	}
	// upstream and downstream routes are the same
	memcpy(downstream_route, upstream_route, sizeof (*upstream_route));

	rule_id = nes_acl_find_rule_id(lookup_ctx, (struct rte_acl_rule*) &upstream_rule);
	if (rule_id >= 0) {
		upstream_entry = lookup_ctx->entries[
			lookup_ctx->rules[rule_id]->data.userdata - USER_DATA_OFFSET];
	}
	if (rules_differ) {
		rule_id = nes_acl_find_rule_id(lookup_ctx, (struct rte_acl_rule*) &downstream_rule);
		if (rule_id >= 0) {
			downstream_entry = lookup_ctx->entries[
				lookup_ctx->rules[rule_id]->data.userdata - USER_DATA_OFFSET];
		}
	}

	if (NULL == upstream_entry) {
		if ((upstream_entry = rte_malloc("route entry",
				lookup_ctx->entry_size, 0)) == NULL) {
			NES_LOG(ERR, "Failed to allocate new entry\n");
			return NES_FAIL;
		}
		nes_sq_ctor(upstream_entry);

		rule_ptr = &upstream_rule;
		if (NES_SUCCESS != nes_acl_add_entries(lookup_ctx, (void**) &upstream_entry,
				(struct rte_acl_rule**) &rule_ptr, 1))
			NES_LOG(ERR, "Failed to add upstream entry\n");

		// entry is copied and not used anymore
		rte_free(upstream_entry);
		rule_id = nes_acl_find_rule_id(lookup_ctx, (struct rte_acl_rule*) &upstream_rule);
		upstream_entry = lookup_ctx->entries[
			lookup_ctx->rules[rule_id]->data.userdata - USER_DATA_OFFSET];
	}

	if (NULL == downstream_entry && rules_differ) {
		if ((downstream_entry = rte_malloc("route entry",
				lookup_ctx->entry_size, 0)) == NULL) {
			NES_LOG(ERR, "Failed to allocate new entry\n");
			return NES_FAIL;
		}
		nes_sq_ctor(downstream_entry);
		rule_ptr = &downstream_rule;
		if (NES_SUCCESS != nes_acl_add_entries(lookup_ctx, (void**) &downstream_entry,
				(struct rte_acl_rule**) &rule_ptr, 1))
			NES_LOG(ERR, "Failed to add upstream entry\n");

		// entry is copied and not used anymore
		rte_free(downstream_entry);
		rule_id = nes_acl_find_rule_id(lookup_ctx, (struct rte_acl_rule*) &downstream_rule);
		downstream_entry = lookup_ctx->entries[
			lookup_ctx->rules[rule_id]->data.userdata - USER_DATA_OFFSET];
	}

	// don't add the downstream entry when the rule is the same
	if (NES_SUCCESS != nes_acl_add_entry(upstream_entry, upstream_route) ||
			((rules_differ &&
			(NES_SUCCESS != nes_acl_add_entry(downstream_entry, downstream_route))))) {
		NES_LOG(ERR, "Could not add routing entry");
		return NES_FAIL;
	}
	return NES_SUCCESS;
}

static int
nts_acl_lookup_add_one_dir(nes_acl_ctx_t *lookup_ctx, char *lookup_str, const char *ring_name,
	struct ether_addr mac_addr, nts_edit_modes_t edit_mode) {
	assert(lookup_ctx);

	struct nts_acl_lookup_field rule, ignored_rule;
	struct nts_acl_lookup_field *rule_ptr;
	nts_route_entry_t *route = NULL;
	nes_sq_t *entry = NULL;
	int rule_id;

	if (NULL == lookup_str) {
		NES_LOG(ERR, "Lookup string is empty\n");
		return NES_FAIL;
	}

	if (NES_SUCCESS != nts_acl_cfg_lookup_prepare(&rule, &ignored_rule,
			lookup_str)) {
		NES_LOG(ERR, "Failed parsing: %s\n", lookup_str);
		return NES_FAIL;
	}
	if (NTS_ACL_LOOKUPS_DIFFER != nts_acl_cfg_overlaps(lookup_ctx, &rule))
		NES_LOG(WARNING, "Overlapping rule: %s\n", lookup_str);

	if ((route = rte_malloc("route entry", sizeof (nts_route_entry_t), 0)) == NULL) {
		NES_LOG(ERR, "Unable to allocate new route entries\n");
		return NES_FAIL;
	}

	if (NES_SUCCESS != nts_acl_cfg_route_entry_prepare(ring_name, mac_addr,
			route, edit_mode)) {
		if (NULL == ring_name)
			NES_LOG(ERR, "Failed to add route entry\n");
		else
			NES_LOG(ERR, "Failed to add route entry for %s\n", ring_name);
		return NES_FAIL;
	}

	rule_id = nes_acl_find_rule_id(lookup_ctx, (struct rte_acl_rule *) &rule);
	if (rule_id >= 0) {
		entry = lookup_ctx->entries[
			lookup_ctx->rules[rule_id]->data.userdata - USER_DATA_OFFSET];
	}

	if (NULL == entry) {
		if ((entry = rte_malloc("route entry",
				lookup_ctx->entry_size, 0)) == NULL) {
			NES_LOG(ERR, "Failed to allocate new entry\n");
			return NES_FAIL;
		}
		nes_sq_ctor(entry);

		rule_ptr = &rule;
		if (NES_SUCCESS != nes_acl_add_entries(lookup_ctx, (void **) &entry,
				(struct rte_acl_rule **) &rule_ptr, 1))
			NES_LOG(ERR, "Failed to add upstream entry\n");

		// entry is copied and not used anymore
		rte_free(entry);
		rule_id = nes_acl_find_rule_id(lookup_ctx, (struct rte_acl_rule *) &rule);
		entry = lookup_ctx->entries[
			lookup_ctx->rules[rule_id]->data.userdata - USER_DATA_OFFSET];
	}

	if (NES_SUCCESS != nes_acl_add_entry(entry, route)) {
		NES_LOG(ERR, "Could not add routing entry");
		return NES_FAIL;
	}
	return NES_SUCCESS;
}

static int
nts_acl_add_single_dataplane_entry(nes_acl_ctx_t *lookup_ctx, char *port_name, char *tx_ring_name)
{
	struct rte_cfgfile_entry  cfg_entries[MAX_LOOKUPS_PER_VM];
	int i;
	struct ether_addr ignored_mac_addr = {{0}};

	if (NES_SUCCESS != nes_cfgfile_get_entries(port_name, cfg_entries, MAX_LOOKUPS_PER_VM)) {
		NES_LOG(ERR, "Failed to get entries for %s\n", port_name);
		return NES_FAIL;
	}

	for (i = 0; i < nes_cfgfile_section_num_entries(port_name); i++) {
		if (strncmp(cfg_entries[i].name, NTS_ACL_CFG_ENTRY_NAME, sizeof(NTS_ACL_CFG_ENTRY_NAME)) == 0) {
			if (NES_SUCCESS != nts_acl_lookup_add_one_dir(lookup_ctx, cfg_entries[i].value,
					tx_ring_name, ignored_mac_addr, NTS_EDIT_NULL_CALLBACK)) {
				NES_LOG(ERR, "Failed to add a rule from %s\n", port_name);
				return NES_FAIL;
			}
		}
	}
	return NES_SUCCESS;
}

static int
nts_acl_add_single_lbp_entry(nes_acl_ctx_t* lookup_ctx, char *port_name, char *tx_ring_name)
{
	struct rte_cfgfile_entry  cfg_entries[MAX_LOOKUPS_PER_VM];
	uint8_t is_mirror = 0;
	const char *buffer;
	int i;
	struct ether_addr mac_addr;

	if (NES_SUCCESS != nes_cfgfile_get_entries(port_name, cfg_entries, MAX_LOOKUPS_PER_VM)) {
		NES_LOG(ERR, "Failed to get entries for LBP\n");
		return NES_FAIL;
	}
	if (NES_SUCCESS != nes_cfgfile_entry(port_name, "lbp-mac", &buffer)) {
		NES_LOG(ERR, "Missing: section %s, entry %s, in config file.\n",
			port_name, "lbp-mac");
		return NES_FAIL;
	}
	if (NES_SUCCESS != nes_acl_ether_aton(buffer, &mac_addr)) {
		NES_LOG(ERR, "Invalid mac address %s\n", buffer);
		return NES_FAIL;
	}
	for (i = 0; i < nes_cfgfile_section_num_entries(port_name); i++) {
		is_mirror = strcmp(cfg_entries[i].name, NTS_ACL_CFG_ENTRY_MIRROR_NAME) == 0;
		if (strcmp(cfg_entries[i].name, NTS_ACL_CFG_ENTRY_NAME) == 0 || is_mirror) {
			if (NES_SUCCESS != nts_acl_lookup_add_impl(lookup_ctx, cfg_entries[i].value,
					tx_ring_name, mac_addr, is_mirror ?
					NTS_EDIT_MIRROR : NTS_EDIT_DECAP_ONLY)) {
				NES_LOG(ERR, "Failed to add LBP route from %s\n", port_name);
				return NES_FAIL;
			}
		}
	}
	return NES_SUCCESS;
}

int nts_acl_add_dataplane_entries(nes_acl_ctx_t *lookup_ctx)
{
	assert(entries);
	assert(rules);

	const char *buffer;
	int portid = 0;
	char tx_ring_name[NES_RING_NAME_LEN];
	static char port_name[PORT_NAME_SIZE];

	while (1) {
		snprintf(port_name, sizeof(port_name)/sizeof(port_name[0]),
			PORT_SECTION_NAME"%d", portid);
		if (NES_SUCCESS != nes_cfgfile_has_section(port_name))
			break;

		if (NES_SUCCESS == nes_cfgfile_entry(port_name, TRAFFIC_DIRECTION, &buffer)) {
			snprintf(tx_ring_name, sizeof(tx_ring_name),
			PORT_TX_QUEUE_NAME_TEMPLATE, portid);
			if (0 == strncmp(buffer, TRAFFIC_DIRECTION_LBP,
					sizeof(TRAFFIC_DIRECTION_LBP))) {
				if (NES_SUCCESS != nts_acl_add_single_lbp_entry(lookup_ctx,
						port_name, tx_ring_name))
					return NES_FAIL;
			} else if (NES_SUCCESS != nts_acl_add_single_dataplane_entry(lookup_ctx,
					port_name, tx_ring_name))
				return NES_FAIL;
		}
		portid++;
	}
	return NES_SUCCESS;
}

int
nts_acl_lookup_add_vm(nes_acl_ctx_t* lookup_ctx, char* lookup_str,
	struct ether_addr vm_mac_addr, nts_edit_modes_t edit_mode) {
	if (NES_SUCCESS != is_avp_enabled()) {
		return nts_acl_lookup_add_impl(lookup_ctx, lookup_str, NULL,
			vm_mac_addr, edit_mode);
	} else {
		return nts_acl_lookup_add_impl(lookup_ctx, lookup_str, AVP_TX_RING_NAME,
			vm_mac_addr, edit_mode);
	}
}

int
nts_acl_lookup_remove(nes_acl_ctx_t* lookup_ctx, char* lookup_str) {
	assert(lookup_ctx);

	struct nts_acl_lookup_field lookup_field;
	struct nts_acl_lookup_field revese_lookup_field;
	int rules_differ;

	if (NULL == lookup_str) {
		NES_LOG(ERR, "Lookup string is empty\n");
		return NES_FAIL;
	}

	if (NES_SUCCESS != nts_acl_cfg_lookup_prepare(&lookup_field, &revese_lookup_field,
			lookup_str)) {
		NES_LOG(ERR, "Failed parsing: %s\n", lookup_str);
		return NES_FAIL;
	}
	rules_differ = memcmp(&lookup_field, &revese_lookup_field, sizeof (revese_lookup_field));

	if (NES_SUCCESS != nes_acl_del_entry(lookup_ctx, (struct rte_acl_rule*) &lookup_field) ||
			(rules_differ && NES_SUCCESS != nes_acl_del_entry(lookup_ctx,
				(struct rte_acl_rule*) &revese_lookup_field)))
		return NES_FAIL;

	return NES_SUCCESS;
}

int
nts_acl_lookup_find(nes_acl_ctx_t* lookup_ctx, char* lookup_str, nes_sq_t **upstream_route,
	nes_sq_t **downstream_route) {
	assert(lookup_ctx);

	struct nts_acl_lookup_field lookup_field;
	struct nts_acl_lookup_field revese_lookup_field;
	int i, j;

	*upstream_route = *downstream_route = NULL;
	if (NULL == lookup_str) {
		NES_LOG(ERR, "Lookup string is empty\n");
		return NES_FAIL;
	}

	if (NES_SUCCESS != nts_acl_cfg_lookup_prepare(&lookup_field, &revese_lookup_field,
			lookup_str)) {
		NES_LOG(ERR, "Failed parsing: %s\n", lookup_str);
		return NES_FAIL;
	}
	i = nes_acl_find_rule_id(lookup_ctx, (struct rte_acl_rule*) &lookup_field);
	j = nes_acl_find_rule_id(lookup_ctx, (struct rte_acl_rule*) &revese_lookup_field);
	if (i < 0 || j < 0)
		return NES_FAIL;


	i = lookup_ctx->rules[i]->data.userdata - USER_DATA_OFFSET;
	j = lookup_ctx->rules[j]->data.userdata - USER_DATA_OFFSET;
	*upstream_route = lookup_ctx->entries[i];
	*downstream_route = (i == j) ? NULL : lookup_ctx->entries[j];
	return NES_SUCCESS;
}

void nts_acl_flush(nes_acl_ctx_t* lookup_ctx) {
	uint32_t i;
	rte_spinlock_lock(&lookup_ctx->acl_lock);
	for (i = 0; i < lookup_ctx->max_entries; i++) {
		if (NULL != lookup_ctx->entries[i]) {
			nes_sq_dtor_free(lookup_ctx->entries[i]);
			rte_free(lookup_ctx->entries[i]);
			lookup_ctx->entries[i] = NULL;
		}
		if (NULL != lookup_ctx->rules[i]) {
			rte_free(lookup_ctx->rules[i]);
			lookup_ctx->rules[i] = NULL;
		}
	}
	lookup_ctx->entries_cnt = 0;
	if (NULL != lookup_ctx->acl_ctx) {
		rte_acl_free(lookup_ctx->acl_ctx);
		lookup_ctx->acl_ctx = NULL;
	}
	rte_spinlock_unlock(&lookup_ctx->acl_lock);

	if (NES_SUCCESS == nes_cfgfile_has_section(DNS_AGENT_SECTION)) {
		if (NES_SUCCESS != nes_dns_agent_add_routings(lookup_ctx))
			NES_LOG(ERR, "Failed to setup DNS routing\n");
	}

	if (NES_SUCCESS != nts_acl_add_dataplane_entries(lookup_ctx))
		NES_LOG(ERR, "Failed to add dataplane entries\n");
}

void
nts_acl_lookup_dtor(nes_acl_ctx_t* lookup_ctx) {
	assert(lookup_ctx);

	uint32_t i;
	for (i = 0; i < lookup_ctx->max_entries; i++) {
		if (NULL != lookup_ctx->entries[i])
			nes_sq_dtor_free(lookup_ctx->entries[i]);
	}
	nts_acl_cfg_free_vm_rings_names();
	nes_acl_dtor(lookup_ctx);
}
