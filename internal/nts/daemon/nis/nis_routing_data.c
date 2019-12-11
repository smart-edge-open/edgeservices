/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

/**
 * @file nis_routing_data.c
 * @brief Implementation of nis routing data
 */

#include "libnes_lookup.h"
#include "nis_routing_data.h"
#include "nes_capacity.h"

NES_STATIC nes_lookup_table_t *nis_routing_data_table;

int
nis_routing_data_get(const nis_routing_data_key_t *key, nis_routing_data_t **data) {
	assert(nis_routing_data_table);

	if (NULL == key || NULL == data)
		return NES_FAIL;

	return nes_lookup_entry_find(nis_routing_data_table, key, (void**) data);
}

int
nis_routing_data_init(void) {
	if (NULL != nis_routing_data_table)
		return NES_FAIL;

	struct nes_lookup_params_s lookup_table_params = {
		.name = "nis_routing_data_table",
		/* Double the exact maximum size to avoid hash conflicts */
		.number_of_entries = 2 * NES_MAX_RB,
		.key_len = sizeof (nis_routing_data_key_t),
		.entry_len = sizeof (nis_routing_data_t)
	};
	nis_routing_data_table =
		rte_malloc("Routing data lookup table", sizeof (nes_lookup_table_t), 0);
	if (NULL == nis_routing_data_table) {
		NES_LOG(ERR, "Failed to allocate routing data lookup table\n");
		return NES_FAIL;
	}
	if (NES_SUCCESS != nes_lookup_ctor(nis_routing_data_table, &lookup_table_params)) {
		NES_LOG(ERR, "Failed to create routing data lookup table\n");
		return NES_FAIL;
	}
	return NES_SUCCESS;
}

void
nis_routing_data_dtor(void) {
	assert(nis_routing_data_table);

	nes_lookup_dtor(nis_routing_data_table);
	rte_free(nis_routing_data_table);
	nis_routing_data_table = NULL;
}

int
nis_routing_data_add(const nis_routing_data_key_t *key, nis_routing_data_t *data) {
	assert(nis_routing_data_table);

	nis_routing_data_t *entry = NULL;

	if (NULL == key || NULL == data)
		return NES_FAIL;

	nes_lookup_entry_find(nis_routing_data_table, key, (void**) &entry);
	if (NULL == entry)
		return nes_lookup_entry_add(nis_routing_data_table, key, data);
	else
		rte_memcpy(entry, data, sizeof (nis_routing_data_t));

	return NES_SUCCESS;
}

int
nis_routing_data_del(const nis_routing_data_key_t *key) {
	assert(nis_routing_data_table);

	if (NULL == key)
		return NES_FAIL;

	return nes_lookup_entry_del(nis_routing_data_table, key);
}
