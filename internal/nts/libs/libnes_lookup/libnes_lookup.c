/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

/**
 * @file libnes_lookup.c
 * @brief Implementation of nes library for lookups
 */

#include <assert.h>

#include <rte_hash_crc.h>
#include <rte_malloc.h>
#include <rte_hash.h>
#include <rte_memcpy.h>
#include <rte_jhash.h>
#include <rte_lcore.h>
#include <rte_errno.h>

#include "nes_common.h"
#include "libnes_lookup.h"

#define NES_LOOKUP_ENTRIES_PER_BUCKET_DEFAULT 8

static inline uint32_t
ipv4_hash_crc(const void *data, __attribute__((unused)) uint32_t data_len,
	uint32_t init_val)
{
	return rte_hash_crc_4byte(*(const uint32_t*)data, init_val);
}

static inline uint32_t
nes_jhash_1word(const void *a, __attribute__((unused)) uint32_t keys_num,
	uint32_t initval)
{
	return rte_jhash_1word(*(const uint32_t*)a, initval);
}

static inline uint64_t
nes_lookup_align_power_of_2(const uint64_t arg)
{
	uint64_t retval;
	if (rte_is_power_of_2(arg))
		return arg;

	if (arg > RTE_HASH_ENTRIES_MAX)
		return 0;

	for (retval = 1; retval <= arg; retval <<= 1)
		;
	return retval;
}

int nes_lookup_ctor(nes_lookup_table_t *lookup_table, nes_lookup_params_t *lookup_table_params)
{
	assert(lookup_table);
	assert(lookup_table_params);

	struct rte_hash_parameters hash_params = {
		.name    = lookup_table_params->name,
		.key_len = lookup_table_params->key_len,
		.hash_func_init_val = 0,
		.socket_id = rte_socket_id()
	};

	hash_params.entries = nes_lookup_align_power_of_2(lookup_table_params->number_of_entries);

	if (hash_params.key_len == 4)
		hash_params.hash_func = nes_jhash_1word;
	else if (hash_params.key_len%4 == 0)
		hash_params.hash_func = ipv4_hash_crc;
	else
		hash_params.hash_func = rte_jhash;

	lookup_table->hash = rte_hash_find_existing(lookup_table_params->name);

	if (NULL == lookup_table->hash)
		lookup_table->hash = rte_hash_create(&hash_params);
	else {
		rte_hash_reset(lookup_table->hash);
		if (NULL != lookup_table->entries)
			rte_free(lookup_table->entries);
	}

	if (NULL == lookup_table->hash) {
		NES_LOG(ERR,"Failed to create hash %s (%s)\n", lookup_table_params->name,
			rte_strerror(rte_errno));
		return NES_FAIL;
	}

	lookup_table->entries = rte_calloc(
		"Entries associated to hashes",
		hash_params.entries,
		sizeof(uintptr_t),
		0);

	if (NULL == lookup_table->entries) {
		NES_LOG(ERR,"Failed to create entry table for hash %s\n",
			lookup_table_params->name);
		return NES_FAIL;
	}
	memset(lookup_table->positions, 0, sizeof(lookup_table->positions));
	lookup_table->number_of_entries = lookup_table_params->number_of_entries;
	lookup_table->key_len           = lookup_table_params->key_len;
	lookup_table->entry_len         = lookup_table_params->entry_len;

	return NES_SUCCESS;
}

void nes_lookup_dtor(nes_lookup_table_t *lookup_table)
{
	uint32_t i;

	assert(lookup_table);

	rte_hash_free(lookup_table->hash);
	for (i = 0; i < lookup_table->number_of_entries; i++) {
		if (NULL != lookup_table->entries[i])
			rte_free(lookup_table->entries[i]);
	}

	rte_free(lookup_table->entries);
	lookup_table->hash    = NULL;
	lookup_table->entries = NULL;
}

int  nes_lookup_entry_get(nes_lookup_table_t *lookup_table, const void *key, void **pentry)
{
	void **lookup_entry;
	int32_t index;

	assert(lookup_table);
	assert(key);

	index = rte_hash_add_key(lookup_table->hash, key);

	switch (index) {
	case -EINVAL:
		NES_LOG(ERR, "the parameters are invalid");
		return NES_FAIL;
	case -ENOSPC:
		NES_LOG(ERR, "there is no space in the hash for this key");
		return NES_FAIL;
	default:
		break;
	}

	lookup_entry = &lookup_table->entries[index];
	if (NULL == *lookup_entry) {
		*lookup_entry = rte_malloc("Lookup entry", lookup_table->entry_len, 0);
		if (NULL == *lookup_entry) {
			NES_LOG(ERR,"Could not allocate lookup entry data\n");
			return NES_FAIL;
		}
	}
	*pentry = *lookup_entry;
	return NES_SUCCESS;
}

int nes_lookup_entry_find(nes_lookup_table_t *lookup_table, const void *key, void **pentry)
{
	int idx = rte_hash_lookup(lookup_table->hash, key);
	if (0 > idx) {
		*pentry = NULL;
		return NES_FAIL;
	}
	*pentry = lookup_table->entries[idx];
	return NES_SUCCESS;
}

int  nes_lookup_entry_add(nes_lookup_table_t *lookup_table, const void *key, void *entry)
{
	void *lookup_entry;

	assert(lookup_table);
	assert(key);

	if (NES_FAIL == nes_lookup_entry_get(lookup_table, key, &lookup_entry))
		return NES_FAIL;

	rte_memcpy(lookup_entry, entry, lookup_table->entry_len);
	return NES_SUCCESS;
}

int  nes_lookup_entry_del(nes_lookup_table_t *lookup_table, const void *key)
{
	int32_t index;

	assert(lookup_table);
	assert(key);

	index = rte_hash_del_key(lookup_table->hash, key);

	if (0 > index) {
		/* NES_LOG(ERR, "Could not find hash for the key\n"); */
		return NES_FAIL;
	}
	rte_free(lookup_table->entries[index]);
	lookup_table->entries[index] = NULL;
	return NES_SUCCESS;
}

int nes_lookup_bulk_get(nes_lookup_table_t *lookup_table, const void **keys, int num_keys,
	void **result)
{
	int i, j = 0;
	int num_keys_per_bulk, num_keys_to_go = 0;

	assert(lookup_table);
	assert(keys);

	for (j = 0; j < num_keys; j += RTE_HASH_LOOKUP_BULK_MAX) {

		num_keys_to_go = num_keys - j;

		if (num_keys_to_go < RTE_HASH_LOOKUP_BULK_MAX)
			num_keys_per_bulk = num_keys_to_go;
		else
			num_keys_per_bulk = RTE_HASH_LOOKUP_BULK_MAX;

		if (0 != rte_hash_lookup_bulk(lookup_table->hash, keys + j, num_keys_per_bulk,
				lookup_table->positions)) {
			NES_LOG(ERR,"Bulk lookup failed.\n");
			return NES_FAIL;
		}

		for (i = 0; i < num_keys_per_bulk; i++) {
			int32_t index = lookup_table->positions[i];
			result[j + i] = 0 <= index ?
				lookup_table->entries[index] :
				NULL;
		}
	}
	return NES_SUCCESS;
}
