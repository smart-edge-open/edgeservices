/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

/**
 * @file libnes_lookup.h
 * @brief Header file for libnes_lookup
 */

#ifndef _LIBNES_LOOKUP_H
#define _LIBNES_LOOKUP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_hash.h>

typedef struct nes_lookup_params_s {
	const char *name;
	uint32_t    number_of_entries;
	uint32_t    key_len;
	uint32_t    entry_len;
} nes_lookup_params_t;

typedef struct nes_lookup_table_s {
	struct rte_hash *hash;
	void           **entries;
	int32_t          positions[RTE_HASH_LOOKUP_BULK_MAX];
	uint32_t         number_of_entries;
	uint32_t         key_len;
	uint32_t         entry_len;
} nes_lookup_table_t;

/**
* Lookup constructor for NES lookups. Should be used once per instance.
*
* @param[in,out] lookup - hash based lookup instance
* @param[in]     lookup_params - parameters for creating the hash lookup instance
* @return        NES_SUCCESS on success, NES_FAIL if failed.
*/
int  nes_lookup_ctor(nes_lookup_table_t *lookup_struct, nes_lookup_params_t *lookup_params);
/**
* Lookup destructor for NES lookups. Should be used only after connstructor.
* Leaves a lookup instance unusable.
*
* @param[in] lookup - hash based lookup instance
*/
void nes_lookup_dtor(nes_lookup_table_t *);
/**
* Adds or updates an entry associated with the key. If such entry does not exist, creates it.
* Any contents of an entry are updated.
*
* @param[in] lookup - hash based lookup instance
* @param[in] key - a key for lookup
* @param[in] entry - contents of an entry
* @return    NES_SUCCESS on success, NES_FAIL if failed.
*/
int  nes_lookup_entry_add(nes_lookup_table_t *lookup, const void *key, void *entry);
/**
* Gets an entry associated with the key. If such entry does not exist, creates it.
*
* @param[in]  lookup - hash based lookup instance
* @param[in]  key - a key for lookup
* @param[out] pentry - an address of an address of an entry
* @return     NES_SUCCESS on success, NES_FAIL if failed.
*/
int  nes_lookup_entry_get(nes_lookup_table_t *lookup, const void *key, void **pentry);
/**
* Gets an entry associated with the key.
*
* @param[in]  lookup - hash based lookup instance
* @param[in]  key - a key for lookup
* @param[out] pentry - an address of an address of an entry
* @return     NES_SUCCESS on success, NES_FAIL if failed.
*/
int  nes_lookup_entry_find(nes_lookup_table_t *lookup, const void *key, void **pentry);
/**
* Deletes the key and entry associated with the key by freeing entry contents.
* Fails if entry not found.
*
* @param[in] lookup - hash based lookup instance
* @param[in] key - a key for lookup
* @return    NES_SUCCESS on success, NES_FAIL if failed.
*/
int  nes_lookup_entry_del(nes_lookup_table_t *lookup, const void *key);
/**
* Gets a number of entries associated with the keys in one call.
* If number of entries is greater than RTE_HASH_LOOKUP_BULK_MAX function
* internally splits the query appropriately . If a key is not foung, corresponding entry
* is set NULL
*
* @param[in]  lookup - hash based lookup instance
* @param[in]  keys - a keys for lookup
* @param[in]  number - number of lookup keys (can be larger than RTE_HASH_LOOKUP_BULK_MAX)
* @param[out] pentries - entries associated with keys;
*                        NULL means corresponding key was not not found
* @return     NES_SUCCESS on success, NES_FAIL if failed.
*/
int nes_lookup_bulk_get(nes_lookup_table_t *lookup, const void **keys, int number, void **pentries);

#ifdef __cplusplus
}
#endif

#endif /* _LIBNES_LOOKUP_H */
